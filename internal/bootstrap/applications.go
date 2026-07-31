package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

func (b ExecutorBackend) ApplicationVersion(ctx context.Context, req ports.ApplicationVersionRequest) (ports.ApplicationVersionResponse, error) {
	app, err := b.deploymentApp(req.Application)
	if err != nil {
		return ports.ApplicationVersionResponse{}, err
	}
	current, err := b.currentApplicationVersion(ctx, req.Application, app)
	if err != nil {
		return ports.ApplicationVersionResponse{}, err
	}
	available, _ := b.availableApplicationVersion(ctx, req.Application, app)
	current.AvailableVersion = available.AvailableVersion
	current.AvailableDigest = available.AvailableDigest
	current.AvailableCommit = available.AvailableCommit
	return current, nil
}

func (b ExecutorBackend) CheckApplicationUpdate(ctx context.Context, req ports.ApplicationVersionRequest) (ports.ApplicationUpdateCheckResponse, error) {
	version, err := b.ApplicationVersion(ctx, req)
	if err != nil {
		return ports.ApplicationUpdateCheckResponse{}, err
	}
	current := comparableVersion(version.CurrentVersion, version.CurrentDigest, version.CurrentCommit)
	available := comparableVersion(version.AvailableVersion, version.AvailableDigest, version.AvailableCommit)
	return ports.ApplicationUpdateCheckResponse{
		Application:      req.Application,
		UpdateAvailable:  available != "" && current != available,
		CurrentVersion:   version.CurrentVersion,
		AvailableVersion: version.AvailableVersion,
		CurrentDigest:    version.CurrentDigest,
		AvailableDigest:  version.AvailableDigest,
		CurrentCommit:    version.CurrentCommit,
		AvailableCommit:  version.AvailableCommit,
	}, nil
}

func (b ExecutorBackend) UpdateApplication(ctx context.Context, req ports.UpdateApplicationRequest) (ports.ApplicationDeploymentResponse, error) {
	if req.OperationID == "" {
		return ports.ApplicationDeploymentResponse{}, errors.New("operation_id is required")
	}
	app, err := b.deploymentApp(req.Application)
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	current, err := b.currentApplicationVersion(ctx, req.Application, app)
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	available, err := b.availableApplicationVersion(ctx, req.Application, app)
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	targetVersion := firstNonEmpty(req.TargetVersion, available.AvailableVersion)
	targetDigest := firstNonEmpty(req.TargetDigest, available.AvailableDigest)
	targetCommit := firstNonEmpty(req.TargetCommit, available.AvailableCommit)
	if targetVersion == "" && targetDigest == "" && targetCommit == "" {
		return ports.ApplicationDeploymentResponse{}, errors.New("no available application version was found")
	}
	if req.DryRun {
		return ports.ApplicationDeploymentResponse{Status: "simulated", Action: "update_application", Application: req.Application, PreviousVersion: current.CurrentVersion, CurrentVersion: current.CurrentVersion, TargetVersion: targetVersion, ImageDigest: targetDigest, CommitHash: targetCommit, WouldRun: b.applicationWouldRun(app, targetVersion, targetDigest, targetCommit)}, nil
	}
	out, err := b.applyApplicationVersion(ctx, req.Application, app, targetVersion, targetDigest, targetCommit, "update_application")
	if err != nil {
		rollbackOut, rollbackErr := b.applyApplicationVersion(ctx, req.Application, app, current.CurrentVersion, current.CurrentDigest, current.CurrentCommit, "rollback_application")
		out = ports.ApplicationDeploymentResponse{Status: "failed", Action: "update_application", Application: req.Application, PreviousVersion: current.CurrentVersion, TargetVersion: targetVersion, ImageDigest: targetDigest, CommitHash: targetCommit, RollbackAttempted: true}
		if rollbackErr != nil {
			out.RollbackStatus = "failed: " + rollbackErr.Error()
			return out, err
		}
		out.RollbackStatus = rollbackOut.Status
		return out, err
	}
	out.PreviousVersion = current.CurrentVersion
	out.TargetVersion = targetVersion
	return out, nil
}

func (b ExecutorBackend) RollbackApplication(ctx context.Context, req ports.RollbackApplicationRequest) (ports.ApplicationDeploymentResponse, error) {
	if req.OperationID == "" {
		return ports.ApplicationDeploymentResponse{}, errors.New("operation_id is required")
	}
	app, err := b.deploymentApp(req.Application)
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	current, err := b.currentApplicationVersion(ctx, req.Application, app)
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	if req.DryRun {
		return ports.ApplicationDeploymentResponse{Status: "simulated", Action: "rollback_application", Application: req.Application, PreviousVersion: current.CurrentVersion, CurrentVersion: current.CurrentVersion, TargetVersion: req.TargetVersion, ImageDigest: req.TargetDigest, CommitHash: req.TargetCommit, WouldRun: b.applicationWouldRun(app, req.TargetVersion, req.TargetDigest, req.TargetCommit)}, nil
	}
	out, err := b.applyApplicationVersion(ctx, req.Application, app, req.TargetVersion, req.TargetDigest, req.TargetCommit, "rollback_application")
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	out.PreviousVersion = current.CurrentVersion
	return out, nil
}

func (b ExecutorBackend) deploymentApp(alias string) (config.ApplicationConfig, error) {
	app, ok := b.Config.Applications[alias]
	if !ok || app.Kind == "" {
		return config.ApplicationConfig{}, fmt.Errorf("application %q is not configured for deployments", alias)
	}
	return app, nil
}

func (b ExecutorBackend) currentApplicationVersion(ctx context.Context, alias string, app config.ApplicationConfig) (ports.ApplicationVersionResponse, error) {
	out := ports.ApplicationVersionResponse{Application: alias, Kind: app.Kind, Channel: app.Image.Channel, Source: app.Repository.Type}
	switch app.Kind {
	case "container":
		st, err := b.ContainerStatus(ctx, app.ContainerName)
		if err != nil {
			return ports.ApplicationVersionResponse{}, err
		}
		out.CurrentVersion = st.Image
		out.CurrentDigest = st.ImageID
	case "service":
		if app.Version.File != "" {
			data, err := os.ReadFile(app.Version.File)
			if err != nil {
				return ports.ApplicationVersionResponse{}, err
			}
			out.CurrentVersion = strings.TrimSpace(string(data))
		}
		if app.Repository.Path != "" && b.Git != nil {
			commit, err := b.Git.CurrentCommit(ctx, app.Repository.Path)
			if err != nil {
				return ports.ApplicationVersionResponse{}, err
			}
			out.CurrentCommit = commit
			if out.CurrentVersion == "" {
				out.CurrentVersion = shortCommit(commit)
			}
		}
	default:
		return ports.ApplicationVersionResponse{}, fmt.Errorf("application kind %q is not supported", app.Kind)
	}
	return out, nil
}

func (b ExecutorBackend) availableApplicationVersion(ctx context.Context, alias string, app config.ApplicationConfig) (ports.ApplicationVersionResponse, error) {
	out := ports.ApplicationVersionResponse{Application: alias, Kind: app.Kind, Channel: app.Image.Channel, Source: app.Repository.Type}
	switch app.Repository.Type {
	case "git":
		if b.Git == nil {
			return ports.ApplicationVersionResponse{}, errors.New("git client is not configured")
		}
		commit, err := b.Git.RemoteCommit(ctx, app.Repository.URL, app.Repository.Branch)
		if err != nil {
			return ports.ApplicationVersionResponse{}, err
		}
		out.AvailableCommit = commit
		out.AvailableVersion = shortCommit(commit)
	case "container-registry":
		if b.Podman == nil {
			return ports.ApplicationVersionResponse{}, errors.New("podman client is not configured")
		}
		image := configuredImageRef(app)
		digest, err := b.Podman.RemoteImageDigest(ctx, image)
		if err != nil {
			return ports.ApplicationVersionResponse{}, err
		}
		out.AvailableVersion = app.Image.Channel
		out.AvailableDigest = digest
	default:
		return ports.ApplicationVersionResponse{}, fmt.Errorf("repository type %q is not supported", app.Repository.Type)
	}
	return out, nil
}

func (b ExecutorBackend) applyApplicationVersion(ctx context.Context, alias string, app config.ApplicationConfig, version, digest, commit, actionName string) (ports.ApplicationDeploymentResponse, error) {
	switch app.Kind {
	case "container":
		return b.applyContainerApplication(ctx, alias, app, version, digest, actionName)
	case "service":
		return b.applyServiceApplication(ctx, alias, app, version, commit, actionName)
	default:
		return ports.ApplicationDeploymentResponse{}, fmt.Errorf("application kind %q is not supported", app.Kind)
	}
}

func (b ExecutorBackend) applyContainerApplication(ctx context.Context, alias string, app config.ApplicationConfig, version, digest, actionName string) (ports.ApplicationDeploymentResponse, error) {
	if app.Image.DigestRequired && strings.TrimSpace(digest) == "" {
		return ports.ApplicationDeploymentResponse{}, errors.New("image digest is required by policy")
	}
	image := configuredImageRef(app)
	if digest != "" {
		image = app.Image.Registry + "/" + app.Image.Repository + "@" + digest
	}
	pulledDigest, err := b.Podman.PullImage(ctx, image)
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	if app.Image.DigestRequired && pulledDigest != "" && digest != "" && pulledDigest != digest {
		return ports.ApplicationDeploymentResponse{}, errors.New("pulled image digest does not match the expected digest")
	}
	restart, err := b.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: app.ContainerName, OperationID: actionName})
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	health := restart.Health
	if app.Health.RequireHealthyAfterUpdate && health.Configured && health.Status != "healthy" {
		return ports.ApplicationDeploymentResponse{}, errors.New("container health check failed after update")
	}
	return ports.ApplicationDeploymentResponse{Status: "success", Action: actionName, Application: alias, CurrentVersion: version, TargetVersion: version, ImageDigest: firstNonEmpty(digest, pulledDigest), Health: &health}, nil
}

func (b ExecutorBackend) applyServiceApplication(ctx context.Context, alias string, app config.ApplicationConfig, version, commit, actionName string) (ports.ApplicationDeploymentResponse, error) {
	if commit == "" {
		commit = version
	}
	if app.Repository.Path != "" {
		if err := b.Git.Fetch(ctx, app.Repository.Path, app.Repository.Branch); err != nil {
			return ports.ApplicationDeploymentResponse{}, err
		}
		if err := b.Git.CheckoutCommit(ctx, app.Repository.Path, commit); err != nil {
			return ports.ApplicationDeploymentResponse{}, err
		}
	}
	for _, cmd := range app.PostUpdate {
		if b.Runner == nil {
			return ports.ApplicationDeploymentResponse{}, errors.New("command runner is not configured")
		}
		if _, err := b.Runner.Run(ctx, cmd.Command, cmd.Args...); err != nil {
			return ports.ApplicationDeploymentResponse{}, err
		}
	}
	restart, err := b.RestartService(ctx, ports.RestartServiceRequest{Service: app.ServiceName, OperationID: actionName})
	if err != nil {
		return ports.ApplicationDeploymentResponse{}, err
	}
	if app.Health.RequireHealthyAfterUpdate && restart.Healthcheck != nil && !restart.Healthcheck.Healthy {
		return ports.ApplicationDeploymentResponse{}, errors.New("service health check failed after update")
	}
	return ports.ApplicationDeploymentResponse{Status: "success", Action: actionName, Application: alias, CurrentVersion: version, TargetVersion: version, CommitHash: commit, Healthcheck: restart.Healthcheck}, nil
}

func (b ExecutorBackend) applicationWouldRun(app config.ApplicationConfig, version, digest, commit string) []string {
	switch app.Kind {
	case "container":
		image := configuredImageRef(app)
		if digest != "" {
			image = app.Image.Registry + "/" + app.Image.Repository + "@" + digest
		}
		return []string{b.Config.Podman.Binary + " pull " + image, "restart configured container " + app.ContainerName}
	case "service":
		out := []string{"git fetch origin refs/heads/" + app.Repository.Branch, "git checkout --detach " + firstNonEmpty(commit, version)}
		for _, cmd := range app.PostUpdate {
			out = append(out, cmd.Command+" "+strings.Join(cmd.Args, " "))
		}
		out = append(out, "restart configured service "+app.ServiceName)
		return out
	default:
		return nil
	}
}

func configuredImageRef(app config.ApplicationConfig) string {
	return app.Image.Registry + "/" + app.Image.Repository + ":" + app.Image.Channel
}

func comparableVersion(version, digest, commit string) string {
	return firstNonEmpty(digest, commit, version)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
