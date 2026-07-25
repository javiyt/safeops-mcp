package redaction

import (
	"encoding/json"
	"regexp"
	"strings"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)[^\s]+`),
	regexp.MustCompile(`(?i)\b(token|api_key|apikey|password|secret)=([^&\s]+)`),
	regexp.MustCompile(`(?i)([A-Z0-9_]*(TOKEN|API_KEY|APIKEY|PASSWORD|SECRET)[A-Z0-9_]*=)[^\s]+`),
	regexp.MustCompile(`(?i)(https?://)[^:/\s]+:[^@\s]+@`),
	regexp.MustCompile(`(?i)("(token|api_key|apikey|password|secret)"\s*:\s*")[^"]+(")`),
}

func Redact(input string) string {
	out := input
	out = patterns[0].ReplaceAllString(out, `${1}[REDACTED]`)
	out = patterns[1].ReplaceAllString(out, `${1}=[REDACTED]`)
	out = patterns[2].ReplaceAllString(out, `${1}[REDACTED]`)
	out = patterns[3].ReplaceAllString(out, `${1}[REDACTED]@`)
	out = patterns[4].ReplaceAllString(out, `${1}[REDACTED]${3}`)
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		var value any
		if json.Unmarshal([]byte(out), &value) == nil {
			redactJSON(value)
			if data, err := json.Marshal(value); err == nil {
				return string(data)
			}
		}
	}
	return out
}

func redactJSON(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, val := range typed {
			if sensitiveKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			redactJSON(val)
		}
	case []any:
		for _, item := range typed {
			redactJSON(item)
		}
	}
}

func sensitiveKey(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "token") || strings.Contains(k, "api_key") || strings.Contains(k, "apikey") || strings.Contains(k, "password") || strings.Contains(k, "secret")
}
