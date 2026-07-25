# Contributing

All comments, documentation, examples, CLI help, and user-facing strings in this repository must be written in English.

Use idiomatic Go, keep packages focused, avoid global mutable state, and prefer explicit domain names over generic helper packages.

Before opening a pull request, run:

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
```

Pull requests should explain the behavior change, security impact, and tests added.
