# PrimeCloud Go Coding Standards

Phase 00 — Module AG-00-04.

## Scope

Applies to all Go code in PrimeCloud:

- PrimeCloud Agent
- PrimeCloud CLI

## Go Version

- Go 1.22 or later.

## Style

- **gofmt** is mandatory.
- **goimports** for import grouping.
- **go vet** is mandatory.
- **staticcheck** for additional static analysis.
- **golangci-lint** aggregates the above and additional linters.

## Formatting

- `gofmt -s` for formatting.
- Tabs for indentation (Go standard).
- No trailing whitespace.
- LF line endings.

## Naming

- `PascalCase` for exported identifiers.
- `camelCase` for unexported identifiers.
- Short variable names for short scopes.
- Descriptive names for longer scopes.
- Avoid abbreviations unless widely known.

## Package Structure

- Small, focused packages.
- Package names are short, lowercase, single-word.
- Avoid `util`, `common`, `helpers` package names.
- Internal code under `internal/`.
- Public code under `pkg/` only if intentionally exported.

## Imports

- Standard library first.
- Third-party second.
- Internal third.
- No dot imports.

## Error Handling

- Errors are values, not exceptions.
- Return errors, do not panic.
- Wrap errors with context: `fmt.Errorf("...: %w", err)`.
- Use `errors.Is` and `errors.As` for error inspection.
- Never ignore errors silently.

## Concurrency

- Use channels for communication.
- Use `sync` primitives for state.
- Avoid shared mutable state.
- Use `context.Context` for cancellation.
- Every goroutine must have a clear termination path.

## Context

- First argument of blocking functions.
- Passed through call chains.
- Used for cancellation and deadlines.

## Logging

- Structured logging (e.g., `slog`).
- Never log secrets.
- Log at appropriate levels.

## Testing

- Table-driven tests.
- `go test ./...` must pass.
- Use `testify` for assertions where helpful.
- Test names: `TestFunctionName_Scenario_Expected`.
- No tests hitting real production systems.

## Security

- Never trust input.
- Use `crypto/rand` for tokens, not `math/rand`.
- Use `subtle.ConstantTimeCompare` for secret comparison.
- Avoid `os/exec` with user input; when unavoidable, use exact argument matching.
- Do not log secrets.
- Do not hardcode credentials.

## Documentation

- Every exported identifier has a doc comment.
- Package doc comment for each package.
- README per module.

## Configuration

- Environment variables for runtime.
- Config loaded and validated at startup.
- No secrets in code.

## Build

- `go build ./...` must succeed.
- `go mod verify` must pass.
- Build tags used sparingly.
