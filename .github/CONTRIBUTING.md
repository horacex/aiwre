# Contributing to AIWRE

Thanks for contributing.

## Development Setup

1. Install Go (version matching `go.mod`).
2. Clone the repo.
3. Run:

```bash
go test ./...
go build ./...
```

## Contribution Scope

Good contribution areas:

1. Protocol correctness and interoperability.
2. Relay throughput and reliability improvements.
3. CLI UX and integration ergonomics.
4. Documentation quality and consistency.
5. Test coverage and regression hardening.

## Pull Request Rules

1. Keep PRs focused and minimal.
2. Add or update tests for behavior changes.
3. Update docs when user-facing behavior changes.
4. Use clear commit messages.
5. Ensure `go test ./...` passes locally before opening PR.

## Commit Guidance

Recommended prefixes:

1. `feat:` new capability
2. `fix:` bug fix
3. `docs:` documentation updates
4. `chore:` maintenance/refactor without behavior change
5. `test:` test-only changes

## Reporting Bugs

Open a GitHub issue with:

1. Expected behavior
2. Actual behavior
3. Reproduction steps
4. Environment details
5. Relevant logs/output

For security issues, do not open a public issue. See `SECURITY.md`.
