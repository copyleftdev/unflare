# Contributing to unflare

Thank you for your interest in contributing to unflare!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/unflare.git`
3. Create a branch: `git checkout -b feature/your-feature`

## Development Setup

### Requirements

- Zig 0.13.0 or later
- OpenSSL development headers (for TLS)

### Build & Test

```bash
# Run tests
zig build test

# Build debug
zig build

# Build release
zig build -Doptimize=ReleaseSafe

# Format code
zig fmt src/
```

## Code Guidelines

### Style

- Run `zig fmt src/` before committing
- Maximum line length: 100 characters
- Use descriptive variable names
- Add doc comments for public functions

### Architecture

- **Keep functions small** — Target < 40 lines
- **No deep nesting** — Maximum 4 levels of indentation
- **Explicit error handling** — No ignored errors
- **Test everything** — Every function should have tests

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add support for IPv6 detection
fix: handle empty response body in probe
docs: update installation instructions
test: add edge cases for CIDR parsing
```

### Tests

All new features must include tests:

```zig
test "myFunction handles edge case" {
    const result = myFunction(edge_input);
    try std.testing.expectEqual(expected, result);
}
```

Run the full test suite before submitting:

```bash
zig build test
```

## Submitting Changes

1. Ensure all tests pass: `zig build test`
2. Format your code: `zig fmt src/`
3. Push to your fork
4. Open a Pull Request with a clear description

## Reporting Issues

### Bug Reports

Include:
- unflare version (`unflare version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant output/errors

### Feature Requests

Include:
- Use case description
- Proposed solution (if any)
- Alternatives considered

## Security Issues

For security vulnerabilities, please email donj@codetestcode.io instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
