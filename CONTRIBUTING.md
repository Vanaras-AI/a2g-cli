# Contributing to A2G CLI

Thank you for your interest in contributing to A2G CLI.

## Getting Started

### Prerequisites

- Rust stable toolchain (install via [rustup](https://rustup.rs/))
- Bash (for integration tests)

### Building

```bash
cargo build
```

### Running Tests

Unit tests:

```bash
cargo test
```

Integration / battle tests:

```bash
bash tests/battle_test.sh
```

## Code Style

- Format code before committing:

  ```bash
  cargo fmt
  ```

- Ensure no lint warnings:

  ```bash
  cargo clippy -- -D warnings
  ```

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Write or update tests** for any new functionality.
3. **Run the full test suite** (`cargo test` and `bash tests/battle_test.sh`) and ensure everything passes.
4. **Run `cargo fmt` and `cargo clippy`** with no warnings.
5. **Submit a pull request** with a clear description of the change and its motivation.
6. A maintainer will review your PR. Address any feedback promptly.

## Reporting Issues

When filing an issue, please include:

- A clear, descriptive title.
- Steps to reproduce the problem.
- Expected vs. actual behavior.
- Your OS, Rust version (`rustc --version`), and A2G CLI version.
- Relevant logs or error output.

For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
