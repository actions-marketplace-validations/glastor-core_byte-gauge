# Contributing to GLASTOR® Byte-Gauge

Thank you for your interest in contributing to **`@glastor-core/byte-gauge`**, part of the **[GLASTOR® Core](https://github.com/glastor-core)** DevSecOps ecosystem alongside [`vortex`](https://github.com/glastor-core/vortex) and [`medusa`](https://github.com/glastor-core/medusa).

## Development Workflow

1. **Clone the repository:**
   ```bash
   git clone https://github.com/glastor-core/byte-gauge.git
   cd byte-gauge
   git config core.hooksPath .githooks
   ```
2. **Quality Gates (Zero Warnings Policy):**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --verbose
   ```
3. **Commit Convention:**
   Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `perf:`, `docs:`, `ci:`, `chore:`, `test:`, `refactor:`, `security:`).

## Contact

- **Official Website:** [https://glastor.es](https://glastor.es)
- **Engineering & Security Contact:** [ventas@glastor.es](mailto:ventas@glastor.es)

