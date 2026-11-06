## 📋 Summary

Describe the purpose of this Pull Request and how it impacts `byte-gauge` (and optionally `vortex` / `medusa` integration).

## ✅ Quality & Security Checklist

- [ ] `cargo fmt --all -- --check` passes with no formatting diffs
- [ ] `cargo clippy --all-targets -- -D warnings` passes with 0 warnings
- [ ] `cargo test` passes (including 64 KB chunk-boundary SIMD tests)
- [ ] Self-audit (`byte-gauge --file-path ./target/release/byte-gauge --fail-on-debug`) passes `🟢 PASSED`

