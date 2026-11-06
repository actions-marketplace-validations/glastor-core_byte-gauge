# Changelog

All notable changes to **`@glastor-core/byte-gauge`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-06

### Added
- **Single-Pass Streaming SIMD Engine (`src/scanner.rs`)**: 64 KB fixed-memory buffer with overlap window (`max_pattern_len - 1`) and `memchr::memmem::Finder` hardware vectorization (`AVX2` / `NEON`), eliminating 64 KB chunk-boundary false negatives.
- **Multi-Format & WebAssembly (`.wasm`) Section Analyzer (`src/scanner.rs`)**:
  - Native inspection of **ELF (Linux)**, **PE/PE32+ (Windows)**, **Mach-O (macOS)**, and **WebAssembly (`.wasm` v1 via zero-dependency uLEB128 parser)** binaries.
  - Reports top section weights (`.text`, `.rodata`/`.rdata`, `Code (Bytecode)`, `Data (Static Memory)`), stripped/debug symbol status (`.debug`, `.symtab`, Wasm `name`), and dynamically linked libraries (`DT_NEEDED` / DLLs).
- **Native `checksec` Binary Hardening Inspector (`src/scanner.rs`)**: Audits `ASLR / PIE`, `64-bit High-Entropy VA`, `NX / DEP`, `Full/Partial RELRO`, `Control Flow Guard (CFG)`, and `Wasm Linear Memory Sandbox`.
- **Localized 64 KB Peak Window Entropy & Masked Heuristic Secret Hunter (`src/scanner.rs`)**:
  - Tracks both global Shannon entropy and the highest 64 KB window entropy (`peak_chunk_entropy`) with its exact hex offset (`peak_entropy_offset`).
  - Optional `--scan-entropy-secrets` flag detects high-entropy alphanumeric/Base64 secret candidates (`32..=64` bytes, $H \ge 4.70$) and masks them (`abcd...wxyz`) to prevent CI log leakage.
- **Native CycloneDX 1.5 SBOM Generator (`src/sbom.rs`)**: Exports `--output-sbom` JSON Software Bill of Materials containing the binary's SHA-256 digest, `checksec` properties, and runtime shared library dependency graph.
- **Native SARIF 2.1.0 Exporter (`src/sarif.rs`)**: Generates GitHub Advanced Security / Code Scanning compliant SARIF v2.1.0 reports (`--output-sarif`, rules `BG001`–`BG007` with `byteOffset` locations).
- **Multi-Artifact Batch Mode & FinOps Regression Gatekeeper (`src/report.rs`)**:
  - Supports comma-separated `--file-path` batch auditing with a consolidated comparative Markdown matrix.
  - Blocks CI pipelines when binary size growth exceeds `--max-regression-pct` relative to `--baseline-json`.
- **PR Sticky Comments, `glastor-core/nemesis` Dogfooding & SLSA Provenance (`action.yml`, `.github/workflows/`)**:
  - Auto-creates/updates Pull Request Sticky Comments (`<!-- glastor-byte-gauge-sticky-comment -->`).
  - Automated SemVer, Changelog, floating `v1` tag, `SHA256SUMS.txt`, CycloneDX SBOMs, and Sigstore **SLSA Build Provenance** (`actions/attest-build-provenance@v2`).
