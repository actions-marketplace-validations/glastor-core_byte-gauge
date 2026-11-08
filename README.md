# 🛡️ GLASTOR® Byte-Gauge (`@glastor-core/byte-gauge`)

[![CI & Self-Audit](https://img.shields.io/badge/CI-Byte--Gauge%20SIMD-success?style=flat-square&logo=rust)](https://github.com/glastor-core/byte-gauge)
[![Ecosystem](https://img.shields.io/badge/GLASTOR%C2%AE%20Core-Nemesis%20%7C%20Specter%20%7C%20Vortex%20%7C%20Byte--Gauge%20%7C%20Medusa-0A66C2?style=flat-square)](https://github.com/glastor-core)
[![SARIF 2.1.0](https://img.shields.io/badge/GitHub%20Security-SARIF%202.1.0-purple?style=flat-square&logo=github)](https://github.com/glastor-core/byte-gauge)
[![CycloneDX 1.5](https://img.shields.io/badge/SBOM-CycloneDX%201.5-orange?style=flat-square)](https://github.com/glastor-core/byte-gauge)
[![SLSA Provenance](https://img.shields.io/badge/SLSA-Build%20Provenance-brightgreen?style=flat-square)](https://github.com/glastor-core/byte-gauge)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](./LICENSE)

**Motor de auditoría binaria de alto rendimiento en Rust** (`std::fs` síncrono + **SIMD `memchr`** + **`checksec` / Binary Hardening** + análisis estructural **ELF / PE / Mach-O / WebAssembly (`.wasm`)** + **Entropía de Shannon Global y por Ventana de 64 KB** + **Cazador Heurístico de Secretos Enmascarados** + exportación **SARIF 2.1.0** + **SBOM CycloneDX 1.5** + **PR Sticky Comments**).

Diseñado para cerrar el eslabón de certificación de artefactos compilados dentro del ecosistema **[GLASTOR® Core](https://github.com/glastor-core)** en sinergia directa con **[`glastor-core/specter`](https://github.com/glastor-core/specter)**, **[`glastor-core/vortex`](https://github.com/glastor-core/vortex)**, **[`glastor-core/medusa`](https://github.com/glastor-core/medusa)** y **[`glastor-core/nemesis`](https://github.com/glastor-core/nemesis)**.

---

## 🔗 Sinergia del Ecosistema GLASTOR® Core (`Nemesis` ➔ `Specter` ➔ `Vortex` ➔ `Byte-Gauge` ➔ `Medusa`)

<p align="center">
  <img src="./assets/ecosystem-synergy.svg" alt="GLASTOR® Core — Zero-Trust DevSecOps & Artifact Supply Chain Pipeline" width="100%" />
</p>

| Etapa | Repositorio | Rol en la Cadena de Suministro |
| :--- | :--- | :--- |
| **01 • SAST & IaC** | **[`glastor-core/nemesis`](https://github.com/glastor-core/nemesis)** | Auditoría estática de código fuente, prevención de fugas de secretos y seguridad IaC en GitHub Actions. |
| **02 • API Contract** | **[`glastor-core/specter`](https://github.com/glastor-core/specter)** | Diferenciador AST políglota (`< 5 ms`), huella criptográfica de superficie pública y bloqueo de *Trojan Breaking Changes* SemVer. |
| **03 • Pre-Build DAG** | **[`glastor-core/vortex`](https://github.com/glastor-core/vortex)** | Grafo de impacto AST (*Blast Radius*), particionamiento matemático LPT de tests y compilación multiplataforma. |
| **04 • Artifact Gate** | **`glastor-core/byte-gauge`** | **Certificación binaria SIMD (`ELF`/`PE`/`Mach-O`/`Wasm`), `checksec`, entropía de Shannon por bloques de `64 KB`, SARIF 2.1.0 y SBOM CycloneDX 1.5.** |
| **05 • Edge Runtime** | **[`glastor-core/medusa`](https://github.com/glastor-core/medusa)** | Gateway Zero-Trust resiliente en el borde con *Circuit Breaker* para ejecutar binarios y módulos Wasm certificados. |

---

## 🚀 Capacidades Enterprise (`v0.1.0`)

1. **🌐 Soporte Multi-Formato Nativo (`ELF` + `PE/PE32+` + `Mach-O` + `WebAssembly .wasm`)**:
   - Inspecciona ejecutables nativos con `goblin` y módulos **WebAssembly (`.wasm` v1)** con un decodificador nativo `uLEB128` sin dependencias externas (`Code (Bytecode)`, `Data (Static Memory)`, `Import`, `Export` y detección de secciones `name` / `.debug*` sin limpiar).
2. **🛡️ Binary Hardening (`checksec` Nativo)**:
   - Verifica `ASLR / PIE`, `64-bit High-Entropy VA`, `NX / DEP`, `Full/Partial RELRO`, `Control Flow Guard (CFG)` y `Wasm Linear Memory Sandbox`.
3. **🎯 Entropía Localizada (Ventanas de `64 KB`) + 🕵️ Cazador Heurístico de Secretos Enmascarados (`--scan-entropy-secrets`)**:
   - Calcula la entropía de Shannon global y el **pico máximo por bloque de 64 KB (`peak_chunk_entropy`)** con su offset hexadecimal exacto (`0x...`).
   - Detecta tokens de alta entropía (`32..=64` bytes, $H \ge 4.70\text{ bits/B}$) y los **enmascara (`aB3d...cE6g`)** para jamás exponer secretos en los logs públicos del CI.
4. **📦 Generador Nativo de SBOM CycloneDX 1.5 (`--output-sbom`) + 🔒 SARIF 2.1.0 (`--output-sarif`)**:
   - Exporta el **Software Bill of Materials (CycloneDX v1.5 JSON)** con el digest SHA-256 del binario y el grafo de librerías dinámicas (`DT_NEEDED` / DLLs).
   - Exporta **SARIF 2.1.0** (`BG001` a `BG007`) integrado con **GitHub Security Code Scanning**.
5. **⚡ Modo Batch Multi-Binario + 💬 PR Sticky Comments + 📉 Gatekeeper FinOps (`--max-regression-pct`)**:
   - Soporta múltiples rutas separadas por coma (`--file-path "dist/app-linux,dist/app-win.exe,dist/edge.wasm"`) generando una **Matriz Comparativa Multi-Binario**.
   - Publica y actualiza automáticamente un **Sticky Comment en el Pull Request** (`post-pr-comment: "true"`).

---

## ⚙️ Uso como GitHub Action (`glastor-core/byte-gauge@v1`)

```yaml
- name: Audit Release Binaries & Wasm Modules
  id: gauge
  uses: glastor-core/byte-gauge@v1
  with:
    file-path: "dist/vortex-linux-x64,dist/medusa-edge.wasm"
    scan-entropy-secrets: "true"
    max-size-mb: "120.0"
    max-regression-pct: "5.0"
    fail-on-debug: "true"
    baseline-json: ".byte-gauge/baseline.json"
    output-json: ".byte-gauge/current-audit.json"
    output-sarif: ".byte-gauge/byte-gauge.sarif"
    output-sbom: ".byte-gauge/byte-gauge.cdx.json"
    post-pr-comment: "true"
```

---

## 📄 Licencia y Autoría

Distribuido bajo licencia **MIT**.  
© 2026 **Andrés Antonio Cardoso — GLASTOR® Core ([@glastor-dev](https://github.com/glastor-dev))** — [https://glastor.es](https://glastor.es) (`ventas@glastor.es`).
