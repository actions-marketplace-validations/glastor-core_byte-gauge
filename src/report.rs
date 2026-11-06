use crate::scanner::AuditResult;
use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub const PR_STICKY_MARKER: &str = "<!-- glastor-byte-gauge-sticky-comment -->";

pub struct PolicyConfig {
    pub max_size_mb: Option<f64>,
    pub max_regression_pct: Option<f64>,
    pub max_entropy: f64,
    pub fail_on_debug_symbols: bool,
    pub baseline: Option<AuditResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    Passed,
    Warning,
    Failed,
}

impl AuditVerdict {
    pub fn badge(&self) -> &'static str {
        match self {
            AuditVerdict::Passed => "🟢 PASSED",
            AuditVerdict::Warning => "🟡 WARNING",
            AuditVerdict::Failed => "🔴 FAILED",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AuditVerdict::Passed => "passed",
            AuditVerdict::Warning => "warning",
            AuditVerdict::Failed => "failed",
        }
    }
}

pub fn compute_regression_pct(result: &AuditResult, baseline: Option<&AuditResult>) -> Option<f64> {
    let base = baseline?;
    if base.total_bytes == 0 {
        return None;
    }
    let diff = (result.total_bytes as i128) - (base.total_bytes as i128);
    Some(((diff as f64) / (base.total_bytes as f64)) * 100.0)
}

pub fn evaluate_verdict(
    result: &AuditResult,
    policy: &PolicyConfig,
) -> (AuditVerdict, Vec<String>) {
    let mut reasons = Vec::new();
    let mut failed = false;
    let mut warning = false;

    if result.total_issues > 0 {
        failed = true;
        reasons.push(format!(
            "Se detectaron `{}` secuencias binarias prohibidas en el artefacto.",
            result.total_issues
        ));
    }

    if let Some(max_mb) = policy.max_size_mb
        && result.size_mb > max_mb
    {
        failed = true;
        reasons.push(format!(
            "El tamaño del binario (`{:.2} MB`) excede el presupuesto máximo permitido (`{:.2} MB`).",
            result.size_mb, max_mb
        ));
    }

    if let Some(max_reg_pct) = policy.max_regression_pct
        && let Some(reg_pct) = compute_regression_pct(result, policy.baseline.as_ref())
        && reg_pct > max_reg_pct
    {
        failed = true;
        reasons.push(format!(
            "Regresión de peso detectada (`+{:.2}%`), superando el umbral máximo permitido (`+{:.2}%`) respecto al baseline.",
            reg_pct, max_reg_pct
        ));
    }

    if result.binary_meta.has_debug_symbols {
        if policy.fail_on_debug_symbols {
            failed = true;
            reasons.push(
                "El binario contiene símbolos de depuración sin limpiar (`strip`).".to_string(),
            );
        } else {
            warning = true;
            reasons.push(
                "El binario incluye símbolos de depuración (`.debug`/`.symtab`/Wasm `name`). Considera activar `strip = \"symbols\"`."
                    .to_string(),
            );
        }
    }

    if !result.entropy_secrets.is_empty() {
        warning = true;
        reasons.push(format!(
            "Se detectaron `{}` candidatos heurísticos a secretos de alta entropía (enmascarados por seguridad).",
            result.entropy_secrets.len()
        ));
    }

    if result.shannon_entropy > policy.max_entropy || result.peak_chunk_entropy > policy.max_entropy
    {
        warning = true;
        reasons.push(format!(
            "Entropía de Shannon elevada (Global: `{:.3}`, Pico 64KB: `{:.3}` en `0x{:08X}`, umbral `{:.2} bits/B`): posible compresión UPX o payload cifrado.",
            result.shannon_entropy,
            result.peak_chunk_entropy,
            result.peak_entropy_offset,
            policy.max_entropy
        ));
    }

    let h = &result.binary_meta.hardening;
    if h.applicable && (!h.aslr_pie || !h.nx_dep) {
        warning = true;
        reasons.push(format!(
            "Mitigaciones de memoria incompletas (`ASLR/PIE={}`, `NX/DEP={}`): se recomienda habilitar posición independiente y pila no ejecutable.",
            h.aslr_pie, h.nx_dep
        ));
    }

    if reasons.is_empty() {
        reasons.push(
            "El binario cumple con todas las políticas de seguridad, mitigaciones de memoria (`checksec`), entropía y presupuesto FinOps de tamaño."
                .to_string(),
        );
    }

    let verdict = if failed {
        AuditVerdict::Failed
    } else if warning {
        AuditVerdict::Warning
    } else {
        AuditVerdict::Passed
    };

    (verdict, reasons)
}

pub fn render_markdown_summary(result: &AuditResult, policy: &PolicyConfig) -> String {
    let (verdict, reasons) = evaluate_verdict(result, policy);

    let size_delta_str = if let Some(ref base) = policy.baseline {
        let diff_bytes = (result.total_bytes as i128) - (base.total_bytes as i128);
        let diff_kb = (diff_bytes as f64) / 1024.0;
        let pct = compute_regression_pct(result, Some(base)).unwrap_or(0.0);
        if diff_bytes > 0 {
            format!(" (+{:.1} KB / +{:.2}% 📈)", diff_kb, pct)
        } else if diff_bytes < 0 {
            format!(" ({:.1} KB / {:.2}% 📉)", diff_kb, pct)
        } else {
            " (0.0 KB / = Sin cambios)".to_string()
        }
    } else {
        String::new()
    };

    let debug_status = if result.binary_meta.has_debug_symbols {
        "⚠️ Presentes (No Stripped)"
    } else {
        "✅ Limpio (Stripped)"
    };

    let entropy_badge = if result.shannon_entropy > policy.max_entropy {
        format!("`{:.3} bits/B` ⚠️ *(Alta)*", result.shannon_entropy)
    } else {
        format!("`{:.3} bits/B` ✅ *(Normal)*", result.shannon_entropy)
    };

    let peak_entropy_badge = if result.peak_chunk_entropy > policy.max_entropy {
        format!(
            "`{:.3} bits/B` en `0x{:08X}` ⚠️ *(Pico Alto)*",
            result.peak_chunk_entropy, result.peak_entropy_offset
        )
    } else {
        format!(
            "`{:.3} bits/B` en `0x{:08X}` ✅",
            result.peak_chunk_entropy, result.peak_entropy_offset
        )
    };

    let h = &result.binary_meta.hardening;
    let hardening_summary = if h.applicable {
        let aslr = if h.aslr_pie {
            "ASLR/PIE ✅"
        } else {
            "ASLR/PIE ❌"
        };
        let nx = if h.nx_dep { "NX/DEP ✅" } else { "NX/DEP ❌" };
        let heva = if h.high_entropy_va {
            "64b-HEVA ✅"
        } else {
            "64b-HEVA ➖"
        };
        format!("`{}` · `{}` · `{}` · `{}`", aslr, nx, heva, h.relro_or_cfg)
    } else {
        "`N/A (Raw Binary / Blob)`".to_string()
    };

    let linkage_summary = if result.binary_meta.is_statically_linked {
        "🔒 `100% Estático / Autónomo` (0 librerías externas)".to_string()
    } else {
        let libs = &result.binary_meta.dynamic_libraries;
        let preview: Vec<&str> = libs.iter().take(5).map(|s| s.as_str()).collect();
        let extra = if libs.len() > 5 {
            format!(" (+{} más)", libs.len() - 5)
        } else {
            String::new()
        };
        format!(
            "🔗 `Dinámico ({} libs)`: `{}`{}",
            libs.len(),
            preview.join("`, `"),
            extra
        )
    };

    let mut mermaid_lines = String::from(
        "```mermaid\npie showData\n    title Distribución de Secciones del Binario (KB)\n",
    );
    for sec in &result.binary_meta.sections {
        let kb = (sec.size_bytes as f64 / 1024.0).max(0.01);
        let clean_name = sec.name.replace('"', "'");
        mermaid_lines.push_str(&format!("    \"{}\" : {:.2}\n", clean_name, kb));
    }
    mermaid_lines.push_str("```\n");

    let mut patterns_table = String::from(
        "| Patrón Auditado | Coincidencias | Primer Offset (Hex) | Estado |\n| :--- | :---: | :---: | :---: |\n",
    );
    for m in &result.matches {
        let offset_str = m
            .first_offset
            .map(|o| format!("`0x{:08X}`", o))
            .unwrap_or_else(|| "—".to_string());
        let row_status = if m.count == 0 {
            "✅ OK"
        } else {
            "🚨 DETECTADO"
        };
        patterns_table.push_str(&format!(
            "| `{}` | `{}` | {} | {} |\n",
            m.pattern, m.count, offset_str, row_status
        ));
    }

    if !result.entropy_secrets.is_empty() {
        patterns_table.push_str(
            "\n#### 🕵️ Candidatos Heurísticos de Alta Entropía (Enmascarados)\n| Muestra Enmascarada | Longitud | Entropía (`bits/B`) | Offset (Hex) |\n| :--- | :---: | :---: | :---: |\n",
        );
        for sec in &result.entropy_secrets {
            patterns_table.push_str(&format!(
                "| `{}` | `{}` | `{:.3}` | `0x{:08X}` |\n",
                sec.masked_preview, sec.length, sec.entropy, sec.offset
            ));
        }
    }

    let notes_list: String = reasons
        .iter()
        .map(|r| format!("> - {}", r))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"{marker}
# 🛡️ Byte-Gauge: Rust Binary Audit Summary

### 📊 Estado del Escaneo: {badge}

| Métrica | Detalle |
| :--- | :--- |
| **Archivo Auditado** | `{filename}` |
| **Formato / Arquitectura** | `{format}` — `{arch}` |
| **Tamaño del Artefacto** | `{size_mb:.2} MB` (`{total_bytes}` bytes){delta} |
| **SHA-256 Digest** | `{sha256}` |
| **Entropía Global** | {entropy} |
| **Entropía Pico (Ventana 64KB)** | {peak_entropy} |
| **Hardening (`checksec`)** | {hardening} |
| **Enlace y Dependencias** | {linkage} |
| **Símbolos de Debug** | {debug_status} |
| **Patrones Prohibidos** | `{issues}` anomalías encontradas |
| **Rendimiento del Motor** | `{duration_ms:.2} ms` (`{throughput:.1} MB/s` — Streaming SIMD) |

> 💡 **Dictamen del Auditor:**
{notes}

<details>
<summary>🔍 <b>Desglose de Secciones y Reglas de Seguridad (Click para expandir)</b></summary>

#### 🧬 Radiografía de Secciones
{mermaid}

#### 🔐 Auditoría de Patrones Binarios (SIMD `memchr`)
{patterns_table}
</details>

---
*Reporte autogenerado por [`glastor-core/byte-gauge`](https://github.com/glastor-core/byte-gauge) — Motor Síncrono Zero-Copy + SIMD en Rust para el ecosistema DevSecOps [**Vortex**](https://github.com/glastor-core/vortex) y [**Medusa**](https://github.com/glastor-core/medusa).*
"#,
        marker = PR_STICKY_MARKER,
        badge = verdict.badge(),
        filename = result.file_name,
        format = result.binary_meta.format,
        arch = result.binary_meta.architecture,
        size_mb = result.size_mb,
        total_bytes = result.total_bytes,
        delta = size_delta_str,
        sha256 = result.sha256,
        entropy = entropy_badge,
        peak_entropy = peak_entropy_badge,
        hardening = hardening_summary,
        linkage = linkage_summary,
        debug_status = debug_status,
        issues = result.total_issues,
        duration_ms = result.duration_ms,
        throughput = result.throughput_mb_s,
        notes = notes_list,
        mermaid = mermaid_lines,
        patterns_table = patterns_table,
    )
}

/// Renderiza una matriz comparativa consolidada cuando se auditan múltiples binarios en lote (`--file-path a,b,c`).
pub fn render_batch_markdown_summary(results: &[AuditResult], policy: &PolicyConfig) -> String {
    if results.len() == 1 {
        return render_markdown_summary(&results[0], policy);
    }

    let mut out = format!(
        "{}\n# 📦 Byte-Gauge: Matriz Comparativa Multi-Binario ({} Artefactos)\n\n",
        PR_STICKY_MARKER,
        results.len()
    );
    out.push_str(
        "| Artefacto | Formato / Arch | Tamaño | Entropía (Global / Pico) | Hardening (`checksec`) | Estado |\n| :--- | :--- | :---: | :---: | :--- | :---: |\n",
    );

    for res in results {
        let (v, _) = evaluate_verdict(res, policy);
        let h = &res.binary_meta.hardening;
        let checksec_short = if h.applicable {
            format!(
                "PIE:{} NX:{}",
                if h.aslr_pie { "✅" } else { "❌" },
                if h.nx_dep { "✅" } else { "❌" }
            )
        } else {
            "N/A".to_string()
        };
        out.push_str(&format!(
            "| `{}` | `{}` (`{}`) | `{:.2} MB` | `{:.2}` / `{:.2}` | `{}` | {} |\n",
            res.file_name,
            res.binary_meta.format,
            res.binary_meta.architecture,
            res.size_mb,
            res.shannon_entropy,
            res.peak_chunk_entropy,
            checksec_short,
            v.badge()
        ));
    }

    out.push_str("\n---\n");
    for res in results {
        let single = render_markdown_summary(res, policy).replace(PR_STICKY_MARKER, "");
        out.push_str(&single);
        out.push('\n');
    }
    out
}

pub fn append_github_step_summary(summary_path: &Path, markdown: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(summary_path)
        .with_context(|| {
            format!(
                "No se pudo abrir GITHUB_STEP_SUMMARY en: {}",
                summary_path.display()
            )
        })?;

    file.write_all(markdown.as_bytes())
        .context("Error al escribir el reporte Markdown en GITHUB_STEP_SUMMARY")?;
    Ok(())
}

pub fn write_github_outputs(
    output_path: &Path,
    result: &AuditResult,
    policy: &PolicyConfig,
    verdict: AuditVerdict,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_path)
        .with_context(|| {
            format!(
                "No se pudo abrir GITHUB_OUTPUT en: {}",
                output_path.display()
            )
        })?;

    let reg_pct = compute_regression_pct(result, policy.baseline.as_ref()).unwrap_or(0.0);

    writeln!(file, "status={}", verdict.as_str())?;
    writeln!(file, "size_bytes={}", result.total_bytes)?;
    writeln!(file, "size_mb={:.4}", result.size_mb)?;
    writeln!(file, "sha256={}", result.sha256)?;
    writeln!(file, "entropy={:.4}", result.shannon_entropy)?;
    writeln!(file, "peak_entropy={:.4}", result.peak_chunk_entropy)?;
    writeln!(
        file,
        "peak_entropy_offset=0x{:08X}",
        result.peak_entropy_offset
    )?;
    writeln!(file, "issues={}", result.total_issues)?;
    writeln!(file, "format={}", result.binary_meta.format)?;
    writeln!(file, "architecture={}", result.binary_meta.architecture)?;
    writeln!(
        file,
        "has_debug_symbols={}",
        result.binary_meta.has_debug_symbols
    )?;
    writeln!(file, "aslr_pie={}", result.binary_meta.hardening.aslr_pie)?;
    writeln!(file, "nx_dep={}", result.binary_meta.hardening.nx_dep)?;
    writeln!(
        file,
        "dynamic_libs_count={}",
        result.binary_meta.dynamic_libraries.len()
    )?;
    writeln!(file, "regression_pct={:.4}", reg_pct)?;
    writeln!(file, "duration_ms={:.2}", result.duration_ms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::build_sarif_report;
    use crate::scanner::{BinaryHardening, BinaryMetadata, PatternMatch, SectionInfo};

    fn sample_result(total_bytes: u64, total_issues: u64) -> AuditResult {
        AuditResult {
            file_name: "app.exe".to_string(),
            total_bytes,
            size_mb: total_bytes as f64 / 1_048_576.0,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            shannon_entropy: 6.2,
            peak_chunk_entropy: 6.8,
            peak_entropy_offset: 0x0001_0000,
            total_issues,
            matches: vec![PatternMatch {
                pattern: "EVIL".to_string(),
                count: total_issues,
                first_offset: if total_issues > 0 { Some(0x1040) } else { None },
            }],
            entropy_secrets: vec![],
            binary_meta: BinaryMetadata {
                format: "PE (Windows)".to_string(),
                architecture: "x86_64 (PE32+)".to_string(),
                has_debug_symbols: false,
                is_statically_linked: false,
                dynamic_libraries: vec!["KERNEL32.dll".to_string()],
                hardening: BinaryHardening {
                    applicable: true,
                    aslr_pie: true,
                    high_entropy_va: true,
                    nx_dep: true,
                    relro_or_cfg: "Control Flow Guard (CFG)".to_string(),
                },
                sections: vec![SectionInfo {
                    name: ".text".to_string(),
                    size_bytes: total_bytes,
                    percentage: 100.0,
                }],
            },
            duration_ms: 1.5,
            throughput_mb_s: 512.0,
        }
    }

    #[test]
    fn renders_mermaid_hardening_and_baseline_delta_in_summary() {
        let base = sample_result(1_000_000, 0);
        let current = sample_result(1_051_200, 0);
        let policy = PolicyConfig {
            max_size_mb: Some(5.0),
            max_regression_pct: Some(10.0),
            max_entropy: 7.2,
            fail_on_debug_symbols: true,
            baseline: Some(base),
        };

        let md = render_markdown_summary(&current, &policy);
        assert!(md.contains(PR_STICKY_MARKER));
        assert!(md.contains("🟢 PASSED"));
        assert!(md.contains("```mermaid"));
        assert!(md.contains("+50.0 KB"));
        assert!(md.contains("ASLR/PIE ✅"));
        assert!(md.contains("KERNEL32.dll"));
    }

    #[test]
    fn renders_consolidated_batch_comparison_matrix_for_multiple_artifacts() {
        let r1 = sample_result(1_000_000, 0);
        let r2 = sample_result(2_000_000, 0);
        let policy = PolicyConfig {
            max_size_mb: Some(5.0),
            max_regression_pct: None,
            max_entropy: 7.2,
            fail_on_debug_symbols: false,
            baseline: None,
        };

        let batch_md = render_batch_markdown_summary(&[r1, r2], &policy);
        assert!(batch_md.contains("Matriz Comparativa Multi-Binario (2 Artefactos)"));
    }

    #[test]
    fn fails_when_regression_pct_exceeds_threshold_and_generates_sarif() {
        let base = sample_result(1_000_000, 0);
        let current = sample_result(1_100_000, 1);
        let policy = PolicyConfig {
            max_size_mb: Some(5.0),
            max_regression_pct: Some(5.0),
            max_entropy: 7.2,
            fail_on_debug_symbols: true,
            baseline: Some(base),
        };

        let (verdict, _) = evaluate_verdict(&current, &policy);
        assert_eq!(verdict, AuditVerdict::Failed);

        let sarif = build_sarif_report(&current, &policy, "dist/app.exe");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn writes_all_16_github_outputs_and_step_summary_files() {
        let temp_dir = std::env::temp_dir();
        let out_path = temp_dir.join("byte_gauge_gh_output_test.txt");
        let sum_path = temp_dir.join("byte_gauge_gh_summary_test.md");
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&sum_path);

        let res = sample_result(1_048_576, 0);
        let policy = PolicyConfig {
            max_size_mb: Some(5.0),
            max_regression_pct: Some(5.0),
            max_entropy: 7.2,
            fail_on_debug_symbols: false,
            baseline: None,
        };

        let md = render_markdown_summary(&res, &policy);
        append_github_step_summary(&sum_path, &md).unwrap();
        write_github_outputs(&out_path, &res, &policy, AuditVerdict::Passed).unwrap();

        let outputs_content = std::fs::read_to_string(&out_path).unwrap();
        let summary_content = std::fs::read_to_string(&sum_path).unwrap();
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&sum_path);

        assert_eq!(outputs_content.lines().count(), 16);
        assert!(outputs_content.contains("status=passed"));
        assert!(outputs_content.contains("aslr_pie=true"));
        assert!(outputs_content.contains("nx_dep=true"));
        assert!(outputs_content.contains("peak_entropy_offset=0x00010000"));
        assert!(summary_content.contains("# 🛡️ Byte-Gauge: Rust Binary Audit Summary"));
    }
}
