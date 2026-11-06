use crate::report::{PolicyConfig, compute_regression_pct};
use crate::scanner::AuditResult;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::path::Path;

/// Construye un documento SARIF v2.1.0 estándar compatible con GitHub Advanced Security
/// (`github/codeql-action/upload-sarif@v3`).
pub fn build_sarif_report(
    result: &AuditResult,
    policy: &PolicyConfig,
    artifact_uri: &str,
) -> Value {
    let clean_uri = artifact_uri
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string();
    let uri = if clean_uri.is_empty() {
        result.file_name.clone()
    } else {
        clean_uri
    };

    let mut sarif_results: Vec<Value> = Vec::new();

    // BG001: Patrones binarios / secretos prohibidos
    for m in &result.matches {
        if m.count > 0 {
            let offset = m.first_offset.unwrap_or(0);
            sarif_results.push(make_sarif_result(
                "BG001",
                "error",
                format!(
                    "Detected {} occurrence(s) of forbidden byte sequence '{}' in '{}' (first at offset 0x{:08X}).",
                    m.count, m.pattern, result.file_name, offset
                ),
                &uri,
                Some(offset),
            ));
        }
    }

    // BG002: Presupuesto absoluto de tamaño superado
    if let Some(max_mb) = policy.max_size_mb
        && result.size_mb > max_mb
    {
        sarif_results.push(make_sarif_result(
            "BG002",
            "error",
            format!(
                "Binary artifact '{}' size ({:.2} MB) exceeds maximum budget ({:.2} MB).",
                result.file_name, result.size_mb, max_mb
            ),
            &uri,
            None,
        ));
    }

    // BG003: Regresión porcentual frente a baseline superada
    if let Some(max_reg_pct) = policy.max_regression_pct
        && let Some(reg_pct) = compute_regression_pct(result, policy.baseline.as_ref())
        && reg_pct > max_reg_pct
    {
        sarif_results.push(make_sarif_result(
            "BG003",
            "error",
            format!(
                "Binary size regression (+{:.2}%) for '{}' exceeds maximum allowed threshold (+{:.2}%).",
                reg_pct, result.file_name, max_reg_pct
            ),
            &uri,
            None,
        ));
    }

    // BG004: Símbolos de depuración presentes
    if result.binary_meta.has_debug_symbols {
        let level = if policy.fail_on_debug_symbols {
            "error"
        } else {
            "warning"
        };
        sarif_results.push(make_sarif_result(
            "BG004",
            level,
            format!(
                "Binary '{}' contains unstripped debug symbols (.debug / .symtab / Wasm name).",
                result.file_name
            ),
            &uri,
            None,
        ));
    }

    // BG005: Entropía de Shannon elevada (global o ventana de 64 KB)
    if result.shannon_entropy > policy.max_entropy || result.peak_chunk_entropy > policy.max_entropy
    {
        sarif_results.push(make_sarif_result(
            "BG005",
            "warning",
            format!(
                "High Shannon entropy in '{}': global {:.3} bits/B, peak 64KB window {:.3} bits/B at offset 0x{:08X} (threshold {:.2} bits/B).",
                result.file_name,
                result.shannon_entropy,
                result.peak_chunk_entropy,
                result.peak_entropy_offset,
                policy.max_entropy
            ),
            &uri,
            Some(result.peak_entropy_offset),
        ));
    }

    // BG006: Mitigaciones de memoria ausentes (ASLR/PIE o NX/DEP)
    let h = &result.binary_meta.hardening;
    if h.applicable && (!h.aslr_pie || !h.nx_dep) {
        sarif_results.push(make_sarif_result(
            "BG006",
            "warning",
            format!(
                "Executable '{}' lacks recommended OS memory mitigations (ASLR/PIE={}, NX/DEP={}).",
                result.file_name, h.aslr_pie, h.nx_dep
            ),
            &uri,
            None,
        ));
    }

    // BG007: Secretos heurísticos de alta entropía enmascarados
    for sec in &result.entropy_secrets {
        sarif_results.push(make_sarif_result(
            "BG007",
            "warning",
            format!(
                "High-entropy secret candidate '{}' (len={}, entropy={:.2} bits/B) detected in '{}' at offset 0x{:08X}.",
                sec.masked_preview, sec.length, sec.entropy, result.file_name, sec.offset
            ),
            &uri,
            Some(sec.offset),
        ));
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GLASTOR Byte-Gauge",
                        "organization": "GLASTOR Core",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/glastor-core/byte-gauge",
                        "rules": [
                            {
                                "id": "BG001",
                                "name": "ForbiddenByteSequence",
                                "shortDescription": { "text": "Forbidden byte sequence or secret detected in binary" },
                                "defaultConfiguration": { "level": "error" },
                                "properties": { "security-severity": "9.0", "tags": ["security", "secrets", "binary"] }
                            },
                            {
                                "id": "BG002",
                                "name": "SizeBudgetExceeded",
                                "shortDescription": { "text": "Binary artifact exceeds maximum size budget" },
                                "defaultConfiguration": { "level": "error" },
                                "properties": { "security-severity": "5.0", "tags": ["performance", "finops"] }
                            },
                            {
                                "id": "BG003",
                                "name": "SizeRegressionExceeded",
                                "shortDescription": { "text": "Binary size growth exceeds baseline regression threshold" },
                                "defaultConfiguration": { "level": "error" },
                                "properties": { "security-severity": "5.0", "tags": ["performance", "regression", "finops"] }
                            },
                            {
                                "id": "BG004",
                                "name": "UnstrippedDebugSymbols",
                                "shortDescription": { "text": "Unstripped debug symbols present in release binary" },
                                "defaultConfiguration": { "level": "warning" },
                                "properties": { "security-severity": "4.0", "tags": ["security", "hardening"] }
                            },
                            {
                                "id": "BG005",
                                "name": "HighShannonEntropy",
                                "shortDescription": { "text": "Elevated global or localized 64KB Shannon entropy" },
                                "defaultConfiguration": { "level": "warning" },
                                "properties": { "security-severity": "6.5", "tags": ["security", "entropy", "obfuscation"] }
                            },
                            {
                                "id": "BG006",
                                "name": "MissingBinaryHardening",
                                "shortDescription": { "text": "Missing OS memory exploit mitigations (ASLR/PIE or NX/DEP)" },
                                "defaultConfiguration": { "level": "warning" },
                                "properties": { "security-severity": "7.5", "tags": ["security", "hardening", "checksec"] }
                            },
                            {
                                "id": "BG007",
                                "name": "HighEntropySecretCandidate",
                                "shortDescription": { "text": "Heuristic high-entropy token or API key candidate detected" },
                                "defaultConfiguration": { "level": "warning" },
                                "properties": { "security-severity": "8.0", "tags": ["security", "secrets", "entropy"] }
                            }
                        ]
                    }
                },
                "results": sarif_results
            }
        ]
    })
}

fn make_sarif_result(
    rule_id: &str,
    level: &str,
    message: String,
    uri: &str,
    byte_offset: Option<u64>,
) -> Value {
    let region = match byte_offset {
        Some(offset) => json!({
            "startLine": 1,
            "byteOffset": offset
        }),
        None => json!({
            "startLine": 1
        }),
    };

    json!({
        "ruleId": rule_id,
        "level": level,
        "message": { "text": message },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri
                    },
                    "region": region
                }
            }
        ]
    })
}

pub fn write_sarif_file(
    sarif_path: &Path,
    result: &AuditResult,
    policy: &PolicyConfig,
    artifact_uri: &str,
) -> Result<()> {
    if let Some(parent) = sarif_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_string_pretty(&build_sarif_report(result, policy, artifact_uri))?;
    std::fs::write(sarif_path, payload).with_context(|| {
        format!(
            "No se pudo escribir el reporte SARIF en {}",
            sarif_path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{
        BinaryHardening, BinaryMetadata, EntropySecretFinding, PatternMatch, SectionInfo,
    };

    #[test]
    fn emits_all_seven_sarif_rules_and_normalizes_windows_paths() {
        let base = AuditResult {
            file_name: "medusa.bin".to_string(),
            total_bytes: 1_000_000,
            size_mb: 0.95,
            sha256: "abc".to_string(),
            shannon_entropy: 5.0,
            peak_chunk_entropy: 5.2,
            peak_entropy_offset: 0,
            total_issues: 0,
            matches: vec![],
            entropy_secrets: vec![],
            binary_meta: BinaryMetadata {
                format: "ELF".to_string(),
                architecture: "x86_64".to_string(),
                has_debug_symbols: false,
                is_statically_linked: true,
                dynamic_libraries: vec![],
                hardening: BinaryHardening {
                    applicable: true,
                    aslr_pie: true,
                    high_entropy_va: true,
                    nx_dep: true,
                    relro_or_cfg: "Full RELRO".to_string(),
                },
                sections: vec![],
            },
            duration_ms: 1.0,
            throughput_mb_s: 500.0,
        };

        let vulnerable = AuditResult {
            file_name: "medusa.bin".to_string(),
            total_bytes: 2_000_000,
            size_mb: 1.91,
            sha256: "def".to_string(),
            shannon_entropy: 7.5,
            peak_chunk_entropy: 7.9,
            peak_entropy_offset: 0x0002_0000,
            total_issues: 1,
            matches: vec![PatternMatch {
                pattern: "APILAYER_API_KEY".to_string(),
                count: 1,
                first_offset: Some(0x0000_ABCD),
            }],
            entropy_secrets: vec![EntropySecretFinding {
                masked_preview: "aB3d...cE6g".to_string(),
                offset: 0x0000_1200,
                length: 40,
                entropy: 4.85,
            }],
            binary_meta: BinaryMetadata {
                format: "ELF".to_string(),
                architecture: "x86_64".to_string(),
                has_debug_symbols: true,
                is_statically_linked: false,
                dynamic_libraries: vec!["libc.so.6".to_string()],
                hardening: BinaryHardening {
                    applicable: true,
                    aslr_pie: false,
                    high_entropy_va: false,
                    nx_dep: false,
                    relro_or_cfg: "No RELRO".to_string(),
                },
                sections: vec![SectionInfo {
                    name: ".text".to_string(),
                    size_bytes: 2_000_000,
                    percentage: 100.0,
                }],
            },
            duration_ms: 2.0,
            throughput_mb_s: 500.0,
        };

        let policy = PolicyConfig {
            max_size_mb: Some(1.0),
            max_regression_pct: Some(10.0),
            max_entropy: 7.2,
            fail_on_debug_symbols: true,
            baseline: Some(base),
        };

        let sarif = build_sarif_report(&vulnerable, &policy, r".\dist\medusa.bin");
        assert_eq!(sarif["version"], "2.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            7,
            "Debe emitir las 7 reglas SARIF (BG001 a BG007) cuando fallan todas las políticas"
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "dist/medusa.bin"
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["byteOffset"],
            0xABCD
        );
    }
}
