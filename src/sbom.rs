use crate::scanner::AuditResult;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::path::Path;

/// Construye un Software Bill of Materials (SBOM) estándar en formato CycloneDX v1.5 JSON
/// incluyendo el digest SHA-256 del binario, propiedades `checksec` y el grafo de librerías dinámicas.
pub fn build_cyclonedx_sbom(result: &AuditResult) -> Value {
    let root_bom_ref = format!(
        "pkg:binary/{}@sha256:{}",
        result.file_name,
        &result.sha256[..16]
    );

    let mut components: Vec<Value> = Vec::new();
    let mut depends_on: Vec<String> = Vec::new();

    for lib in &result.binary_meta.dynamic_libraries {
        let clean_lib = lib.trim();
        if clean_lib.is_empty() {
            continue;
        }
        let bom_ref = format!("pkg:generic/{}", clean_lib);
        depends_on.push(bom_ref.clone());
        components.push(json!({
            "type": "library",
            "bom-ref": bom_ref,
            "name": clean_lib,
            "purl": bom_ref,
            "scope": "required",
            "properties": [
                {
                    "name": "byte-gauge:linkage",
                    "value": "dynamic"
                }
            ]
        }));
    }

    let h = &result.binary_meta.hardening;

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", deterministic_uuid_from_sha256(&result.sha256)),
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "author": "GLASTOR Core (@glastor-dev)",
                        "name": "byte-gauge",
                        "version": env!("CARGO_PKG_VERSION"),
                        "externalReferences": [
                            {
                                "type": "website",
                                "url": "https://github.com/glastor-core/byte-gauge"
                            }
                        ]
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_bom_ref,
                "name": result.file_name,
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": result.sha256
                    }
                ],
                "properties": [
                    { "name": "byte-gauge:format", "value": result.binary_meta.format },
                    { "name": "byte-gauge:architecture", "value": result.binary_meta.architecture },
                    { "name": "byte-gauge:size_bytes", "value": result.total_bytes.to_string() },
                    { "name": "byte-gauge:shannon_entropy", "value": format!("{:.4}", result.shannon_entropy) },
                    { "name": "byte-gauge:peak_chunk_entropy", "value": format!("{:.4}", result.peak_chunk_entropy) },
                    { "name": "byte-gauge:statically_linked", "value": result.binary_meta.is_statically_linked.to_string() },
                    { "name": "byte-gauge:aslr_pie", "value": h.aslr_pie.to_string() },
                    { "name": "byte-gauge:nx_dep", "value": h.nx_dep.to_string() },
                    { "name": "byte-gauge:relro_or_cfg", "value": h.relro_or_cfg }
                ]
            }
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_bom_ref,
                "dependsOn": depends_on
            }
        ]
    })
}

/// Deriva un UUID v4-compatible determinista a partir de los primeros 32 caracteres hexadecimales del SHA-256.
fn deterministic_uuid_from_sha256(sha256: &str) -> String {
    let hex = if sha256.len() >= 32 {
        &sha256[..32]
    } else {
        "00000000000040008000000000000000"
    };
    format!(
        "{}-{}-4{}-a{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

pub fn write_cyclonedx_sbom(sbom_path: &Path, result: &AuditResult) -> Result<()> {
    if let Some(parent) = sbom_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_string_pretty(&build_cyclonedx_sbom(result))?;
    std::fs::write(sbom_path, payload).with_context(|| {
        format!(
            "No se pudo escribir el SBOM CycloneDX en {}",
            sbom_path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{BinaryHardening, BinaryMetadata, SectionInfo};

    #[test]
    fn generates_valid_cyclonedx_1_5_sbom_with_dependencies() {
        let res = AuditResult {
            file_name: "vortex-linux-x64".to_string(),
            total_bytes: 2_048_000,
            size_mb: 1.95,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            shannon_entropy: 6.1,
            peak_chunk_entropy: 6.4,
            peak_entropy_offset: 0,
            total_issues: 0,
            matches: vec![],
            entropy_secrets: vec![],
            binary_meta: BinaryMetadata {
                format: "ELF".to_string(),
                architecture: "x86_64".to_string(),
                has_debug_symbols: false,
                is_statically_linked: false,
                dynamic_libraries: vec!["libc.so.6".to_string(), "libm.so.6".to_string()],
                hardening: BinaryHardening {
                    applicable: true,
                    aslr_pie: true,
                    high_entropy_va: true,
                    nx_dep: true,
                    relro_or_cfg: "Full RELRO".to_string(),
                },
                sections: vec![SectionInfo {
                    name: ".text".to_string(),
                    size_bytes: 2_048_000,
                    percentage: 100.0,
                }],
            },
            duration_ms: 1.2,
            throughput_mb_s: 500.0,
        };

        let sbom = build_cyclonedx_sbom(&res);
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        let comps = sbom["components"].as_array().unwrap();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0]["name"], "libc.so.6");
        let deps = sbom["dependencies"][0]["dependsOn"].as_array().unwrap();
        assert_eq!(deps.len(), 2);
    }
}
