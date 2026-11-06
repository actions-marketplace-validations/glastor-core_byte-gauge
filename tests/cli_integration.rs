use std::fs;
use std::io::Write;
use std::process::Command;

const CHUNK_SIZE: usize = 64 * 1024;

#[test]
fn e2e_cli_passes_clean_self_audit_and_writes_github_env_files() {
    let bin = env!("CARGO_BIN_EXE_byte-gauge");
    let temp_dir = std::env::temp_dir().join("byte_gauge_e2e_self");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let summary_file = temp_dir.join("step_summary.md");
    let output_file = temp_dir.join("github_output.txt");
    let json_file = temp_dir.join("audit.json");
    let sarif_file = temp_dir.join("audit.sarif");

    let status = Command::new(bin)
        .arg("--file-path")
        .arg(bin)
        .arg("--max-size-mb")
        .arg("50.0")
        .arg("--output-json")
        .arg(&json_file)
        .arg("--output-sarif")
        .arg(&sarif_file)
        .env("GITHUB_STEP_SUMMARY", &summary_file)
        .env("GITHUB_OUTPUT", &output_file)
        .status()
        .expect("Failed to execute byte-gauge binary");

    assert!(status.success(), "Self-audit should exit with code 0");

    let summary_md = fs::read_to_string(&summary_file).unwrap();
    let gh_output = fs::read_to_string(&output_file).unwrap();
    let sarif_str = fs::read_to_string(&sarif_file).unwrap();

    assert!(summary_md.contains("# 🛡️ Byte-Gauge: Rust Binary Audit Summary"));
    assert!(summary_md.contains("```mermaid"));
    assert!(gh_output.contains("issues=0"));
    assert!(gh_output.contains("aslr_pie=true"));
    assert!(sarif_str.contains("\"version\": \"2.1.0\""));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn e2e_cli_blocks_leaked_medusa_secret_across_64kb_boundary() {
    let bin = env!("CARGO_BIN_EXE_byte-gauge");
    let temp_dir = std::env::temp_dir().join("byte_gauge_e2e_secret");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let artifact_path = temp_dir.join("medusa_leaked.bin");
    let sarif_path = temp_dir.join("leaked.sarif");

    // Inyectamos "MEDUSA_ADMIN_TOKEN" partido justo en la frontera de 64 KB (65536)
    let secret = b"MEDUSA_ADMIN_TOKEN";
    let split_pos = CHUNK_SIZE - 6;
    let mut payload = vec![b'0'; CHUNK_SIZE + 2048];
    payload[split_pos..split_pos + secret.len()].copy_from_slice(secret);

    {
        let mut f = fs::File::create(&artifact_path).unwrap();
        f.write_all(&payload).unwrap();
    }

    let output = Command::new(bin)
        .arg("--file-path")
        .arg(&artifact_path)
        .arg("--output-sarif")
        .arg(&sarif_path)
        .output()
        .expect("Failed to execute byte-gauge");

    assert!(
        !output.status.success(),
        "Debe fallar (exit code 1) cuando detecta MEDUSA_ADMIN_TOKEN filtrado"
    );

    let sarif_str = fs::read_to_string(&sarif_path).unwrap();
    assert!(
        sarif_str.contains("BG001"),
        "El archivo SARIF debe registrar la alerta BG001 (ForbiddenByteSequence)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn e2e_cli_blocks_finops_size_regression_against_baseline() {
    let bin = env!("CARGO_BIN_EXE_byte-gauge");
    let temp_dir = std::env::temp_dir().join("byte_gauge_e2e_regression");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let base_bin = temp_dir.join("vortex_v1.bin");
    let bloated_bin = temp_dir.join("vortex_v2.bin");
    let baseline_json = temp_dir.join("baseline.json");
    let sarif_path = temp_dir.join("regression.sarif");

    fs::write(&base_bin, vec![b'X'; 100_000]).unwrap();
    fs::write(&bloated_bin, vec![b'X'; 120_000]).unwrap(); // +20% growth

    // 1. Generar baseline JSON con 100 KB
    let status_base = Command::new(bin)
        .arg("--file-path")
        .arg(&base_bin)
        .arg("--output-json")
        .arg(&baseline_json)
        .status()
        .unwrap();
    assert!(status_base.success());

    // 2. Auditar binario de 120 KB (+20%) con límite de regresión de +5.0%
    let status_reg = Command::new(bin)
        .arg("--file-path")
        .arg(&bloated_bin)
        .arg("--baseline-json")
        .arg(&baseline_json)
        .arg("--max-regression-pct")
        .arg("5.0")
        .arg("--output-sarif")
        .arg(&sarif_path)
        .status()
        .unwrap();

    assert!(
        !status_reg.success(),
        "Debe bloquear el pipeline cuando el crecimiento (+20%) supera --max-regression-pct 5.0"
    );

    let sarif_str = fs::read_to_string(&sarif_path).unwrap();
    assert!(
        sarif_str.contains("BG003"),
        "El reporte SARIF debe incluir la regla BG003 (SizeRegressionExceeded)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn e2e_cli_fails_gracefully_on_missing_file() {
    let bin = env!("CARGO_BIN_EXE_byte-gauge");
    let output = Command::new(bin)
        .arg("--file-path")
        .arg("non_existent_artifact_12345.bin")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("::error title=Error de Lectura Binaria::"));
}

#[test]
fn e2e_cli_audits_wasm_batch_and_exports_cyclonedx_sbom_and_sticky_markdown() {
    let bin = env!("CARGO_BIN_EXE_byte-gauge");
    let temp_dir = std::env::temp_dir().join("byte_gauge_e2e_wasm_batch");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let wasm_file = temp_dir.join("medusa_edge.wasm");
    let raw_file = temp_dir.join("vortex_worker.bin");
    let sbom_file = temp_dir.join("medusa.cdx.json");
    let md_file = temp_dir.join("sticky.md");

    // Crear módulo Wasm válido sin sección "name" (stripped)
    let mut wasm_bytes = Vec::new();
    wasm_bytes.extend_from_slice(b"\0asm\x01\x00\x00\x00");
    wasm_bytes.extend_from_slice(&[10, 6, 1, 4, 0, 65, 42, 11]);
    fs::write(&wasm_file, &wasm_bytes).unwrap();
    fs::write(&raw_file, vec![b'Z'; 4096]).unwrap();

    let batch_arg = format!("{},{}", wasm_file.display(), raw_file.display());

    let status = Command::new(bin)
        .arg("--file-path")
        .arg(&batch_arg)
        .arg("--output-sbom")
        .arg(&sbom_file)
        .arg("--output-markdown")
        .arg(&md_file)
        .status()
        .unwrap();

    assert!(status.success());

    let sbom_content = fs::read_to_string(&sbom_file).unwrap();
    let md_content = fs::read_to_string(&md_file).unwrap();

    assert!(sbom_content.contains("\"bomFormat\": \"CycloneDX\""));
    assert!(sbom_content.contains("\"WebAssembly (Wasm)\""));
    assert!(md_content.contains("<!-- glastor-byte-gauge-sticky-comment -->"));
    assert!(md_content.contains("Matriz Comparativa Multi-Binario (2 Artefactos)"));

    let _ = fs::remove_dir_all(&temp_dir);
}
