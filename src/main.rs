mod report;
mod sarif;
mod sbom;
mod scanner;

use anyhow::{Context, Result};
use clap::Parser;
use report::{
    AuditVerdict, PolicyConfig, append_github_step_summary, evaluate_verdict,
    render_batch_markdown_summary, write_github_outputs,
};
use sarif::write_sarif_file;
use sbom::write_cyclonedx_sbom;
use scanner::{AuditResult, analyze_file_with_options};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "byte-gauge",
    version,
    about = "Auditor binario de alto rendimiento (SIMD + ELF/PE/Mach-O/Wasm + checksec + Entropía + SARIF 2.1.0 + SBOM CycloneDX 1.5)"
)]
struct Cli {
    /// Ruta del espacio de trabajo (inyectado automáticamente en GitHub Actions)
    #[arg(short, long, env = "GITHUB_WORKSPACE")]
    workspace: Option<PathBuf>,

    /// Ruta(s) relativa(s) o absoluta(s) de los archivos binarios a auditar (separadas por coma para modo batch)
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_value = "dist/app.bin",
        env = "INPUT_FILE_PATH"
    )]
    file_path: Vec<PathBuf>,

    /// Lista de patrones prohibidos separados por coma (búsqueda SIMD en ventana deslizante sin pérdida en fronteras)
    #[arg(short, long, value_delimiter = ',', env = "INPUT_FORBIDDEN_PATTERNS")]
    patterns: Vec<String>,

    /// Activar caza heurística de tokens/secretos de alta entropía enmascarados (32..=64 bytes)
    #[arg(long, default_value_t = false, env = "INPUT_SCAN_ENTROPY_SECRETS")]
    scan_entropy_secrets: bool,

    /// Presupuesto máximo de tamaño en MB (falla el pipeline si el binario lo supera)
    #[arg(long, env = "INPUT_MAX_SIZE_MB")]
    max_size_mb: Option<String>,

    /// Porcentaje máximo permitido de crecimiento respecto al baseline JSON (ej. 5.0 para +5%)
    #[arg(long, env = "INPUT_MAX_REGRESSION_PCT")]
    max_regression_pct: Option<String>,

    /// Umbral de alerta para la Entropía de Shannon global y por ventana de 64KB (0.0 a 8.0 bits/byte)
    #[arg(long, default_value_t = 7.2, env = "INPUT_MAX_ENTROPY")]
    max_entropy: f64,

    /// Fallar la auditoría si el binario aún contiene símbolos de depuración (.debug / .symtab / Wasm name)
    #[arg(long, default_value_t = false, env = "INPUT_FAIL_ON_DEBUG")]
    fail_on_debug: bool,

    /// Ruta opcional para exportar las métricas en formato JSON (para artefactos o caché de historial)
    #[arg(long, env = "INPUT_OUTPUT_JSON")]
    output_json: Option<PathBuf>,

    /// Ruta opcional para exportar reporte SARIF 2.1.0 para GitHub Security (Code Scanning)
    #[arg(long, env = "INPUT_OUTPUT_SARIF")]
    output_sarif: Option<PathBuf>,

    /// Ruta opcional para exportar SBOM en formato CycloneDX 1.5 JSON
    #[arg(long, env = "INPUT_OUTPUT_SBOM")]
    output_sbom: Option<PathBuf>,

    /// Ruta opcional para guardar el reporte Markdown en disco (usado para Sticky Comments en PRs)
    #[arg(long, env = "INPUT_OUTPUT_MARKDOWN")]
    output_markdown: Option<PathBuf>,

    /// Ruta opcional a un JSON de auditoría previa para calcular el delta de tamaño (regresión de peso)
    #[arg(long, env = "INPUT_BASELINE_JSON")]
    baseline_json: Option<PathBuf>,

    /// Variable nativa de GitHub Actions para inyectar el Job Summary en Markdown
    #[arg(long, env = "GITHUB_STEP_SUMMARY", hide_env_values = true)]
    github_step_summary: Option<PathBuf>,

    /// Variable nativa de GitHub Actions para exportar outputs a pasos posteriores
    #[arg(long, env = "GITHUB_OUTPUT", hide_env_values = true)]
    github_output: Option<PathBuf>,

    /// Imprimir también el reporte Markdown por salida estándar (útil en ejecución local)
    #[arg(long, default_value_t = false)]
    print_markdown: bool,
}

/// Construye los patrones por defecto en tiempo de ejecución sin alojar las secuencias
/// contiguas literales dentro de `.rodata`/`.rdata`, permitiendo que `byte-gauge` se
/// auto-audite a sí mismo y proteja artefactos de `vortex` y `medusa` sin falsos positivos.
fn default_forbidden_patterns() -> Vec<String> {
    [
        "E|V|I|L",
        "BEGIN RSA |PRIVATE KEY",
        "BEGIN OPENSSH |PRIVATE KEY",
        "AWS_SECRET_|ACCESS_KEY",
        "APILAYER_|API_KEY",
        "MEDUSA_ADMIN_|TOKEN",
    ]
    .into_iter()
    .map(|raw| raw.replace('|', ""))
    .collect()
}

/// Escapa caracteres de control (`%`, `\r`, `\n`) para prevenir inyección de comandos
/// en anotaciones de GitHub Actions (`::notice`, `::warning`, `::error` — CWE-74).
fn escape_gh_annotation(input: &str) -> String {
    input
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn main() -> Result<()> {
    let args = Cli::parse();

    let active_patterns: Vec<String> = args
        .patterns
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();

    let patterns = if active_patterns.is_empty() {
        default_forbidden_patterns()
    } else {
        active_patterns
    };

    let mut results: Vec<AuditResult> = Vec::new();
    let mut primary_uri = String::new();

    for (idx, raw_path) in args.file_path.iter().enumerate() {
        let target_file = if raw_path.is_absolute() {
            raw_path.clone()
        } else if let Some(ref ws) = args.workspace {
            ws.join(raw_path)
        } else {
            raw_path.clone()
        };

        if idx == 0 {
            primary_uri = raw_path.to_string_lossy().into_owned();
        }

        println!(
            "::notice title=Byte-Gauge Audit::Iniciando escaneo binario síncrono SIMD sobre '{}'",
            escape_gh_annotation(&target_file.display().to_string())
        );

        match analyze_file_with_options(&target_file, &patterns, args.scan_entropy_secrets) {
            Ok(res) => results.push(res),
            Err(err) => {
                println!(
                    "::error title=Error de Lectura Binaria::{}",
                    escape_gh_annotation(&format!("{:#}", err))
                );
                std::process::exit(1);
            }
        }
    }

    if results.is_empty() {
        anyhow::bail!("No se especificó ningún archivo binario para auditar.");
    }

    // Cargar línea base (baseline) si existe para comparar delta de tamaño
    let baseline: Option<AuditResult> = match args.baseline_json {
        Some(ref base_path) if !base_path.as_os_str().is_empty() && base_path.exists() => {
            let content = std::fs::read_to_string(base_path).with_context(|| {
                format!("Error leyendo baseline JSON en {}", base_path.display())
            })?;
            serde_json::from_str(&content).ok()
        }
        _ => None,
    };

    let max_size_mb = args
        .max_size_mb
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<f64>().context("Valor inválido en --max-size-mb"))
        .transpose()?;

    let max_regression_pct = args
        .max_regression_pct
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<f64>()
                .context("Valor inválido en --max-regression-pct")
        })
        .transpose()?;

    let policy = PolicyConfig {
        max_size_mb,
        max_regression_pct,
        max_entropy: args.max_entropy,
        fail_on_debug_symbols: args.fail_on_debug,
        baseline,
    };

    let markdown = render_batch_markdown_summary(&results, &policy);
    let primary_result = &results[0];

    if args.print_markdown {
        println!("\n{}", markdown);
    }

    // Guardar Markdown en archivo si se solicitó (usado para Sticky Comments en PRs)
    if let Some(ref md_path) = args.output_markdown
        && !md_path.as_os_str().is_empty()
    {
        if let Some(parent) = md_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(md_path, &markdown)?;
    }

    // Exportar JSON si se solicitó
    if let Some(ref json_path) = args.output_json
        && !json_path.as_os_str().is_empty()
    {
        if let Some(parent) = json_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let json_payload = serde_json::to_string_pretty(primary_result)?;
        std::fs::write(json_path, json_payload).with_context(|| {
            format!(
                "No se pudo guardar el reporte JSON en {}",
                json_path.display()
            )
        })?;
    }

    // Exportar SARIF 2.1.0 si se solicitó (para GitHub Security Code Scanning)
    if let Some(ref sarif_path) = args.output_sarif
        && !sarif_path.as_os_str().is_empty()
    {
        write_sarif_file(sarif_path, primary_result, &policy, &primary_uri)?;
    }

    // Exportar SBOM CycloneDX 1.5 si se solicitó
    if let Some(ref sbom_path) = args.output_sbom
        && !sbom_path.as_os_str().is_empty()
    {
        write_cyclonedx_sbom(sbom_path, primary_result)?;
    }

    // Escribir en GITHUB_STEP_SUMMARY si estamos en GitHub Actions (o si se pasó por parámetro)
    if let Some(ref summary_path) = args.github_step_summary
        && !summary_path.as_os_str().is_empty()
    {
        append_github_step_summary(summary_path, &markdown)?;
    }

    // Evaluar veredicto global de todos los archivos auditados
    let mut overall_verdict = AuditVerdict::Passed;
    for res in &results {
        let (verdict, reasons) = evaluate_verdict(res, &policy);
        let safe_file = escape_gh_annotation(&res.file_name);

        match verdict {
            AuditVerdict::Passed => {
                println!(
                    "::notice title=Auditoría Aprobada ({})::{} ({:.2} MB, SHA256: {}..., {:.2} ms)",
                    safe_file,
                    escape_gh_annotation(&reasons.join(" ")),
                    res.size_mb,
                    &res.sha256[..12],
                    res.duration_ms
                );
            }
            AuditVerdict::Warning => {
                if overall_verdict == AuditVerdict::Passed {
                    overall_verdict = AuditVerdict::Warning;
                }
                for r in &reasons {
                    println!(
                        "::warning title=Alerta de Auditoría ({})::{}",
                        safe_file,
                        escape_gh_annotation(r)
                    );
                }
            }
            AuditVerdict::Failed => {
                overall_verdict = AuditVerdict::Failed;
                for r in &reasons {
                    println!(
                        "::error title=Fallo de Auditoría ({})::{}",
                        safe_file,
                        escape_gh_annotation(r)
                    );
                }
            }
        }
    }

    // Escribir outputs para pasos posteriores en GITHUB_OUTPUT
    if let Some(ref output_path) = args.github_output
        && !output_path.as_os_str().is_empty()
    {
        write_github_outputs(output_path, primary_result, &policy, overall_verdict)?;
    }

    if overall_verdict == AuditVerdict::Failed {
        std::process::exit(1);
    }

    Ok(())
}
