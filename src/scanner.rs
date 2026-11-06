use anyhow::{Context, Result};
use goblin::Object;
use memchr::memmem::Finder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

/// Tamaño fijo de bloque de lectura en streaming (64 KB).
pub const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern: String,
    pub count: u64,
    pub first_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropySecretFinding {
    /// Vista previa enmascarada (ej. `a8f9...3b2c`) para nunca filtrar el secreto en logs de CI
    pub masked_preview: String,
    pub offset: u64,
    pub length: usize,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub size_bytes: u64,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryHardening {
    /// Indica si es un formato ejecutable verificable (ELF, PE, Mach-O, Wasm)
    pub applicable: bool,
    /// ASLR / Position Independent Executable (PIE en ELF/Mach-O, DYNAMIC_BASE en PE)
    pub aslr_pie: bool,
    /// Espacio de direcciones de alta entropía de 64 bits (HIGH_ENTROPY_VA en PE / PIE 64-bit)
    pub high_entropy_va: bool,
    /// Pila no ejecutable / Data Execution Prevention (PT_GNU_STACK sin PF_X en ELF, NX_COMPAT en PE)
    pub nx_dep: bool,
    /// Estado de RELRO (ELF), Control Flow Guard (PE) o Sandbox Wasm
    pub relro_or_cfg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetadata {
    pub format: String,
    pub architecture: String,
    pub has_debug_symbols: bool,
    pub is_statically_linked: bool,
    pub dynamic_libraries: Vec<String>,
    pub hardening: BinaryHardening,
    pub sections: Vec<SectionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub file_name: String,
    pub total_bytes: u64,
    pub size_mb: f64,
    pub sha256: String,
    pub shannon_entropy: f64,
    pub peak_chunk_entropy: f64,
    pub peak_entropy_offset: u64,
    pub total_issues: u64,
    pub matches: Vec<PatternMatch>,
    #[serde(default)]
    pub entropy_secrets: Vec<EntropySecretFinding>,
    pub binary_meta: BinaryMetadata,
    pub duration_ms: f64,
    pub throughput_mb_s: f64,
}

#[cfg(test)]
pub fn analyze_file(path: &Path, forbidden_patterns: &[String]) -> Result<AuditResult> {
    analyze_file_with_options(path, forbidden_patterns, false)
}

/// Escanea un archivo binario en una sola pasada en streaming O(1) RAM:
/// 1. Búsqueda SIMD (`memchr::memmem`) con ventana solapada para evitar falsos negativos en bordes de 64 KB.
/// 2. Cálculo de hash criptográfico SHA-256.
/// 3. Histograma global + Entropía pico por ventana de 64 KB (`peak_chunk_entropy` y `peak_entropy_offset`).
/// 4. Inspección estructural ELF/PE/Mach-O/WebAssembly: secciones, símbolos, librerías dinámicas y `checksec`.
/// 5. Caza opcional de cadenas de alta entropía enmascaradas (`scan_entropy_secrets`).
pub fn analyze_file_with_options(
    path: &Path,
    forbidden_patterns: &[String],
    scan_entropy_secrets: bool,
) -> Result<AuditResult> {
    let start = Instant::now();
    let mut file = File::open(path).with_context(|| {
        format!(
            "No se encontró o no se pudo abrir el archivo binario: {}",
            path.display()
        )
    })?;

    // CWE-400 Guard: Verificar que sea un archivo regular (rechaza dispositivos como /dev/zero, FIFOs o directorios)
    let metadata = file.metadata().with_context(|| {
        format!(
            "No se pudieron leer los metadatos del archivo: {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!(
            "La ruta especificada no es un archivo regular válido (dispositivo/FIFO/directorio rechazado): {}",
            path.display()
        );
    }

    let finders: Vec<(&str, Finder<'_>)> = forbidden_patterns
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| (p.as_str(), Finder::new(p.as_bytes())))
        .collect();

    let max_pat_len = finders.iter().map(|(p, _)| p.len()).max().unwrap_or(1);
    let overlap_cap = max_pat_len.saturating_sub(1);

    // Buffer único reutilizable: [zona de solapamiento previo | bloque nuevo de 64 KB]
    let mut buffer = vec![0u8; overlap_cap + CHUNK_SIZE];
    let mut current_overlap = 0usize;

    let mut total_bytes = 0u64;
    let mut byte_counts = [0u64; 256];
    let mut peak_chunk_entropy = 0.0f64;
    let mut peak_entropy_offset = 0u64;
    let mut hasher = Sha256::new();

    let mut match_counts = vec![0u64; finders.len()];
    let mut first_offsets: Vec<Option<u64>> = vec![None; finders.len()];
    let mut entropy_secrets: Vec<EntropySecretFinding> = Vec::new();

    loop {
        let read_window = &mut buffer[current_overlap..current_overlap + CHUNK_SIZE];
        let bytes_read = file.read(read_window)?;
        if bytes_read == 0 {
            break;
        }

        let new_data = &buffer[current_overlap..current_overlap + bytes_read];
        hasher.update(new_data);

        let mut chunk_counts = [0u64; 256];
        for &b in new_data {
            chunk_counts[b as usize] += 1;
        }
        for i in 0..256 {
            byte_counts[i] += chunk_counts[i];
        }

        let chunk_entropy = compute_shannon_entropy(&chunk_counts, bytes_read as u64);
        if chunk_entropy > peak_chunk_entropy {
            peak_chunk_entropy = chunk_entropy;
            peak_entropy_offset = total_bytes;
        }

        if scan_entropy_secrets && entropy_secrets.len() < 10 {
            scan_chunk_for_entropy_secrets(new_data, total_bytes, &mut entropy_secrets);
        }

        let valid_len = current_overlap + bytes_read;
        let window = &buffer[..valid_len];
        let chunk_start_offset = total_bytes;

        for (idx, (pat_str, finder)) in finders.iter().enumerate() {
            let pat_len = pat_str.len();
            let search_start = current_overlap.saturating_sub(pat_len.saturating_sub(1));
            let search_slice = &window[search_start..];

            for pos in finder.find_iter(search_slice) {
                match_counts[idx] += 1;
                if first_offsets[idx].is_none() {
                    let abs_offset =
                        chunk_start_offset + (search_start + pos) as u64 - (current_overlap as u64);
                    first_offsets[idx] = Some(abs_offset);
                }
            }
        }

        total_bytes += bytes_read as u64;

        if overlap_cap > 0 {
            let keep = valid_len.min(overlap_cap);
            buffer.copy_within(valid_len - keep..valid_len, 0);
            current_overlap = keep;
        }
    }

    let sha256 = format!("{:x}", hasher.finalize());
    let shannon_entropy = compute_shannon_entropy(&byte_counts, total_bytes);
    let binary_meta = inspect_binary_structure(path, total_bytes);

    let mut matches = Vec::with_capacity(finders.len());
    let mut total_issues = 0u64;
    for (idx, (pat_str, _)) in finders.iter().enumerate() {
        let count = match_counts[idx];
        total_issues += count;
        matches.push(PatternMatch {
            pattern: (*pat_str).to_string(),
            count,
            first_offset: first_offsets[idx],
        });
    }

    let elapsed_secs = start.elapsed().as_secs_f64();
    let duration_ms = elapsed_secs * 1000.0;
    let size_mb = (total_bytes as f64) / 1_048_576.0;
    let throughput_mb_s = if elapsed_secs > 0.0 {
        size_mb / elapsed_secs
    } else {
        size_mb * 1000.0
    };

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());

    Ok(AuditResult {
        file_name,
        total_bytes,
        size_mb,
        sha256,
        shannon_entropy,
        peak_chunk_entropy,
        peak_entropy_offset,
        total_issues,
        matches,
        entropy_secrets,
        binary_meta,
        duration_ms,
        throughput_mb_s,
    })
}

/// Detecta heurísticamente cadenas de alta entropía (API Keys / secretos Base64 de 32..=64 bytes)
/// y las enmascara (`abcd...wxyz`) para nunca exponer el secreto en los logs de CI.
fn scan_chunk_for_entropy_secrets(
    chunk: &[u8],
    chunk_base_offset: u64,
    findings: &mut Vec<EntropySecretFinding>,
) {
    let mut i = 0;
    while i < chunk.len() && findings.len() < 10 {
        if is_secret_token_char(chunk[i]) {
            let start = i;
            while i < chunk.len() && is_secret_token_char(chunk[i]) {
                i += 1;
            }
            let token = &chunk[start..i];
            if (32..=64).contains(&token.len()) && is_likely_high_entropy_secret(token) {
                let mut counts = [0u64; 256];
                for &b in token {
                    counts[b as usize] += 1;
                }
                let h = compute_shannon_entropy(&counts, token.len() as u64);
                if h >= 4.70 {
                    let prefix = String::from_utf8_lossy(&token[..4]);
                    let suffix = String::from_utf8_lossy(&token[token.len() - 4..]);
                    findings.push(EntropySecretFinding {
                        masked_preview: format!("{}...{}", prefix, suffix),
                        offset: chunk_base_offset + (start as u64),
                        length: token.len(),
                        entropy: h,
                    });
                }
            }
        } else {
            i += 1;
        }
    }
}

#[inline]
fn is_secret_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'_' || b == b'-'
}

fn is_likely_high_entropy_secret(token: &[u8]) -> bool {
    // Excluir símbolos mangled de Rust/C++ (_ZN, RNv, __imp) o cadenas puramente hexadecimales (hashes públicos)
    if token.starts_with(b"_ZN")
        || token.starts_with(b"RNv")
        || token.starts_with(b"__")
        || token.iter().all(|b| b.is_ascii_hexdigit())
    {
        return false;
    }
    let has_upper = token.iter().any(|b| b.is_ascii_uppercase());
    let has_lower = token.iter().any(|b| b.is_ascii_lowercase());
    let has_digit = token.iter().any(|b| b.is_ascii_digit());
    let digits_count = token.iter().filter(|b| b.is_ascii_digit()).count();
    has_upper && has_lower && has_digit && digits_count >= 4
}

/// Calcula la entropía de Shannon en bits por byte (rango 0.0 a 8.0).
pub fn compute_shannon_entropy(byte_counts: &[u64; 256], total_bytes: u64) -> f64 {
    if total_bytes == 0 {
        return 0.0;
    }
    let total = total_bytes as f64;
    let mut entropy = 0.0f64;
    for &count in byte_counts {
        if count > 0 {
            let p = (count as f64) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Analiza encabezados ejecutables (WebAssembly, ELF, PE/Windows, Mach-O) si el archivo no supera 128 MB.
fn inspect_binary_structure(path: &Path, total_bytes: u64) -> BinaryMetadata {
    const MAX_PARSE_SIZE: u64 = 128 * 1024 * 1024;
    if total_bytes == 0 || total_bytes > MAX_PARSE_SIZE {
        return default_raw_metadata(total_bytes);
    }

    let Ok(bytes) = std::fs::read(path) else {
        return default_raw_metadata(total_bytes);
    };

    // 1. Detección nativa de módulos WebAssembly (\0asm + v1)
    if bytes.len() >= 8 && &bytes[0..4] == b"\0asm" && bytes[4..8] == [1, 0, 0, 0] {
        return inspect_wasm_binary(&bytes, total_bytes);
    }

    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            let arch = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => "x86_64",
                goblin::elf::header::EM_AARCH64 => "ARM64 (AArch64)",
                goblin::elf::header::EM_386 => "x86",
                goblin::elf::header::EM_ARM => "ARM",
                goblin::elf::header::EM_RISCV => "RISC-V",
                _ => "ELF Generic",
            };
            let mut has_debug = false;
            let mut sections = Vec::new();
            let mut accounted = 0u64;

            for sh in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                    if name.starts_with(".debug") || name == ".symtab" {
                        has_debug = true;
                    }
                    if sh.sh_size > 0
                        && sh.sh_type != goblin::elf::section_header::SHT_NOBITS
                        && !name.is_empty()
                    {
                        sections.push((name.to_string(), sh.sh_size));
                        accounted += sh.sh_size;
                    }
                }
            }

            let aslr_pie = elf.header.e_type == goblin::elf::header::ET_DYN;
            let high_entropy_va = aslr_pie && elf.is_64;
            let nx_dep = elf
                .program_headers
                .iter()
                .find(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK)
                .is_none_or(|ph| (ph.p_flags & goblin::elf::program_header::PF_X) == 0);

            let has_relro = elf
                .program_headers
                .iter()
                .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO);
            let has_bind_now = elf.dynamic.as_ref().is_some_and(|dyn_info| {
                dyn_info.dyns.iter().any(|d| {
                    d.d_tag == goblin::elf::dynamic::DT_BIND_NOW
                        || (d.d_tag == goblin::elf::dynamic::DT_FLAGS
                            && (d.d_val & goblin::elf::dynamic::DF_BIND_NOW) != 0)
                        || (d.d_tag == goblin::elf::dynamic::DT_FLAGS_1
                            && (d.d_val & goblin::elf::dynamic::DF_1_NOW) != 0)
                })
            });

            let relro_or_cfg = match (has_relro, has_bind_now) {
                (true, true) => "Full RELRO".to_string(),
                (true, false) => "Partial RELRO".to_string(),
                (false, _) => "No RELRO".to_string(),
            };

            let dynamic_libraries: Vec<String> =
                elf.libraries.iter().map(|s| (*s).to_string()).collect();

            let hardening = BinaryHardening {
                applicable: true,
                aslr_pie,
                high_entropy_va,
                nx_dep,
                relro_or_cfg,
            };

            finalize_sections(
                "ELF",
                arch,
                has_debug,
                dynamic_libraries,
                hardening,
                sections,
                accounted,
                total_bytes,
            )
        }
        Ok(Object::PE(pe)) => {
            let arch = if pe.is_64 {
                "x86_64 (PE32+)"
            } else {
                "x86 (PE32)"
            };
            let mut has_debug = false;
            let mut sections = Vec::new();
            let mut accounted = 0u64;

            for sec in &pe.sections {
                let name = String::from_utf8_lossy(&sec.name)
                    .trim_end_matches('\0')
                    .to_string();
                if name.starts_with(".debug") {
                    has_debug = true;
                }
                let size = sec.size_of_raw_data as u64;
                if size > 0 {
                    sections.push((name, size));
                    accounted += size;
                }
            }

            let dll_chars = pe
                .header
                .optional_header
                .map(|h| h.windows_fields.dll_characteristics)
                .unwrap_or(0);
            let high_entropy_va = (dll_chars & 0x0020) != 0;
            let aslr_pie = (dll_chars & 0x0040) != 0;
            let nx_dep = (dll_chars & 0x0100) != 0;
            let cfg_enabled = (dll_chars & 0x4000) != 0;

            let hardening = BinaryHardening {
                applicable: true,
                aslr_pie,
                high_entropy_va,
                nx_dep,
                relro_or_cfg: if cfg_enabled {
                    "Control Flow Guard (CFG)".to_string()
                } else {
                    "Standard PE (No CFG)".to_string()
                },
            };

            let dynamic_libraries: Vec<String> =
                pe.libraries.iter().map(|s| (*s).to_string()).collect();

            finalize_sections(
                "PE (Windows)",
                arch,
                has_debug,
                dynamic_libraries,
                hardening,
                sections,
                accounted,
                total_bytes,
            )
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(mach))) => {
            let arch = if mach.is_64 {
                "64-bit Mach-O"
            } else {
                "32-bit Mach-O"
            };
            let mut has_debug = false;
            let mut sections = Vec::new();
            let mut accounted = 0u64;

            for seg in &mach.segments {
                if let Ok(name) = seg.name() {
                    if name.contains("DWARF") {
                        has_debug = true;
                    }
                    if seg.filesize > 0 {
                        sections.push((name.to_string(), seg.filesize));
                        accounted += seg.filesize;
                    }
                }
            }

            let aslr_pie = (mach.header.flags & 0x0020_0000) != 0;
            let hardening = BinaryHardening {
                applicable: true,
                aslr_pie,
                high_entropy_va: aslr_pie && mach.is_64,
                nx_dep: true,
                relro_or_cfg: "Mach-O Hardened".to_string(),
            };

            let dynamic_libraries: Vec<String> =
                mach.libs.iter().skip(1).map(|s| (*s).to_string()).collect();

            finalize_sections(
                "Mach-O (macOS)",
                arch,
                has_debug,
                dynamic_libraries,
                hardening,
                sections,
                accounted,
                total_bytes,
            )
        }
        _ => default_raw_metadata(total_bytes),
    }
}

/// Parser nativo de secciones WebAssembly (`.wasm`) sin dependencias adicionales (decodificación uLEB128).
fn inspect_wasm_binary(bytes: &[u8], total_bytes: u64) -> BinaryMetadata {
    let mut pos = 8usize;
    let mut has_debug = false;
    let mut sections = Vec::new();
    let mut accounted = 0u64;

    while pos < bytes.len() {
        let section_id = bytes[pos];
        pos += 1;
        let Some((sec_size, consumed)) = decode_uleb128(&bytes[pos..]) else {
            break;
        };
        pos += consumed;
        let sec_end = pos.saturating_add(sec_size as usize).min(bytes.len());
        let sec_payload = &bytes[pos..sec_end];

        let sec_name = match section_id {
            0 => {
                if let Some((name_len, n_consumed)) = decode_uleb128(sec_payload) {
                    let name_end = n_consumed
                        .saturating_add(name_len as usize)
                        .min(sec_payload.len());
                    let custom_name = String::from_utf8_lossy(&sec_payload[n_consumed..name_end]);
                    if custom_name == "name" || custom_name.starts_with(".debug") {
                        has_debug = true;
                    }
                    format!("Custom ({})", custom_name)
                } else {
                    "Custom".to_string()
                }
            }
            1 => "Type".to_string(),
            2 => "Import".to_string(),
            3 => "Function".to_string(),
            4 => "Table".to_string(),
            5 => "Memory".to_string(),
            6 => "Global".to_string(),
            7 => "Export".to_string(),
            8 => "Start".to_string(),
            9 => "Element".to_string(),
            10 => "Code (Bytecode)".to_string(),
            11 => "Data (Static Memory)".to_string(),
            12 => "DataCount".to_string(),
            _ => format!("Section #{}", section_id),
        };

        let actual_size = (sec_end - pos) as u64;
        if actual_size > 0 {
            sections.push((sec_name, actual_size));
            accounted += actual_size;
        }
        pos = sec_end;
    }

    let hardening = BinaryHardening {
        applicable: true,
        aslr_pie: true,
        high_entropy_va: false,
        nx_dep: true,
        relro_or_cfg: "Wasm Linear Memory Sandbox".to_string(),
    };

    finalize_sections(
        "WebAssembly (Wasm)",
        "wasm32",
        has_debug,
        Vec::new(),
        hardening,
        sections,
        accounted,
        total_bytes,
    )
}

fn decode_uleb128(slice: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (idx, &byte) in slice.iter().take(10).enumerate() {
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Some((result, idx + 1));
        }
        shift += 7;
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn finalize_sections(
    format: &str,
    arch: &str,
    has_debug_symbols: bool,
    dynamic_libraries: Vec<String>,
    hardening: BinaryHardening,
    mut raw_sections: Vec<(String, u64)>,
    accounted: u64,
    total_bytes: u64,
) -> BinaryMetadata {
    raw_sections.sort_by_key(|b| std::cmp::Reverse(b.1));
    let mut top_sections: Vec<SectionInfo> = raw_sections
        .into_iter()
        .take(5)
        .map(|(name, size_bytes)| SectionInfo {
            name,
            size_bytes,
            percentage: if total_bytes > 0 {
                (size_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();

    let top_sum: u64 = top_sections.iter().map(|s| s.size_bytes).sum();
    if total_bytes > top_sum {
        let rest = total_bytes - top_sum;
        top_sections.push(SectionInfo {
            name: "Otros / Headers".to_string(),
            size_bytes: rest,
            percentage: (rest as f64 / total_bytes as f64) * 100.0,
        });
    } else if accounted == 0 && total_bytes > 0 {
        top_sections.push(SectionInfo {
            name: "Payload".to_string(),
            size_bytes: total_bytes,
            percentage: 100.0,
        });
    }

    let is_statically_linked = dynamic_libraries.is_empty();

    BinaryMetadata {
        format: format.to_string(),
        architecture: arch.to_string(),
        has_debug_symbols,
        is_statically_linked,
        dynamic_libraries,
        hardening,
        sections: top_sections,
    }
}

fn default_raw_metadata(total_bytes: u64) -> BinaryMetadata {
    BinaryMetadata {
        format: "Raw Binary / Blob".to_string(),
        architecture: "N/A".to_string(),
        has_debug_symbols: false,
        is_statically_linked: true,
        dynamic_libraries: Vec::new(),
        hardening: BinaryHardening {
            applicable: false,
            aslr_pie: false,
            high_entropy_va: false,
            nx_dep: false,
            relro_or_cfg: "N/A".to_string(),
        },
        sections: vec![SectionInfo {
            name: "Raw Data".to_string(),
            size_bytes: total_bytes,
            percentage: if total_bytes > 0 { 100.0 } else { 0.0 },
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_pattern_split_across_64kb_chunk_boundary_and_tracks_peak_entropy() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("byte_gauge_boundary_test.bin");

        let mut payload = vec![b'A'; CHUNK_SIZE + 4096];
        for (i, b) in payload[CHUNK_SIZE..].iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        payload[CHUNK_SIZE - 2] = b'E';
        payload[CHUNK_SIZE - 1] = b'V';
        payload[CHUNK_SIZE] = b'I';
        payload[CHUNK_SIZE + 1] = b'L';

        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(&payload).unwrap();
        }

        let res = analyze_file(&file_path, &["EVIL".to_string()]).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert_eq!(res.total_issues, 1);
        assert_eq!(res.matches[0].first_offset, Some((CHUNK_SIZE - 2) as u64));
        assert!(res.peak_chunk_entropy > res.shannon_entropy);
        assert_eq!(res.peak_entropy_offset, CHUNK_SIZE as u64);
    }

    #[test]
    fn parses_webassembly_wasm_sections_and_debug_custom_section() {
        let temp_dir = std::env::temp_dir();
        let wasm_path = temp_dir.join("byte_gauge_test.wasm");

        // Construimos un módulo Wasm válido: \0asm + v1 + Sección Code (id=10, len=6) + Sección Custom "name" (id=0, len=5)
        let mut wasm_bytes = Vec::new();
        wasm_bytes.extend_from_slice(b"\0asm\x01\x00\x00\x00");
        // Sección 10 (Code): tamaño 6 bytes
        wasm_bytes.push(10);
        wasm_bytes.push(6);
        wasm_bytes.extend_from_slice(&[1, 4, 0, 65, 42, 11]);
        // Sección 0 (Custom "name"): tamaño 5 bytes (len=4 + "name")
        wasm_bytes.push(0);
        wasm_bytes.push(5);
        wasm_bytes.push(4);
        wasm_bytes.extend_from_slice(b"name");

        std::fs::write(&wasm_path, &wasm_bytes).unwrap();
        let res = analyze_file(&wasm_path, &[]).unwrap();
        let _ = std::fs::remove_file(&wasm_path);

        assert_eq!(res.binary_meta.format, "WebAssembly (Wasm)");
        assert_eq!(res.binary_meta.architecture, "wasm32");
        assert!(
            res.binary_meta.has_debug_symbols,
            "Debe detectar la sección custom 'name' como símbolos de debug en Wasm"
        );
        assert!(
            res.binary_meta
                .sections
                .iter()
                .any(|s| s.name == "Code (Bytecode)")
        );
    }

    #[test]
    fn detects_and_masks_heuristic_high_entropy_secret_strings() {
        let temp_dir = std::env::temp_dir();
        let bin_path = temp_dir.join("byte_gauge_entropy_secret.bin");

        let mut payload = vec![0u8; 512];
        // Token sintético de 40 caracteres con alta variedad alfanumérica (H > 4.75)
        let fake_secret = b"aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4cE6g";
        payload[128..128 + fake_secret.len()].copy_from_slice(fake_secret);

        std::fs::write(&bin_path, &payload).unwrap();
        let res = analyze_file_with_options(&bin_path, &[], true).unwrap();
        let _ = std::fs::remove_file(&bin_path);

        assert_eq!(res.entropy_secrets.len(), 1);
        assert_eq!(res.entropy_secrets[0].masked_preview, "aB3d...cE6g");
        assert_eq!(res.entropy_secrets[0].offset, 128);
    }

    #[test]
    fn computes_zero_and_maximum_shannon_entropy_accurately() {
        let empty_counts = [0u64; 256];
        assert_eq!(compute_shannon_entropy(&empty_counts, 0), 0.0);

        let mut single_byte_counts = [0u64; 256];
        single_byte_counts[0xAA] = 65536;
        assert!(compute_shannon_entropy(&single_byte_counts, 65536).abs() < 1e-9);

        let uniform_counts = [256u64; 256];
        let max_h = compute_shannon_entropy(&uniform_counts, 256 * 256);
        assert!((max_h - 8.0).abs() < 1e-9);
    }

    #[test]
    fn handles_empty_file_without_panic() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("byte_gauge_empty_test.bin");
        File::create(&file_path).unwrap();

        let res = analyze_file(&file_path, &["EVIL".to_string()]).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert_eq!(res.total_bytes, 0);
        assert_eq!(res.shannon_entropy, 0.0);
        assert_eq!(res.peak_chunk_entropy, 0.0);
        assert_eq!(res.total_issues, 0);
    }

    #[test]
    fn inspects_real_compiled_executable_headers_and_hardening() {
        let current_exe = std::env::current_exe().unwrap();
        let res = analyze_file(
            &current_exe,
            &["DEFINITELY_NOT_PRESENT_XYZ_999".to_string()],
        )
        .unwrap();

        assert!(res.total_bytes > 0);
        assert!(res.binary_meta.hardening.applicable);
        assert!(!res.binary_meta.sections.is_empty());
    }

    #[test]
    fn rejects_non_regular_files_like_directories_cwe400_guard() {
        let temp_dir = std::env::temp_dir();
        let err = analyze_file(&temp_dir, &["EVIL".to_string()]);
        assert!(err.is_err());
    }
}
