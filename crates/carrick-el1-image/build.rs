use std::path::{Path, PathBuf};
use std::process::Command;

fn get_sysroot() -> String {
    let output = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("failed to run rustc --print sysroot");
    String::from_utf8(output.stdout)
        .expect("sysroot is not valid utf-8")
        .trim()
        .to_string()
}

fn find_sysroot_tool(tool: &str, sysroot: &str, host: &str) -> PathBuf {
    let sysroot_path = Path::new(sysroot)
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(tool);
    if sysroot_path.exists() {
        return sysroot_path;
    }

    if Command::new(tool).arg("--version").output().is_ok() {
        return PathBuf::from(tool);
    }

    panic!(
        "{tool} not found in sysroot ({sysroot_path:?}) or on PATH.\n\
         Install the llvm-tools component with:\n    rustup component add llvm-tools-preview"
    );
}

fn check_no_fp_simd_instructions(llvm_objdump: &Path, elf_path: &Path) {
    let output = Command::new(llvm_objdump)
        .arg("-d")
        .arg("--no-show-raw-insn")
        .arg(elf_path)
        .output()
        .expect("failed to run llvm-objdump");
    if !output.status.success() {
        panic!(
            "llvm-objdump failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).expect("disassembly not valid utf-8");

    let mut violations = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        let Some((addr, rest)) = trimmed.split_once(':') else {
            continue;
        };
        // In disassembly, instruction lines start with hex address: "<hex>:\t<instruction>"
        if u64::from_str_radix(addr.trim(), 16).is_err() {
            continue;
        }
        let rest = rest.trim();
        if rest.is_empty() {
            continue;
        }

        // Strip comments (// or ;)
        let code_part = if let Some((code, _)) = rest.split_once("//") {
            code.trim()
        } else if let Some((code, _)) = rest.split_once(';') {
            code.trim()
        } else {
            rest
        };

        let parts: Vec<&str> = code_part.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let mnemonic = parts[0];
        let operands = if parts.len() > 1 {
            &code_part[mnemonic.len()..].trim()
        } else {
            ""
        };

        let mut is_violation = false;
        // Check for floating-point/SIMD mnemonics starting with 'f'
        // (AArch64 floating point instructions: fadd, fsub, fmul, fdiv, fmov, fcmp, fcvt*, etc.)
        if mnemonic.starts_with('f') {
            is_violation = true;
        }

        // Check for SIMD specific mnemonics
        let simd_mnemonics = [
            "tbl", "tbx", "dup", "ins", "smov", "umov", "ext", "zip1", "zip2", "uzp1", "uzp2",
            "trn1", "trn2", "addv", "saddv", "uaddv", "smaxv", "sminv", "umaxv", "uminv",
        ];
        if simd_mnemonics.contains(&mnemonic) {
            is_violation = true;
        }

        // Tokenize operands: split by commas, brackets, braces, whitespace
        for token in operands.split(|c: char| {
            c == ',' || c == '[' || c == ']' || c == '{' || c == '}' || c.is_whitespace()
        }) {
            let token = token.trim();
            if token.is_empty() || token.starts_with('#') || token.starts_with("0x") {
                continue;
            }
            // Strip vector element specs like .4s, .16b, [0]
            let reg_base = token.split('.').next().unwrap_or(token);
            let reg_base = reg_base.split('[').next().unwrap_or(reg_base);

            if reg_base.eq_ignore_ascii_case("fpcr") || reg_base.eq_ignore_ascii_case("fpsr") {
                is_violation = true;
                break;
            }

            // Check if reg_base is q0..q31, v0..v31, d0..d31, s0..s31, h0..h31, b0..b31
            if reg_base.len() >= 2 && reg_base.len() <= 3 {
                let first = reg_base.as_bytes()[0].to_ascii_lowercase();
                if matches!(first, b'q' | b'v' | b'd' | b's' | b'h' | b'b') {
                    if let Ok(reg_num) = reg_base[1..].parse::<u32>() {
                        if reg_num <= 31 {
                            is_violation = true;
                            break;
                        }
                    }
                }
            }
        }

        if is_violation {
            violations.push(line.to_string());
        }
    }

    if !violations.is_empty() {
        panic!(
            "\n\n======================================================================\n\
             ERROR: FP/SIMD instructions detected in carrick-el1 image!\n\
             The EL1 vector hook does not save/restore FP/SIMD registers (q0-q31, FPCR, FPSR).\n\
             Any FP/SIMD use in EL1 will silently corrupt guest userspace registers.\n\
             Violating instructions ({} found):\n  {}\n\
             ======================================================================\n\n",
            violations.len(),
            violations.join("\n  ")
        );
    }
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let host = std::env::var("HOST").expect("HOST not set");
    let sysroot = get_sysroot();

    // Verify that the aarch64-unknown-none-softfloat target is installed
    let target_dir = Path::new(&sysroot).join("lib/rustlib/aarch64-unknown-none-softfloat");
    if !target_dir.exists() {
        panic!(
            "\n\n======================================================================\n\
             ERROR: Target 'aarch64-unknown-none-softfloat' is required to build carrick-el1-image.\n\
             Install it with:\n\
                 rustup target add aarch64-unknown-none-softfloat\n\
             ======================================================================\n\n"
        );
    }

    let rust_objcopy = find_sysroot_tool("rust-objcopy", &sysroot, &host);
    let llvm_objdump = find_sysroot_tool("llvm-objdump", &sysroot, &host);

    let el1_target_dir = Path::new(&out_dir).join("el1-target");

    // Build carrick-el1 for aarch64-unknown-none-softfloat --release
    let mut build_cmd = Command::new(&cargo);
    build_cmd
        .arg("build")
        .arg("-p")
        .arg("carrick-el1")
        .arg("--target")
        .arg("aarch64-unknown-none-softfloat")
        .arg("--release")
        .arg("--target-dir")
        .arg(&el1_target_dir);

    // Remove cargo env vars that might interfere with nested cargo invocation
    build_cmd.env_remove("CARGO_MAKEFLAGS");
    build_cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    let status = build_cmd
        .status()
        .expect("failed to invoke cargo build for carrick-el1");
    if !status.success() {
        panic!(
            "failed to build carrick-el1 for aarch64-unknown-none-softfloat (exit code: {status})"
        );
    }

    let elf_path = el1_target_dir.join("aarch64-unknown-none-softfloat/release/carrick-el1");
    let bin_path = Path::new(&out_dir).join("carrick-el1.bin");

    // Verify that no FP/SIMD instructions or register references exist in the ELF
    check_no_fp_simd_instructions(&llvm_objdump, &elf_path);

    // Convert ELF executable to raw binary using rust-objcopy -O binary
    let mut objcopy_cmd = Command::new(&rust_objcopy);
    objcopy_cmd
        .arg("-O")
        .arg("binary")
        .arg(&elf_path)
        .arg(&bin_path);

    let objcopy_status = objcopy_cmd.status().expect("failed to run rust-objcopy");
    if !objcopy_status.success() {
        panic!("rust-objcopy failed (exit code: {objcopy_status})");
    }

    println!("cargo:rerun-if-changed=../carrick-el1/src");
    println!("cargo:rerun-if-changed=../carrick-el1/link.ld");
    println!("cargo:rerun-if-changed=../carrick-el1/build.rs");
    println!("cargo:rerun-if-changed=../carrick-el1/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-el1-abi/src");
    println!("cargo:rerun-if-changed=../carrick-el1-abi/Cargo.toml");
}
