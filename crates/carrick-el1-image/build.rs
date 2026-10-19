use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn get_sysroot(cargo: &Path) -> Result<String, String> {
    // Cargo supplies its executable path. Query that toolchain's sibling
    // rustc, independently of PATH and any census compiler wrappers.
    let cargo_bin = cargo
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("Cargo path {cargo:?} has no compiler directory"))?;
    let mut command = Command::new(cargo_bin.join("rustc"));
    let output = command
        .args(["--print", "sysroot"])
        .output()
        .map_err(|error| format!("failed to query compiler sysroot ({command:?}): {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "compiler sysroot query ({command:?}) failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let sysroot = String::from_utf8(output.stdout)
        .map_err(|error| format!("sysroot is not valid UTF-8: {error}"))?;
    let sysroot = sysroot.trim();
    if sysroot.is_empty() {
        return Err(format!(
            "compiler sysroot query ({command:?}) returned an empty path"
        ));
    }
    Ok(sysroot.to_owned())
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

/// Pin the frames that actually retain stack across owner entry and exit.
/// Tail-call wrappers do not stand in for their callee's budget.
fn check_process_exit_frames(disassembly: &str) {
    let budgets = [
        // Runtime table construction must stay in-place on the heap, never
        // materialize the pending-fork array on a 16 KiB EL1 stack.
        ("::PendingForkStorage::initialize::", 0x100, true),
        ("::dispatch::dispatch_syscall::", 0x600, true),
        ("::aarch64_process::admit_entry_runtime::", 0x1200, true),
        ("::exit_with_status::", 0x600, true),
        ("::finish_exit::", 0x800, true),
        ("::aarch64_process::resume_selected::", 0xa00, true),
        (
            "::aarch64_process::drain_native_signal_ingress::",
            0xa00,
            true,
        ),
        ("::resume_checkpoint::", 0x400, true),
        (
            "::arm_signal::restore_live_arm_signal_frame::",
            0x1300,
            true,
        ),
        ("::arm_signal::deliver_on_user_return::", 0x1000, true),
        ("::dispatch::arm_signal_user_return::", 0x1000, true),
        // The Linux codec wraps the neutral ARM backend (#690).
        (
            "LinuxAarch64Backend$u20$as$u20$carrick_personality_linux..signal..SignalBackend$GT$::restore_signal_frame::",
            0x1300,
            true,
        ),
    ];
    for (symbol, ceiling, required) in budgets {
        let mut found = false;
        for body in disassembly.split(">:\n") {
            if !body
                .lines()
                .last()
                .is_some_and(|line| line.contains(symbol))
            {
                continue;
            }
            // The next segment begins with this function's instructions.
            let start = disassembly.find(body).unwrap() + body.len() + 3;
            let mut frame = 0;
            let mut aligned = false;
            for line in disassembly[start..].lines().take(20) {
                // A short tail-call wrapper may end before twenty instructions.
                // Do not charge the next symbol's frame to this function.
                if line.ends_with(">:") {
                    break;
                }
                let Some((_, instruction)) = line.split_once(':') else {
                    continue;
                };
                let instruction = instruction.trim();
                if instruction.starts_with("stp") && instruction.contains("[sp, #-0x") {
                    let hex = instruction
                        .split("#-0x")
                        .nth(1)
                        .unwrap()
                        .split(']')
                        .next()
                        .unwrap();
                    frame += usize::from_str_radix(hex, 16).unwrap();
                }
                // LLVM stack probing computes the final aligned SP in x9;
                // count that target once, rather than counting the probe loop.
                if instruction.starts_with("sub") {
                    let operands = instruction
                        .split_whitespace()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(" ");
                    if operands.starts_with("x9, sp,") {
                        aligned = true;
                    }
                    let counted = if aligned {
                        operands.starts_with("x9, sp,") || operands.starts_with("x9, x9,")
                    } else {
                        operands.starts_with("sp, sp,")
                    };
                    if counted {
                        let hex = operands
                            .split("#0x")
                            .nth(1)
                            .expect("immediate frame allocation")
                            .split([',', ' '])
                            .next()
                            .unwrap();
                        let amount = usize::from_str_radix(hex, 16).unwrap();
                        frame += if operands.contains("lsl #12") {
                            amount << 12
                        } else {
                            amount
                        };
                    }
                }
            }
            if aligned {
                frame += 63;
            }
            assert!(
                frame > 0 && frame <= ceiling,
                "EL1 exit frame {symbol}: {frame:#x} exceeds {ceiling:#x}"
            );
            found = true;
        }
        if required {
            assert!(found, "missing EL1 exit frame {symbol}");
        }
    }
}

/// The CEL1 header stores this same linker expression. The end symbol includes
/// trailing .bss and alignment that are absent from the flat file.
pub(crate) fn loaded_image_size(symbols: &str) -> Result<u64, String> {
    let address = |name: &str| -> Result<u64, String> {
        let line = symbols
            .lines()
            .find(|line| line.split_whitespace().next_back() == Some(name))
            .ok_or_else(|| format!("missing EL1 linker symbol {name}"))?;
        let value = line.split_whitespace().next().unwrap_or_default();
        u64::from_str_radix(value, 16)
            .map_err(|error| format!("invalid EL1 linker symbol {name}: {error}"))
    };
    let start = address("_image_start")?;
    let end = address("_image_end")?;
    end.checked_sub(start)
        .filter(|size| *size != 0)
        .ok_or_else(|| "invalid EL1 loaded image extent".to_owned())
}

fn check_no_fp_simd_instructions(llvm_objdump: &Path, elf_path: &Path) -> u64 {
    let output = Command::new(llvm_objdump)
        .arg("-d")
        .arg("--syms")
        .arg("--no-show-raw-insn")
        .arg("--demangle")
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

    check_process_exit_frames(&stdout);

    // The in-guest thread switch saves and restores the guest's FP/SIMD
    // state in exactly these two audited routines (`carrick-el1`
    // `sched.rs`); every other FP/SIMD instruction is a violation.
    const FPSIMD_SWITCH_ROUTINES: [&str; 2] =
        ["carrick_el1_fpsimd_save", "carrick_el1_fpsimd_load"];
    let mut allowed_hits = [0usize; 2];
    let mut in_routine: Option<usize> = None;
    let mut violations = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        // A symbol header: `0000000000001234 <name>:`.
        if let Some(name) = trimmed
            .strip_suffix(">:")
            .and_then(|head| head.split_once(" <"))
            .map(|(_, name)| name)
        {
            in_routine = FPSIMD_SWITCH_ROUTINES.iter().position(|r| *r == name);
            continue;
        }
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
            code_part[mnemonic.len()..].trim()
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
                if matches!(first, b'q' | b'v' | b'd' | b's' | b'h' | b'b')
                    && let Ok(reg_num) = reg_base[1..].parse::<u32>()
                    && reg_num <= 31
                {
                    is_violation = true;
                    break;
                }
            }
        }

        if is_violation {
            match in_routine {
                Some(routine) => allowed_hits[routine] += 1,
                None => violations.push(line.to_string()),
            }
        }
    }
    // Both routines exist and move all 32 Q registers plus FPSR and FPCR.
    for (routine, hits) in FPSIMD_SWITCH_ROUTINES.iter().zip(allowed_hits) {
        if hits < 18 {
            panic!(
                "carrick-el1 image: FP/SIMD switch routine {routine} missing or incomplete \
                 ({hits} FP/SIMD instructions, expected 16 q-pair moves plus FPSR/FPCR)"
            );
        }
    }

    if !violations.is_empty() {
        panic!(
            "\n\n======================================================================\n\
             ERROR: FP/SIMD instructions detected in carrick-el1 image!\n\
             The EL1 vector hook does not save/restore FP/SIMD registers (q0-q31, FPCR, FPSR).\n\
             Any FP/SIMD use in EL1 outside the audited switch routines\n\
             (carrick_el1_fpsimd_save/_load) silently corrupts guest userspace registers.\n\
             Violating instructions ({} found):\n  {}\n\
             ======================================================================\n\n",
            violations.len(),
            violations.join("\n  ")
        );
    }
    loaded_image_size(&stdout).unwrap_or_else(|error| panic!("{error}"))
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let host = std::env::var("HOST").expect("HOST not set");
    let sysroot = get_sysroot(Path::new(&cargo)).unwrap_or_else(|error| panic!("{error}"));

    // Verify that the aarch64-unknown-none-softfloat target is installed
    let target_dir = Path::new(&sysroot).join("lib/rustlib/aarch64-unknown-none-softfloat");
    if !target_dir.exists() {
        panic!(
            "\n\n======================================================================\n\
             ERROR: Target 'aarch64-unknown-none-softfloat' is required to build carrick-el1-image.\n\
             Compiler sysroot: {sysroot}\n\
             Install it with:\n\
                 rustup target add aarch64-unknown-none-softfloat\n\
             ======================================================================\n\n"
        );
    }

    let rust_objcopy = find_sysroot_tool("rust-objcopy", &sysroot, &host);
    let llvm_objdump = find_sysroot_tool("llvm-objdump", &sysroot, &host);

    let el1_target_dir = Path::new(&out_dir).join("el1-target");

    // Build the carrick-el1 image binary (owned by carrick-el1-linux) for
    // aarch64-unknown-none-softfloat --release
    let mut build_cmd = Command::new(&cargo);
    build_cmd
        .arg("build")
        .arg("-p")
        .arg("carrick-el1-linux")
        .arg("--target")
        .arg("aarch64-unknown-none-softfloat")
        .arg("--release")
        .arg("--target-dir")
        .arg(&el1_target_dir);

    if std::env::var_os("CARGO_FEATURE_ALLOCATOR_TEST_CONTROL").is_some() {
        build_cmd.arg("--features").arg("allocator-test-control");
    }

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
    let image_size = check_no_fp_simd_instructions(&llvm_objdump, &elf_path);

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

    // Reuse the existing artifact inspection, with no additional host file
    // access. Keep the report tied to the ABI's image limit.
    let limit = carrick_el1_abi::EL1_IMAGE_SIZE;
    let headroom = limit
        .checked_sub(image_size)
        .expect("EL1 image exceeds the ABI image budget");
    // Cargo warnings are visible in ordinary CI builds without `-vv`.
    println!(
        "cargo:warning=EL1 image budget: {image_size} bytes loaded / {limit} bytes; {headroom} bytes headroom"
    );

    println!("cargo:rerun-if-changed=../carrick-el1-linux/src");
    println!("cargo:rerun-if-changed=../carrick-el1-linux/link.ld");
    println!("cargo:rerun-if-changed=../carrick-el1-linux/build.rs");
    println!("cargo:rerun-if-changed=../carrick-el1-linux/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-el1/src");
    println!("cargo:rerun-if-changed=../carrick-el1/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-el1-abi/src");
    println!("cargo:rerun-if-changed=../carrick-el1-abi/Cargo.toml");
    // Every crate compiled into the image: a missed dependency here embeds a
    // stale image whose object layout silently disagrees with the host.
    println!("cargo:rerun-if-changed=../carrick-inotify-core/src");
    println!("cargo:rerun-if-changed=../carrick-inotify-core/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-mmu-core/src");
    println!("cargo:rerun-if-changed=../carrick-mmu-core/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-sched-core/src");
    println!("cargo:rerun-if-changed=../carrick-sched-core/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-core/src");
    println!("cargo:rerun-if-changed=../carrick-core/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-core-abi/src");
    println!("cargo:rerun-if-changed=../carrick-core-abi/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-personality-api/src");
    println!("cargo:rerun-if-changed=../carrick-personality-api/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-personality-linux/src");
    println!("cargo:rerun-if-changed=../carrick-personality-linux/Cargo.toml");
}
