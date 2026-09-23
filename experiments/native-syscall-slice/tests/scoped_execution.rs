//! Actual ELF controls through the executable's scoped entry/dispatch boundary.
//! Fixtures are built by fixtures/build.sh; absence is a failure, never a skip.
//! Debug execution validates semantics and checkpoint composition, not timing.
use std::{
    path::Path,
    process::{Command, Stdio},
};

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "Non-product functional harness: execute the selected native test binary and save operator-selected host receipts; guest file paths remain under the kernel VFS"
)]
fn scoped_execution_preserves_all_five_elf_controls() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let binary = env!("CARGO_BIN_EXE_native-syscall-slice");
    let mut receipts = Vec::new();
    for phase in 0..5u64 {
        for scale in [1, 8, 32, 128] {
            let elf = root.join(format!(
                "target/lease-cost/native-slice/fixtures/watch-{phase}-{scale}"
            ));
            assert!(
                elf.is_file(),
                "build the exact ELF controls first: {}",
                elf.display()
            );
            let run_id = format!(
                "native-scope-functional-{phase}-{scale}-{}",
                std::process::id()
            );
            let output = Command::new(binary)
                .arg(&elf)
                .env("CARRICK_RUN_ID", &run_id)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            if let Some(dir) = std::env::var_os("CARRICK_NATIVE_SCOPE_RECEIPT_DIR") {
                std::fs::create_dir_all(&dir).unwrap();
                let dir = Path::new(&dir);
                std::fs::write(dir.join(format!("{run_id}.out")), &output.stdout).unwrap();
                std::fs::write(dir.join(format!("{run_id}.err")), &output.stderr).unwrap();
            }
            assert!(
                output.status.success(),
                "{run_id}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.stdout.len(),
                560,
                "ten complete 56-byte guest records"
            );
            for record in output.stdout.chunks_exact(56) {
                let words: Vec<u64> = record
                    .chunks_exact(8)
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                    .collect();
                assert_eq!(words[0], phase);
                assert_eq!(words[1], scale);
                assert!(words[3] < 1_000_000_000 && words[5] < 1_000_000_000);
                assert_eq!(words[6], if phase == 2 { scale * 16 } else { 0 });
            }
            let reports: Vec<serde_json::Value> = output
                .stderr
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice(line).unwrap())
                .collect();
            let report = &reports[0];
            assert_eq!(
                reports.len(),
                if cfg!(feature = "allocation-metrics") {
                    2
                } else {
                    1
                }
            );
            #[cfg(feature = "allocation-metrics")]
            {
                assert_eq!(reports[1]["positive_control"], true);
                assert_eq!(reports[1]["timing_eligible"], false);
                let windows = reports[1]["allocation_windows"].as_array().unwrap();
                assert_eq!(windows.len(), 10);
                if phase == 0 {
                    for window in windows {
                        assert_eq!(window[0], 2 * scale);
                        assert_eq!(window[1], 2 * scale);
                        assert_eq!(window[2], 0, "scoped invalid-call window allocated");
                    }
                }
            }
            assert_eq!(report["exit"], 0);
            assert_eq!(
                report["requests"].as_u64().unwrap(),
                report["completions"].as_u64().unwrap() + 1
            );
            let count = |nr: &str| report["syscalls"][nr].as_u64().unwrap_or(0);
            assert_eq!(
                count("27"),
                match phase {
                    0 | 2 => 10 * scale,
                    1 => 20 * scale + 10,
                    _ => 0,
                }
            );
            assert_eq!(
                count("28"),
                if phase == 0 || phase == 2 {
                    10 * scale
                } else {
                    0
                }
            );
            assert_eq!(
                report["errno_returns"],
                if phase == 0 { 20 * scale } else { 0 }
            );
            receipts.push(serde_json::json!({"run_id":run_id, "elf":elf, "phase":phase, "scale":scale, "records":10, "exit_code":output.status.code(), "requests":report["requests"], "completions":report["completions"], "gateway_transitions":report["gateway_transitions"], "timing_eligible":false}));
        }
    }
    if let Some(dir) = std::env::var_os("CARRICK_NATIVE_SCOPE_RECEIPT_DIR") {
        std::fs::write(
            Path::new(&dir).join("elf-functional.json"),
            serde_json::to_vec_pretty(&receipts).unwrap(),
        )
        .unwrap();
    }
}
