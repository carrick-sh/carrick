//! #2717 measurement only (do not land): an interleaved, uninstrumented
//! timing A/B of CPython startup through production dispatch, use-aware
//! residency (B, default) against the FIFO opt-out
//! (A, `CARRICK_SOFT_CODE_RESIDENCY=0`). Each arm runs in a fresh child
//! process of this test binary, one at a time, in the order A B B A A B.

const CHILD: &str = "CARRICK_R4L_ABBA_CHILD";
const PYTHON: &str = "/usr/local/bin/python3";

#[test]
#[ignore = "requires CARRICK_A64_PYTHON_ROOT and CARRICK_A64_ELF"]
fn cpython_once() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let el1_elf = std::fs::read(std::env::var_os("CARRICK_A64_ELF").expect("CARRICK_A64_ELF"))
        .expect("read the production EL1 ELF");
    let root = std::path::PathBuf::from(
        std::env::var_os("CARRICK_A64_PYTHON_ROOT").expect("CARRICK_A64_PYTHON_ROOT"),
    );
    let python = std::fs::read(root.join(PYTHON.trim_start_matches('/'))).expect("read python3");
    let config = carrick_softcpu_aarch64_host::SoftSingleProcessConfig {
        elf_bytes: &python,
        executable_path: PYTHON,
        argv: vec![
            PYTHON.as_bytes().to_vec(),
            b"-c".to_vec(),
            b"import sys; print(sys.version.split()[0])".to_vec(),
        ],
        envp: vec![b"HOME=/tmp".to_vec()],
        rootfs_dir: Some(&root),
        el1_elf_override: Some(&el1_elf),
        max_syscalls: 4096,
    };
    let started = std::time::Instant::now();
    let run = carrick_softcpu_aarch64_host::run_single_process(&config).expect("CPython run");
    let elapsed = started.elapsed().as_secs_f64();
    let work = run.engine.vcpu().run_work();
    assert_eq!(
        (run.exit_code, run.stdout.as_slice()),
        (0, b"3.12.16\n".as_slice())
    );
    println!(
        "R4L-ARM elapsed={elapsed:.3} retired={} executed={} decoded={} instr_per_s={:.0} blocks_per_s={:.0} residency={:?}",
        work.retired_instructions,
        work.executed_blocks,
        work.decoded_blocks,
        work.retired_instructions as f64 / elapsed,
        work.executed_blocks as f64 / elapsed,
        run.engine.vcpu().code_residency(),
    );
}

#[test]
#[ignore = "requires CARRICK_A64_PYTHON_ROOT and CARRICK_A64_ELF"]
fn cpython_residency_abba() {
    let exe = std::env::current_exe().expect("current test binary");
    let mut rows = Vec::new();
    for (index, fifo) in [true, false, false, true, true, false]
        .into_iter()
        .enumerate()
    {
        let mut command = std::process::Command::new(&exe);
        command
            .args([
                "--exact",
                "cpython_once",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1");
        if fifo {
            command.env("CARRICK_SOFT_CODE_RESIDENCY", "0");
        } else {
            command.env_remove("CARRICK_SOFT_CODE_RESIDENCY");
        }
        let out = command.output().expect("spawn the CPython arm");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "arm {index} failed: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = stdout
            .lines()
            .find_map(|l| l.find("R4L-ARM ").map(|at| l[at..].to_owned()))
            .expect("arm line");
        let arm = if fifo { "A=fifo1024" } else { "B=clock16k" };
        println!("R4L-ABBA order={index} arm={arm} {line}");
        rows.push((fifo, line));
    }
    for fifo in [true, false] {
        let elapsed: Vec<f64> = rows
            .iter()
            .filter(|(f, _)| *f == fifo)
            .map(|(_, l)| {
                l.split_whitespace()
                    .find_map(|w| w.strip_prefix("elapsed="))
                    .and_then(|v| v.parse().ok())
                    .expect("elapsed")
            })
            .collect();
        println!("R4L-ABBA summary fifo={fifo} elapsed={elapsed:?}");
    }
}
