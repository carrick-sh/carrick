//! VM-free reduction of inotify09 thread B's regular-file write/seek loop.
//! No watcher or guest CPU: this isolates mandatory offset-query work in write.
use carrick_abi::syscall::nr;
use carrick_abi::{LINUX_AT_FDCWD, LINUX_O_CREAT, LINUX_O_RDWR};
use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ExecutionLayer, SemanticAssertion,
};
use carrick_kernel_example::{ScriptedBackend, Step, Syscall, slot, sys};
use carrick_vfs::fs_backend::HostFsBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = std::env::var("CARRICK_OBSERVATION_SOURCE")?;
    let mut observations = Vec::new();
    for scale in [1usize, 8, 32, 128] {
        let scratch = tempfile::tempdir()?;
        let backend = HostFsBackend::new_in(scratch.path())?;
        let mut script = vec![Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/loop",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o600,
            )
            .save(0),
        )];
        for _ in 0..scale {
            script.push(Step::Sys(sys::write(slot(0), &[0x5a; 64]).ret(64)));
            script.push(Step::Sys(
                Syscall::new(
                    "rewind",
                    nr::LSEEK,
                    [slot(0), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
                )
                .ret(0),
            ));
        }
        script.push(Step::Sys(sys::read_tagged(slot(0), 64, "contents").ret(64)));
        script.push(Step::Sys(sys::close(slot(0)).ret(0)));
        script.push(Step::Sys(sys::exit_group(0)));
        let report = ScriptedBackend::new()
            .with_fs_backend(Box::new(backend))
            .run_root(script)?;
        let active = report
            .completions()
            .iter()
            .filter(|c| c.label == "write" && c.result == Ok(64))
            .count()
            == scale
            && report
                .completions()
                .iter()
                .filter(|c| c.label == "rewind" && c.result == Ok(0))
                .count()
                == scale;
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.fs.write-seek")?,
            layer: ExecutionLayer::VmFree,
            implementation_revision: identity.clone(),
            fixture_identity: "script:write-seek-host-file".into(),
            scale: scale as u64,
            semantic_assertions: vec![
                SemanticAssertion {
                    name: "fixture.active".into(),
                    passed: active,
                    detail: None,
                },
                SemanticAssertion {
                    name: "write_then_rewind_preserves_bytes".into(),
                    passed: report.output_tagged("contents") == [0x5a; 64]
                        && report.exit_code() == 0,
                    detail: None,
                },
            ],
            work: Some(report.work_snapshot().clone()),
            timing: None,
            completeness: Completeness::Complete,
        });
    }
    println!("{}", serde_json::to_string(&observations)?);
    Ok(())
}
