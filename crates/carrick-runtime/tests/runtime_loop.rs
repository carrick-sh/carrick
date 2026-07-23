// Test code: helpers are plain `fn`s (not `#[test]`/`#[cfg(test)]`), so clippy's
// allow-unwrap-in-tests heuristic does not exempt them. The no-panic gate targets
// production code, so allow unwrap/expect across this integration test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// This suite drives the macOS HVF syscall loop with scripted AArch64 frames
// (run_syscall_loop / SyscallTrap / Aarch64SyscallFrame), which
// carrick_runtime::runtime only exposes under platform-macos. Gate the whole
// file so the non-macOS cross-checks (which build --all-targets) skip it.
#![cfg(feature = "platform-macos")]

#[path = "integration/common/syscall_support.rs"]
mod support;

use std::collections::VecDeque;
use std::process::Command;

// `Aarch64SyscallFrame` comes from the leaf crate directly: the dispatch
// re-export is gone (the dispatcher is ISA-neutral; this harness scripts
// aarch64 frames and decodes them the way a backend's `GuestArch` would).
use carrick_guest_mem::{Aarch64SyscallFrame, MappingSharing, MemoryError, RepointPrivateError};
use carrick_runtime::dispatch::{GuestMemory, LinearMemory, SyscallDispatcher};
use carrick_runtime::memory::AddressSpace;
use carrick_runtime::rootfs::{LayerSource, RootFs};
use carrick_runtime::runtime::{SyscallTrap, run_syscall_loop, run_syscall_loop_with_dispatcher};
use carrick_runtime::trap::TrapError;
use support::gzip_tar;

const HELLO: &[u8] = b"hello from carrick\n";

#[test]
fn runtime_loop_dispatches_static_elf_write_and_exit() {
    build_linux_fixture();
    let elf = repo_root().join(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
    );
    let mut image = AddressSpace::load_elf(&elf).unwrap();
    let message = image.find_bytes(HELLO).unwrap();
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: 1,
            x1: message,
            x2: HELLO.len() as u64,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 64,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result = run_syscall_loop(&mut image, &mut trap, 8).unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, HELLO);
    assert!(result.stderr.is_empty());
    assert_eq!(result.traps, 2);
    assert_eq!(trap.return_values, [HELLO.len() as i64]);
    assert!(result.report.unhandled_syscalls.is_empty());
}

#[test]
fn runtime_loop_stops_when_guest_never_exits() {
    let mut memory = LinearMemory::new(0x4000, b"x".to_vec());
    let mut trap = ScriptedTrap::new([Aarch64SyscallFrame {
        x0: 1,
        x1: 0x4000,
        x2: 1,
        x3: 0,
        x4: 0,
        x5: 0,
        x8: 64,
    }]);

    let result = run_syscall_loop(&mut memory, &mut trap, 0).unwrap();

    assert!(result.trap_limit_hit);
    assert_eq!(result.exit_code, -1);
    assert_eq!(result.traps, 0);
}

struct SplitForwardMemory {
    base: u64,
    bytes: Vec<u8>,
    repoints: Vec<(u64, u64, usize)>,
    sharing_publications: Vec<(u64, usize, MappingSharing)>,
    combined_publications: usize,
}

impl SplitForwardMemory {
    fn new(base: u64, len: usize) -> Self {
        Self {
            base,
            bytes: vec![0; len],
            repoints: Vec::new(),
            sharing_publications: Vec::new(),
            combined_publications: 0,
        }
    }

    fn offset(&self, address: u64, len: usize) -> Result<usize, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        if offset
            .checked_add(len)
            .is_some_and(|end| end <= self.bytes.len())
        {
            Ok(offset)
        } else {
            Err(MemoryError::OutOfBounds {
                address,
                length: len,
            })
        }
    }
}

impl GuestMemory for SplitForwardMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = self.offset(address, length)?;
        Ok(self.bytes[offset..offset + length].to_vec())
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let offset = self.offset(address, bytes.len())?;
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn repoint_private(
        &mut self,
        va: u64,
        overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), RepointPrivateError> {
        let offset = self.offset(va, len).map_err(RepointPrivateError::clean)?;
        self.bytes[offset..offset + len].copy_from_slice(content);
        self.repoints.push((va, overlay_ipa, len));
        Ok(())
    }

    fn set_mapping_sharing(&mut self, address: u64, len: usize, sharing: MappingSharing) {
        self.sharing_publications.push((address, len, sharing));
    }

    fn set_mapping_protection_and_sharing(
        &mut self,
        address: u64,
        len: usize,
        _no_access: bool,
        _no_write: bool,
        sharing: MappingSharing,
    ) {
        self.combined_publications += 1;
        self.set_mapping_sharing(address, len, sharing);
    }
}

#[test]
fn split_runtime_loop_forwards_private_repoint_and_provenance_publication() {
    const LENGTH: u64 = 0x4000;
    let shared = carrick_runtime::memory::LINUX_SHARED_FILE_BASE;
    let mut memory = SplitForwardMemory::new(shared, LENGTH as usize);
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: 0,
            x1: LENGTH,
            x2: carrick_runtime::linux_abi::LINUX_PROT_READ
                | carrick_runtime::linux_abi::LINUX_PROT_WRITE,
            x3: carrick_runtime::linux_abi::LINUX_MAP_SHARED
                | carrick_runtime::linux_abi::LINUX_MAP_ANONYMOUS,
            x4: u64::MAX,
            x5: 0,
            x8: 222,
        },
        Aarch64SyscallFrame {
            x0: shared,
            x1: LENGTH,
            x2: carrick_runtime::linux_abi::LINUX_PROT_READ
                | carrick_runtime::linux_abi::LINUX_PROT_WRITE,
            x3: carrick_runtime::linux_abi::LINUX_MAP_PRIVATE
                | carrick_runtime::linux_abi::LINUX_MAP_ANONYMOUS
                | carrick_runtime::linux_abi::LINUX_MAP_FIXED,
            x4: u64::MAX,
            x5: 0,
            x8: 222,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result = run_syscall_loop(&mut memory, &mut trap, 8).unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(trap.return_values, [shared as i64, shared as i64]);
    assert_eq!(
        memory.repoints.len(),
        1,
        "SplitView must not use no-op default"
    );
    assert_eq!(memory.repoints[0].0, shared);
    assert_eq!(memory.repoints[0].2, LENGTH as usize);
    assert!(
        memory
            .sharing_publications
            .iter()
            .any(|&(address, len, sharing)| {
                address == shared && len == LENGTH as usize && sharing == MappingSharing::Shared
            })
    );
    assert!(
        memory
            .sharing_publications
            .iter()
            .any(|&(address, len, sharing)| {
                address == shared && len == LENGTH as usize && sharing == MappingSharing::Private
            })
    );
    assert!(memory.combined_publications >= 2);
}

#[test]
fn runtime_loop_publishes_shared_file_alias_provenance_after_install() {
    use carrick_runtime::fs_backend::{FsBackend as _, HostFsBackend};

    let scratch = std::env::temp_dir().join(format!(
        "carrick-runtime-alias-provenance-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    let mut host = HostFsBackend::new_in(&scratch).expect("host fs backend");
    host.set_file_contents("/shared.bin", vec![0x41; 4096])
        .expect("seed shared file");
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(host));

    let mut memory = SplitForwardMemory::new(0x4000, 0x1000);
    memory.write_bytes(0x4000, b"/shared.bin\0").unwrap();
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: (-100_i64) as u64,
            x1: 0x4000,
            x2: 2, // O_RDWR
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 56,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 4096,
            x2: carrick_runtime::linux_abi::LINUX_PROT_READ
                | carrick_runtime::linux_abi::LINUX_PROT_WRITE,
            x3: carrick_runtime::linux_abi::LINUX_MAP_SHARED,
            x4: 3,
            x5: 0,
            x8: 222,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result = run_syscall_loop_with_dispatcher(&mut memory, &mut trap, dispatcher, 8).unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(trap.alias_installs, 1);
    let mapped = trap.return_values[1] as u64;
    assert!(
        memory
            .sharing_publications
            .iter()
            .any(|entry| { *entry == (mapped, 4096, MappingSharing::Shared) })
    );
    assert_eq!(memory.combined_publications, 1);
    std::fs::remove_dir_all(scratch).expect("remove scratch root");
}

#[test]
fn runtime_loop_publishes_sysv_alias_provenance_after_install() {
    let mut memory = SplitForwardMemory::new(0x4000, 1);
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: 0, // IPC_PRIVATE
            x1: 4096,
            x2: 0o600,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 194, // shmget
        },
        Aarch64SyscallFrame {
            x0: u64::MAX, // patched from shmget return by ScriptedTrap
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 196, // shmat
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result =
        run_syscall_loop_with_dispatcher(&mut memory, &mut trap, SyscallDispatcher::new(), 8)
            .unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(trap.return_values[0] > 0, "shmget returned a live shmid");
    assert_eq!(trap.alias_installs, 1);
    let attached = trap.return_values[1] as u64;
    assert!(
        memory
            .sharing_publications
            .iter()
            .any(|entry| { *entry == (attached, 0x4000, MappingSharing::Shared) })
    );
    assert_eq!(memory.combined_publications, 1);
}

#[test]
fn runtime_loop_can_cat_a_rootfs_file() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: (-100_i64) as u64,
            x1: 0x4000,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 56,
        },
        Aarch64SyscallFrame {
            x0: 3,
            x1: 0x4100,
            x2: 64,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 63,
        },
        Aarch64SyscallFrame {
            x0: 1,
            x1: 0x4100,
            x2: 18,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 64,
        },
        Aarch64SyscallFrame {
            x0: 3,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 57,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result = run_syscall_loop_with_dispatcher(
        &mut memory,
        &mut trap,
        SyscallDispatcher::with_rootfs(rootfs),
        8,
    )
    .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, b"rootfs says hello\n");
    assert_eq!(result.traps, 5);
    assert_eq!(trap.return_values, [3, 18, 18, 0]);
    assert!(result.report.unhandled_syscalls.is_empty());
}

#[test]
fn runtime_loop_can_list_a_rootfs_directory() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: (-100_i64) as u64,
            x1: 0x4000,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 56,
        },
        Aarch64SyscallFrame {
            x0: 3,
            x1: 0x4100,
            x2: 0x100,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 61,
        },
        Aarch64SyscallFrame {
            x0: 3,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 57,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result = run_syscall_loop_with_dispatcher(
        &mut memory,
        &mut trap,
        SyscallDispatcher::with_rootfs(rootfs),
        8,
    )
    .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.traps, 4);
    assert_eq!(trap.return_values[0], 3);
    assert!(trap.return_values[1] > 0);
    assert_eq!(trap.return_values[2], 0);
    assert!(
        memory
            .read_bytes(0x4100, trap.return_values[1] as usize)
            .unwrap()[..]
            .windows(4)
            .any(|window| window == b"motd")
    );
}

struct ScriptedTrap {
    frames: VecDeque<Aarch64SyscallFrame>,
    return_values: Vec<i64>,
    alias_installs: usize,
}

impl ScriptedTrap {
    fn new(frames: impl IntoIterator<Item = Aarch64SyscallFrame>) -> Self {
        Self {
            frames: frames.into_iter().collect(),
            return_values: Vec::new(),
            alias_installs: 0,
        }
    }
}

impl SyscallTrap for ScriptedTrap {
    fn next_syscall(&mut self) -> Result<Option<carrick_runtime::trap::RawSyscall>, TrapError> {
        // The backend now decodes the per-ISA frame into an ISA-neutral
        // `RawSyscall` (aarch64: x8 -> number, x0..x5 -> args); mirror that here.
        self.frames
            .pop_front()
            .map(|f| {
                Some(carrick_runtime::trap::RawSyscall {
                    number: carrick_runtime::linux_abi::CanonicalNr(f.x8),
                    args: [f.x0, f.x1, f.x2, f.x3, f.x4, f.x5],
                    guest_abi: carrick_runtime::linux_abi::LinuxGuestAbi::Aarch64,
                    native_number: carrick_runtime::linux_abi::NativeNr(f.x8),
                })
            })
            .ok_or_else(|| TrapError::Hypervisor("scripted trap stream exhausted".to_owned()))
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        Ok(0)
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.return_values.push(return_value);
        // Runtime-path SysV test: feed shmget's dynamic inode-based shmid into
        // the immediately following scripted shmat without fabricating backend
        // provenance or bypassing either dispatch/install transaction.
        if let Some(next) = self.frames.front_mut()
            && next.x8 == 196
            && next.x0 == u64::MAX
        {
            next.x0 = return_value as u64;
        }
        Ok(())
    }

    fn fork(&mut self) -> Result<carrick_runtime::trap::ForkOutcome, TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement fork".to_owned(),
        ))
    }

    fn execve_into(&mut self, _: &carrick_runtime::memory::AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement execve".to_owned(),
        ))
    }

    fn inject_signal(
        &mut self,
        _signum: i32,
        _handler: u64,
        _sa_restorer: u64,
        _pending_syscall_retval: Option<i64>,
        _interrupted_pc: Option<u64>,
        _altstack: Option<(u64, u64)>,
        _saved_sigmask: u64,
        _fault_siginfo: Option<(i32, u64)>,
        _queued_siginfo: Option<carrick_runtime::linux_abi::LinuxSiginfo>,
        _restart_syscall: bool,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement inject_signal".to_owned(),
        ))
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement restore_from_sigframe".to_owned(),
        ))
    }

    fn map_host_alias(
        &mut self,
        _va: carrick_guest_mem::GuestVa,
        _ipa: carrick_guest_mem::Gpa,
        _len: u64,
        _payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        if let Some((fd, _, _)) = file {
            // Ownership is transferred by the trait contract; the scripted
            // backend installs no host mapping, so close it here.
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
        self.alias_installs += 1;
        Ok(())
    }
}

/// Repository root, derived from this crate's manifest dir
/// (`<repo>/crates/carrick-runtime`). `cargo test` runs the test binary with
/// CWD set to the crate manifest dir, not the repo root, so fixture and script
/// paths must be anchored here rather than assumed relative to the repo root.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate manifest dir has a <repo>/crates/<crate> shape")
        .to_path_buf()
}

fn build_linux_fixture() {
    let status = Command::new(repo_root().join("scripts/build-linux-fixtures.sh"))
        .current_dir(repo_root())
        .status()
        .unwrap();
    assert!(status.success());
}
