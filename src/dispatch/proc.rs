//! proc syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

impl SyscallDispatcher {
    pub(super) fn personality<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = ctx.arg(0);
        let previous = self.personality;
        if requested != LINUX_PERSONALITY_QUERY {
            self.personality = requested;
        }
        Ok(DispatchOutcome::Returned {
            value: previous as i64,
        })
    }

    pub(super) fn prctl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let option = ctx.request.arg(0);
        Ok(match option {
            LINUX_PR_GET_DUMPABLE => DispatchOutcome::Returned {
                value: self.dumpable,
            },
            LINUX_PR_SET_DUMPABLE => {
                let value = ctx.request.arg(1);
                if value > 1 {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    });
                }
                self.dumpable = value as i64;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_SET_NAME => {
                let address = ctx.request.arg(1);
                let Ok(bytes) = memory.read_bytes(address, LINUX_TASK_COMM_LEN) else {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                };
                self.task_name = linux_task_name_from_bytes(&bytes);
                // Reflect the guest's chosen name into the host
                // process/thread name as `carrick: <name>`, so `ps -M`
                // / Activity Monitor / lldb show which guest each
                // carrick host process is running.
                set_host_process_name(&self.task_name);
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_GET_NAME => {
                let address = ctx.request.arg(1);
                if memory.write_bytes(address, &self.task_name).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        })
    }

    pub(super) fn getcpu<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let cpu_address = ctx.request.arg(0);
        let node_address = ctx.request.arg(1);
        let bootstrap_value = 0u32.to_ne_bytes();

        if cpu_address != 0 && memory.write_bytes(cpu_address, &bootstrap_value).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if node_address != 0 && memory.write_bytes(node_address, &bootstrap_value).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn set_tid_address<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.getpid())
    }

    pub(super) fn set_robust_list<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let len = ctx.arg(1);
        if len == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sched_yield<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        std::thread::yield_now();
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sched_getaffinity<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0);
        let size = ctx.arg(1);
        let address = ctx.arg(2);
        let memory = &mut *ctx.memory;
        let current_pid = std::process::id() as u64;

        if pid != 0 && pid != current_pid {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        if size < LINUX_BOOTSTRAP_AFFINITY_BYTES as u64 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let mut mask = [0_u8; LINUX_BOOTSTRAP_AFFINITY_BYTES];
        mask[0] = 1;
        if memory.write_bytes(address, &mask).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: LINUX_BOOTSTRAP_AFFINITY_BYTES as i64,
        })
    }

    pub(super) fn futex<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let operation = ctx.arg(1);
        let value = ctx.arg(2) as u32;
        let timeout_address = ctx.arg(3);
        let memory = &*ctx.memory;
        let command = operation & LINUX_FUTEX_CMD_MASK;
        let flags = operation & !LINUX_FUTEX_CMD_MASK;
        if flags & !(LINUX_FUTEX_PRIVATE_FLAG | LINUX_FUTEX_CLOCK_REALTIME) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if flags & LINUX_FUTEX_CLOCK_REALTIME != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let word = match read_u32(memory, address) {
            Ok(word) => word,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        Ok(match command {
            LINUX_FUTEX_WAKE => DispatchOutcome::Returned { value: 0 },
            LINUX_FUTEX_WAIT => {
                if word != value {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    });
                }
                if timeout_address == 0 {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    });
                }
                let timespec = match read_timespec(memory, timeout_address) {
                    Ok(timespec) => timespec,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                };
                let timeout = match duration_from_linux_timespec(timespec) {
                    Ok(timeout) => timeout,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                };
                if let Some(timeout) = timeout {
                    std::thread::sleep(timeout);
                }
                DispatchOutcome::Errno {
                    errno: LINUX_ETIMEDOUT,
                }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        })
    }

    pub(super) fn uname<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let address = ctx.request.arg(0);
        if memory
            .write_bytes(address, LinuxUtsname::carrick_aarch64().abi_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn ptrace<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Bootstrap: no debugger surface yet. Linux returns ENOSYS when ptrace
        // is built out of the kernel; we surface the same answer so glibc /
        // gdb fall back cleanly.
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }

    pub(super) fn reboot<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // We're not root and we wouldn't honour the request anyway.
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn sethostname<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn setdomainname<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn setpgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        let pgid = i32::from_ne_bytes((ctx.arg(1) as u32).to_ne_bytes());
        if pgid < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if pid != 0 && pid != 1 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getpgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        if pid != 0 && pid != 1 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    pub(super) fn getsid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        if pid != 0 && pid != 1 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    pub(super) fn setsid<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    pub(super) fn waitid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let idtype = ctx.arg(0);
        let options = ctx.arg(3);
        match idtype {
            LINUX_P_ALL | LINUX_P_PID | LINUX_P_PGID | LINUX_P_PIDFD => {}
            _ => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }
        if options & !LINUX_WAITID_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if options & LINUX_WAITID_STATE_MASK == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ECHILD,
        })
    }

    pub(super) fn wait4<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        let wstatus_addr = ctx.arg(1);
        let options = ctx.arg(2);
        let memory = &mut *ctx.memory;
        if options & !LINUX_WAIT4_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        }
        // Linux WNOHANG = 1; macOS WNOHANG = 1. Same bit, pass through.
        let mut host_status: i32 = 0;
        let result = unsafe { libc::waitpid(pid, &mut host_status, options as i32) };
        if result < 0 {
            // ECHILD on macOS == ECHILD on Linux (10).
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        if result == 0 {
            // WNOHANG and no child ready.
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Linux and Darwin agree on the wstatus encoding for exited /
        // signaled children: low 7 bits = signal, bit 7 = core flag,
        // bits 8..15 = exit code. Pass through as-is.
        if wstatus_addr != 0 {
            let bytes = host_status.to_ne_bytes();
            if memory.write_bytes(wstatus_addr, &bytes).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: i64::from(result) })
    }

    /// Linux `execve(2)` (aarch64 syscall 221). Reads pathname, argv,
    /// and envp from guest memory, then surfaces `DispatchOutcome::Execve`
    /// so the runtime can tear down the guest address space and load
    /// the new image. Returns the usual errno on the failure paths
    /// (EFAULT on bad pointers, ENAMETOOLONG on oversized strings).
    pub(super) fn execve<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname_addr = ctx.arg(0);
        let argv_addr = ctx.arg(1);
        let envp_addr = ctx.arg(2);
        let memory = &*ctx.memory;

        let path = match read_guest_c_string(memory, pathname_addr) {
            Ok(p) => p,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let argv = match read_guest_string_array(memory, argv_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let env = match read_guest_string_array(memory, envp_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        Ok(DispatchOutcome::Execve { path, argv, env })
    }

    /// Linux `clone(2)` (aarch64 syscall 220). Real fork delegation:
    /// the dispatcher recognises clone, returns `DispatchOutcome::Fork`,
    /// and the runtime asks the trap engine to do a real macOS fork
    /// against the live HVF state.
    ///
    /// Currently only the simple SIGCHLD case (musl/glibc `fork()` wrapper
    /// → `clone(SIGCHLD, 0, ...)`) is wired. Thread-create flags
    /// (CLONE_VM | CLONE_THREAD) and namespace/process-share variants
    /// fall through to ENOSYS until the next iteration.
    pub(super) fn clone<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FS: u64 = 0x00000200;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_SIGHAND: u64 = 0x00000800;
        const CLONE_THREAD: u64 = 0x00010000;

        let flags = ctx.arg(0);
        // Thread creation needs pthread_create semantics, not fork.
        // Surface as ENOSYS for now so callers see "function not
        // implemented" rather than spuriously cloning the whole address
        // space when they wanted a thread.
        let thread_mask =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        if (flags & thread_mask) == thread_mask {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            });
        }

        // Anything else (including the SIGCHLD-only fork case) → real fork.
        Ok(DispatchOutcome::Fork)
    }

    /// clone3(2): like clone, but flags and the rest of the parameters live in
    /// a `struct clone_args` pointed to by arg0 (arg1 is its size). glibc's
    /// posix_spawn/fork now prefer clone3; without it apt-get's worker spawn
    /// silently failed and the parent deadlocked waiting on a child that never
    /// came up. We only need `flags` (the first u64) to decide thread-vs-fork.
    fn clone3(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FS: u64 = 0x00000200;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_SIGHAND: u64 = 0x00000800;
        const CLONE_THREAD: u64 = 0x00010000;

        let args_ptr = request.arg(0);
        let args_size = request.arg(1);
        // clone_args is at least flags(8)+pidfd(8)+child_tid(8)+parent_tid(8)
        // +exit_signal(8) = 40 bytes; flags is the first field.
        if args_size < 8 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let flags = match memory.read_bytes(args_ptr, 8) {
            // INVARIANT: read_bytes(_, 8) returns exactly 8 bytes on Ok, so the
            // 8-byte slice always converts into [u8; 8].
            #[allow(clippy::unwrap_used)]
            Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            Err(_) => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        };

        let thread_mask =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        if (flags & thread_mask) == thread_mask {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            };
        }

        // posix_spawn's CLONE_VM|CLONE_VFORK|SIGCHLD and plain SIGCHLD forks
        // both land here. A real fork is a valid implementation of vfork (the
        // child execs or _exits immediately), so route to the same path.
        DispatchOutcome::Fork
    }

    pub(super) fn getrandom<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = usize::try_from(ctx.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let memory = &mut *ctx.memory;
        let mut bytes = vec![0; length];
        if getrandom::fill(&mut bytes).is_err() {
            fill_deterministic_bootstrap_random(&mut bytes);
        }
        if memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn rseq(&self) -> DispatchOutcome {
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    pub(super) fn sys_exit<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.exit(ctx.request))
    }

    pub(super) fn sys_clone3<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.clone3(ctx.request, &*ctx.memory))
    }

    pub(super) fn sys_rseq<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.rseq())
    }

    fn exit(&self, request: SyscallRequest) -> DispatchOutcome {
        DispatchOutcome::Exit {
            code: request.arg(0) as i32,
        }
    }
}

fn fill_deterministic_bootstrap_random(bytes: &mut [u8]) {
    let mut state = 0xca22_1c_u64;
    for byte in bytes {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        *byte = state as u8;
    }
}
