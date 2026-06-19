//! PROC concern: execve of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn handle_execve(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<(), RuntimeError> {
        crate::probes::execve_argv(&path, &argv);
        // The proctitle / /proc/self/cmdline identity is display text; lossily
        // decode the byte argv (a genuinely non-UTF-8 argv is rare).
        let proc_argv: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let base = path.rsplit('/').next().unwrap_or(&path).to_owned();
        crate::dispatch::set_host_process_name(base.as_bytes());
        let proc_env = env.clone();
        match load_execve_image(&kernel.dispatcher, &path, argv, env) {
            Ok(img) => {
                crate::probes::execve_loaded(
                    &path,
                    img.entry(),
                    img.initial_stack_pointer().unwrap_or(0),
                    img.regions().len() as u64,
                );
                kernel
                    .dispatcher
                    .set_executable_identity(path.clone(), proc_argv, proc_env);
                // Refresh /proc/self/maps + /proc/self/auxv for the new image.
                apply_image_proc_state(&kernel.dispatcher, &img);
                kernel.dispatcher.close_cloexec_fds();
                if self.registry.live_count() > 1 {
                    self.terminate_siblings_for_exec(kernel, engine)?;
                }
                engine.execve_into(&img)?;
                // execve_into rebuilt a fresh vCPU: re-stamp the identity page
                // (zeroed) and TPIDR_EL1 (reset) for the same thread/tid.
                stamp_identity_page(engine, &kernel.dispatcher);
                stamp_guest_tid(engine, self.this_tid, &self.registry);
                // vfork: the execve SUCCEEDED and we now have our own private VM.
                // Release the suspended parent by writing one byte to the
                // inherited pipe, then close it. A FAILED execve returns above via
                // `?` WITHOUT releasing — the child then `_exit`s and the parent's
                // `read()` gets EOF instead.
                if let Some(fd) = self.vfork_release_fd.take() {
                    let _ = unsafe { libc::write(fd, [0u8; 1].as_ptr().cast(), 1) };
                    unsafe { libc::close(fd) };
                }
                stop_after_traced_exec(&kernel.dispatcher);
                Ok(())
            }
            Err(errno) => {
                let retval = -(errno as i64);
                engine.complete_syscall(retval)?;
                Ok(())
            }
        }
    }
}
