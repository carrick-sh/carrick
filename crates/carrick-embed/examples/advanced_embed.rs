use std::sync::Arc;

use carrick_embed::{
    Carrier, EmbedError, FilterVfs, InMemoryFileVfs, InterceptAction, InterceptedSyscall,
    ProcessInfo, SyscallInterceptor,
};

struct AlphaPolicy;

impl SyscallInterceptor for AlphaPolicy {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        match call.name() {
            "getuid" => InterceptAction::Return(4242),
            "write" if call.effective_args().get(0) == Some(1) => {
                match call.effective_args().with_arg(0, 2) {
                    Ok(args) => InterceptAction::RewriteArgs(args),
                    Err(_) => InterceptAction::Continue,
                }
            }
            _ => InterceptAction::Continue,
        }
    }
}

fn role_files(role: &'static [u8]) -> Result<FilterVfs, EmbedError> {
    let files = InMemoryFileVfs::new();
    files
        .add_file("/config/role", role)
        .map_err(|errno| EmbedError::Config(format!("VFS errno {}", errno.get())))?;
    Ok(FilterVfs::new(Box::new(files)).readonly(true))
}

#[tokio::main]
async fn main() -> Result<(), EmbedError> {
    let carrier = Carrier::new()?;
    let alpha = carrier
        .container("ubuntu:24.04")
        .command(["/bin/sh", "-c", "/usr/bin/id -ru; cat /config/role"])
        .vfs_mount("/config", Box::new(role_files(b"alpha\n")?))
        .interceptor(Arc::new(AlphaPolicy));
    let beta = carrier
        .container("ubuntu:24.04")
        .command(["/bin/sh", "-c", "/usr/bin/id -ru; cat /config/role"])
        .vfs_mount("/config", Box::new(role_files(b"beta\n")?));

    let (alpha_result, beta_result) = tokio::join!(alpha.run(), beta.run());
    let shutdown = carrier.shutdown().await;
    let alpha_result = alpha_result?.ensure_success()?;
    let beta_result = beta_result?.ensure_success()?;
    shutdown?;

    if !alpha_result.stdout.is_empty()
        || !alpha_result.stderr_utf8().contains("4242\nalpha\n")
        || !beta_result.stdout_utf8().contains("0\nbeta\n")
    {
        return Err(EmbedError::Config(
            "container-local interceptor, stdio, or VFS isolation failed".to_owned(),
        ));
    }
    Ok(())
}
