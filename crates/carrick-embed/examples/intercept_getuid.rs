use std::sync::Arc;

use carrick_embed::{
    CanonicalNr, ContainerBuilder, InterceptAction, InterceptedSyscall, ProcessInfo,
    SyscallInterceptor,
};

struct Uid1000;

impl SyscallInterceptor for Uid1000 {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        if call.canonical_number() == CanonicalNr(174) {
            InterceptAction::Return(1000)
        } else {
            InterceptAction::Continue
        }
    }
}

fn main() -> anyhow::Result<()> {
    let result = ContainerBuilder::from_image("ubuntu:24.04")
        .command(["/usr/bin/id", "-ru"])
        .interceptor(Arc::new(Uid1000))
        .run_blocking()?
        .ensure_success()?;
    print!("{}", result.stdout_utf8());
    Ok(())
}
