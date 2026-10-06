//! Publish executable bytes in a separate process. Parallel test commands
//! cannot inherit this writer's descriptor across another thread's fork.
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

fn main() -> std::io::Result<()> {
    let path = std::env::args_os().nth(1).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing executable path")
    })?;
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}
