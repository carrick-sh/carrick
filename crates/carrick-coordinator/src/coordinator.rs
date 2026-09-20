use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceClass {
    Build,
    SignedGuestRun,
    DockerPhase,
    TracingSession,
    TimingWindow,
}

impl ResourceClass {
    pub const ALL: [ResourceClass; 5] = [
        ResourceClass::Build,
        ResourceClass::SignedGuestRun,
        ResourceClass::DockerPhase,
        ResourceClass::TracingSession,
        ResourceClass::TimingWindow,
    ];

    pub fn filename_prefix(&self) -> &'static str {
        match self {
            ResourceClass::Build => "build",
            ResourceClass::SignedGuestRun => "signed_guest_run",
            ResourceClass::DockerPhase => "docker_phase",
            ResourceClass::TracingSession => "tracing_session",
            ResourceClass::TimingWindow => "timing_window",
        }
    }

    pub fn conflicts_with(&self, other: ResourceClass) -> bool {
        if *self == ResourceClass::TimingWindow || other == ResourceClass::TimingWindow {
            return true;
        }
        matches!(
            (self, other),
            (ResourceClass::SignedGuestRun, ResourceClass::DockerPhase)
                | (ResourceClass::DockerPhase, ResourceClass::SignedGuestRun)
                | (ResourceClass::SignedGuestRun, ResourceClass::Build)
                | (ResourceClass::Build, ResourceClass::SignedGuestRun)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeaseOwner {
    pub host: String,
    pub pid: u32,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investigation_id: Option<String>,
}

#[derive(Debug)]
pub struct Lease {
    pub resource: ResourceClass,
    pub owner: LeaseOwner,
    lock_file: File,
    metadata_path: PathBuf,
}

impl Drop for Lease {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.lock_file.as_raw_fd(), libc::LOCK_UN);
        }
        let _ = fs::remove_file(&self.metadata_path);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("I/O error in coordinator: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "resource {requested:?} conflicts with active lease for {conflicting:?} held by {holder:?}"
    )]
    Conflict {
        requested: ResourceClass,
        conflicting: ResourceClass,
        holder: Option<LeaseOwner>,
    },
    #[error("coordinator serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub struct Coordinator {
    lock_dir: PathBuf,
}

impl Coordinator {
    pub fn new(lock_dir: PathBuf) -> Result<Self, CoordinatorError> {
        fs::create_dir_all(&lock_dir)?;
        Ok(Self { lock_dir })
    }

    pub fn default_dir() -> PathBuf {
        std::env::temp_dir()
            .join("carrick-coordinator")
            .join("locks")
    }

    pub fn recover_stale_leases(&self) -> Result<usize, CoordinatorError> {
        let mut recovered = 0;
        for class in ResourceClass::ALL {
            let meta_path = self.metadata_path(class);
            let Ok(content) = fs::read_to_string(&meta_path) else {
                continue;
            };
            let Ok(owner) = serde_json::from_str::<LeaseOwner>(&content) else {
                continue;
            };
            let is_dead = unsafe {
                let res = libc::kill(owner.pid as libc::pid_t, 0);
                res == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            };
            if is_dead {
                let _ = fs::remove_file(&meta_path);
                // Also clear lock file
                let lock_path = self.lock_path(class);
                let _ = fs::remove_file(&lock_path);
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    fn lock_path(&self, class: ResourceClass) -> PathBuf {
        self.lock_dir
            .join(format!("{}.lock", class.filename_prefix()))
    }

    fn metadata_path(&self, class: ResourceClass) -> PathBuf {
        self.lock_dir
            .join(format!("{}.lease.json", class.filename_prefix()))
    }

    pub fn try_acquire(
        &self,
        resource: ResourceClass,
        owner: LeaseOwner,
    ) -> Result<Option<Lease>, CoordinatorError> {
        self.recover_stale_leases()?;

        // Check for conflicting active classes
        for other in ResourceClass::ALL {
            if resource.conflicts_with(other) {
                let meta_path = self.metadata_path(other);
                if meta_path.exists() {
                    let holder = fs::read_to_string(&meta_path)
                        .ok()
                        .and_then(|c| serde_json::from_str::<LeaseOwner>(&c).ok());
                    return Err(CoordinatorError::Conflict {
                        requested: resource,
                        conflicting: other,
                        holder,
                    });
                }
            }
        }

        // Try to lock requested resource file
        let lock_path = self.lock_path(resource);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let meta_path = self.metadata_path(resource);
            let holder = fs::read_to_string(&meta_path)
                .ok()
                .and_then(|c| serde_json::from_str::<LeaseOwner>(&c).ok());
            return Err(CoordinatorError::Conflict {
                requested: resource,
                conflicting: resource,
                holder,
            });
        }

        // Write lease metadata
        let metadata_path = self.metadata_path(resource);
        let meta_json = serde_json::to_string_pretty(&owner)?;
        fs::write(&metadata_path, meta_json)?;

        Ok(Some(Lease {
            resource,
            owner,
            lock_file,
            metadata_path,
        }))
    }
}
