//! Capability-based, personality-neutral positional file services.
//!
//! No destructor performs I/O. Pins must be released explicitly. F4 will supply
//! owned pending continuations for host-bound work; callers already distinguish
//! completion from suspension and must retain the initiating operation's state.
use crate::personality::{CallContext, ServiceError};
use alloc::{string::String, vec::Vec};
use carrick_guest_arch::{DefaultMmOwner, EntryArch, MmuArch, UserRange};

macro_rules! key {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(u64);
        impl $name {
            /// Backend-issued key. The receiving service authenticates its scope.
            pub const fn from_backend(value: u64) -> Self {
                Self(value)
            }
            pub const fn backend_value(self) -> u64 {
                self.0
            }
        }
    };
}
key!(FileRoot);
key!(FileIdentity);
key!(FilePinKey);

/// An explicit service-owned reference, with no implicit release or cloning.
#[must_use = "release the file pin explicitly"]
#[derive(Debug)]
pub struct FilePin {
    key: FilePinKey,
}
impl FilePin {
    pub const fn from_backend(key: FilePinKey) -> Self {
        Self { key }
    }
    /// Read the backend key; the service authenticates its live incarnation.
    pub const fn key(&self) -> FilePinKey {
        self.key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamePath(Vec<String>);
impl NamePath {
    /// Components are UTF-8 by construction. Empty paths name the root.
    pub fn from_components<'a>(
        components: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, IoError> {
        let mut names = Vec::new();
        for name in components {
            if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
                return Err(IoError::InvalidName);
            }
            names
                .try_reserve(1)
                .map_err(|_| IoError::CapacityExhausted)?;
            let mut owned = String::new();
            owned
                .try_reserve(name.len())
                .map_err(|_| IoError::CapacityExhausted)?;
            owned.push_str(name);
            names.push(owned);
        }
        Ok(Self(names))
    }
    pub fn components(&self) -> &[String] {
        &self.0
    }
}
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FileAccess: u8 { const READ = 1; const WRITE = 2; const APPEND = 4; }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenDisposition {
    OpenExisting,
    CreateNew,
    OpenOrCreate,
    TruncateExisting,
    CreateOrTruncate,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Any,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameMatch {
    Exact,
    CaseFold,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenRequest {
    pub access: FileAccess,
    pub disposition: OpenDisposition,
    pub expect: FileKind,
    pub follow_final: bool,
    pub name_match: NameMatch,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileAttributes {
    pub kind: FileKind,
    pub len: u64,
    pub read_only: bool,
}
#[derive(Debug)]
pub struct OpenOutcome {
    pub pin: FilePin,
    pub created: bool,
    pub identity: FileIdentity,
    pub attrs: FileAttributes,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteAt {
    Offset(u64),
    End,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoError {
    NameNotFound,
    PathNotFound,
    Exists,
    NotADirectory,
    IsADirectory,
    AccessDenied,
    ReadOnly,
    NoSpace,
    TooLarge,
    InvalidName,
    NameTooLong,
    Stale,
    Fault,
    CapacityExhausted,
    Unsupported,
}
/// Reserved owned-continuation extension point. Uninhabited in F0. F4 will
/// give this private representation ownership of buffers and completion authority,
/// never references to a call context or an active vCPU lease.
#[derive(Debug)]
pub struct FilePending {
    _reserved: core::convert::Infallible,
}
#[must_use]
#[derive(Debug)]
pub enum FileOperation<T> {
    Ready(Result<T, IoError>),
    Pending(FilePending),
}
impl<T> From<Result<T, IoError>> for FileOperation<T> {
    fn from(value: Result<T, IoError>) -> Self {
        Self::Ready(value)
    }
}
/// Backend operations must authenticate roots and pins in their own namespace.
/// APPEND pins write only at End; End selection and mutation are one transaction.
/// CaseFold applies to the final component, with indexed bounded leaf lookup.
/// No backend may retain borrowed buffers when returning Pending.
pub trait FileService {
    fn open(
        &mut self,
        root: &FileRoot,
        path: NamePath,
        request: OpenRequest,
    ) -> FileOperation<OpenOutcome>;
    fn read_at(&mut self, pin: &FilePin, offset: u64, dst: &mut [u8]) -> FileOperation<usize>;
    fn write_at(&mut self, pin: &FilePin, at: WriteAt, src: &[u8]) -> FileOperation<usize>;
    fn attributes(&mut self, pin: &FilePin) -> FileOperation<FileAttributes>;
    fn release(&mut self, pin: FilePin) -> FileOperation<()>;
}
/// Call-scoped service handle. Guest copies use the same user-memory authority
/// as all other personality operations. Scratch allocation is bounded to 64 KiB.
pub struct Files<'s, 'a, A: EntryArch> {
    cx: &'s mut CallContext<'a, A>,
}
impl<'s, 'a, A: EntryArch + MmuArch + DefaultMmOwner> Files<'s, 'a, A>
where
    ServiceError: From<A::Error>,
{
    pub(crate) fn new(cx: &'s mut CallContext<'a, A>) -> Self {
        Self { cx }
    }
    pub fn open(
        &mut self,
        root: &FileRoot,
        path: NamePath,
        request: OpenRequest,
    ) -> FileOperation<OpenOutcome> {
        match self.cx.file_service.as_deref_mut() {
            Some(fs) => fs.open(root, path, request),
            None => Err(IoError::Unsupported).into(),
        }
    }
    fn buffer(range: UserRange) -> Result<Vec<u8>, IoError> {
        let len = usize::try_from(range.len().raw()).map_err(|_| IoError::TooLarge)?;
        if len > 65536 {
            return Err(IoError::TooLarge);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| IoError::CapacityExhausted)?;
        bytes.resize(len, 0);
        Ok(bytes)
    }
    pub fn read_at(&mut self, pin: &FilePin, offset: u64, dst: UserRange) -> FileOperation<usize> {
        let mut bytes = match Self::buffer(dst) {
            Ok(b) => b,
            Err(e) => return Err(e).into(),
        };
        let result = match self.cx.file_service.as_deref_mut() {
            Some(fs) => fs.read_at(pin, offset, &mut bytes),
            None => return Err(IoError::Unsupported).into(),
        };
        match result {
            FileOperation::Ready(Ok(n)) if n <= bytes.len() => {
                match self.cx.user().copy_out(dst.start(), &bytes[..n]) {
                    Ok(_) => Ok(n).into(),
                    Err(_) => Err(IoError::Fault).into(),
                }
            }
            FileOperation::Ready(Ok(_)) => Err(IoError::Fault).into(),
            other => other,
        }
    }
    pub fn write_at(&mut self, pin: &FilePin, at: WriteAt, src: UserRange) -> FileOperation<usize> {
        let mut bytes = match Self::buffer(src) {
            Ok(b) => b,
            Err(e) => return Err(e).into(),
        };
        if self.cx.user().copy_in(src, &mut bytes).is_err() {
            return Err(IoError::Fault).into();
        }
        match self.cx.file_service.as_deref_mut() {
            Some(fs) => fs.write_at(pin, at, &bytes),
            None => Err(IoError::Unsupported).into(),
        }
    }
    pub fn attributes(&mut self, pin: &FilePin) -> FileOperation<FileAttributes> {
        match self.cx.file_service.as_deref_mut() {
            Some(fs) => fs.attributes(pin),
            None => Err(IoError::Unsupported).into(),
        }
    }
    pub fn release(&mut self, pin: FilePin) -> FileOperation<()> {
        match self.cx.file_service.as_deref_mut() {
            Some(fs) => fs.release(pin),
            None => Err(IoError::Unsupported).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn name_components_are_validated() {
        for invalid in ["/", "a/b", "\0", "a\0b", "", ".", ".."] {
            assert_eq!(
                NamePath::from_components([invalid]),
                Err(IoError::InvalidName)
            );
        }
        let path = NamePath::from_components(["hello", "世界", "a\\b", "...", "x.y"]).unwrap();
        assert_eq!(path.components().len(), 5);
        assert!(
            NamePath::from_components(core::iter::empty())
                .unwrap()
                .components()
                .is_empty()
        );
    }
    #[test]
    fn access_and_request_construction() {
        for disposition in [
            OpenDisposition::OpenExisting,
            OpenDisposition::CreateNew,
            OpenDisposition::OpenOrCreate,
            OpenDisposition::TruncateExisting,
            OpenDisposition::CreateOrTruncate,
        ] {
            let request = OpenRequest {
                access: FileAccess::READ | FileAccess::WRITE | FileAccess::APPEND,
                disposition,
                expect: FileKind::Any,
                follow_final: false,
                name_match: NameMatch::CaseFold,
            };
            assert!(request.access.contains(FileAccess::READ));
            assert!(request.access.contains(FileAccess::WRITE));
            assert!(request.access.contains(FileAccess::APPEND));
            assert_eq!(request.disposition, disposition);
            assert_eq!(request.expect, FileKind::Any);
            assert!(!request.follow_final);
            assert_eq!(request.name_match, NameMatch::CaseFold);
        }
        assert!(FileAccess::from_bits(8).is_none());
        assert_eq!(FileAccess::READ & FileAccess::WRITE, FileAccess::empty());
    }
    #[test]
    fn errors_are_distinct_and_exhaustive() {
        fn ordinal(error: IoError) -> usize {
            match error {
                IoError::NameNotFound => 0,
                IoError::PathNotFound => 1,
                IoError::Exists => 2,
                IoError::NotADirectory => 3,
                IoError::IsADirectory => 4,
                IoError::AccessDenied => 5,
                IoError::ReadOnly => 6,
                IoError::NoSpace => 7,
                IoError::TooLarge => 8,
                IoError::InvalidName => 9,
                IoError::NameTooLong => 10,
                IoError::Stale => 11,
                IoError::Fault => 12,
                IoError::CapacityExhausted => 13,
                IoError::Unsupported => 14,
            }
        }
        let errors = [
            IoError::NameNotFound,
            IoError::PathNotFound,
            IoError::Exists,
            IoError::NotADirectory,
            IoError::IsADirectory,
            IoError::AccessDenied,
            IoError::ReadOnly,
            IoError::NoSpace,
            IoError::TooLarge,
            IoError::InvalidName,
            IoError::NameTooLong,
            IoError::Stale,
            IoError::Fault,
            IoError::CapacityExhausted,
            IoError::Unsupported,
        ];
        for (index, error) in errors.into_iter().enumerate() {
            assert_eq!(ordinal(error), index);
        }
    }
}
