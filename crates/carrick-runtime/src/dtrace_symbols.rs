//! Owned kernel object and symbol snapshots from a live Darwin libdtrace handle.
//!
//! Apple libdtrace owns every string pointer returned by the object and symbol
//! interfaces. Those pointers are invalidated by `dtrace_update` and cannot
//! outlive the handle. This module performs the one cache refresh up front,
//! copies all records immediately, and returns only validated owned values.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_ulong, c_void};
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::{Deserialize, Serialize};

pub const KERNEL_SYMBOL_SCHEMA: &str = "carrick.kernel-symbols.v1";
pub const DTRACE_OBJ_F_KERNEL: c_uint = 0x1;

const AUXILIARY_SYMBOL_NAME_CAPACITY: usize = 4096;
const MAX_SYSCTL_VALUE_SIZE: usize = 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DtraceObjInfo {
    pub dto_name: *const c_char,
    pub dto_file: *const c_char,
    pub dto_id: c_int,
    pub dto_flags: c_uint,
    pub dto_text_va: u64,
    pub dto_text_size: u64,
    pub dto_data_va: u64,
    pub dto_data_size: u64,
    pub dto_bss_va: u64,
    pub dto_bss_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DtraceSymInfo {
    pub dts_object: *const c_char,
    pub dts_name: *const c_char,
    pub dts_id: c_ulong,
}

/// Apple's arm64 `GElf_Sym`, including the architecture sub-info word.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GElfSym {
    pub st_name: std::ffi::c_long,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: c_ulong,
    pub st_size: c_ulong,
    pub st_arch_subinfo: u32,
}

#[repr(C)]
struct DtraceHdl(c_void);

type DtraceObjectCallback =
    extern "C" fn(*mut DtraceHdl, *const DtraceObjInfo, *mut c_void) -> c_int;

#[link(name = "dtrace")]
unsafe extern "C" {
    fn dtrace_update(hdl: *mut DtraceHdl);
    fn dtrace_object_iter(
        hdl: *mut DtraceHdl,
        callback: DtraceObjectCallback,
        argument: *mut c_void,
    ) -> c_int;
    #[allow(dead_code)]
    fn dtrace_object_info(
        hdl: *mut DtraceHdl,
        name: *const c_char,
        info: *mut DtraceObjInfo,
    ) -> c_int;
    fn dtrace_lookup_by_addr(
        hdl: *mut DtraceHdl,
        address: u64,
        auxiliary_symbol_name: *mut c_char,
        auxiliary_size: usize,
        symbol: *mut GElfSym,
        info: *mut DtraceSymInfo,
    ) -> c_int;
    #[allow(dead_code)]
    fn dtrace_addr2str(
        hdl: *mut DtraceHdl,
        address: u64,
        buffer: *mut c_char,
        length: c_int,
    ) -> c_int;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct KernelIdentity {
    pub osversion: String,
    pub version: String,
    pub uuid: String,
    pub machine: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct KernelObjectRange {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub id: c_int,
    pub flags: c_uint,
    pub text_start: u64,
    pub text_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct KernelSymbolRange {
    pub address: u64,
    pub object: String,
    pub symbol: String,
    pub symbol_id: c_ulong,
    pub symbol_start: u64,
    pub symbol_size: u64,
    pub offset: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct KernelSymbolSnapshot {
    pub schema: String,
    pub identity: KernelIdentity,
    pub objects: Vec<KernelObjectRange>,
    pub symbols: Vec<KernelSymbolRange>,
}

#[derive(Debug, thiserror::Error)]
pub enum KernelSymbolError {
    #[error("invalid kernel identity: {0}")]
    InvalidIdentity(String),
    #[error("invalid kernel object: {0}")]
    InvalidObject(String),
    #[error("invalid kernel symbol: {0}")]
    InvalidSymbol(String),
    #[error("kernel object iteration failed: {0}")]
    ObjectIteration(String),
    #[error("kernel symbol lookup failed for {address:#x}: {detail}")]
    Lookup { address: u64, detail: String },
    #[error("kernel symbol snapshot address mismatch: {0}")]
    AddressMismatch(String),
    #[error("sysctl {name:?} failed: {source}")]
    Sysctl {
        name: &'static str,
        source: std::io::Error,
    },
}

#[derive(Clone, Copy)]
struct BorrowedObject<'a> {
    name: Option<&'a [u8]>,
    file: Option<&'a [u8]>,
    id: c_int,
    flags: c_uint,
    text_start: u64,
    text_size: u64,
}

#[derive(Clone, Copy)]
struct BorrowedSymbol<'a> {
    object: Option<&'a [u8]>,
    symbol: Option<&'a [u8]>,
    symbol_id: c_ulong,
    symbol_start: u64,
    symbol_size: u64,
    auxiliary: &'a [u8],
}

fn required_string(value: Option<&[u8]>, field: &str) -> Result<String, KernelSymbolError> {
    let value =
        value.ok_or_else(|| KernelSymbolError::InvalidObject(format!("{field} is null")))?;
    let value = std::str::from_utf8(value)
        .map_err(|_| KernelSymbolError::InvalidObject(format!("{field} is not strict UTF-8")))?;
    if value.is_empty() || value.contains('\0') {
        return Err(KernelSymbolError::InvalidObject(format!(
            "{field} is empty or contains NUL"
        )));
    }
    Ok(value.to_owned())
}

fn required_symbol_string(value: Option<&[u8]>, field: &str) -> Result<String, KernelSymbolError> {
    let value =
        value.ok_or_else(|| KernelSymbolError::InvalidSymbol(format!("{field} is null")))?;
    let value = std::str::from_utf8(value)
        .map_err(|_| KernelSymbolError::InvalidSymbol(format!("{field} is not strict UTF-8")))?;
    if value.is_empty() || value.contains('\0') {
        return Err(KernelSymbolError::InvalidSymbol(format!(
            "{field} is empty or contains NUL"
        )));
    }
    Ok(value.to_owned())
}

fn own_object(record: BorrowedObject<'_>) -> Result<KernelObjectRange, KernelSymbolError> {
    let name = required_string(record.name, "object name")?;
    let file = match record.file {
        None | Some([]) => None,
        Some(value) => Some(required_string(Some(value), "object file")?),
    };
    if record.text_size == 0 {
        return Err(KernelSymbolError::InvalidObject(format!(
            "{name:?} has zero text size"
        )));
    }
    record
        .text_start
        .checked_add(record.text_size)
        .ok_or_else(|| {
            KernelSymbolError::InvalidObject(format!("{name:?} text range overflows"))
        })?;
    Ok(KernelObjectRange {
        name,
        file,
        id: record.id,
        flags: record.flags,
        text_start: record.text_start,
        text_size: record.text_size,
    })
}

fn own_symbol(
    address: u64,
    status: c_int,
    record: BorrowedSymbol<'_>,
) -> Result<KernelSymbolRange, KernelSymbolError> {
    if status != 0 {
        return Err(KernelSymbolError::Lookup {
            address,
            detail: format!("libdtrace returned status {status}"),
        });
    }
    if !record.auxiliary.contains(&0) {
        return Err(KernelSymbolError::Lookup {
            address,
            detail: "auxiliary symbol-name buffer lacks a NUL terminator".to_owned(),
        });
    }
    let object = required_symbol_string(record.object, "symbol object")?;
    let symbol = required_symbol_string(record.symbol, "symbol name")?;
    if record.symbol_size == 0 {
        return Err(KernelSymbolError::InvalidSymbol(format!(
            "{symbol:?} has zero size"
        )));
    }
    let symbol_end = record
        .symbol_start
        .checked_add(record.symbol_size)
        .ok_or_else(|| KernelSymbolError::InvalidSymbol(format!("{symbol:?} range overflows")))?;
    if !(record.symbol_start..symbol_end).contains(&address) {
        return Err(KernelSymbolError::InvalidSymbol(format!(
            "address {address:#x} is outside {symbol:?} range {:#x}..{symbol_end:#x}",
            record.symbol_start
        )));
    }
    Ok(KernelSymbolRange {
        address,
        object,
        symbol,
        symbol_id: record.symbol_id,
        symbol_start: record.symbol_start,
        symbol_size: record.symbol_size,
        offset: address - record.symbol_start,
    })
}

fn validate_identity(identity: &KernelIdentity) -> Result<(), KernelSymbolError> {
    for (field, value) in [
        ("kern.osversion", identity.osversion.as_str()),
        ("kern.version", identity.version.as_str()),
        ("kern.uuid", identity.uuid.as_str()),
        ("hw.machine", identity.machine.as_str()),
    ] {
        if value.is_empty() || value.contains('\0') {
            return Err(KernelSymbolError::InvalidIdentity(format!(
                "{field} is empty or contains NUL"
            )));
        }
    }
    let bytes = identity.uuid.as_bytes();
    if bytes.len() != 36
        || [8, 13, 18, 23].iter().any(|index| bytes[*index] != b'-')
        || bytes
            .iter()
            .enumerate()
            .any(|(index, value)| ![8, 13, 18, 23].contains(&index) && !value.is_ascii_hexdigit())
    {
        return Err(KernelSymbolError::InvalidIdentity(format!(
            "kern.uuid {:?} is not canonical 8-4-4-4-12 hexadecimal",
            identity.uuid
        )));
    }
    if identity.machine != "arm64" {
        return Err(KernelSymbolError::InvalidIdentity(format!(
            "hw.machine is {:?}, expected \"arm64\"",
            identity.machine
        )));
    }
    Ok(())
}

fn validate_object(object: &KernelObjectRange) -> Result<u64, KernelSymbolError> {
    if object.name.is_empty() || object.name.contains('\0') {
        return Err(KernelSymbolError::InvalidObject(
            "object name is empty or contains NUL".to_owned(),
        ));
    }
    if object
        .file
        .as_ref()
        .is_some_and(|file| file.is_empty() || file.contains('\0'))
    {
        return Err(KernelSymbolError::InvalidObject(format!(
            "{:?} has an empty file name or one containing NUL",
            object.name
        )));
    }
    if object.flags & DTRACE_OBJ_F_KERNEL == 0 {
        return Err(KernelSymbolError::InvalidObject(format!(
            "{:?} is not a kernel object",
            object.name
        )));
    }
    if object.text_size == 0 {
        return Err(KernelSymbolError::InvalidObject(format!(
            "{:?} has zero text size",
            object.name
        )));
    }
    object
        .text_start
        .checked_add(object.text_size)
        .ok_or_else(|| {
            KernelSymbolError::InvalidObject(format!("{:?} text range overflows", object.name))
        })
}

fn validate_symbol(symbol: &KernelSymbolRange) -> Result<u64, KernelSymbolError> {
    if symbol.object.is_empty()
        || symbol.object.contains('\0')
        || symbol.symbol.is_empty()
        || symbol.symbol.contains('\0')
    {
        return Err(KernelSymbolError::InvalidSymbol(
            "symbol object/name is empty or contains NUL".to_owned(),
        ));
    }
    if symbol.symbol_size == 0 {
        return Err(KernelSymbolError::InvalidSymbol(format!(
            "{:?} has zero size",
            symbol.symbol
        )));
    }
    let end = symbol
        .symbol_start
        .checked_add(symbol.symbol_size)
        .ok_or_else(|| {
            KernelSymbolError::InvalidSymbol(format!("{:?} range overflows", symbol.symbol))
        })?;
    if !(symbol.symbol_start..end).contains(&symbol.address) {
        return Err(KernelSymbolError::InvalidSymbol(format!(
            "address {:#x} is outside {:?} range",
            symbol.address, symbol.symbol
        )));
    }
    if symbol.offset != symbol.address - symbol.symbol_start {
        return Err(KernelSymbolError::InvalidSymbol(format!(
            "{:?} offset {} does not match address/start",
            symbol.symbol, symbol.offset
        )));
    }
    Ok(end)
}

impl KernelSymbolSnapshot {
    pub fn from_parts(
        identity: KernelIdentity,
        mut objects: Vec<KernelObjectRange>,
        symbols: Vec<KernelSymbolRange>,
        requested: impl IntoIterator<Item = u64>,
    ) -> Result<Self, KernelSymbolError> {
        validate_identity(&identity)?;
        if objects.is_empty() {
            return Err(KernelSymbolError::InvalidObject(
                "kernel object catalog is empty".to_owned(),
            ));
        }
        objects.sort_by(|left, right| {
            (left.text_start, left.text_size, left.name.as_str(), left.id).cmp(&(
                right.text_start,
                right.text_size,
                right.name.as_str(),
                right.id,
            ))
        });
        let mut identities = BTreeSet::new();
        let mut ranges = BTreeSet::new();
        for object in &objects {
            validate_object(object)?;
            if !identities.insert((object.name.clone(), object.id)) {
                return Err(KernelSymbolError::InvalidObject(format!(
                    "duplicate object identity {:?}/{}",
                    object.name, object.id
                )));
            }
            if !ranges.insert((object.text_start, object.text_size)) {
                return Err(KernelSymbolError::InvalidObject(format!(
                    "duplicate object range {:#x}+{:#x}",
                    object.text_start, object.text_size
                )));
            }
        }

        let mut symbols_by_address = BTreeMap::<u64, KernelSymbolRange>::new();
        for symbol in symbols {
            validate_symbol(&symbol)?;
            let containing = objects
                .iter()
                .filter(|object| {
                    object
                        .text_start
                        .checked_add(object.text_size)
                        .is_some_and(|end| (object.text_start..end).contains(&symbol.address))
                })
                .collect::<Vec<_>>();
            if containing.len() != 1 {
                return Err(KernelSymbolError::InvalidSymbol(format!(
                    "address {:#x} is contained by {} kernel object ranges",
                    symbol.address,
                    containing.len()
                )));
            }
            if containing[0].name != symbol.object {
                return Err(KernelSymbolError::InvalidSymbol(format!(
                    "address {:#x} lookup object {:?} does not match containing object {:?}",
                    symbol.address, symbol.object, containing[0].name
                )));
            }
            match symbols_by_address.entry(symbol.address) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(symbol);
                }
                std::collections::btree_map::Entry::Occupied(slot) if slot.get() == &symbol => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(KernelSymbolError::InvalidSymbol(format!(
                        "conflicting duplicate result for address {:#x}",
                        symbol.address
                    )));
                }
            }
        }
        let snapshot = Self {
            schema: KERNEL_SYMBOL_SCHEMA.to_owned(),
            identity,
            objects,
            symbols: symbols_by_address.into_values().collect(),
        };
        snapshot.reconcile_addresses(requested)?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), KernelSymbolError> {
        if self.schema != KERNEL_SYMBOL_SCHEMA {
            return Err(KernelSymbolError::AddressMismatch(format!(
                "schema is {:?}, expected {KERNEL_SYMBOL_SCHEMA:?}",
                self.schema
            )));
        }
        let rebuilt = Self::from_parts(
            self.identity.clone(),
            self.objects.clone(),
            self.symbols.clone(),
            self.symbols.iter().map(|symbol| symbol.address),
        )?;
        if &rebuilt != self {
            return Err(KernelSymbolError::AddressMismatch(
                "snapshot is not in deterministic canonical order".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn reconcile_addresses(
        &self,
        requested: impl IntoIterator<Item = u64>,
    ) -> Result<(), KernelSymbolError> {
        let requested = requested.into_iter().collect::<BTreeSet<_>>();
        if requested.is_empty() {
            return Err(KernelSymbolError::AddressMismatch(
                "requested kernel address set is empty".to_owned(),
            ));
        }
        let actual = self
            .symbols
            .iter()
            .map(|symbol| symbol.address)
            .collect::<BTreeSet<_>>();
        if actual.len() != self.symbols.len() {
            return Err(KernelSymbolError::AddressMismatch(
                "snapshot contains duplicate symbol addresses".to_owned(),
            ));
        }
        if requested != actual {
            let missing = requested.difference(&actual).copied().collect::<Vec<_>>();
            let extra = actual.difference(&requested).copied().collect::<Vec<_>>();
            return Err(KernelSymbolError::AddressMismatch(format!(
                "missing={missing:#x?}, extra={extra:#x?}"
            )));
        }
        Ok(())
    }
}

trait SymbolSource {
    fn sysctl(&mut self, name: &'static str) -> Result<Vec<u8>, KernelSymbolError>;
    fn update(&mut self) -> Result<(), KernelSymbolError>;
    fn objects(&mut self) -> Result<Vec<KernelObjectRange>, KernelSymbolError>;
    fn lookup(&mut self, address: u64) -> Result<KernelSymbolRange, KernelSymbolError>;
}

fn identity_value(bytes: Vec<u8>, name: &'static str) -> Result<String, KernelSymbolError> {
    if bytes.len() < 2 || bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(KernelSymbolError::InvalidIdentity(format!(
            "{name} is not one nonempty NUL-terminated value"
        )));
    }
    std::str::from_utf8(&bytes[..bytes.len() - 1])
        .map(str::to_owned)
        .map_err(|_| KernelSymbolError::InvalidIdentity(format!("{name} is not strict UTF-8")))
}

fn snapshot_with_source(
    source: &mut impl SymbolSource,
    requested: impl IntoIterator<Item = u64>,
) -> Result<KernelSymbolSnapshot, KernelSymbolError> {
    let identity = KernelIdentity {
        osversion: identity_value(source.sysctl("kern.osversion")?, "kern.osversion")?,
        version: identity_value(source.sysctl("kern.version")?, "kern.version")?,
        uuid: identity_value(source.sysctl("kern.uuid")?, "kern.uuid")?,
        machine: identity_value(source.sysctl("hw.machine")?, "hw.machine")?,
    };
    validate_identity(&identity)?;
    source.update()?;
    let objects = source.objects()?;
    let requested = requested.into_iter().collect::<BTreeSet<_>>();
    if requested.is_empty() {
        return Err(KernelSymbolError::AddressMismatch(
            "requested kernel address set is empty".to_owned(),
        ));
    }
    let symbols = requested
        .iter()
        .map(|address| source.lookup(*address))
        .collect::<Result<Vec<_>, _>>()?;
    KernelSymbolSnapshot::from_parts(identity, objects, symbols, requested)
}

#[derive(Default)]
struct ObjectCallbackContext {
    objects: Vec<KernelObjectRange>,
    error: Option<KernelSymbolError>,
    callback_panicked: bool,
    #[cfg(test)]
    panic_before_conversion: bool,
    #[cfg(test)]
    panic_before_record: bool,
}

unsafe fn optional_c_bytes<'a>(value: *const c_char) -> Option<&'a [u8]> {
    if value.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(value) }.to_bytes())
    }
}

unsafe fn auxiliary_symbol_name_bytes(
    value: *const c_char,
    auxiliary: &[u8],
    address: u64,
) -> Result<&[u8], KernelSymbolError> {
    if value.is_null() {
        return Err(KernelSymbolError::Lookup {
            address,
            detail: "libdtrace returned a null auxiliary symbol-name pointer".to_owned(),
        });
    }
    let start = auxiliary.as_ptr() as usize;
    let end = start
        .checked_add(auxiliary.len())
        .ok_or_else(|| KernelSymbolError::Lookup {
            address,
            detail: "auxiliary symbol-name buffer address overflows".to_owned(),
        })?;
    let pointer = value as usize;
    if pointer < start || pointer >= end {
        return Err(KernelSymbolError::Lookup {
            address,
            detail: "libdtrace symbol-name pointer is outside the auxiliary buffer".to_owned(),
        });
    }
    let offset = pointer - start;
    let suffix = &auxiliary[offset..];
    let nul =
        suffix
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| KernelSymbolError::Lookup {
                address,
                detail: "auxiliary symbol-name buffer lacks a NUL after the returned pointer"
                    .to_owned(),
            })?;
    if nul == 0 || nul == suffix.len() - 1 {
        return Err(KernelSymbolError::Lookup {
            address,
            detail: "auxiliary symbol-name buffer has an empty or truncated terminal NUL"
                .to_owned(),
        });
    }
    Ok(&suffix[..nul])
}

extern "C" fn object_callback(
    _hdl: *mut DtraceHdl,
    info: *const DtraceObjInfo,
    argument: *mut c_void,
) -> c_int {
    if argument.is_null() {
        return 0;
    }
    let context = unsafe { &mut *argument.cast::<ObjectCallbackContext>() };
    if context.error.is_some() || context.callback_panicked {
        return 0;
    }
    let conversion = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(test)]
        if context.panic_before_conversion {
            std::panic::resume_unwind(Box::new("injected callback panic"));
        }
        let info = unsafe {
            info.as_ref().ok_or_else(|| {
                KernelSymbolError::InvalidObject("object callback received null info".to_owned())
            })?
        };
        if info.dto_flags & DTRACE_OBJ_F_KERNEL == 0 {
            return Ok(());
        }
        let object = own_object(BorrowedObject {
            name: unsafe { optional_c_bytes(info.dto_name) },
            file: unsafe { optional_c_bytes(info.dto_file) },
            id: info.dto_id,
            flags: info.dto_flags,
            text_start: info.dto_text_va,
            text_size: info.dto_text_size,
        })?;
        #[cfg(test)]
        if context.panic_before_record {
            std::panic::resume_unwind(Box::new("injected callback record panic"));
        }
        context.objects.push(object);
        Ok(())
    }));
    match conversion {
        Ok(Ok(())) => {}
        Ok(Err(error)) => context.error = Some(error),
        Err(_) => context.callback_panicked = true,
    }
    0
}

fn finish_object_iteration(
    context: ObjectCallbackContext,
    status: c_int,
) -> Result<Vec<KernelObjectRange>, KernelSymbolError> {
    if status != 0 {
        return Err(KernelSymbolError::ObjectIteration(format!(
            "libdtrace returned status {status}"
        )));
    }
    if context.callback_panicked {
        return Err(KernelSymbolError::ObjectIteration(
            "object callback panicked".to_owned(),
        ));
    }
    if let Some(error) = context.error {
        return Err(error);
    }
    Ok(context.objects)
}

struct LiveSymbolSource {
    hdl: *mut DtraceHdl,
}

impl SymbolSource for LiveSymbolSource {
    fn sysctl(&mut self, name: &'static str) -> Result<Vec<u8>, KernelSymbolError> {
        read_sysctl(name)
    }

    fn update(&mut self) -> Result<(), KernelSymbolError> {
        unsafe { dtrace_update(self.hdl) };
        Ok(())
    }

    fn objects(&mut self) -> Result<Vec<KernelObjectRange>, KernelSymbolError> {
        let mut context = ObjectCallbackContext::default();
        let status = unsafe {
            dtrace_object_iter(
                self.hdl,
                object_callback,
                (&mut context as *mut ObjectCallbackContext).cast(),
            )
        };
        finish_object_iteration(context, status)
    }

    fn lookup(&mut self, address: u64) -> Result<KernelSymbolRange, KernelSymbolError> {
        let mut auxiliary = vec![0xff_u8; AUXILIARY_SYMBOL_NAME_CAPACITY];
        let mut symbol = GElfSym::default();
        let mut info = DtraceSymInfo {
            dts_object: std::ptr::null(),
            dts_name: std::ptr::null(),
            dts_id: 0,
        };
        let status = unsafe {
            dtrace_lookup_by_addr(
                self.hdl,
                address,
                auxiliary.as_mut_ptr().cast(),
                auxiliary.len(),
                &mut symbol,
                &mut info,
            )
        };
        if status != 0 {
            return Err(KernelSymbolError::Lookup {
                address,
                detail: format!("libdtrace returned status {status}"),
            });
        }
        own_symbol(
            address,
            0,
            BorrowedSymbol {
                object: unsafe { optional_c_bytes(info.dts_object) },
                symbol: Some(unsafe {
                    auxiliary_symbol_name_bytes(info.dts_name, &auxiliary, address)?
                }),
                symbol_id: info.dts_id,
                symbol_start: symbol.st_value,
                symbol_size: symbol.st_size,
                auxiliary: &auxiliary,
            },
        )
    }
}

fn read_sysctl(name: &'static str) -> Result<Vec<u8>, KernelSymbolError> {
    let c_name = CString::new(name).map_err(|_| {
        KernelSymbolError::InvalidIdentity(format!("sysctl name {name:?} contains NUL"))
    })?;
    let mut length = 0_usize;
    if unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(KernelSymbolError::Sysctl {
            name,
            source: std::io::Error::last_os_error(),
        });
    }
    if length == 0 || length > MAX_SYSCTL_VALUE_SIZE {
        return Err(KernelSymbolError::InvalidIdentity(format!(
            "sysctl {name:?} reported invalid length {length}"
        )));
    }
    let mut bytes = vec![0_u8; length];
    let mut read_length = length;
    if unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut read_length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(KernelSymbolError::Sysctl {
            name,
            source: std::io::Error::last_os_error(),
        });
    }
    if read_length == 0 || read_length > length {
        return Err(KernelSymbolError::InvalidIdentity(format!(
            "sysctl {name:?} returned invalid length {read_length} for capacity {length}"
        )));
    }
    bytes.truncate(read_length);
    Ok(bytes)
}

/// A live symbol resolver whose borrow is bounded by the libdtrace handle.
///
/// The raw handle is private and the result contains only owned data, so no
/// libdtrace pointer can escape the post-stop callback.
pub struct LiveDtraceSymbolizer<'handle> {
    hdl: *mut c_void,
    _handle: PhantomData<&'handle mut c_void>,
}

impl<'handle> LiveDtraceSymbolizer<'handle> {
    pub(crate) fn new(hdl: *mut c_void) -> Self {
        Self {
            hdl,
            _handle: PhantomData,
        }
    }

    pub fn snapshot(
        self,
        addresses: impl IntoIterator<Item = u64>,
    ) -> Result<KernelSymbolSnapshot, KernelSymbolError> {
        let mut source = LiveSymbolSource {
            hdl: self.hdl.cast(),
        };
        snapshot_with_source(&mut source, addresses)
    }
}

#[cfg(test)]
fn link_only_apple_symbols() {
    let update: unsafe extern "C" fn(*mut DtraceHdl) = dtrace_update;
    let object_iter: unsafe extern "C" fn(
        *mut DtraceHdl,
        DtraceObjectCallback,
        *mut c_void,
    ) -> c_int = dtrace_object_iter;
    let object_info: unsafe extern "C" fn(
        *mut DtraceHdl,
        *const c_char,
        *mut DtraceObjInfo,
    ) -> c_int = dtrace_object_info;
    let lookup: unsafe extern "C" fn(
        *mut DtraceHdl,
        u64,
        *mut c_char,
        usize,
        *mut GElfSym,
        *mut DtraceSymInfo,
    ) -> c_int = dtrace_lookup_by_addr;
    let addr2str: unsafe extern "C" fn(*mut DtraceHdl, u64, *mut c_char, c_int) -> c_int =
        dtrace_addr2str;
    std::hint::black_box((update, object_iter, object_info, lookup, addr2str));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    fn identity() -> KernelIdentity {
        KernelIdentity {
            osversion: "26A5388g".to_owned(),
            version: "Darwin Kernel Version 26.0.0".to_owned(),
            uuid: "01234567-89AB-CDEF-0123-456789ABCDEF".to_owned(),
            machine: "arm64".to_owned(),
        }
    }

    fn object(name: &str, id: i32, start: u64, size: u64) -> KernelObjectRange {
        KernelObjectRange {
            name: name.to_owned(),
            file: Some(format!("/System/{name}")),
            id,
            flags: DTRACE_OBJ_F_KERNEL,
            text_start: start,
            text_size: size,
        }
    }

    fn symbol(address: u64, object: &str, name: &str, start: u64, size: u64) -> KernelSymbolRange {
        KernelSymbolRange {
            address,
            object: object.to_owned(),
            symbol: name.to_owned(),
            symbol_id: address,
            symbol_start: start,
            symbol_size: size,
            offset: address - start,
        }
    }

    #[test]
    fn apple_public_abi_layouts_are_exact() {
        assert_eq!(size_of::<DtraceObjInfo>(), 72);
        assert_eq!(align_of::<DtraceObjInfo>(), 8);
        assert_eq!(offset_of!(DtraceObjInfo, dto_name), 0);
        assert_eq!(offset_of!(DtraceObjInfo, dto_file), 8);
        assert_eq!(offset_of!(DtraceObjInfo, dto_id), 16);
        assert_eq!(offset_of!(DtraceObjInfo, dto_flags), 20);
        assert_eq!(offset_of!(DtraceObjInfo, dto_text_va), 24);
        assert_eq!(offset_of!(DtraceObjInfo, dto_text_size), 32);
        assert_eq!(offset_of!(DtraceObjInfo, dto_data_va), 40);
        assert_eq!(offset_of!(DtraceObjInfo, dto_data_size), 48);
        assert_eq!(offset_of!(DtraceObjInfo, dto_bss_va), 56);
        assert_eq!(offset_of!(DtraceObjInfo, dto_bss_size), 64);

        assert_eq!(size_of::<DtraceSymInfo>(), 24);
        assert_eq!(align_of::<DtraceSymInfo>(), 8);
        assert_eq!(offset_of!(DtraceSymInfo, dts_object), 0);
        assert_eq!(offset_of!(DtraceSymInfo, dts_name), 8);
        assert_eq!(offset_of!(DtraceSymInfo, dts_id), 16);

        assert_eq!(size_of::<GElfSym>(), 40);
        assert_eq!(align_of::<GElfSym>(), 8);
        assert_eq!(offset_of!(GElfSym, st_name), 0);
        assert_eq!(offset_of!(GElfSym, st_info), 8);
        assert_eq!(offset_of!(GElfSym, st_other), 9);
        assert_eq!(offset_of!(GElfSym, st_shndx), 10);
        assert_eq!(offset_of!(GElfSym, st_value), 16);
        assert_eq!(offset_of!(GElfSym, st_size), 24);
        assert_eq!(offset_of!(GElfSym, st_arch_subinfo), 32);
    }

    #[test]
    fn borrowed_records_are_deep_copied_before_backing_storage_reuse() {
        let mut object_name = b"kernel".to_vec();
        let mut object_file = b"/System/kernel".to_vec();
        let owned = own_object(BorrowedObject {
            name: Some(&object_name),
            file: Some(&object_file),
            id: 7,
            flags: DTRACE_OBJ_F_KERNEL,
            text_start: 0x1000,
            text_size: 0x100,
        })
        .expect("owned object");
        object_name.fill(b'x');
        object_file.fill(b'y');
        assert_eq!(owned.name, "kernel");
        assert_eq!(owned.file.as_deref(), Some("/System/kernel"));

        let mut symbol_name = b"machine_startup".to_vec();
        let mut aux = b"machine_startup\0".to_vec();
        let owned = own_symbol(
            0x1018,
            0,
            BorrowedSymbol {
                object: Some(b"kernel"),
                symbol: Some(&symbol_name),
                symbol_id: 9,
                symbol_start: 0x1010,
                symbol_size: 0x20,
                auxiliary: &aux,
            },
        )
        .expect("owned symbol");
        symbol_name.fill(b'z');
        aux.fill(0xff);
        assert_eq!(owned.symbol, "machine_startup");
        assert_eq!(owned.offset, 8);
    }

    #[test]
    fn optional_object_file_normalizes_empty_but_rejects_invalid_values() {
        for file in [None, Some(b"".as_slice())] {
            let owned = own_object(BorrowedObject {
                name: Some(b"kernel"),
                file,
                id: 1,
                flags: DTRACE_OBJ_F_KERNEL,
                text_start: 0x1000,
                text_size: 0x100,
            })
            .expect("optional file");
            assert_eq!(owned.file, None);
        }

        let owned = own_object(BorrowedObject {
            name: Some(b"kernel"),
            file: Some(b"/System/kernel"),
            id: 1,
            flags: DTRACE_OBJ_F_KERNEL,
            text_start: 0x1000,
            text_size: 0x100,
        })
        .expect("valid file");
        assert_eq!(owned.file.as_deref(), Some("/System/kernel"));

        for file in [Some(&[0xff][..]), Some(b"bad\0file".as_slice())] {
            assert!(
                own_object(BorrowedObject {
                    name: Some(b"kernel"),
                    file,
                    id: 1,
                    flags: DTRACE_OBJ_F_KERNEL,
                    text_start: 0x1000,
                    text_size: 0x100,
                })
                .is_err()
            );
        }
    }

    #[test]
    fn snapshot_sorting_dedup_and_exact_reconciliation_are_deterministic() {
        let requested = [0x2018, 0x1018, 0x2018];
        let snapshot = KernelSymbolSnapshot::from_parts(
            identity(),
            vec![
                object("com.apple.driver", 2, 0x2000, 0x100),
                object("kernel", 1, 0x1000, 0x100),
            ],
            vec![
                symbol(0x2018, "com.apple.driver", "driver_fn", 0x2010, 0x20),
                symbol(0x1018, "kernel", "kernel_fn", 0x1010, 0x20),
                symbol(0x2018, "com.apple.driver", "driver_fn", 0x2010, 0x20),
            ],
            requested,
        )
        .expect("valid snapshot");

        assert_eq!(snapshot.schema, KERNEL_SYMBOL_SCHEMA);
        assert_eq!(
            snapshot
                .objects
                .iter()
                .map(|record| record.text_start)
                .collect::<Vec<_>>(),
            [0x1000, 0x2000]
        );
        assert_eq!(
            snapshot
                .symbols
                .iter()
                .map(|record| record.address)
                .collect::<Vec<_>>(),
            [0x1018, 0x2018]
        );
        snapshot
            .reconcile_addresses([0x1018, 0x2018])
            .expect("exact address set");
        assert!(snapshot.reconcile_addresses([0x1018]).is_err());
        assert!(
            snapshot
                .reconcile_addresses([0x1018, 0x2018, 0x3018])
                .is_err()
        );
    }

    #[test]
    fn snapshot_rejects_invalid_identity_objects_symbols_and_conflicts() {
        let valid_object = object("kernel", 1, 0x1000, 0x100);
        let valid_symbol = symbol(0x1018, "kernel", "kernel_fn", 0x1010, 0x20);

        let mut cases = Vec::new();
        let mut bad_identity = identity();
        bad_identity.uuid = "not-a-uuid".to_owned();
        cases.push((
            bad_identity,
            vec![valid_object.clone()],
            vec![valid_symbol.clone()],
            vec![0x1018],
        ));
        cases.push((identity(), vec![], vec![valid_symbol.clone()], vec![0x1018]));
        let mut zero_object = valid_object.clone();
        zero_object.text_size = 0;
        cases.push((
            identity(),
            vec![zero_object],
            vec![valid_symbol.clone()],
            vec![0x1018],
        ));
        let mut overflow_object = valid_object.clone();
        overflow_object.text_start = u64::MAX;
        cases.push((
            identity(),
            vec![overflow_object],
            vec![valid_symbol.clone()],
            vec![0x1018],
        ));
        let mut zero_symbol = valid_symbol.clone();
        zero_symbol.symbol_size = 0;
        cases.push((
            identity(),
            vec![valid_object.clone()],
            vec![zero_symbol],
            vec![0x1018],
        ));
        let mut bad_offset = valid_symbol.clone();
        bad_offset.offset = 9;
        cases.push((
            identity(),
            vec![valid_object.clone()],
            vec![bad_offset],
            vec![0x1018],
        ));
        let mut outside_symbol = valid_symbol.clone();
        outside_symbol.address = 0x1040;
        cases.push((
            identity(),
            vec![valid_object.clone()],
            vec![outside_symbol],
            vec![0x1040],
        ));
        cases.push((
            identity(),
            vec![valid_object.clone(), object("other", 2, 0x1000, 0x100)],
            vec![valid_symbol.clone()],
            vec![0x1018],
        ));
        cases.push((
            identity(),
            vec![valid_object.clone(), object("kernel", 1, 0x2000, 0x100)],
            vec![valid_symbol.clone()],
            vec![0x1018],
        ));
        let mut wrong_object = valid_symbol.clone();
        wrong_object.object = "other".to_owned();
        cases.push((
            identity(),
            vec![valid_object.clone()],
            vec![wrong_object],
            vec![0x1018],
        ));
        cases.push((
            identity(),
            vec![valid_object.clone()],
            vec![
                valid_symbol.clone(),
                symbol(0x1018, "kernel", "other_fn", 0x1010, 0x20),
            ],
            vec![0x1018],
        ));

        for (identity, objects, symbols, requested) in cases {
            assert!(
                KernelSymbolSnapshot::from_parts(identity, objects, symbols, requested).is_err()
            );
        }
    }

    #[test]
    fn borrowed_conversion_rejects_bad_strings_ranges_lookup_and_auxiliary_buffer() {
        let object_cases = [
            BorrowedObject {
                name: None,
                file: None,
                id: 1,
                flags: DTRACE_OBJ_F_KERNEL,
                text_start: 1,
                text_size: 1,
            },
            BorrowedObject {
                name: Some(b""),
                file: None,
                id: 1,
                flags: DTRACE_OBJ_F_KERNEL,
                text_start: 1,
                text_size: 1,
            },
            BorrowedObject {
                name: Some(&[0xff]),
                file: None,
                id: 1,
                flags: DTRACE_OBJ_F_KERNEL,
                text_start: 1,
                text_size: 1,
            },
            BorrowedObject {
                name: Some(b"kernel"),
                file: None,
                id: 1,
                flags: DTRACE_OBJ_F_KERNEL,
                text_start: 1,
                text_size: 0,
            },
            BorrowedObject {
                name: Some(b"kernel"),
                file: None,
                id: 1,
                flags: DTRACE_OBJ_F_KERNEL,
                text_start: u64::MAX,
                text_size: 2,
            },
        ];
        for record in object_cases {
            assert!(own_object(record).is_err());
        }

        let symbol_cases = [
            (
                0x1018,
                1,
                BorrowedSymbol {
                    object: Some(b"kernel"),
                    symbol: Some(b"fn"),
                    symbol_id: 1,
                    symbol_start: 0x1010,
                    symbol_size: 0x20,
                    auxiliary: b"fn\0",
                },
            ),
            (
                0x1018,
                0,
                BorrowedSymbol {
                    object: None,
                    symbol: Some(b"fn"),
                    symbol_id: 1,
                    symbol_start: 0x1010,
                    symbol_size: 0x20,
                    auxiliary: b"fn\0",
                },
            ),
            (
                0x1018,
                0,
                BorrowedSymbol {
                    object: Some(b"kernel"),
                    symbol: Some(b""),
                    symbol_id: 1,
                    symbol_start: 0x1010,
                    symbol_size: 0x20,
                    auxiliary: b"fn\0",
                },
            ),
            (
                0x1018,
                0,
                BorrowedSymbol {
                    object: Some(b"kernel"),
                    symbol: Some(&[0xff]),
                    symbol_id: 1,
                    symbol_start: 0x1010,
                    symbol_size: 0x20,
                    auxiliary: b"fn\0",
                },
            ),
            (
                0x1018,
                0,
                BorrowedSymbol {
                    object: Some(b"kernel"),
                    symbol: Some(b"fn"),
                    symbol_id: 1,
                    symbol_start: 0x1010,
                    symbol_size: 0,
                    auxiliary: b"fn\0",
                },
            ),
            (
                0x1018,
                0,
                BorrowedSymbol {
                    object: Some(b"kernel"),
                    symbol: Some(b"fn"),
                    symbol_id: 1,
                    symbol_start: u64::MAX,
                    symbol_size: 2,
                    auxiliary: b"fn\0",
                },
            ),
            (
                0x1018,
                0,
                BorrowedSymbol {
                    object: Some(b"kernel"),
                    symbol: Some(b"fn"),
                    symbol_id: 1,
                    symbol_start: 0x1020,
                    symbol_size: 0x20,
                    auxiliary: b"fn\0",
                },
            ),
            (
                0x1018,
                0,
                BorrowedSymbol {
                    object: Some(b"kernel"),
                    symbol: Some(b"fn"),
                    symbol_id: 1,
                    symbol_start: 0x1010,
                    symbol_size: 0x20,
                    auxiliary: b"unterminated",
                },
            ),
        ];
        for (address, status, record) in symbol_cases {
            assert!(own_symbol(address, status, record).is_err());
        }
    }

    #[test]
    fn auxiliary_symbol_name_requires_a_bounded_nonterminal_c_string() {
        let auxiliary = b".kernel_fn\0padding";
        let valid = unsafe {
            auxiliary_symbol_name_bytes(
                auxiliary.as_ptr().wrapping_add(1).cast(),
                auxiliary,
                0x1018,
            )
        }
        .expect("in-buffer symbol name");
        assert_eq!(valid, b"kernel_fn");

        let unterminated = b".unterminated";
        let outside = b"outside\0";
        assert!(
            unsafe {
                auxiliary_symbol_name_bytes(
                    unterminated.as_ptr().wrapping_add(1).cast(),
                    unterminated,
                    0x1018,
                )
            }
            .is_err()
        );
        for pointer in [outside.as_ptr().cast(), std::ptr::null()] {
            assert!(unsafe { auxiliary_symbol_name_bytes(pointer, auxiliary, 0x1018) }.is_err());
        }

        let terminal = b".terminal\0";
        assert!(
            unsafe {
                auxiliary_symbol_name_bytes(
                    terminal.as_ptr().wrapping_add(1).cast(),
                    terminal,
                    0x1018,
                )
            }
            .is_err()
        );
    }

    #[test]
    fn resolver_orders_identity_update_iteration_and_lookups_once() {
        let mut source = MockSource::valid();
        let snapshot =
            snapshot_with_source(&mut source, [0x2018, 0x1018, 0x2018]).expect("snapshot");
        assert_eq!(
            source.calls,
            [
                "sysctl:kern.osversion",
                "sysctl:kern.version",
                "sysctl:kern.uuid",
                "sysctl:hw.machine",
                "update",
                "objects",
                "lookup:0x1018",
                "lookup:0x2018",
            ]
        );
        assert_eq!(snapshot.symbols.len(), 2);

        for bytes in [
            Vec::new(),
            b"\0".to_vec(),
            b"unterminated".to_vec(),
            b"embedded\0nul\0".to_vec(),
            vec![0xff, 0],
        ] {
            assert!(identity_value(bytes, "test.identity").is_err());
        }
        let mut empty_source = MockSource::valid();
        assert!(snapshot_with_source(&mut empty_source, []).is_err());
    }

    #[test]
    fn object_callback_captures_conversion_error_and_always_returns_zero() {
        let bad_name = [0xff_u8, 0];
        let info = DtraceObjInfo {
            dto_name: bad_name.as_ptr().cast(),
            dto_file: std::ptr::null(),
            dto_id: 1,
            dto_flags: DTRACE_OBJ_F_KERNEL,
            dto_text_va: 0x1000,
            dto_text_size: 0x100,
            dto_data_va: 0,
            dto_data_size: 0,
            dto_bss_va: 0,
            dto_bss_size: 0,
        };
        let mut context = ObjectCallbackContext::default();
        let status = object_callback(
            std::ptr::null_mut(),
            &info,
            (&mut context as *mut ObjectCallbackContext).cast(),
        );
        assert_eq!(status, 0);
        assert!(context.error.is_some());
        assert!(context.objects.is_empty());

        let mut panic_context = ObjectCallbackContext {
            panic_before_conversion: true,
            ..ObjectCallbackContext::default()
        };
        let status = object_callback(
            std::ptr::null_mut(),
            &info,
            (&mut panic_context as *mut ObjectCallbackContext).cast(),
        );
        assert_eq!(status, 0);
        assert!(panic_context.callback_panicked);

        let mut record_panic_context = ObjectCallbackContext {
            panic_before_record: true,
            ..ObjectCallbackContext::default()
        };
        let status = object_callback(
            std::ptr::null_mut(),
            &DtraceObjInfo {
                dto_name: b"kernel\0".as_ptr().cast(),
                dto_file: std::ptr::null(),
                dto_id: 1,
                dto_flags: DTRACE_OBJ_F_KERNEL,
                dto_text_va: 0x1000,
                dto_text_size: 0x100,
                dto_data_va: 0,
                dto_data_size: 0,
                dto_bss_va: 0,
                dto_bss_size: 0,
            },
            (&mut record_panic_context as *mut ObjectCallbackContext).cast(),
        );
        assert_eq!(status, 0);
        assert!(record_panic_context.callback_panicked);
        assert!(record_panic_context.objects.is_empty());
        record_panic_context.panic_before_record = false;

        let status = object_callback(
            std::ptr::null_mut(),
            &DtraceObjInfo {
                dto_name: b"kernel\0".as_ptr().cast(),
                dto_file: std::ptr::null(),
                dto_id: 1,
                dto_flags: DTRACE_OBJ_F_KERNEL,
                dto_text_va: 0x1000,
                dto_text_size: 0x100,
                dto_data_va: 0,
                dto_data_size: 0,
                dto_bss_va: 0,
                dto_bss_size: 0,
            },
            (&mut record_panic_context as *mut ObjectCallbackContext).cast(),
        );
        assert_eq!(status, 0);
        assert!(record_panic_context.objects.is_empty());

        let error = finish_object_iteration(
            ObjectCallbackContext {
                callback_panicked: true,
                ..ObjectCallbackContext::default()
            },
            0,
        )
        .expect_err("record-time panic must become a typed iteration error");
        assert!(matches!(error, KernelSymbolError::ObjectIteration(_)));
    }

    fn snapshot_from_owned_symbolizer(
        symbolizer: LiveDtraceSymbolizer<'_>,
    ) -> Result<KernelSymbolSnapshot, KernelSymbolError> {
        symbolizer.snapshot(Vec::new())
    }

    #[test]
    fn snapshot_consumes_the_live_symbolizer() {
        let _ = snapshot_from_owned_symbolizer;
    }

    #[test]
    fn apple_symbol_declarations_link_without_opening_dtrace() {
        link_only_apple_symbols();
    }

    struct MockSource {
        calls: Vec<String>,
        objects: Vec<KernelObjectRange>,
        symbols: Vec<KernelSymbolRange>,
    }

    impl MockSource {
        fn valid() -> Self {
            Self {
                calls: Vec::new(),
                objects: vec![
                    object("com.apple.driver", 2, 0x2000, 0x100),
                    object("kernel", 1, 0x1000, 0x100),
                ],
                symbols: vec![
                    symbol(0x1018, "kernel", "kernel_fn", 0x1010, 0x20),
                    symbol(0x2018, "com.apple.driver", "driver_fn", 0x2010, 0x20),
                ],
            }
        }
    }

    impl SymbolSource for MockSource {
        fn sysctl(&mut self, name: &'static str) -> Result<Vec<u8>, KernelSymbolError> {
            self.calls.push(format!("sysctl:{name}"));
            let value = match name {
                "kern.osversion" => b"26A5388g\0".as_slice(),
                "kern.version" => b"Darwin Kernel Version 26.0.0\0".as_slice(),
                "kern.uuid" => b"01234567-89AB-CDEF-0123-456789ABCDEF\0".as_slice(),
                "hw.machine" => b"arm64\0".as_slice(),
                _ => return Err(KernelSymbolError::InvalidIdentity(name.to_owned())),
            };
            Ok(value.to_vec())
        }

        fn update(&mut self) -> Result<(), KernelSymbolError> {
            self.calls.push("update".to_owned());
            Ok(())
        }

        fn objects(&mut self) -> Result<Vec<KernelObjectRange>, KernelSymbolError> {
            self.calls.push("objects".to_owned());
            Ok(self.objects.clone())
        }

        fn lookup(&mut self, address: u64) -> Result<KernelSymbolRange, KernelSymbolError> {
            self.calls.push(format!("lookup:{address:#x}"));
            self.symbols
                .iter()
                .find(|symbol| symbol.address == address)
                .cloned()
                .ok_or(KernelSymbolError::Lookup {
                    address,
                    detail: "missing mock symbol".to_owned(),
                })
        }
    }
}
