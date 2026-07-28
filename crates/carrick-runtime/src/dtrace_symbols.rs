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
use sha2::{Digest, Sha256};

pub const KERNEL_SYMBOL_SCHEMA: &str = "carrick.kernel-symbols.v1";
pub const SAMPLED_KERNEL_SYMBOL_SCHEMA: &str = "carrick.sampled-kernel-symbols.v1";
pub const DTRACE_OBJ_F_KERNEL: c_uint = 0x1;

const AUXILIARY_SYMBOL_NAME_CAPACITY: usize = 4096;
const PERSISTENT_SYMBOL_NAME_CAPACITY: usize = 4096;
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
    fn dtrace_errno(hdl: *mut DtraceHdl) -> c_int;
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
    pub bootsessionuuid: String,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SampledKernelSymbol {
    pub address: u64,
    pub symbol: String,
    pub symbol_start: u64,
    pub symbol_size: u64,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnresolvedKernelAddress {
    pub address: u64,
    pub status: c_int,
    pub dtrace_errno: c_int,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SampledKernelSymbolOverlay {
    pub schema: String,
    pub identity: KernelIdentity,
    pub requested_sha256: String,
    pub requested_count: u64,
    pub resolved_sha256: String,
    pub resolved_count: u64,
    pub unresolved_sha256: String,
    pub unresolved_count: u64,
    pub symbols: Vec<SampledKernelSymbol>,
    pub unresolved: Vec<UnresolvedKernelAddress>,
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
    #[error(
        "kernel symbol lookup census passed but schema publication is disabled: requested={requested}, resolved={resolved}, name-private-valid={name_private_valid}, name-aux-valid={name_aux_valid}, objects={objects:?}"
    )]
    LookupCensusPassed {
        requested: usize,
        resolved: usize,
        name_private_valid: usize,
        name_aux_valid: usize,
        objects: Vec<String>,
    },
    #[error("{0}")]
    LookupCensusFailed(Box<LookupCensusFailureSummary>),
    #[error("sysctl {name:?} failed: {source}")]
    Sysctl {
        name: &'static str,
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub struct LookupCensusFailureSummary {
    requested: usize,
    resolved: usize,
    status: usize,
    status_histogram: Vec<(c_int, c_int, usize)>,
    name_private_valid: usize,
    name_aux_valid: usize,
    name_invalid: usize,
    raw_address_fallback: usize,
    zero_or_overflow: usize,
    range: usize,
    owner: usize,
    duplicate: usize,
    address_set: usize,
    unexpected: usize,
    accounting: usize,
}

impl std::fmt::Display for LookupCensusFailureSummary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "kernel symbol lookup census failed: requested={}, resolved={}, status={}, \
             status-histogram={:?}, name-private-valid={}, name-aux-valid={}, \
             name-invalid={}, raw-address-fallback={}, zero-or-overflow={}, \
             containment-or-offset={}, owner={}, duplicate={}, address-set={}, unexpected={}, \
             accounting={}",
            self.requested,
            self.resolved,
            self.status,
            self.status_histogram,
            self.name_private_valid,
            self.name_aux_valid,
            self.name_invalid,
            self.raw_address_fallback,
            self.zero_or_overflow,
            self.range,
            self.owner,
            self.duplicate,
            self.address_set,
            self.unexpected,
            self.accounting,
        )
    }
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
}

/// A copied `dtrace_object_iter`/`dtrace_object_info` record that has not yet
/// passed the published `KernelObjectRange` text-range invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProvisionalObject {
    name: String,
    file: Option<String>,
    id: c_int,
    flags: c_uint,
    text_start: u64,
    text_size: u64,
    data_start: u64,
    data_size: u64,
    bss_start: u64,
    bss_size: u64,
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

fn own_provisional_object(info: &DtraceObjInfo) -> Result<ProvisionalObject, KernelSymbolError> {
    let name = required_string(unsafe { optional_c_bytes(info.dto_name) }, "object name")?;
    let file = match unsafe { optional_c_bytes(info.dto_file) } {
        None | Some([]) => None,
        Some(value) => Some(required_string(Some(value), "object file")?),
    };
    let object = ProvisionalObject {
        name,
        file,
        id: info.dto_id,
        flags: info.dto_flags,
        text_start: info.dto_text_va,
        text_size: info.dto_text_size,
        data_start: info.dto_data_va,
        data_size: info.dto_data_size,
        bss_start: info.dto_bss_va,
        bss_size: info.dto_bss_size,
    };
    validate_provisional_ranges(&object)?;
    Ok(object)
}

fn validate_provisional_ranges(object: &ProvisionalObject) -> Result<(), KernelSymbolError> {
    for (start, size, range) in [
        (object.text_start, object.text_size, "text"),
        (object.data_start, object.data_size, "data"),
        (object.bss_start, object.bss_size, "bss"),
    ] {
        if size != 0 {
            start.checked_add(size).ok_or_else(|| {
                KernelSymbolError::InvalidObject(format!(
                    "{:?} {range} range overflows",
                    object.name
                ))
            })?;
        }
    }
    Ok(())
}

fn published_object(object: ProvisionalObject) -> Result<KernelObjectRange, KernelSymbolError> {
    own_object(BorrowedObject {
        name: Some(object.name.as_bytes()),
        file: object.file.as_deref().map(str::as_bytes),
        id: object.id,
        flags: object.flags,
        text_start: object.text_start,
        text_size: object.text_size,
    })
}

fn object_info_mismatch_fields(
    original: &ProvisionalObject,
    resolved: &ProvisionalObject,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if resolved.name != original.name {
        fields.push("name");
    }
    if original.file.is_some() && original.file != resolved.file {
        fields.push("file");
    }
    if resolved.id != original.id {
        fields.push("id");
    }
    if resolved.flags != original.flags {
        fields.push("flags");
    }
    if resolved.flags & DTRACE_OBJ_F_KERNEL == 0 {
        fields.push("kernel-bit");
    }
    if original.text_start != 0 && original.text_start != resolved.text_start {
        fields.push("text-start");
    }
    if original.text_size != 0 && original.text_size != resolved.text_size {
        fields.push("text-size");
    }
    if resolved.text_size == 0 {
        fields.push("unresolved-text-size");
    }
    for (original, resolved, field) in [
        (original.data_start, resolved.data_start, "data-start"),
        (original.data_size, resolved.data_size, "data-size"),
        (original.bss_start, resolved.bss_start, "bss-start"),
        (original.bss_size, resolved.bss_size, "bss-size"),
    ] {
        if original != 0 && original != resolved {
            fields.push(field);
        }
    }
    fields
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CensusFailureClass {
    Status,
    Name,
    RawAddressFallback,
    ZeroOrOverflow,
    ContainmentOrOffset,
    Unexpected,
}

#[derive(Debug)]
struct CensusLookupFailure {
    class: CensusFailureClass,
    error: KernelSymbolError,
    status_key: Option<(c_int, c_int)>,
}

impl CensusLookupFailure {
    fn new(class: CensusFailureClass, error: KernelSymbolError) -> Self {
        Self {
            class,
            error,
            status_key: None,
        }
    }

    fn status(error: KernelSymbolError, status: c_int, errno: c_int) -> Self {
        Self {
            class: CensusFailureClass::Status,
            error,
            status_key: Some((status, errno)),
        }
    }

    fn unexpected(error: KernelSymbolError) -> Self {
        Self::new(CensusFailureClass::Unexpected, error)
    }

    fn into_error(self) -> KernelSymbolError {
        self.error
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolNameProvenance {
    Private,
    Auxiliary,
}

struct CensusLookupOutcome {
    symbol: KernelSymbolRange,
    name_provenance: SymbolNameProvenance,
}

#[derive(Default)]
struct LookupCensusCounts {
    status: usize,
    status_histogram: BTreeMap<(c_int, c_int), usize>,
    name_private_valid: usize,
    name_aux_valid: usize,
    name_invalid: usize,
    raw_address_fallback: usize,
    zero_or_overflow: usize,
    range: usize,
    unexpected: usize,
    owner: usize,
    duplicate: usize,
    address_set: usize,
    accounting: usize,
}

impl LookupCensusCounts {
    fn record_failure(&mut self, failure: CensusLookupFailure) {
        match failure.class {
            CensusFailureClass::Status => {
                self.status += 1;
                if let Some(key) = failure.status_key {
                    *self.status_histogram.entry(key).or_default() += 1;
                } else {
                    self.unexpected += 1;
                }
            }
            CensusFailureClass::Name => self.name_invalid += 1,
            CensusFailureClass::RawAddressFallback => self.raw_address_fallback += 1,
            CensusFailureClass::ZeroOrOverflow => self.zero_or_overflow += 1,
            CensusFailureClass::ContainmentOrOffset => self.range += 1,
            CensusFailureClass::Unexpected => self.unexpected += 1,
        }
    }

    fn is_empty(&self) -> bool {
        self.status == 0
            && self.name_invalid == 0
            && self.raw_address_fallback == 0
            && self.zero_or_overflow == 0
            && self.range == 0
            && self.unexpected == 0
            && self.owner == 0
            && self.duplicate == 0
            && self.address_set == 0
            && self.accounting == 0
    }

    fn finalize_reconciliation(&mut self, requested: usize, resolved: usize) {
        let histogram_total = self
            .status_histogram
            .values()
            .try_fold(0_usize, |total, count| total.checked_add(*count));
        let provenance_total = self.name_private_valid.checked_add(self.name_aux_valid);
        let terminal_total = [
            resolved,
            self.status,
            self.name_invalid,
            self.raw_address_fallback,
            self.zero_or_overflow,
            self.range,
            self.unexpected,
            self.owner,
            self.address_set,
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add);
        self.accounting = usize::from(histogram_total != Some(self.status))
            + usize::from(provenance_total != Some(resolved))
            + usize::from(terminal_total != Some(requested));
    }

    fn into_error(mut self, requested: usize, resolved: usize) -> KernelSymbolError {
        self.finalize_reconciliation(requested, resolved);
        KernelSymbolError::LookupCensusFailed(Box::new(LookupCensusFailureSummary {
            requested,
            resolved,
            status: self.status,
            status_histogram: self
                .status_histogram
                .into_iter()
                .map(|((status, errno), count)| (status, errno, count))
                .collect(),
            name_private_valid: self.name_private_valid,
            name_aux_valid: self.name_aux_valid,
            name_invalid: self.name_invalid,
            raw_address_fallback: self.raw_address_fallback,
            zero_or_overflow: self.zero_or_overflow,
            range: self.range,
            owner: self.owner,
            duplicate: self.duplicate,
            address_set: self.address_set,
            unexpected: self.unexpected,
            accounting: self.accounting,
        }))
    }
}

fn has_observed_unresolved_mach_kernel(objects: &[ProvisionalObject]) -> bool {
    let kernel = objects
        .iter()
        .filter(|object| object.flags & DTRACE_OBJ_F_KERNEL != 0)
        .collect::<Vec<_>>();
    let unresolved = kernel
        .iter()
        .filter(|object| object.text_size == 0)
        .copied()
        .collect::<Vec<_>>();
    unresolved.len() == 1
        && unresolved[0].name == "mach_kernel"
        && kernel
            .iter()
            .filter(|object| object.name == "mach_kernel")
            .count()
            == 1
}

fn lookup_census(
    objects: &[ProvisionalObject],
    requested: &BTreeSet<u64>,
    mut lookup: impl FnMut(u64) -> Result<CensusLookupOutcome, CensusLookupFailure>,
) -> KernelSymbolError {
    let owners = objects
        .iter()
        .filter(|object| object.flags & DTRACE_OBJ_F_KERNEL != 0)
        .fold(BTreeMap::<&str, usize>::new(), |mut owners, object| {
            *owners.entry(&object.name).or_default() += 1;
            owners
        });
    let mut counts = LookupCensusCounts::default();
    let mut symbols = Vec::with_capacity(requested.len());
    let mut names = BTreeSet::new();
    for address in requested {
        match lookup(*address) {
            Ok(outcome) => {
                let symbol = outcome.symbol;
                if symbol.address != *address {
                    counts.address_set += 1;
                    continue;
                }
                if let Err(failure) =
                    validate_symbol(&symbol).map_err(CensusLookupFailure::unexpected)
                {
                    counts.record_failure(failure);
                    continue;
                }
                if owners.get(symbol.object.as_str()) != Some(&1) {
                    counts.owner += 1;
                    continue;
                }
                match outcome.name_provenance {
                    SymbolNameProvenance::Private => counts.name_private_valid += 1,
                    SymbolNameProvenance::Auxiliary => counts.name_aux_valid += 1,
                }
                names.insert(symbol.object.clone());
                symbols.push(symbol);
            }
            Err(error) => counts.record_failure(error),
        }
    }
    let addresses = symbols
        .iter()
        .map(|symbol| symbol.address)
        .collect::<BTreeSet<_>>();
    counts.duplicate += symbols.len().saturating_sub(addresses.len());
    if counts.status == 0
        && counts.name_invalid == 0
        && counts.raw_address_fallback == 0
        && counts.zero_or_overflow == 0
        && counts.range == 0
        && counts.unexpected == 0
        && counts.owner == 0
        && counts.duplicate == 0
        && counts.address_set == 0
        && addresses != *requested
    {
        counts.address_set = 1;
    }
    counts.finalize_reconciliation(requested.len(), symbols.len());
    if counts.is_empty() {
        return KernelSymbolError::LookupCensusPassed {
            requested: requested.len(),
            resolved: symbols.len(),
            name_private_valid: counts.name_private_valid,
            name_aux_valid: counts.name_aux_valid,
            objects: names.into_iter().collect(),
        };
    }
    counts.into_error(requested.len(), symbols.len())
}

fn refine_kernel_objects(
    mut objects: Vec<ProvisionalObject>,
    mut query: impl FnMut(&str) -> Result<ProvisionalObject, KernelSymbolError>,
) -> Result<Vec<KernelObjectRange>, KernelSymbolError> {
    for object in &objects {
        validate_provisional_ranges(object)?;
    }
    let mut queries = objects
        .iter()
        .filter(|object| object.text_size == 0)
        .map(|object| (object.name.clone(), object.id))
        .collect::<Vec<_>>();
    queries.sort();
    for (name, id) in queries {
        if objects.iter().filter(|object| object.name == name).count() != 1 {
            return Err(KernelSymbolError::InvalidObject(format!(
                "object-info name-only query for {name:?} is ambiguous"
            )));
        }
        let resolved = query(&name)?;
        validate_provisional_ranges(&resolved)?;
        let original = objects
            .iter_mut()
            .find(|object| object.name == name && object.id == id)
            .ok_or_else(|| {
                KernelSymbolError::InvalidObject(format!("missing zero-size object {name:?}"))
            })?;
        let mismatches = object_info_mismatch_fields(original, &resolved);
        if !mismatches.is_empty() {
            return Err(KernelSymbolError::InvalidObject(format!(
                "object-info mismatch for {name:?}: {}",
                mismatches.join(", ")
            )));
        }
        *original = resolved;
    }
    objects.into_iter().map(published_object).collect()
}

fn finish_object_info(
    name: &str,
    status: c_int,
    info: &DtraceObjInfo,
) -> Result<ProvisionalObject, KernelSymbolError> {
    if status != 0 {
        return Err(KernelSymbolError::ObjectIteration(format!(
            "object-info {name:?} returned status {status}"
        )));
    }
    own_provisional_object(info)
}

#[cfg(test)]
fn own_symbol(
    address: u64,
    status: c_int,
    record: BorrowedSymbol<'_>,
) -> Result<KernelSymbolRange, KernelSymbolError> {
    dtrace_lookup_status(address, status).map_err(CensusLookupFailure::into_error)?;
    own_symbol_for_census(address, record).map_err(CensusLookupFailure::into_error)
}

#[cfg(test)]
fn dtrace_lookup_status(address: u64, status: c_int) -> Result<(), CensusLookupFailure> {
    if status != 0 {
        return Err(CensusLookupFailure::status(
            KernelSymbolError::Lookup {
                address,
                detail: format!("libdtrace returned status {status}"),
            },
            status,
            0,
        ));
    }
    Ok(())
}

fn own_symbol_for_census(
    address: u64,
    record: BorrowedSymbol<'_>,
) -> Result<KernelSymbolRange, CensusLookupFailure> {
    let object = required_symbol_string(record.object, "symbol object")
        .map_err(|error| CensusLookupFailure::new(CensusFailureClass::Name, error))?;
    let symbol = required_symbol_string(record.symbol, "symbol name")
        .map_err(|error| CensusLookupFailure::new(CensusFailureClass::Name, error))?;
    if record.symbol_size == 0 {
        return Err(CensusLookupFailure::new(
            CensusFailureClass::ZeroOrOverflow,
            KernelSymbolError::InvalidSymbol(format!("{symbol:?} has zero size")),
        ));
    }
    let symbol_end = record
        .symbol_start
        .checked_add(record.symbol_size)
        .ok_or_else(|| {
            CensusLookupFailure::new(
                CensusFailureClass::ZeroOrOverflow,
                KernelSymbolError::InvalidSymbol(format!("{symbol:?} range overflows")),
            )
        })?;
    if !(record.symbol_start..symbol_end).contains(&address) {
        return Err(CensusLookupFailure::new(
            CensusFailureClass::ContainmentOrOffset,
            KernelSymbolError::InvalidSymbol(format!(
                "address {address:#x} is outside {symbol:?} range {:#x}..{symbol_end:#x}",
                record.symbol_start
            )),
        ));
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
        ("kern.bootsessionuuid", identity.bootsessionuuid.as_str()),
    ] {
        if value.trim().is_empty() || value.contains('\0') {
            return Err(KernelSymbolError::InvalidIdentity(format!(
                "{field} is empty or contains NUL"
            )));
        }
    }
    validate_uuid("kern.uuid", &identity.uuid)?;
    validate_uuid("kern.bootsessionuuid", &identity.bootsessionuuid)?;
    if identity.machine != "arm64" {
        return Err(KernelSymbolError::InvalidIdentity(format!(
            "hw.machine is {:?}, expected \"arm64\"",
            identity.machine
        )));
    }
    Ok(())
}

fn validate_uuid(field: &str, value: &str) -> Result<(), KernelSymbolError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || [8, 13, 18, 23].iter().any(|index| bytes[*index] != b'-')
        || bytes
            .iter()
            .enumerate()
            .any(|(index, value)| ![8, 13, 18, 23].contains(&index) && !value.is_ascii_hexdigit())
    {
        return Err(KernelSymbolError::InvalidIdentity(format!(
            "{field} {value:?} is not canonical 8-4-4-4-12 hexadecimal"
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

fn validate_sampled_symbol(symbol: &SampledKernelSymbol) -> Result<u64, KernelSymbolError> {
    if symbol.symbol.is_empty() || symbol.symbol.contains('\0') {
        return Err(KernelSymbolError::InvalidSymbol(
            "sampled symbol name is empty or contains NUL".to_owned(),
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

fn address_set_sha256(addresses: impl IntoIterator<Item = u64>) -> String {
    let mut digest = Sha256::new();
    for address in addresses {
        digest.update(address.to_be_bytes());
    }
    format!("{:x}", digest.finalize())
}

impl SampledKernelSymbolOverlay {
    pub fn from_parts(
        identity: KernelIdentity,
        requested: impl IntoIterator<Item = u64>,
        symbols: Vec<SampledKernelSymbol>,
        unresolved: Vec<UnresolvedKernelAddress>,
    ) -> Result<Self, KernelSymbolError> {
        validate_identity(&identity)?;

        let mut requested_addresses = BTreeSet::new();
        for address in requested {
            if !requested_addresses.insert(address) {
                return Err(KernelSymbolError::AddressMismatch(format!(
                    "duplicate requested kernel address {address:#x}"
                )));
            }
        }

        let mut symbols_by_address = BTreeMap::new();
        for symbol in symbols {
            validate_sampled_symbol(&symbol)?;
            let address = symbol.address;
            if symbols_by_address.insert(address, symbol).is_some() {
                return Err(KernelSymbolError::AddressMismatch(format!(
                    "duplicate resolved kernel address {address:#x}"
                )));
            }
        }

        let mut unresolved_by_address = BTreeMap::new();
        for unresolved in unresolved {
            let address = unresolved.address;
            if unresolved_by_address.insert(address, unresolved).is_some() {
                return Err(KernelSymbolError::AddressMismatch(format!(
                    "duplicate unresolved kernel address {address:#x}"
                )));
            }
        }

        let resolved_addresses = symbols_by_address.keys().copied().collect::<BTreeSet<_>>();
        let unresolved_addresses = unresolved_by_address
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let overlap = resolved_addresses
            .intersection(&unresolved_addresses)
            .copied()
            .collect::<Vec<_>>();
        if !overlap.is_empty() {
            return Err(KernelSymbolError::AddressMismatch(format!(
                "resolved and unresolved kernel addresses overlap: {overlap:#x?}"
            )));
        }
        let actual_addresses = resolved_addresses
            .union(&unresolved_addresses)
            .copied()
            .collect::<BTreeSet<_>>();
        if requested_addresses != actual_addresses {
            let missing = requested_addresses
                .difference(&actual_addresses)
                .copied()
                .collect::<Vec<_>>();
            let extra = actual_addresses
                .difference(&requested_addresses)
                .copied()
                .collect::<Vec<_>>();
            return Err(KernelSymbolError::AddressMismatch(format!(
                "missing={missing:#x?}, extra={extra:#x?}"
            )));
        }

        let requested_count = u64::try_from(requested_addresses.len()).map_err(|_| {
            KernelSymbolError::AddressMismatch("requested address count exceeds u64".to_owned())
        })?;
        let resolved_count = u64::try_from(resolved_addresses.len()).map_err(|_| {
            KernelSymbolError::AddressMismatch("resolved address count exceeds u64".to_owned())
        })?;
        let unresolved_count = u64::try_from(unresolved_addresses.len()).map_err(|_| {
            KernelSymbolError::AddressMismatch("unresolved address count exceeds u64".to_owned())
        })?;

        Ok(Self {
            schema: SAMPLED_KERNEL_SYMBOL_SCHEMA.to_owned(),
            identity,
            requested_sha256: address_set_sha256(requested_addresses.iter().copied()),
            requested_count,
            resolved_sha256: address_set_sha256(resolved_addresses.iter().copied()),
            resolved_count,
            unresolved_sha256: address_set_sha256(unresolved_addresses.iter().copied()),
            unresolved_count,
            symbols: symbols_by_address.into_values().collect(),
            unresolved: unresolved_by_address.into_values().collect(),
        })
    }

    pub fn validate(&self) -> Result<(), KernelSymbolError> {
        if self.schema != SAMPLED_KERNEL_SYMBOL_SCHEMA {
            return Err(KernelSymbolError::AddressMismatch(format!(
                "schema is {:?}, expected {SAMPLED_KERNEL_SYMBOL_SCHEMA:?}",
                self.schema
            )));
        }
        let requested = self
            .symbols
            .iter()
            .map(|symbol| symbol.address)
            .chain(self.unresolved.iter().map(|unresolved| unresolved.address))
            .collect::<Vec<_>>();
        let rebuilt = Self::from_parts(
            self.identity.clone(),
            requested,
            self.symbols.clone(),
            self.unresolved.clone(),
        )?;
        if &rebuilt != self {
            return Err(KernelSymbolError::AddressMismatch(
                "sampled overlay is not canonical or has invalid counts/hashes".to_owned(),
            ));
        }
        Ok(())
    }
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
    fn objects(&mut self) -> Result<Vec<ProvisionalObject>, KernelSymbolError>;
    fn object_info(&mut self, name: &str) -> Result<ProvisionalObject, KernelSymbolError>;
    fn lookup(&mut self, address: u64) -> Result<KernelSymbolRange, KernelSymbolError>;
    fn census_lookup(&mut self, address: u64) -> Result<CensusLookupOutcome, CensusLookupFailure>;
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

fn read_identity(source: &mut impl SymbolSource) -> Result<KernelIdentity, KernelSymbolError> {
    let identity = KernelIdentity {
        osversion: identity_value(source.sysctl("kern.osversion")?, "kern.osversion")?,
        version: identity_value(source.sysctl("kern.version")?, "kern.version")?,
        uuid: identity_value(source.sysctl("kern.uuid")?, "kern.uuid")?,
        machine: identity_value(source.sysctl("hw.machine")?, "hw.machine")?,
        bootsessionuuid: identity_value(
            source.sysctl("kern.bootsessionuuid")?,
            "kern.bootsessionuuid",
        )?,
    };
    validate_identity(&identity)?;
    Ok(identity)
}

fn sampled_overlay_with_source(
    source: &mut impl SymbolSource,
    requested: Vec<u64>,
) -> Result<SampledKernelSymbolOverlay, KernelSymbolError> {
    let mut requested_addresses = BTreeSet::new();
    for address in &requested {
        if !requested_addresses.insert(*address) {
            return Err(KernelSymbolError::AddressMismatch(format!(
                "duplicate requested kernel address {address:#x}"
            )));
        }
    }

    let identity = read_identity(source)?;
    source.update()?;
    let mut symbols = Vec::new();
    let mut unresolved = Vec::new();
    for address in &requested_addresses {
        match source.census_lookup(*address) {
            Ok(outcome) => {
                let symbol = outcome.symbol;
                symbols.push(SampledKernelSymbol {
                    address: symbol.address,
                    symbol: symbol.symbol,
                    symbol_start: symbol.symbol_start,
                    symbol_size: symbol.symbol_size,
                    offset: symbol.offset,
                });
            }
            Err(failure) => match (failure.class, failure.status_key) {
                (CensusFailureClass::Status, Some((status, dtrace_errno))) => {
                    unresolved.push(UnresolvedKernelAddress {
                        address: *address,
                        status,
                        dtrace_errno,
                    });
                }
                _ => return Err(failure.into_error()),
            },
        }
    }
    SampledKernelSymbolOverlay::from_parts(identity, requested, symbols, unresolved)
}

fn snapshot_with_source(
    source: &mut impl SymbolSource,
    requested: impl IntoIterator<Item = u64>,
) -> Result<KernelSymbolSnapshot, KernelSymbolError> {
    let identity = read_identity(source)?;
    source.update()?;
    let provisional_objects = source.objects()?;
    if has_observed_unresolved_mach_kernel(&provisional_objects) {
        let requested = requested.into_iter().collect::<BTreeSet<_>>();
        if requested.is_empty() {
            return Err(KernelSymbolError::AddressMismatch(
                "requested kernel address set is empty".to_owned(),
            ));
        }
        return Err(lookup_census(&provisional_objects, &requested, |address| {
            source.census_lookup(address)
        }));
    }
    let objects = refine_kernel_objects(provisional_objects, |name| source.object_info(name))?;
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
    objects: Vec<ProvisionalObject>,
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

unsafe fn copy_live_symbol_string(
    value: *const c_char,
    field: &str,
) -> Result<String, CensusLookupFailure> {
    if value.is_null() {
        return Err(CensusLookupFailure::new(
            CensusFailureClass::Name,
            KernelSymbolError::InvalidSymbol(format!("{field} is null")),
        ));
    }
    let length = unsafe { libc::strnlen(value, PERSISTENT_SYMBOL_NAME_CAPACITY) };
    if length == PERSISTENT_SYMBOL_NAME_CAPACITY {
        return Err(CensusLookupFailure::new(
            CensusFailureClass::Name,
            KernelSymbolError::InvalidSymbol(format!("{field} lacks a bounded NUL terminator")),
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), length) };
    required_symbol_string(Some(bytes), field)
        .map_err(|error| CensusLookupFailure::new(CensusFailureClass::Name, error))
}

unsafe fn copy_live_dtrace_name(
    value: *const c_char,
    auxiliary: &[u8],
) -> Result<(String, SymbolNameProvenance), CensusLookupFailure> {
    if value.is_null() {
        return Err(CensusLookupFailure::new(
            CensusFailureClass::Name,
            KernelSymbolError::InvalidSymbol("symbol name is null".to_owned()),
        ));
    }
    let start = auxiliary.as_ptr() as usize;
    let end = start.checked_add(auxiliary.len()).ok_or_else(|| {
        CensusLookupFailure::new(
            CensusFailureClass::Name,
            KernelSymbolError::InvalidSymbol(
                "auxiliary symbol-name buffer address overflows".to_owned(),
            ),
        )
    })?;
    let pointer = value as usize;
    let (name, provenance) = if (start..end).contains(&pointer) {
        let suffix = &auxiliary[pointer - start..];
        let nul = suffix.iter().position(|byte| *byte == 0).ok_or_else(|| {
            CensusLookupFailure::new(
                CensusFailureClass::Name,
                KernelSymbolError::Lookup {
                    address: 0,
                    detail: "auxiliary symbol name lacks NUL".to_owned(),
                },
            )
        })?;
        let bytes = &suffix[..nul];
        let name = required_symbol_string(Some(bytes), "symbol name")
            .map_err(|error| CensusLookupFailure::new(CensusFailureClass::Name, error))?;
        (name, SymbolNameProvenance::Auxiliary)
    } else {
        (
            unsafe { copy_live_symbol_string(value, "symbol name") }?,
            SymbolNameProvenance::Private,
        )
    };
    let bytes = name.as_bytes();
    if (bytes.len() == 10 || bytes.len() == 18)
        && bytes.starts_with(b"0x")
        && bytes[2..].iter().all(u8::is_ascii_hexdigit)
    {
        return Err(CensusLookupFailure::new(
            CensusFailureClass::RawAddressFallback,
            KernelSymbolError::InvalidSymbol("raw-address symbol fallback".to_owned()),
        ));
    }
    Ok((name, provenance))
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
        let object = own_provisional_object(info)?;
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
) -> Result<Vec<ProvisionalObject>, KernelSymbolError> {
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

    fn objects(&mut self) -> Result<Vec<ProvisionalObject>, KernelSymbolError> {
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

    fn object_info(&mut self, name: &str) -> Result<ProvisionalObject, KernelSymbolError> {
        let copied_name = CString::new(name)
            .map_err(|_| KernelSymbolError::InvalidObject("object name contains NUL".to_owned()))?;
        let mut info = DtraceObjInfo {
            dto_name: std::ptr::null(),
            dto_file: std::ptr::null(),
            dto_id: 0,
            dto_flags: 0,
            dto_text_va: 0,
            dto_text_size: 0,
            dto_data_va: 0,
            dto_data_size: 0,
            dto_bss_va: 0,
            dto_bss_size: 0,
        };
        let status = unsafe { dtrace_object_info(self.hdl, copied_name.as_ptr(), &mut info) };
        finish_object_info(name, status, &info)
    }

    fn lookup(&mut self, address: u64) -> Result<KernelSymbolRange, KernelSymbolError> {
        self.census_lookup(address)
            .map(|outcome| outcome.symbol)
            .map_err(CensusLookupFailure::into_error)
    }

    fn census_lookup(&mut self, address: u64) -> Result<CensusLookupOutcome, CensusLookupFailure> {
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
            let errno = unsafe { dtrace_errno(self.hdl) };
            return Err(CensusLookupFailure::status(
                KernelSymbolError::Lookup {
                    address,
                    detail: format!("libdtrace lookup status={status} errno={errno}"),
                },
                status,
                errno,
            ));
        }
        let object = unsafe { copy_live_symbol_string(info.dts_object, "symbol object") }?;
        let (name, name_provenance) = unsafe { copy_live_dtrace_name(info.dts_name, &auxiliary) }?;
        let symbol = own_symbol_for_census(
            address,
            BorrowedSymbol {
                object: Some(object.as_bytes()),
                symbol: Some(name.as_bytes()),
                symbol_id: info.dts_id,
                symbol_start: symbol.st_value,
                symbol_size: symbol.st_size,
            },
        )?;
        Ok(CensusLookupOutcome {
            symbol,
            name_provenance,
        })
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

    pub fn sampled_overlay(
        &mut self,
        requested: Vec<u64>,
    ) -> Result<SampledKernelSymbolOverlay, KernelSymbolError> {
        let mut source = LiveSymbolSource {
            hdl: self.hdl.cast(),
        };
        sampled_overlay_with_source(&mut source, requested)
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
    let errno: unsafe extern "C" fn(*mut DtraceHdl) -> c_int = dtrace_errno;
    let addr2str: unsafe extern "C" fn(*mut DtraceHdl, u64, *mut c_char, c_int) -> c_int =
        dtrace_addr2str;
    std::hint::black_box((update, object_iter, object_info, lookup, errno, addr2str));
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
            bootsessionuuid: "FEDCBA98-7654-3210-FEDC-BA9876543210".to_owned(),
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

    fn provisional_object(name: &str, id: c_int, text_size: u64) -> ProvisionalObject {
        ProvisionalObject {
            name: name.to_owned(),
            file: None,
            id,
            flags: DTRACE_OBJ_F_KERNEL,
            text_start: 0x1000,
            text_size,
            data_start: 0x2000,
            data_size: 0x20,
            bss_start: 0x3000,
            bss_size: 0x30,
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

    fn census_symbol(
        symbol: KernelSymbolRange,
        name_provenance: SymbolNameProvenance,
    ) -> CensusLookupOutcome {
        CensusLookupOutcome {
            symbol,
            name_provenance,
        }
    }

    fn sampled_symbol(address: u64, name: &str, start: u64, size: u64) -> SampledKernelSymbol {
        SampledKernelSymbol {
            address,
            symbol: name.to_owned(),
            symbol_start: start,
            symbol_size: size,
            offset: address - start,
        }
    }

    #[test]
    fn sampled_overlay_exact_partition_is_sorted_hashed_and_identity_free() {
        let requested = vec![0x3018, 0x1018, 0x2018];
        let mut first = OverlaySource::new([
            (
                0x1018,
                OverlayLookup::Resolved(symbol(0x1018, "opaque-first", "kernel_fn", 0x1010, 0x20)),
            ),
            (
                0x2018,
                OverlayLookup::Resolved(symbol(
                    0x2018,
                    "opaque-driver-first",
                    "driver_fn",
                    0x2010,
                    0x20,
                )),
            ),
            (0x3018, OverlayLookup::Status(-1, 1015)),
        ]);
        let mut second = OverlaySource::new([
            (
                0x1018,
                OverlayLookup::Resolved(symbol(0x1018, "opaque-second", "kernel_fn", 0x1010, 0x20)),
            ),
            (
                0x2018,
                OverlayLookup::Resolved(symbol(
                    0x2018,
                    "opaque-driver-second",
                    "driver_fn",
                    0x2010,
                    0x20,
                )),
            ),
            (0x3018, OverlayLookup::Status(-1, 1015)),
        ]);

        let overlay = sampled_overlay_with_source(&mut first, requested.clone())
            .expect("mixed sampled overlay");
        let opaque_variant =
            sampled_overlay_with_source(&mut second, requested).expect("opaque object variant");

        assert_eq!(overlay, opaque_variant);
        assert_eq!(overlay.schema, SAMPLED_KERNEL_SYMBOL_SCHEMA);
        assert_eq!(overlay.requested_count, 3);
        assert_eq!(
            overlay.requested_sha256,
            "a2181a1f562115d3d4ac720e41123754e69ed8704219cdfca1527f5722547972"
        );
        assert_eq!(overlay.resolved_count, 2);
        assert_eq!(
            overlay.resolved_sha256,
            "f8910f09f6203dc870c9d4a6d0f9f86781de88608f2dafe40869d871533a5f47"
        );
        assert_eq!(overlay.unresolved_count, 1);
        assert_eq!(
            overlay.unresolved_sha256,
            "a19400073da4d5f7ebf9401b4b0123c3fbe5e6f666262b37529e38469d6ee7cf"
        );
        assert_eq!(
            overlay.symbols,
            vec![
                sampled_symbol(0x1018, "kernel_fn", 0x1010, 0x20),
                sampled_symbol(0x2018, "driver_fn", 0x2010, 0x20),
            ]
        );
        assert_eq!(
            overlay.unresolved,
            vec![UnresolvedKernelAddress {
                address: 0x3018,
                status: -1,
                dtrace_errno: 1015,
            }]
        );
        assert_eq!(
            first.calls,
            vec![
                "sysctl:kern.osversion",
                "sysctl:kern.version",
                "sysctl:kern.uuid",
                "sysctl:hw.machine",
                "sysctl:kern.bootsessionuuid",
                "update",
                "census:0x1018",
                "census:0x2018",
                "census:0x3018",
            ]
        );
        assert_eq!(
            serde_json::to_vec(&overlay).expect("serialize overlay"),
            serde_json::to_vec(&opaque_variant).expect("serialize opaque variant")
        );
        overlay.validate().expect("valid sampled overlay");
    }

    #[test]
    fn sampled_overlay_preserves_non_census_status_for_frame_role_rejection() {
        let mut source = OverlaySource::new([(0x1018, OverlayLookup::Status(-2, 999))]);
        let overlay =
            sampled_overlay_with_source(&mut source, vec![0x1018]).expect("status overlay");
        assert_eq!(
            overlay.unresolved,
            vec![UnresolvedKernelAddress {
                address: 0x1018,
                status: -2,
                dtrace_errno: 999,
            }]
        );
    }

    #[test]
    fn sampled_overlay_empty_set_uses_sha256_of_empty_bytes() {
        let mut source = OverlaySource::new([]);
        let overlay = sampled_overlay_with_source(&mut source, Vec::new()).expect("empty overlay");
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(overlay.requested_sha256, empty_hash);
        assert_eq!(overlay.resolved_sha256, empty_hash);
        assert_eq!(overlay.unresolved_sha256, empty_hash);
        assert_eq!(overlay.requested_count, 0);
        assert_eq!(overlay.resolved_count, 0);
        assert_eq!(overlay.unresolved_count, 0);
        assert!(overlay.symbols.is_empty());
        assert!(overlay.unresolved.is_empty());
    }

    #[test]
    fn sampled_overlay_rejects_duplicate_requested_addresses() {
        let mut source = OverlaySource::new([(0x1018, OverlayLookup::Status(-1, 1015))]);
        let error = sampled_overlay_with_source(&mut source, vec![0x1018, 0x1018])
            .expect_err("duplicate requested address must fail");
        assert!(matches!(error, KernelSymbolError::AddressMismatch(_)));
        assert!(source.calls.is_empty());
    }

    #[test]
    fn sampled_overlay_rejects_duplicate_and_overlapping_results() {
        let valid = sampled_symbol(0x1018, "kernel_fn", 0x1010, 0x20);
        let unresolved = UnresolvedKernelAddress {
            address: 0x2018,
            status: -1,
            dtrace_errno: 1015,
        };
        for (label, symbols, unresolved) in [
            (
                "duplicate resolved",
                vec![valid.clone(), valid.clone()],
                Vec::new(),
            ),
            (
                "duplicate unresolved",
                Vec::new(),
                vec![unresolved, unresolved],
            ),
            (
                "resolved/unresolved overlap",
                vec![valid.clone()],
                vec![UnresolvedKernelAddress {
                    address: valid.address,
                    status: -1,
                    dtrace_errno: 1015,
                }],
            ),
        ] {
            let error = SampledKernelSymbolOverlay::from_parts(
                identity(),
                vec![0x1018, 0x2018],
                symbols,
                unresolved,
            )
            .expect_err(label);
            assert!(matches!(error, KernelSymbolError::AddressMismatch(_)));
        }
    }

    #[test]
    fn sampled_overlay_rejects_missing_and_extra_results() {
        for (label, requested, symbols) in [
            (
                "missing",
                vec![0x1018, 0x2018],
                vec![sampled_symbol(0x1018, "kernel_fn", 0x1010, 0x20)],
            ),
            (
                "extra",
                vec![0x1018],
                vec![
                    sampled_symbol(0x1018, "kernel_fn", 0x1010, 0x20),
                    sampled_symbol(0x2018, "driver_fn", 0x2010, 0x20),
                ],
            ),
        ] {
            let error =
                SampledKernelSymbolOverlay::from_parts(identity(), requested, symbols, Vec::new())
                    .expect_err(label);
            assert!(matches!(error, KernelSymbolError::AddressMismatch(_)));
        }
    }

    #[test]
    fn sampled_overlay_rejects_invalid_symbol_ranges_and_offsets() {
        let valid = sampled_symbol(0x1018, "kernel_fn", 0x1010, 0x20);
        let mut cases = Vec::new();
        let mut zero = valid.clone();
        zero.symbol_size = 0;
        cases.push(zero);
        let mut overflow = valid.clone();
        overflow.symbol_start = u64::MAX - 1;
        overflow.symbol_size = 2;
        overflow.address = u64::MAX - 1;
        overflow.offset = 0;
        cases.push(overflow);
        let mut outside = valid.clone();
        outside.address = 0x1030;
        outside.offset = 0x20;
        cases.push(outside);
        let mut wrong_offset = valid;
        wrong_offset.offset = 7;
        cases.push(wrong_offset);

        for invalid in cases {
            let error = SampledKernelSymbolOverlay::from_parts(
                identity(),
                vec![invalid.address],
                vec![invalid],
                Vec::new(),
            )
            .expect_err("invalid sampled range");
            assert!(matches!(error, KernelSymbolError::InvalidSymbol(_)));
        }
    }

    #[test]
    fn sampled_overlay_rejects_each_empty_identity_field() {
        for field in ["osversion", "version", "uuid", "machine", "bootsessionuuid"] {
            let mut invalid = identity();
            match field {
                "osversion" => invalid.osversion.clear(),
                "version" => invalid.version.clear(),
                "uuid" => invalid.uuid.clear(),
                "machine" => invalid.machine.clear(),
                "bootsessionuuid" => invalid.bootsessionuuid.clear(),
                _ => unreachable!(),
            }
            let error =
                SampledKernelSymbolOverlay::from_parts(invalid, Vec::new(), Vec::new(), Vec::new())
                    .expect_err(field);
            assert!(matches!(error, KernelSymbolError::InvalidIdentity(_)));
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
        let owned = own_symbol(
            0x1018,
            0,
            BorrowedSymbol {
                object: Some(b"kernel"),
                symbol: Some(&symbol_name),
                symbol_id: 9,
                symbol_start: 0x1010,
                symbol_size: 0x20,
            },
        )
        .expect("owned symbol");
        symbol_name.fill(b'z');
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
    fn zero_text_kernel_object_is_refined_once_before_symbol_lookup() {
        let provisional = provisional_object("mach_kernel", 1, 0);
        let mut queries = Vec::new();
        let objects = refine_kernel_objects(vec![provisional.clone()], |name| {
            queries.push(name.to_owned());
            Ok(ProvisionalObject {
                text_size: 0x1000,
                ..provisional.clone()
            })
        })
        .expect("refined kernel object");
        assert_eq!(queries, ["mach_kernel"]);
        assert_eq!(objects[0].text_size, 0x1000);
    }

    #[test]
    fn refinement_never_queries_nonzero_objects_and_rejects_ambiguous_names() {
        let published = provisional_object("already-sized", 1, 0x1000);
        let objects = refine_kernel_objects(vec![published.clone()], |_| {
            panic!("nonzero object must not be queried")
        })
        .expect("published object needs no query");
        assert_eq!(objects[0].name, published.name);

        let zero = provisional_object("mach_kernel", 1, 0);
        let nonzero = provisional_object("mach_kernel", 2, 0x1000);
        let error = refine_kernel_objects(vec![zero, nonzero], |_| {
            panic!("ambiguous name must be rejected before a query")
        })
        .expect_err("zero plus nonzero duplicate name is ambiguous");
        assert!(matches!(error, KernelSymbolError::InvalidObject(_)));
    }

    #[test]
    fn refinement_rejects_mismatched_records_and_unresolved_ranges() {
        let original = provisional_object("mach_kernel", 7, 0);
        let mut cases = Vec::new();
        let mut name = original.clone();
        name.name = "other".to_owned();
        cases.push(name);
        let mut id = original.clone();
        id.id += 1;
        cases.push(id);
        let mut flags = original.clone();
        flags.flags = 0;
        cases.push(flags);
        let mut file = original.clone();
        file.file = Some("/System/mach_kernel".to_owned());
        let mut known_file = original.clone();
        known_file.file = Some("/System/known".to_owned());
        let mut changed_known_file = known_file.clone();
        changed_known_file.file = Some("/System/other".to_owned());
        let mut text_start = original.clone();
        text_start.text_start += 1;
        cases.push(text_start);
        let mut data_start = original.clone();
        data_start.data_start += 1;
        cases.push(data_start);
        let mut data_size = original.clone();
        data_size.data_size += 1;
        cases.push(data_size);
        let mut bss_start = original.clone();
        bss_start.bss_start += 1;
        cases.push(bss_start);
        let mut bss_size = original.clone();
        bss_size.bss_size += 1;
        cases.push(bss_size);

        for mut resolved in cases {
            resolved.text_size = 0x1000;
            assert!(
                refine_kernel_objects(vec![original.clone()], |_| Ok(resolved.clone())).is_err()
            );
        }
        assert!(
            refine_kernel_objects(vec![known_file], |_| Ok(changed_known_file.clone())).is_err()
        );
        assert!(refine_kernel_objects(vec![original.clone()], |_| Ok(original.clone())).is_err());

        let mut enriched_file = original.clone();
        enriched_file.file = Some("/System/mach_kernel".to_owned());
        enriched_file.text_size = 0x1000;
        let enriched = refine_kernel_objects(vec![original.clone()], |_| Ok(enriched_file.clone()))
            .expect("unknown iterator file may be enriched by object-info");
        assert_eq!(enriched[0].file.as_deref(), Some("/System/mach_kernel"));

        let mut overflow = original.clone();
        overflow.text_start = u64::MAX;
        overflow.text_size = 1;
        assert!(refine_kernel_objects(vec![original], |_| Ok(overflow.clone())).is_err());
    }

    #[test]
    fn refinement_mismatch_diagnostics_name_every_changed_field_in_stable_order() {
        let mut original = provisional_object("mach_kernel", 7, 0);
        original.file = Some("/System/mach_kernel".to_owned());

        let mut resolved = original.clone();
        resolved.name = "other_kernel".to_owned();
        resolved.file = Some("/System/other_kernel".to_owned());
        resolved.id += 1;
        resolved.flags = 0;
        resolved.text_start += 1;
        resolved.data_start += 1;
        resolved.data_size += 1;
        resolved.bss_start += 1;
        resolved.bss_size += 1;
        let error = refine_kernel_objects(vec![original], |_| Ok(resolved.clone()))
            .expect_err("all changed fields must reject");
        assert_eq!(
            error.to_string(),
            "invalid kernel object: object-info mismatch for \"mach_kernel\": \
name, file, id, flags, kernel-bit, text-start, unresolved-text-size, \
data-start, data-size, bss-start, bss-size"
        );
    }

    #[test]
    fn refinement_mismatch_diagnostics_report_only_the_changed_fields() {
        let mut original = provisional_object("mach_kernel", 7, 0);
        original.file = Some("/System/mach_kernel".to_owned());
        let mut cases: Vec<(&str, ProvisionalObject)> = Vec::new();

        let mut name = original.clone();
        name.name = "other_kernel".to_owned();
        cases.push(("name", name));
        let mut file = original.clone();
        file.file = Some("/System/other_kernel".to_owned());
        cases.push(("file", file));
        let mut id = original.clone();
        id.id += 1;
        cases.push(("id", id));
        let mut flags = original.clone();
        flags.flags |= 0x2;
        cases.push(("flags", flags));
        let mut kernel_bit = original.clone();
        kernel_bit.flags = 0;
        cases.push(("flags, kernel-bit", kernel_bit));
        let mut text_start = original.clone();
        text_start.text_start += 1;
        cases.push(("text-start", text_start));
        let mut data_start = original.clone();
        data_start.data_start += 1;
        cases.push(("data-start", data_start));
        let mut data_size = original.clone();
        data_size.data_size += 1;
        cases.push(("data-size", data_size));
        let mut bss_start = original.clone();
        bss_start.bss_start += 1;
        cases.push(("bss-start", bss_start));
        let mut bss_size = original.clone();
        bss_size.bss_size += 1;
        cases.push(("bss-size", bss_size));

        for (expected_fields, mut resolved) in cases {
            resolved.text_size = 0x1000;
            let error = refine_kernel_objects(vec![original.clone()], |_| Ok(resolved.clone()))
                .expect_err("changed field must reject");
            assert_eq!(
                error.to_string(),
                format!(
                    "invalid kernel object: object-info mismatch for \"mach_kernel\": {expected_fields}"
                )
            );
        }

        let error = refine_kernel_objects(vec![original.clone()], |_| Ok(original.clone()))
            .expect_err("zero text must remain unresolved");
        assert_eq!(
            error.to_string(),
            "invalid kernel object: object-info mismatch for \"mach_kernel\": unresolved-text-size"
        );
    }

    #[test]
    fn refinement_mismatch_diagnostic_preserves_the_valid_none_file_policy() {
        let original = provisional_object("mach_kernel", 7, 0);
        let mut resolved = original.clone();
        resolved.file = Some("/System/mach_kernel".to_owned());
        resolved.text_size = 0x1000;
        let objects = refine_kernel_objects(vec![original], |_| Ok(resolved.clone()))
            .expect("an unknown iterator file may be enriched");
        assert_eq!(objects[0].file.as_deref(), Some("/System/mach_kernel"));
    }

    #[test]
    fn unresolved_text_runs_a_sorted_lookup_census_but_never_publishes() {
        let mut alpha = provisional_object("alpha", 2, 0x100);
        alpha.text_start = 0x2000;
        let objects = vec![provisional_object("mach_kernel", 1, 0), alpha];
        let requested = BTreeSet::from([0x1018, 0x2018]);
        let mut calls = Vec::new();
        let error = lookup_census(&objects, &requested, |address| {
            calls.push(address);
            let symbol = match address {
                0x1018 => symbol(0x1018, "mach_kernel", "startup", 0x1010, 0x20),
                0x2018 => symbol(0x2018, "alpha", "alpha_fn", 0x2010, 0x20),
                _ => unreachable!("requested set is fixed"),
            };
            let provenance = if address == 0x1018 {
                SymbolNameProvenance::Private
            } else {
                SymbolNameProvenance::Auxiliary
            };
            Ok(census_symbol(symbol, provenance))
        });
        assert_eq!(calls, [0x1018, 0x2018]);
        assert_eq!(
            error.to_string(),
            "kernel symbol lookup census passed but schema publication is disabled: \
requested=2, resolved=2, name-private-valid=1, name-aux-valid=1, \
objects=[\"alpha\", \"mach_kernel\"]"
        );
        assert!(!error.to_string().contains("0x"));
    }

    #[test]
    fn unresolved_text_census_skips_object_info_after_one_update_and_iteration() {
        let mut alpha = provisional_object("alpha", 2, 0x100);
        alpha.text_start = 0x2000;
        let mut source = MockSource {
            calls: Vec::new(),
            objects: vec![provisional_object("mach_kernel", 1, 0), alpha],
            resolutions: BTreeMap::new(),
            symbols: vec![
                symbol(0x1018, "mach_kernel", "startup", 0x1010, 0x20),
                symbol(0x2018, "alpha", "alpha_fn", 0x2010, 0x20),
            ],
        };
        let error = snapshot_with_source(&mut source, [0x2018, 0x1018, 0x2018])
            .expect_err("the census cannot publish a schema v1 snapshot");
        assert!(matches!(
            error,
            KernelSymbolError::LookupCensusPassed { .. }
        ));
        assert_eq!(
            source.calls,
            [
                "sysctl:kern.osversion",
                "sysctl:kern.version",
                "sysctl:kern.uuid",
                "sysctl:hw.machine",
                "sysctl:kern.bootsessionuuid",
                "update",
                "objects",
                "lookup:0x1018",
                "lookup:0x2018",
            ]
        );
    }

    #[test]
    fn census_trigger_matches_only_the_observed_mach_kernel_shape() {
        assert!(has_observed_unresolved_mach_kernel(&[provisional_object(
            "mach_kernel",
            1,
            0,
        )]));
        assert!(!has_observed_unresolved_mach_kernel(&[provisional_object(
            "other_kernel",
            1,
            0,
        )]));
        assert!(!has_observed_unresolved_mach_kernel(&[
            provisional_object("mach_kernel", 1, 0),
            provisional_object("other_kernel", 2, 0),
        ]));
        assert!(!has_observed_unresolved_mach_kernel(&[
            provisional_object("mach_kernel", 1, 0),
            provisional_object("mach_kernel", 2, 0x100),
        ]));
    }

    #[test]
    fn other_zero_text_kernel_object_still_refines_and_publishes() {
        let mut provisional = provisional_object("other_kernel", 1, 0);
        provisional.text_start = 0x1000;
        let resolved = ProvisionalObject {
            text_size: 0x100,
            ..provisional.clone()
        };
        let mut source = MockSource {
            calls: Vec::new(),
            objects: vec![provisional],
            resolutions: BTreeMap::from([("other_kernel".to_owned(), resolved)]),
            symbols: vec![symbol(0x1018, "other_kernel", "other_fn", 0x1010, 0x20)],
        };
        snapshot_with_source(&mut source, [0x1018])
            .expect("a non-mach zero range must retain object-info refinement");
        assert_eq!(
            source.calls,
            [
                "sysctl:kern.osversion",
                "sysctl:kern.version",
                "sysctl:kern.uuid",
                "sysctl:hw.machine",
                "sysctl:kern.bootsessionuuid",
                "update",
                "objects",
                "object-info:other_kernel",
                "lookup:0x1018",
            ]
        );
    }

    #[test]
    fn lookup_census_rejects_swapped_results_without_address_values() {
        let objects = vec![provisional_object("mach_kernel", 1, 0)];
        let requested = BTreeSet::from([0x1018, 0x2018]);
        let error = lookup_census(&objects, &requested, |requested| {
            let symbol = match requested {
                0x1018 => symbol(0x2018, "mach_kernel", "fn", 0x2010, 0x20),
                0x2018 => symbol(0x1018, "mach_kernel", "fn", 0x1010, 0x20),
                _ => unreachable!("requested set is fixed"),
            };
            Ok(census_symbol(symbol, SymbolNameProvenance::Private))
        });
        assert!(error.to_string().contains("address-set=2"));
        assert!(!error.to_string().contains("0x"));
    }

    #[test]
    fn lookup_census_reports_owner_duplicate_and_address_set_counts() {
        let objects = vec![provisional_object("mach_kernel", 1, 0)];
        let requested = BTreeSet::from([0x1018]);
        let error = lookup_census(&objects, &requested, |_| {
            Ok(census_symbol(
                symbol(0x1018, "missing", "fn", 0x1010, 0x20),
                SymbolNameProvenance::Private,
            ))
        });
        assert!(error.to_string().contains("owner=1"));

        let duplicate_identities = vec![
            provisional_object("mach_kernel", 1, 0),
            provisional_object("mach_kernel", 2, 0x100),
        ];
        let error = lookup_census(&duplicate_identities, &requested, |_| {
            Ok(census_symbol(
                symbol(0x1018, "mach_kernel", "fn", 0x1010, 0x20),
                SymbolNameProvenance::Private,
            ))
        });
        assert!(error.to_string().contains("owner=1"));
        assert!(!error.to_string().contains("0x"));

        let requested = BTreeSet::from([0x1018, 0x2018]);
        let error = lookup_census(&objects, &requested, |_| {
            Ok(census_symbol(
                symbol(0x1018, "mach_kernel", "fn", 0x1010, 0x20),
                SymbolNameProvenance::Private,
            ))
        });
        assert!(error.to_string().contains("duplicate=0"));
        assert!(error.to_string().contains("address-set=1"));

        let error = lookup_census(&objects, &requested, |address| {
            let symbol = match address {
                0x1018 => symbol(0x1018, "mach_kernel", "fn", 0x1010, 0x20),
                0x2018 => symbol(0x2019, "mach_kernel", "fn", 0x2010, 0x20),
                _ => unreachable!("requested set is fixed"),
            };
            Ok(census_symbol(symbol, SymbolNameProvenance::Private))
        });
        assert!(error.to_string().contains("address-set=1"));
        assert!(!error.to_string().contains("0x"));
    }

    #[test]
    fn census_failure_classes_come_from_actual_lookup_validation_sources() {
        let record = BorrowedSymbol {
            object: Some(b"mach_kernel"),
            symbol: Some(b"startup"),
            symbol_id: 1,
            symbol_start: 0x1010,
            symbol_size: 0x20,
        };
        assert_eq!(
            dtrace_lookup_status(0x1018, 1)
                .expect_err("status must classify")
                .class,
            CensusFailureClass::Status
        );
        assert_eq!(
            own_symbol_for_census(
                0x1018,
                BorrowedSymbol {
                    object: None,
                    ..record
                }
            )
            .expect_err("missing object must classify")
            .class,
            CensusFailureClass::Name
        );
        assert_eq!(
            own_symbol_for_census(
                0x1018,
                BorrowedSymbol {
                    symbol_size: 0,
                    ..record
                }
            )
            .expect_err("zero size must classify")
            .class,
            CensusFailureClass::ZeroOrOverflow
        );
        assert_eq!(
            own_symbol_for_census(0x1040, BorrowedSymbol { ..record })
                .expect_err("containment must classify")
                .class,
            CensusFailureClass::ContainmentOrOffset
        );
        let failures = [
            (
                "status",
                dtrace_lookup_status(0x1018, 1).expect_err("status must fail"),
            ),
            (
                "name-invalid",
                own_symbol_for_census(
                    0x1018,
                    BorrowedSymbol {
                        object: None,
                        ..record
                    },
                )
                .expect_err("missing object must fail"),
            ),
            (
                "zero-or-overflow",
                own_symbol_for_census(
                    0x1018,
                    BorrowedSymbol {
                        symbol_size: 0,
                        ..record
                    },
                )
                .expect_err("zero size must fail"),
            ),
            (
                "containment-or-offset",
                own_symbol_for_census(0x1040, BorrowedSymbol { ..record })
                    .expect_err("containment must fail"),
            ),
            (
                "unexpected",
                CensusLookupFailure::unexpected(KernelSymbolError::AddressMismatch(
                    "injected unexpected census failure".to_owned(),
                )),
            ),
        ];
        let objects = vec![provisional_object("mach_kernel", 1, 0)];
        let requested = BTreeSet::from([0x1018]);
        for (class, failure) in failures {
            let mut failure = Some(failure);
            let error = lookup_census(&objects, &requested, |_| {
                Err(failure
                    .take()
                    .expect("one requested address consumes one failure"))
            });
            let text = error.to_string();
            assert!(text.contains(&format!("{class}=1")));
            assert!(!text.contains("0x"));
            assert!(!text.contains("1018"));
        }
    }

    #[test]
    fn live_name_copy_accepts_bounded_private_and_aux_names_but_rejects_raw_fallback() {
        let auxiliary = vec![0xff_u8; 64];
        let mut private = b"private_symbol\0".to_vec();
        let (copied, provenance) = unsafe {
            copy_live_dtrace_name(private.as_ptr().cast(), auxiliary.as_slice())
                .expect("bounded persistent name")
        };
        private.fill(b'x');
        assert_eq!(copied, "private_symbol");
        assert_eq!(provenance, SymbolNameProvenance::Private);

        let auxiliary = b"aux_symbol\0".to_vec();
        let (copied, provenance) = unsafe {
            copy_live_dtrace_name(auxiliary.as_ptr().cast(), auxiliary.as_slice())
                .expect("a final-byte NUL is a complete auxiliary name")
        };
        assert_eq!(copied, "aux_symbol");
        assert_eq!(provenance, SymbolNameProvenance::Auxiliary);

        for raw in [b"0x01234567\0".as_slice(), b"0x0123456789abcdef\0"] {
            let auxiliary = raw.to_vec();
            let failure = unsafe { copy_live_dtrace_name(auxiliary.as_ptr().cast(), &auxiliary) }
                .expect_err("raw auxiliary address text is not symbol evidence");
            assert_eq!(failure.class, CensusFailureClass::RawAddressFallback);

            let private = raw.to_vec();
            let auxiliary = vec![0xff_u8; 64];
            let failure = unsafe { copy_live_dtrace_name(private.as_ptr().cast(), &auxiliary) }
                .expect_err("raw private address text is not symbol evidence");
            assert_eq!(failure.class, CensusFailureClass::RawAddressFallback);
        }

        let empty = b"\0";
        let invalid_utf8 = [0xff_u8, 0];
        let no_nul = vec![b'x'; PERSISTENT_SYMBOL_NAME_CAPACITY];
        for pointer in [
            std::ptr::null(),
            empty.as_ptr().cast(),
            invalid_utf8.as_ptr().cast(),
            no_nul.as_ptr().cast(),
        ] {
            let failure = unsafe { copy_live_dtrace_name(pointer, &auxiliary) }
                .expect_err("invalid private name must fail closed");
            assert_eq!(failure.class, CensusFailureClass::Name);
        }

        let auxiliary_without_nul = b"aux_without_nul".to_vec();
        let failure = unsafe {
            copy_live_dtrace_name(
                auxiliary_without_nul.as_ptr().cast(),
                &auxiliary_without_nul,
            )
        }
        .expect_err("unterminated auxiliary name must fail closed");
        assert_eq!(failure.class, CensusFailureClass::Name);
    }

    #[test]
    fn census_status_histogram_and_raw_fallback_are_aggregate_only() {
        let objects = vec![provisional_object("mach_kernel", 1, 0)];
        let requested = BTreeSet::from([0x1018]);
        let mut failure = Some(CensusLookupFailure::status(
            KernelSymbolError::Lookup {
                address: 0x1018,
                detail: "private status detail".to_owned(),
            },
            -1,
            123,
        ));
        let error = lookup_census(&objects, &requested, |_| {
            Err(failure.take().expect("one status result"))
        });
        let text = error.to_string();
        assert!(text.contains("requested=1, resolved=0, status=1"));
        assert!(text.contains("status-histogram=[(-1, 123, 1)]"));
        assert!(!text.contains("0x"));
        assert!(!text.contains("private status detail"));

        let raw = b"0x0123456789abcdef\0".to_vec();
        let mut failure = Some(
            unsafe { copy_live_dtrace_name(raw.as_ptr().cast(), raw.as_slice()) }
                .expect_err("raw fallback must classify"),
        );
        let error = lookup_census(&objects, &requested, |_| {
            Err(failure.take().expect("one raw fallback result"))
        });
        let text = error.to_string();
        assert!(text.contains("raw-address-fallback=1"));
        assert!(!text.contains("0x0123456789abcdef"));

        let requested = BTreeSet::from([0x1018, 0x2018, 0x3018]);
        let error = lookup_census(&objects, &requested, |address| match address {
            0x1018 => Err(CensusLookupFailure::status(
                KernelSymbolError::Lookup {
                    address,
                    detail: "first private status detail".to_owned(),
                },
                -1,
                456,
            )),
            0x2018 => Ok(census_symbol(
                symbol(address, "mach_kernel", "fn", 0x2010, 0x20),
                SymbolNameProvenance::Private,
            )),
            0x3018 => Err(CensusLookupFailure::status(
                KernelSymbolError::Lookup {
                    address,
                    detail: "second private status detail".to_owned(),
                },
                -1,
                123,
            )),
            _ => unreachable!("requested set is fixed"),
        });
        let text = error.to_string();
        assert!(text.contains("requested=3, resolved=1, status=2"));
        assert!(text.contains("status-histogram=[(-1, 123, 1), (-1, 456, 1)]"));
        assert!(text.contains("name-private-valid=1, name-aux-valid=0"));
        assert!(text.contains("accounting=0"));
        assert!(!text.contains("0x"));
    }

    #[test]
    fn census_aggregate_reconciliation_detects_internal_drift() {
        let counts = LookupCensusCounts {
            status: 1,
            ..LookupCensusCounts::default()
        };
        assert!(counts.into_error(1, 0).to_string().contains("accounting=1"));
    }

    #[test]
    fn object_info_status_does_not_decode_poisoned_output_and_copies_buffers() {
        let poisoned = DtraceObjInfo {
            dto_name: std::ptr::NonNull::<c_char>::dangling().as_ptr(),
            dto_file: std::ptr::NonNull::<c_char>::dangling().as_ptr(),
            dto_id: 1,
            dto_flags: DTRACE_OBJ_F_KERNEL,
            dto_text_va: 0,
            dto_text_size: 0,
            dto_data_va: 0,
            dto_data_size: 0,
            dto_bss_va: 0,
            dto_bss_size: 0,
        };
        assert!(finish_object_info("mach_kernel", 1, &poisoned).is_err());

        let mut name = b"mach_kernel\0".to_vec();
        let mut file = b"/System/mach_kernel\0".to_vec();
        let info = DtraceObjInfo {
            dto_name: name.as_ptr().cast(),
            dto_file: file.as_ptr().cast(),
            dto_id: 1,
            dto_flags: DTRACE_OBJ_F_KERNEL,
            dto_text_va: 0x1000,
            dto_text_size: 0,
            dto_data_va: 0,
            dto_data_size: 0,
            dto_bss_va: 0,
            dto_bss_size: 0,
        };
        let copied = finish_object_info("mach_kernel", 0, &info).expect("copy object-info");
        name.fill(b'x');
        file.fill(b'y');
        assert_eq!(copied.name, "mach_kernel");
        assert_eq!(copied.file.as_deref(), Some("/System/mach_kernel"));
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
    fn borrowed_conversion_rejects_bad_strings_ranges_and_lookup_results() {
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
                },
            ),
        ];
        for (address, status, record) in symbol_cases {
            assert!(own_symbol(address, status, record).is_err());
        }
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
                "sysctl:kern.bootsessionuuid",
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
    fn resolver_preserves_nonzero_object_publication_before_lookups() {
        let mut alpha = provisional_object("alpha", 2, 0x100);
        alpha.text_start = 0x1000;
        let mut zeta = provisional_object("zeta", 1, 0x100);
        zeta.text_start = 0x2000;
        let resolved_alpha = alpha.clone();
        let resolved_zeta = zeta.clone();
        let mut source = MockSource {
            calls: Vec::new(),
            objects: vec![zeta, alpha],
            resolutions: [
                ("alpha".to_owned(), resolved_alpha),
                ("zeta".to_owned(), resolved_zeta),
            ]
            .into_iter()
            .collect(),
            symbols: vec![
                symbol(0x1018, "alpha", "alpha_fn", 0x1010, 0x20),
                symbol(0x2018, "zeta", "zeta_fn", 0x2010, 0x20),
            ],
        };
        snapshot_with_source(&mut source, [0x2018, 0x1018]).expect("published snapshot");
        assert_eq!(
            source.calls,
            [
                "sysctl:kern.osversion",
                "sysctl:kern.version",
                "sysctl:kern.uuid",
                "sysctl:hw.machine",
                "sysctl:kern.bootsessionuuid",
                "update",
                "objects",
                "lookup:0x1018",
                "lookup:0x2018",
            ]
        );
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

    enum OverlayLookup {
        Resolved(KernelSymbolRange),
        Status(c_int, c_int),
    }

    struct OverlaySource {
        calls: Vec<String>,
        lookups: BTreeMap<u64, OverlayLookup>,
    }

    impl OverlaySource {
        fn new(lookups: impl IntoIterator<Item = (u64, OverlayLookup)>) -> Self {
            Self {
                calls: Vec::new(),
                lookups: lookups.into_iter().collect(),
            }
        }
    }

    impl SymbolSource for OverlaySource {
        fn sysctl(&mut self, name: &'static str) -> Result<Vec<u8>, KernelSymbolError> {
            self.calls.push(format!("sysctl:{name}"));
            let value = match name {
                "kern.osversion" => b"26A5388g\0".as_slice(),
                "kern.version" => b"Darwin Kernel Version 26.0.0\0".as_slice(),
                "kern.uuid" => b"01234567-89AB-CDEF-0123-456789ABCDEF\0".as_slice(),
                "hw.machine" => b"arm64\0".as_slice(),
                "kern.bootsessionuuid" => b"FEDCBA98-7654-3210-FEDC-BA9876543210\0".as_slice(),
                _ => return Err(KernelSymbolError::InvalidIdentity(name.to_owned())),
            };
            Ok(value.to_vec())
        }

        fn update(&mut self) -> Result<(), KernelSymbolError> {
            self.calls.push("update".to_owned());
            Ok(())
        }

        fn objects(&mut self) -> Result<Vec<ProvisionalObject>, KernelSymbolError> {
            Err(KernelSymbolError::ObjectIteration(
                "sampled overlay must not iterate objects".to_owned(),
            ))
        }

        fn object_info(&mut self, _name: &str) -> Result<ProvisionalObject, KernelSymbolError> {
            Err(KernelSymbolError::ObjectIteration(
                "sampled overlay must not query object info".to_owned(),
            ))
        }

        fn lookup(&mut self, address: u64) -> Result<KernelSymbolRange, KernelSymbolError> {
            Err(KernelSymbolError::Lookup {
                address,
                detail: "sampled overlay must use census lookup".to_owned(),
            })
        }

        fn census_lookup(
            &mut self,
            address: u64,
        ) -> Result<CensusLookupOutcome, CensusLookupFailure> {
            self.calls.push(format!("census:{address:#x}"));
            match self.lookups.get(&address) {
                Some(OverlayLookup::Resolved(symbol)) => Ok(CensusLookupOutcome {
                    symbol: symbol.clone(),
                    name_provenance: SymbolNameProvenance::Private,
                }),
                Some(OverlayLookup::Status(status, errno)) => Err(CensusLookupFailure::status(
                    KernelSymbolError::Lookup {
                        address,
                        detail: format!(
                            "libdtrace returned status {status} with dtrace errno {errno}"
                        ),
                    },
                    *status,
                    *errno,
                )),
                None => Err(CensusLookupFailure::unexpected(KernelSymbolError::Lookup {
                    address,
                    detail: "missing overlay mock lookup".to_owned(),
                })),
            }
        }
    }

    struct MockSource {
        calls: Vec<String>,
        objects: Vec<ProvisionalObject>,
        resolutions: BTreeMap<String, ProvisionalObject>,
        symbols: Vec<KernelSymbolRange>,
    }

    impl MockSource {
        fn valid() -> Self {
            let mut driver = provisional_object("com.apple.driver", 2, 0x100);
            driver.text_start = 0x2000;
            let kernel = provisional_object("kernel", 1, 0x100);
            let objects = vec![driver, kernel];
            Self {
                calls: Vec::new(),
                resolutions: objects
                    .iter()
                    .cloned()
                    .map(|object| (object.name.clone(), object))
                    .collect(),
                objects,
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
                "kern.bootsessionuuid" => b"FEDCBA98-7654-3210-FEDC-BA9876543210\0".as_slice(),
                _ => return Err(KernelSymbolError::InvalidIdentity(name.to_owned())),
            };
            Ok(value.to_vec())
        }

        fn update(&mut self) -> Result<(), KernelSymbolError> {
            self.calls.push("update".to_owned());
            Ok(())
        }

        fn objects(&mut self) -> Result<Vec<ProvisionalObject>, KernelSymbolError> {
            self.calls.push("objects".to_owned());
            Ok(self.objects.clone())
        }

        fn object_info(&mut self, name: &str) -> Result<ProvisionalObject, KernelSymbolError> {
            self.calls.push(format!("object-info:{name}"));
            self.resolutions.get(name).cloned().ok_or_else(|| {
                KernelSymbolError::InvalidObject(format!("missing mock object {name:?}"))
            })
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

        fn census_lookup(
            &mut self,
            address: u64,
        ) -> Result<CensusLookupOutcome, CensusLookupFailure> {
            self.lookup(address)
                .map(|symbol| CensusLookupOutcome {
                    symbol,
                    name_provenance: SymbolNameProvenance::Private,
                })
                .map_err(|error| CensusLookupFailure::status(error, -1, 0))
        }
    }
}
