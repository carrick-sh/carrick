//! Setting the host process title on macOS, the way libuv/Node do it.
//!
//! Three surfaces, three mechanisms:
//!   * `ps` COMMAND column — overwrite argv[0] in place (handled in
//!     `dispatch::set_host_process_name` via `_NSGetArgv`).
//!   * lldb / Instruments / sample / crash reports — `pthread_setname_np`
//!     (also in `dispatch::set_host_process_name`).
//!   * Activity Monitor's process name — this module. Activity Monitor
//!     reads the LaunchServices "display name", which is set through
//!     PRIVATE LaunchServices functions resolved at runtime from the
//!     `com.apple.LaunchServices` bundle (exactly what
//!     `src/unix/darwin-proctitle.c` in libuv does).
//!
//! Everything here is best-effort and heavily guarded: any missing
//! symbol, null pointer, or non-GUI session leaves the process title
//! unchanged rather than crashing. carrick is a CLI tool, so the
//! LaunchServices check-in may legitimately do nothing; that's fine.

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::bundle::{
    CFBundleGetBundleWithIdentifier, CFBundleGetDataPointerForName,
    CFBundleGetFunctionPointerForName, CFBundleRef,
};
use core_foundation_sys::string::{
    kCFStringEncodingUTF8, CFStringCreateWithCString, CFStringRef,
};

// Private LaunchServices signatures, as used by libuv. The ASN
// ("Application Serial Number") is an opaque CFType-like handle.
type LSGetCurrentApplicationAsnFn = unsafe extern "C" fn() -> CFTypeRef;
type LSSetApplicationInformationItemFn = unsafe extern "C" fn(
    c_int,      // session id (libuv passes -2)
    CFTypeRef,  // app ASN
    CFStringRef, // key (_kLSDisplayNameKey)
    CFStringRef, // value (our title)
    *mut c_void, // out dict (NULL)
) -> c_int;

struct LaunchServices {
    get_asn: LSGetCurrentApplicationAsnFn,
    set_info: LSSetApplicationInformationItemFn,
    display_name_key: CFStringRef,
}

// SAFETY: the function pointers + the static display-name-key CFString
// are process-global and immutable for the program's lifetime.
unsafe impl Send for LaunchServices {}
unsafe impl Sync for LaunchServices {}

fn launch_services() -> Option<&'static LaunchServices> {
    static LS: OnceLock<Option<LaunchServices>> = OnceLock::new();
    LS.get_or_init(|| unsafe { resolve_launch_services() }).as_ref()
}

unsafe fn cfstr(s: &str) -> CFStringRef {
    let c = std::ffi::CString::new(s).unwrap_or_default();
    CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), kCFStringEncodingUTF8)
}

unsafe fn resolve_launch_services() -> Option<LaunchServices> {
    let ident = cfstr("com.apple.LaunchServices");
    if ident.is_null() {
        return None;
    }
    let bundle: CFBundleRef = CFBundleGetBundleWithIdentifier(ident);
    CFRelease(ident as CFTypeRef);
    if bundle.is_null() {
        return None;
    }

    let get_asn_name = cfstr("_LSGetCurrentApplicationASN");
    let set_info_name = cfstr("_LSSetApplicationInformationItem");
    let key_name = cfstr("_kLSDisplayNameKey");
    let result = (|| {
        if get_asn_name.is_null() || set_info_name.is_null() || key_name.is_null() {
            return None;
        }
        let get_asn = CFBundleGetFunctionPointerForName(bundle, get_asn_name);
        let set_info = CFBundleGetFunctionPointerForName(bundle, set_info_name);
        // The key is a `CFStringRef*` data symbol; deref once.
        let key_ptr = CFBundleGetDataPointerForName(bundle, key_name) as *const CFStringRef;
        if get_asn.is_null() || set_info.is_null() || key_ptr.is_null() {
            return None;
        }
        let display_name_key = *key_ptr;
        if display_name_key.is_null() {
            return None;
        }
        Some(LaunchServices {
            get_asn: std::mem::transmute::<*const c_void, LSGetCurrentApplicationAsnFn>(get_asn),
            set_info: std::mem::transmute::<
                *const c_void,
                LSSetApplicationInformationItemFn,
            >(set_info),
            display_name_key,
        })
    })();
    if !get_asn_name.is_null() {
        CFRelease(get_asn_name as CFTypeRef);
    }
    if !set_info_name.is_null() {
        CFRelease(set_info_name as CFTypeRef);
    }
    if !key_name.is_null() {
        CFRelease(key_name as CFTypeRef);
    }
    result
}

/// Set the Activity-Monitor-visible display name to `title`.
/// Best-effort: silently does nothing if LaunchServices private
/// symbols can't be resolved or there's no application ASN.
pub fn set_activity_monitor_name(title: &str) {
    let Some(ls) = launch_services() else {
        return;
    };
    unsafe {
        let asn = (ls.get_asn)();
        if asn.is_null() {
            return;
        }
        let cf_title = cfstr(title);
        if cf_title.is_null() {
            return;
        }
        // session id -2 == kLSDefaultSessionID, per libuv.
        (ls.set_info)(-2, asn, ls.display_name_key, cf_title, std::ptr::null_mut());
        CFRelease(cf_title as CFTypeRef);
    }
}

// Re-export the c_char type so callers don't need a separate import.
#[allow(unused)]
type _Char = c_char;
