//! Experimental physical-register envelope; no guest TLS, async signals or DSR translation.
use std::ffi::c_void;
std::arch::global_asm!(include_str!("gateway.S"));
unsafe extern "C" {
    fn floor_gateway(
        context: *mut c_void,
        callback: unsafe extern "C" fn(*mut c_void) -> i64,
        stack: *mut u8,
    ) -> i64;
    fn floor_gateway_oracle(
        context: *mut c_void,
        callback: unsafe extern "C" fn(*mut c_void) -> i64,
        stack: *mut u8,
        snapshots: *mut u8,
    );
    fn floor_clobber(context: *mut c_void) -> i64;
}

pub struct GatewayStack {
    storage: Vec<u128>,
}
impl GatewayStack {
    pub fn new() -> Self {
        Self {
            storage: vec![0; 65536],
        }
    }
    fn top(&mut self) -> *mut u8 {
        self.storage
            .as_mut_ptr()
            .wrapping_add(self.storage.len())
            .cast()
    }
    pub fn verify(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshots = [0_u128; 100];
        // SAFETY: assembly writes exactly two 800-byte snapshots; callback obeys native ABI.
        unsafe {
            floor_gateway_oracle(
                std::ptr::null_mut(),
                floor_clobber,
                self.top(),
                snapshots.as_mut_ptr().cast(),
            );
        }
        let bytes = unsafe { std::slice::from_raw_parts(snapshots.as_ptr().cast::<u8>(), 1600) };
        let mut bad = Vec::new();
        for (name, start, len) in (1..30)
            .filter(|i| *i != 3)
            .map(|i| (format!("x{i}"), i * 8, 8))
            .chain([(String::from("NZCV/FPSR/FPCR/SP"), 248, 32)])
            .chain((0..32).map(|i| (format!("q{i}"), 288 + i * 16, 16)))
        {
            if bytes[start..start + len] != bytes[800 + start..800 + start + len] {
                bad.push(name);
            }
        }
        let retval = u64::from_ne_bytes(bytes[800..808].try_into()?);
        let before_x3 = u64::from_ne_bytes(bytes[24..32].try_into()?);
        let after_x3 = u64::from_ne_bytes(bytes[824..832].try_into()?);
        if after_x3 != before_x3 + 800 {
            bad.push(String::from("x3"));
        }
        if retval != 77 {
            bad.push(String::from("return value"));
        }
        if !bad.is_empty() {
            return Err(format!("gateway preservation failed: {bad:?}").into());
        }
        let low = self.storage.as_ptr() as usize;
        let high = self.top() as usize;
        let mut observed = 0_usize;
        self.invoke(true, &mut || { unsafe { std::arch::asm!("mov {}, sp", out(reg) observed, options(nomem, nostack, preserves_flags)); } 0 });
        if !(low..high).contains(&observed) {
            return Err("callback did not use alternate stack".into());
        }
        Ok(())
    }
    pub fn invoke<F: FnMut() -> i64>(&mut self, gateway: bool, call: &mut F) -> i64 {
        #[inline(never)]
        unsafe extern "C" fn callback<F: FnMut() -> i64>(context: *mut c_void) -> i64 {
            // SAFETY: invoke lends exclusive F for this synchronous call only.
            unsafe { (&mut *context.cast::<F>())() }
        }
        let context = std::ptr::from_mut(call).cast::<c_void>();
        let callback =
            std::hint::black_box(callback::<F> as unsafe extern "C" fn(*mut c_void) -> i64);
        // SAFETY: stack is aligned, disjoint, resident; no unwinding or asynchronous switching supported.
        unsafe {
            if gateway {
                floor_gateway(context, callback, self.top())
            } else {
                callback(context)
            }
        }
    }
}
