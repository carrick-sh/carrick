//! macOS/AArch64 JIT transport. No guest VA is used as a native SP or pointer.
use crate::{Image, Instruction, Memory, branch_target, classify};
use anyhow::{Result, ensure};
use std::{ffi::c_void, marker::PhantomData, rc::Rc};

#[repr(C, align(16))]
pub struct State {
    pub x: [u64; 31],
    pub pc: u64,
    pub nzcv: u64,
    pub fpsr: u64,
    pub fpcr: u64,
    pub sp: u64,
    pub tls: u64,
    pad: u64,
    pub vectors: [u128; 32],
    user: *mut c_void,
    callback: unsafe extern "C" fn(*mut State, *mut c_void) -> usize,
    gateway: usize,
    resume: usize,
    backedge_budget: u64,
    data_guest_base: u64,
    data_last_eight: u64,
    data_host_base: *mut u8,
    memory_nzcv: u64,
}
impl State {
    pub fn new(pc: u64) -> Self {
        unsafe extern "C" fn no_callback(_: *mut State, _: *mut c_void) -> usize {
            0
        }
        Self {
            x: [0; 31],
            pc,
            nzcv: 0,
            fpsr: 0,
            fpcr: 0,
            sp: 0,
            tls: 0,
            pad: 0,
            vectors: [0; 32],
            user: std::ptr::null_mut(),
            callback: no_callback,
            gateway: 0,
            resume: 0,
            backedge_budget: 256,
            data_guest_base: 0,
            data_last_eight: 0,
            data_host_base: std::ptr::null_mut(),
            memory_nzcv: 0,
        }
    }
}
const _: () = {
    assert!(std::mem::offset_of!(State, pc) == 248);
    assert!(std::mem::offset_of!(State, vectors) == 304);
    assert!(std::mem::offset_of!(State, user) == 816);
    assert!(std::mem::offset_of!(State, gateway) == 832);
    assert!(std::mem::offset_of!(State, backedge_budget) == 848);
    assert!(std::mem::offset_of!(State, data_guest_base) == 856);
    assert!(std::mem::offset_of!(State, data_last_eight) == 864);
    assert!(std::mem::offset_of!(State, data_host_base) == 872);
    assert!(std::mem::offset_of!(State, memory_nzcv) == 880);
};

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("this diagnostic execution slice requires macOS AArch64");
std::arch::global_asm!(include_str!("gateway.S"));
unsafe extern "C" {
    fn slice_enter(state: *mut State, entry: usize);
    fn slice_gateway();
    fn pthread_jit_write_protect_np(enabled: libc::c_int);
    fn pthread_jit_write_protect_supported_np() -> libc::c_int;
    fn sys_icache_invalidate(address: *mut c_void, length: usize);
}

const SLOT: usize = 64;
// All encodings here are authored for the whitelisted unsigned scalar form.
fn load_state(r: u32, offset: u32) -> u32 {
    0xf9400000 | ((offset / 8) << 10) | (28 << 5) | r
}
fn store_state(r: u32, offset: u32) -> u32 {
    0xf9000000 | ((offset / 8) << 10) | (28 << 5) | r
}
fn branch(from: usize, to: usize) -> u32 {
    let delta = to as i64 - from as i64;
    // <=4096 instructions and bounded stubs are far inside B's signed range.
    assert!((-33554432..33554432).contains(&delta));
    0x14000000 | ((delta as u32) & 0x3ffffff)
}
fn restore_memory_scratch(words: &mut Vec<u32>) {
    words.extend([load_state(16, 880), 0xd51b4210, load_state(16, 128)]);
}
/// Native work is constant per access, independent of the mapping population.
/// Misses restore guest scratch/flags before the existing semantic callback.
fn emit_memory(words: &mut Vec<u32>, w: u32, slow: usize, next: usize) {
    let rn = (w >> 5) & 31;
    let rt = w & 31;
    let width = 1 << (w >> 30);
    let offset = ((w >> 10) & 4095) * width;
    let load = w & (1 << 22) != 0;
    // x17 already lives in its authoritative snapshot; only x16 needs saving.
    words.extend([store_state(16, 128), 0xd53b4210, store_state(16, 880)]);
    words.push(match rn {
        16 | 17 | 18 | 28 => load_state(17, rn * 8),
        31 => load_state(17, 280),    // virtual guest SP
        _ => 0xaa0003f1 | (rn << 16), // mov x17,xN
    });
    if offset & 4095 != 0 {
        words.push(0x91000231 | ((offset & 4095) << 10));
    }
    if offset >> 12 != 0 {
        words.push(0x91400231 | ((offset >> 12) << 10));
    }
    words.extend([
        load_state(16, 856),
        0xcb100231, // sub x17,x17,x16; underflow compares as out of bounds
        load_state(16, 864),
    ]);
    if width == 4 {
        words.push(0x91001210); // add x16,x16,#4; last valid 4-byte start
    }
    words.push(0xeb10023f); // cmp x17,x16: complete access, not just first byte
    let miss = words.len();
    words.push(0); // b.hi miss
    words.extend([load_state(16, 872), 0x8b110211]); // add x17,x16,x17
    let virtual_rt = matches!(rt, 16 | 17 | 18 | 28);
    if !load && virtual_rt {
        words.push(load_state(16, rt * 8));
    }
    words.push((w & !0x3fffff) | (w & (1 << 22)) | (17 << 5) | if virtual_rt { 16 } else { rt });
    if load && virtual_rt {
        words.push(store_state(16, rt * 8));
    }
    restore_memory_scratch(words);
    words.push(branch(words.len(), next));
    let target = words.len();
    words[miss] = 0x54000008 | (((target - miss) as u32) << 5);
    restore_memory_scratch(words);
    words.push(branch(words.len(), slow));
}
/// Least fixed point of memory reachability before a carrier checkpoint.
/// Both conditional successors count, including backedges. Barriers are exactly
/// the instructions which unconditionally return from the carrier invocation;
/// an unknown instruction or branch target is an error, never a data-free proof.
fn data_demand(image: &Image) -> Result<Vec<bool>> {
    let count = image.words.len();
    let mut predecessors = vec![Vec::new(); count + 1];
    let mut required = vec![false; count + 1];
    let mut pending = Vec::new();
    for (i, &word) in image.words.iter().enumerate() {
        match classify(word).map_err(anyhow::Error::msg)? {
            Instruction::Memory => {
                required[i] = true;
                pending.push(i);
            }
            Instruction::Syscall | Instruction::Tls => {}
            Instruction::Address if matches!(word & 31, 18 | 28) => {}
            Instruction::Branch => {
                let target = branch_target(word, image.base + i as u64 * 4);
                ensure!(
                    target >= image.base
                        && target < image.base + count as u64 * 4
                        && target.is_multiple_of(4),
                    "branch outside executable authority"
                );
                predecessors[((target - image.base) / 4) as usize].push(i);
                if word & 0x7c000000 != 0x14000000 {
                    predecessors[i + 1].push(i);
                }
            }
            Instruction::Integer | Instruction::Address => predecessors[i + 1].push(i),
        }
    }
    while let Some(i) = pending.pop() {
        for &predecessor in &predecessors[i] {
            if !required[predecessor] {
                required[predecessor] = true;
                pending.push(predecessor);
            }
        }
    }
    Ok(required)
}

pub struct Code {
    ptr: *mut u8,
    length: usize,
    base: u64,
    count: usize,
    data_demand: Vec<bool>,
    identity: std::sync::Arc<()>,
    epoch: u64,
    // Index and shape only: Code never retains a backing pointer across runs.
    data_region: Option<(usize, u64, usize)>,
    // W^X toggling/execution is confined to the owning host thread.
    _thread: PhantomData<Rc<()>>,
}
impl Code {
    pub fn publish(image: &Image, memory: &Memory) -> Result<Self> {
        memory.validate(image)?;
        ensure!(image.words.len() <= 4096, "bounded executor code limit");
        let data_demand = data_demand(image)?;
        // One bounded data-region cache. Other mappings use checked emulation.
        // Former executable backing cannot bypass write-generation revocation.
        let data_region = memory.segments.iter().enumerate().find_map(|(n, s)| {
            (s.flags == 6 && !s.ever_executable && s.bytes.len() >= 8).then_some((
                n,
                s.base,
                s.bytes.len(),
            ))
        });
        let mut words = vec![0xd503201f_u32; image.words.len() * SLOT / 4 + SLOT / 4];
        // Terminal fallthrough always enters the checked callback and fails.
        for i in 0..=image.words.len() {
            let at = i * SLOT / 4;
            words[at] = 0xf9400000 | (17 << 10) | (28 << 5) | 17;
            let pc = image.base + i as u64 * 4;
            let instruction = image.words.get(i).copied();
            if let Some(w) = instruction {
                let kind = classify(w).map_err(anyhow::Error::msg)?;
                if kind == Instruction::Integer {
                    words[at + 1] = w;
                    words[at + 2] = 0xf9000000 | (17 << 10) | (28 << 5) | 17;
                    words[at + 3] = 0x1400000d;
                    continue;
                }
                if kind == Instruction::Address {
                    let rd = w & 31;
                    if rd != 18 && rd != 28 {
                        let raw = ((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)) << 11;
                        let imm = (raw as i32 >> 11) as i64;
                        let value = if w >> 31 == 0 {
                            pc.wrapping_add_signed(imm)
                        } else {
                            (pc & !4095).wrapping_add_signed(imm << 12)
                        };
                        words[at + 1] = 0xd2800000 | (((value & 65535) as u32) << 5) | rd;
                        for half in 1..4 {
                            words[at + 1 + half] = 0xf2800000
                                | ((half as u32) << 21)
                                | ((((value >> (half * 16)) & 65535) as u32) << 5)
                                | rd;
                        }
                        if rd == 17 {
                            words[at + 5] = 0xf9000000 | (17 << 10) | (28 << 5) | 17;
                        }
                        words[at + 6] = 0x1400000a;
                        continue;
                    }
                }
                if kind == Instruction::Branch {
                    let target = branch_target(w, pc);
                    ensure!(
                        target >= image.base
                            && target < image.base + image.words.len() as u64 * 4
                            && target.is_multiple_of(4),
                        "branch outside executable authority"
                    );
                    // Forward edges remain native. Every backward edge checkpoints.
                    if target > pc {
                        let delta = (target - pc) / 4 * SLOT as u64 / 4 - 1;
                        words[at + 1] = if w & 0x7c000000 == 0x14000000 {
                            ensure!(delta < 1 << 25, "branch range");
                            (w & 0xfc000000) | delta as u32
                        } else {
                            ensure!(delta < 1 << 18, "conditional range");
                            (w & !0xffffe0) | ((delta as u32) << 5)
                        };
                        words[at + 2] = 0x1400000e;
                        continue;
                    }
                    // A fixed native decrement keeps all backward edges bounded.
                    // SVC/other callbacks also check cancellation and reset it.
                    // Thus 256 edges is a maximum interval, never a polling wait.
                    words[at + 1] = 0xf9400000 | (106 << 10) | (28 << 5) | 17;
                    words[at + 2] = 0xd1000000 | (1 << 10) | (17 << 5) | 17;
                    words[at + 3] = 0xf9000000 | (106 << 10) | (28 << 5) | 17;
                    words[at + 4] = 0xb4000000 | (5 << 5) | 17;
                    words[at + 5] = 0xf9400000 | (17 << 10) | (28 << 5) | 17;
                    let delta = (target as i64 - pc as i64) / 4 * (SLOT / 4) as i64 - 6;
                    words[at + 6] = if w & 0x7c000000 == 0x14000000 {
                        ensure!((-33554432..33554432).contains(&delta), "branch range");
                        (w & 0xfc000000) | ((delta as u32) & 0x3ffffff)
                    } else {
                        ensure!((-262144..262144).contains(&delta), "conditional range");
                        (w & !0xffffe0) | (((delta as u32) & 0x7ffff) << 5)
                    };
                    words[at + 7] = 0x14000009;
                    words[at + 9] = 0xd2800000 | (((pc & 65535) as u32) << 5) | 17;
                    for half in 1..4 {
                        words[at + 9 + half] = 0xf2800000
                            | ((half as u32) << 21)
                            | ((((pc >> (half * 16)) & 65535) as u32) << 5)
                            | 17;
                    }
                    words[at + 13] = 0xf9000000 | (31 << 10) | (28 << 5) | 17;
                    words[at + 14] = 0xf9400000 | (104 << 10) | (28 << 5) | 17;
                    words[at + 15] = 0xd61f0220;
                    continue;
                }
            }
            // Save guest x17 before using it to identify the semantic guest PC.
            words[at + 1] = 0xf9000000 | (17 << 10) | (28 << 5) | 17;
            words[at + 2] = 0xd2800000 | (((pc & 65535) as u32) << 5) | 17;
            for half in 1..4 {
                words[at + 2 + half] = 0xf2800000
                    | ((half as u32) << 21)
                    | ((((pc >> (half * 16)) & 65535) as u32) << 5)
                    | 17;
            }
            words[at + 6] = 0xf9000000 | (31 << 10) | (28 << 5) | 17;
            words[at + 7] = 0xf9400000 | (104 << 10) | (28 << 5) | 17;
            words[at + 8] = 0xd61f0220; // br x17 into the private gateway only
            if let Some(w) = instruction
                && classify(w).map_err(anyhow::Error::msg)? == Instruction::Memory
                && data_region.is_some()
            {
                let stub = words.len();
                words[at + 1] = branch(at + 1, stub);
                emit_memory(&mut words, w, at + 2, at + SLOT / 4);
            }
        }
        ensure!(
            unsafe { pthread_jit_write_protect_supported_np() } != 0,
            "JIT W^X unsupported"
        );
        let length = (words.len() * 4 + 16383) & !16383;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        ensure!(
            ptr != libc::MAP_FAILED,
            "JIT mmap: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: fresh private region, no execution/pointers published yet;
        // the one owner switches to RX and flushes before constructing Code.
        unsafe {
            pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(words.as_ptr().cast::<u8>(), ptr.cast(), words.len() * 4);
            pthread_jit_write_protect_np(1);
            sys_icache_invalidate(ptr, length);
        }
        Ok(Self {
            ptr: ptr.cast(),
            length,
            base: image.base,
            count: image.words.len(),
            data_demand,
            identity: image.identity.clone(),
            epoch: image.epoch,
            data_region,
            _thread: PhantomData,
        })
    }
    /// Research adapter. The returned count records an actual successful data
    /// activation, allowing the interval's demand contract to observe real work.
    pub fn run_scoped_carrier_until_checkpoint(
        &self,
        image: &Image,
        memory: &Memory,
        prepared: &mut carrick_kernel::kernel::mm_access::PreparedNativeData,
        scope: &carrick_kernel::dispatch::native_execution::NativeExecution<'_>,
        state: &mut State,
        force_data: bool,
    ) -> Result<bool> {
        if force_data || self.requires_native_data(state.pc)? {
            let mut data = prepared.activate(scope)?;
            self.run_carrier_until_checkpoint(image, memory, &mut data, state)?;
            return Ok(true);
        }
        ensure!(!scope.stop_requested(), "native control pending");
        ensure!(state.user.is_null(), "native State is already executing");
        memory.validate(image)?;
        ensure!(
            std::sync::Arc::ptr_eq(&self.identity, &image.identity) && self.epoch == image.epoch,
            "wrong executable publication"
        );
        let entry = self.address(state.pc)?;
        // No carrier or ELF data pointer is installed. The immutable publication
        // proves every path from this PC reaches a checkpoint before memory.
        state.data_host_base = std::ptr::null_mut();
        state.data_guest_base = 0;
        state.data_last_eight = 0;
        // SAFETY: the exact running scope outlives entry; the private executable
        // publication is current; its conservative graph excludes all native
        // memory accesses until return. Existing bounded backedges are unchanged.
        unsafe { self.enter_carrier_checkpoint(state, entry) };
        Ok(false)
    }

    /// This fact belongs to this immutable code publication, never to caller
    /// metadata. A new PC, image, or code generation must be validated afresh.
    pub fn requires_native_data(&self, pc: u64) -> Result<bool> {
        self.address(pc)?;
        Ok(self.data_demand[((pc - self.base) / 4) as usize])
    }

    pub fn address(&self, pc: u64) -> Result<usize> {
        ensure!(
            pc >= self.base && pc.is_multiple_of(4),
            "invalid guest PC {pc:#x}"
        );
        let index = (pc - self.base) / 4;
        ensure!(index < self.count as u64, "guest PC outside code {pc:#x}");
        Ok(self.ptr as usize + index as usize * SLOT)
    }
    /// Refresh after every callback reborrow; the native pointer is never a
    /// durable code-cache entry. Caller has already authenticated identity/epoch.
    fn bind_data(&self, memory: &mut Memory, state: &mut State) -> Result<()> {
        state.data_host_base = std::ptr::null_mut();
        if let Some((index, base, length)) = self.data_region {
            let s = memory
                .segments
                .get_mut(index)
                .ok_or_else(|| anyhow::anyhow!("data backing absent"))?;
            ensure!(
                s.base == base && s.bytes.len() == length && s.flags == 6 && !s.ever_executable,
                "data backing permission or shape changed"
            );
            state.data_guest_base = base;
            state.data_last_eight = (length - 8) as u64;
            // SAFETY: exclusively borrowed, private Vec with fixed length. No
            // Rust byte reference survives native execution. Callback entry ends
            // native access; refresh this pointer after every callback reborrow.
            state.data_host_base = s.bytes.as_mut_ptr();
        }
        Ok(())
    }
    /// Execute one bounded interval using the exact active carrier data grant.
    /// Every SVC, slow operation or backward-edge checkpoint returns to the
    /// caller; there is no private-memory fallback or in-scope host dispatch.
    /// Text still belongs to this research executor's private immutable ELF
    /// publication. This is not carrier-backed code publication authority.
    pub fn run_carrier_until_checkpoint(
        &self,
        image: &Image,
        memory: &Memory,
        data: &mut carrick_kernel::kernel::mm_access::ActiveNativeData<'_, '_>,
        state: &mut State,
    ) -> Result<()> {
        ensure!(state.user.is_null(), "native State is already executing");
        memory.validate(image)?;
        ensure!(
            std::sync::Arc::ptr_eq(&self.identity, &image.identity) && self.epoch == image.epoch,
            "wrong executable publication"
        );
        let (_, base, length) = self
            .data_region
            .ok_or_else(|| anyhow::anyhow!("ELF has no bounded writable data region"))?;
        ensure!(
            data.len() >= 8
                && data.start().raw() >= base
                && data
                    .start()
                    .raw()
                    .checked_add(data.len() as u64)
                    .zip(base.checked_add(length as u64))
                    .is_some_and(|(end, limit)| end <= limit),
            "carrier grant is outside the ELF data region"
        );
        let entry = self.address(state.pc)?;
        state.data_guest_base = data.start().raw();
        state.data_last_eight = (data.len() - 8) as u64;
        // SAFETY: the exclusive grant and its execution scope outlive this
        // entire invocation. Emitted scalar accesses check their full width
        // against this exact range. A miss only returns to the caller. No Rust
        // alias, pointer escape, dispatcher entry or executable write occurs.
        state.data_host_base = unsafe { data.as_mut_ptr() };
        // SAFETY: validation above and the borrowed active grant protect code,
        // running scope, and every pointer for the entire native invocation.
        unsafe { self.enter_carrier_checkpoint(state, entry) };
        Ok(())
    }

    /// Caller retains the exact running scope and proves either an active data
    /// grant or absence of reachable memory instructions through this interval.
    unsafe fn enter_carrier_checkpoint(&self, state: &mut State, entry: usize) {
        unsafe extern "C" fn checkpoint(s: *mut State, _: *mut c_void) -> usize {
            // SAFETY: slice_enter receives the exclusively borrowed live State.
            // No guest pointers or invocation payload are dereferenced here.
            let state = unsafe { &mut *s };
            state.backedge_budget = 256;
            state.data_host_base = std::ptr::null_mut();
            0
        }
        let mut invocation = 0u8;
        state.user = std::ptr::from_mut(&mut invocation).cast();
        state.callback = checkpoint;
        state.gateway = slice_gateway as *const () as usize;
        unsafe { slice_enter(state, entry) };
        state.data_host_base = std::ptr::null_mut();
        state.user = std::ptr::null_mut();
    }

    /// Exclusive Memory borrow remains live throughout native code and callbacks.
    /// The callback receives that exact backing; no other owner can mutate it.
    pub fn run<F>(
        &self,
        image: &Image,
        memory: &mut Memory,
        state: &mut State,
        f: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&mut State, &mut Memory) -> Result<bool>,
    {
        ensure!(state.user.is_null(), "native State is already executing");
        memory.validate(image)?;
        ensure!(
            std::sync::Arc::ptr_eq(&self.identity, &image.identity) && self.epoch == image.epoch,
            "wrong executable publication"
        );
        struct Invocation<'a, F> {
            memory: &'a mut Memory,
            code: &'a Code,
            image: &'a Image,
            f: &'a mut F,
            error: Option<anyhow::Error>,
        }
        unsafe extern "C" fn callback<F: FnMut(&mut State, &mut Memory) -> Result<bool>>(
            s: *mut State,
            user: *mut c_void,
        ) -> usize {
            // SAFETY: run owns both references until slice_enter returns; native
            // access to backing is suspended until this callback returns. No
            // native pointer is used during Rust access or retained in Code.
            let invocation = unsafe { &mut *user.cast::<Invocation<'_, F>>() };
            let state = unsafe { &mut *s };
            state.backedge_budget = 256;
            state.data_host_base = std::ptr::null_mut();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if (invocation.f)(state, invocation.memory)? {
                    invocation.memory.validate(invocation.image)?;
                    invocation.code.bind_data(invocation.memory, state)?;
                    invocation.code.address(state.pc)
                } else {
                    Ok(0)
                }
            }));
            match result {
                Ok(Ok(address)) => address,
                Ok(Err(e)) => {
                    invocation.error = Some(e);
                    0
                }
                Err(_) => {
                    invocation.error = Some(anyhow::anyhow!("callback panicked"));
                    0
                }
            }
        }
        let entry = self.address(state.pc)?;
        self.bind_data(memory, state)?;
        let mut invocation = Invocation {
            memory,
            code: self,
            image,
            f,
            error: None,
        };
        state.user = std::ptr::from_mut(&mut invocation).cast();
        state.callback = callback::<F>;
        state.gateway = slice_gateway as *const () as usize;
        // SAFETY: whitelist, validated same-owner RX image, private code, no
        // guest host pointers, stable State, bounded backward-edge callbacks.
        unsafe { slice_enter(state, entry) };
        state.user = std::ptr::null_mut();
        state.data_host_base = std::ptr::null_mut();
        if let Some(e) = invocation.error {
            return Err(e);
        }
        Ok(())
    }
}
impl Drop for Code {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.cast(), self.length);
        }
    }
}
