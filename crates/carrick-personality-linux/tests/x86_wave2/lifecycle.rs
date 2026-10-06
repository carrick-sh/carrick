#![allow(clippy::unwrap_used, clippy::expect_used)]
//! VM-free native context hooks for the actual Linux clone/exit policy.
use carrick_core::lifecycle::Lifecycle;
use carrick_core_abi::{
    BornInZoneSource, EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration,
    ExecutionBinding,
};
use carrick_el1_abi::TrapFrame;
use carrick_personality_linux::{
    abi::{entry::LinuxTaskState, thread::*},
    dispatch::{self, PendingFamilies},
    lifecycle::{ChildContext, ExitRecord, LifecycleNative, UserCopy},
    thread::LifecycleThread,
};
use carrick_sched_core::{RecordRef, SlotId, ThreadIdentity, ZoneTables};
use carrick_x86::cpl0_entry::NativeFrame;
use std::sync::atomic::{AtomicU64, Ordering};

const SLOT: SlotId = SlotId::new(0);
const FLAGS: u64 = 0x003d_0f00 | 0x0100_0000;
#[derive(Clone)]
enum Context {
    Arm(TrapFrame, u64, u64),
    X86(NativeFrame, u64),
}
impl Context {
    fn new(x86: bool) -> Self {
        if x86 {
            Self::X86(
                NativeFrame {
                    rbx: 0xfeed,
                    ..Default::default()
                },
                0x1111,
            )
        } else {
            let mut f = TrapFrame::default();
            f.x[19] = 0xfeed;
            Self::Arm(f, 0x2222, 0x1111)
        }
    }
    fn result(&self) -> i64 {
        match self {
            Self::Arm(f, ..) => f.x[0] as i64,
            Self::X86(f, _) => f.rax as i64,
        }
    }
    fn set_result(&mut self, result: i64) {
        match self {
            Self::Arm(f, ..) => f.x[0] = result as u64,
            Self::X86(f, _) => f.rax = result as u64,
        }
    }
    fn child(&mut self, context: ChildContext) {
        self.set_result(context.result.raw());
        match self {
            Self::Arm(f, sp, tls) => {
                *sp = context.stack.raw();
                if let Some(value) = context.tls {
                    *tls = value.raw();
                }
                assert_eq!(f.x[19], 0xfeed);
            }
            Self::X86(f, fs) => {
                f.rsp = context.stack.raw();
                if let Some(value) = context.tls {
                    *fs = value.raw();
                }
                assert_eq!(f.rbx, 0xfeed);
            }
        }
    }
}
struct Process {
    page: ThreadLifecyclePage,
    slots: [ThreadControlSlot; 9],
    state: LinuxTaskState,
    zone: Box<ZoneTables>,
    mm: u64,
    served: AtomicU64,
    refused: AtomicU64,
}
impl Process {
    fn new(mm: u64) -> Self {
        // SAFETY: the shared zone's documented empty representation is zero;
        // allocation is aligned, uniquely owned and retained by this fixture.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>())
                .cast::<ZoneTables>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        zone.drive(SLOT, 1);
        zone.publish_slot(SLOT, mm, Some(0), 0);
        let space = zone.spaces.publish_closed(mm, mm << 12, 0).unwrap();
        zone.spaces.open(space);
        zone.enter_guest(SLOT);
        Self {
            page: ThreadLifecyclePage::new(),
            slots: std::array::from_fn(|_| ThreadControlSlot::new()),
            state: LinuxTaskState::new(),
            zone,
            mm,
            served: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}
struct Turn<'a> {
    handoff: Option<carrick_core_abi::EntryHandoffReceipt>,
    process: &'a Process,
    binding: ExecutionBinding,
    args: [u64; 6],
    context: Context,
    child: Option<(RecordRef, Context)>,
    current: Option<RecordRef>,
    words: [u32; 2],
    fail_copy: Option<u64>,
    wakes: u64,
    adopted: bool,
}
use carrick_guest_arch::UserVa;
use carrick_personality_linux::abi::entry::SyscallResult;

impl<'a> Turn<'a> {
    fn new(process: &'a Process, x86: bool) -> Self {
        Self {
            process,
            handoff: None,
            binding: ExecutionBinding {
                task: EntryTaskKey::from_raw(40),
                generation: EntryGeneration::from_raw(1),
                mm: EntryMmKey::from_raw(process.mm),
                thread_generation: EntryThreadGeneration::from_raw(1000),
            },
            args: [0; 6],
            context: Context::new(x86),
            child: None,
            current: None,
            words: [71, 72],
            fail_copy: None,
            wakes: 0,
            adopted: false,
        }
    }
    fn syscall(&mut self, ordinal: u64, args: [u64; 6]) -> dispatch::CompletionRoute {
        self.args = args;
        dispatch::dispatch(ordinal, u64::MAX, self)
    }
    fn enter_child(&mut self) {
        let id = self.process.zone.switch_in(SLOT).unwrap();
        self.process
            .zone
            .install_space(SLOT, self.process.mm)
            .unwrap();
        let (record, context) = self.child.as_ref().unwrap();
        assert_eq!(id, record.id);
        let identity = self.process.zone.record(id).identity();
        self.current = Some(*record);
        self.context = context.clone();
        self.binding.task = EntryTaskKey::from_raw(identity.tid);
        self.binding.thread_generation = EntryThreadGeneration::from_raw(identity.serial);
        self.binding.generation = EntryGeneration::from_raw(0);
    }
}
impl UserCopy for Turn<'_> {
    fn copy_in(&mut self, dst: &mut [u8], address: UserVa) -> bool {
        let index = match address.raw() {
            0x1000 => 0,
            0x1004 => 1,
            _ => return false,
        };
        if dst.len() != 4 {
            return false;
        }
        dst.copy_from_slice(&self.words[index].to_le_bytes());
        true
    }
    fn copy_out(&mut self, address: UserVa, src: &[u8]) -> bool {
        if self.fail_copy == Some(address.raw()) {
            self.fail_copy = None;
            return false;
        }
        let index = match address.raw() {
            0x1000 => 0,
            0x1004 => 1,
            _ => return false,
        };
        if src.len() != 4 {
            return false;
        }
        self.words[index] = u32::from_le_bytes(src.try_into().unwrap());
        true
    }
}
impl<'a> LifecycleNative<'a> for Turn<'a> {
    fn arguments(&self) -> [u64; 6] {
        self.args
    }
    fn binding(&self) -> Option<ExecutionBinding> {
        Some(self.binding)
    }
    fn task_state(&self) -> Option<&'a LinuxTaskState> {
        Some(&self.process.state)
    }
    fn thread(&self) -> Option<LifecycleThread<'a>> {
        Some(LifecycleThread {
            page: &self.process.page,
            slot: &self.process.slots[usize::from(self.current.is_some())],
        })
    }
    fn born_slot(
        &self,
        page: &ThreadLifecyclePage,
        entry: EntryRef,
    ) -> Option<&'a ThreadControlSlot> {
        core::ptr::eq(page, &self.process.page)
            .then(|| self.process.slots.get(entry.index() + 1))
            .flatten()
    }
    fn record_decline(&self, _: LifecycleDecline) {}
    fn has_scheduler(&self) -> bool {
        true
    }
    fn user_sp(&mut self) -> Option<UserVa> {
        Some(UserVa::new(0x2222))
    }
    fn affinity(&self) -> Option<u64> {
        Some(1)
    }
    fn allocate_record(
        &mut self,
        identity: ThreadIdentity,
    ) -> Result<RecordRef, carrick_sched_core::Exhausted> {
        self.process
            .zone
            .alloc_record(identity)
            .map(|id| self.process.zone.record_ref(id))
    }
    fn free_record(&mut self, record: RecordRef) {
        assert_eq!(
            self.process.zone.record(record.id).incarnation(),
            record.incarnation
        );
        self.process.zone.free_record(record.id);
    }
    fn can_prepare_child(&self, stack: UserVa, tls: Option<UserVa>) -> bool {
        !matches!(self.context, Context::X86(..))
            || carrick_x86::cpl0_lifecycle::child_context_supported(stack, tls)
    }
    fn prepare_child(&mut self, record: RecordRef, context: ChildContext) {
        let mut child = self.context.clone();
        child.child(context);
        self.child = Some((record, child));
    }
    fn enqueue_born(&mut self, record: RecordRef) {
        self.process.zone.requeue_preempted(SLOT, record.id);
    }
    fn exit_record(&self) -> Option<ExitRecord> {
        let reference = self.current?;
        let rec = self.process.zone.live(reference)?;
        Some(ExitRecord {
            reference,
            identity: rec.identity(),
            home: false,
            unadopted: !self.adopted,
            on_cpu: true,
            needs_host: false,
            cancelled: false,
            object_operation: false,
        })
    }
    fn wake_child_tid(&mut self, mm: EntryMmKey, address: UserVa) -> bool {
        assert_eq!(mm.raw(), self.process.mm);
        assert_eq!(address.raw(), 0x1004);
        assert_eq!(self.words[1], 0, "clear before wake");
        self.wakes += 1;
        true
    }
    fn release_current(&mut self, record: RecordRef) -> bool {
        assert_eq!(self.current, Some(record));
        assert_eq!(self.words[1], 0, "clear before retirement");
        self.handoff = carrick_core::entry::retire_current(
            self.binding,
            BornInZoneSource {
                zone: &self.process.zone,
                slot: SLOT,
            },
            record.id,
            1024,
        );
        self.handoff.is_some()
    }
    fn run_next(&mut self, _: SyscallResult) -> (carrick_core::Served, SyscallResult) {
        self.current = None;
        self.binding.task = EntryTaskKey::from_raw(40);
        self.binding.generation = EntryGeneration::from_raw(1);
        self.binding.thread_generation = EntryThreadGeneration::from_raw(1000);
        self.context.set_result(0);
        (
            carrick_core::Served::Returned { switched: true },
            SyscallResult::new(0),
        )
    }
    fn result(&self) -> SyscallResult {
        SyscallResult::new(self.context.result())
    }
    fn set_result(&mut self, result: SyscallResult) {
        self.context.set_result(result.raw());
    }
}
impl<'a> PendingFamilies<'a> for Turn<'a> {
    fn take_handoff_receipt(&mut self) -> Option<carrick_core_abi::EntryHandoffReceipt> {
        self.handoff.take()
    }
    fn original_argument0(&self) -> u64 {
        self.args[0]
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.context.set_result(result.raw());
    }
    fn binding(&self) -> Option<ExecutionBinding> {
        Some(self.binding)
    }
    fn record_source(&self) -> Option<BornInZoneSource<'a>> {
        Some(BornInZoneSource {
            zone: &self.process.zone,
            slot: SLOT,
        })
    }
    fn task_state(&self) -> Option<&LinuxTaskState> {
        Some(&self.process.state)
    }
    fn lifecycle_native(&mut self) -> Option<&mut dyn LifecycleNative<'a>> {
        Some(self)
    }
    fn lifecycle_available(&self) -> bool {
        true
    }
    fn record_served(&self, _: u64) {
        self.process.served.fetch_add(1, Ordering::Relaxed);
    }
    fn record_forwarded(&self, _: u64) {
        self.process.refused.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn x5_linux_clone_exit() {
    // The production x86 context qualifier must refuse unavailable native
    // stack/TLS states before any visible output, identity claim or allocation.
    for (stack, tls) in [(1u64 << 47, 0x77770000), (0xdead0000, u64::MAX)] {
        let process = Process::new(9);
        let mut turn = Turn::new(&process, true);
        let entry = process
            .page
            .stock(
                0,
                EntryIdentity {
                    tid: 50,
                    visible_tid: 7,
                    thread_serial: 5050,
                    uid_credit: 1,
                },
            )
            .unwrap();
        assert_eq!(
            turn.syscall(220, [FLAGS, stack, 0x1000, tls, 0x1004, 0]),
            dispatch::CompletionRoute::Forward
        );
        assert_eq!(turn.words, [71, 72]);
        assert_eq!(process.page.live(), 1);
        assert_eq!(
            process.page.state(0),
            Some((entry.generation(), EntryState::Reserved))
        );
        assert!(turn.child.is_none());
    }
    for x86 in [false, true] {
        for births in [16, 64, 256] {
            let a = Process::new(7);
            let b = Process::new(8);
            let mut peer = Turn::new(&b, x86);
            for round in 0..births {
                let mut turn = Turn::new(&a, x86);
                let entry = a
                    .page
                    .stock(
                        0,
                        EntryIdentity {
                            tid: 50,
                            visible_tid: 7,
                            thread_serial: 5050,
                            uid_credit: 1,
                        },
                    )
                    .unwrap();
                a.slots[1].reset_for_host_birth(BlockedMask(0));
                let args = [FLAGS, 0xdead0000, 0x1000, 0x77770000, 0x1004, 0];
                turn.fail_copy = Some(0x1004);
                assert_eq!(turn.syscall(220, args), dispatch::CompletionRoute::Forward);
                assert_eq!(turn.words, [71, 72]);
                assert_eq!(
                    a.page.state(0),
                    Some((entry.generation(), EntryState::Reserved))
                );
                assert_eq!(a.page.live(), 1);
                assert_eq!(turn.syscall(220, args), dispatch::CompletionRoute::Served);
                assert_eq!(turn.words, [7, 7]);
                turn.enter_child();
                assert_eq!(turn.context.result(), 0);
                turn.adopted = true;
                assert_eq!(turn.syscall(93, [0; 6]), dispatch::CompletionRoute::Forward);
                assert_eq!(turn.words[1], 7);
                assert_eq!(turn.wakes, 0);
                turn.adopted = false;
                assert_eq!(turn.syscall(93, [0; 6]), dispatch::CompletionRoute::Served);
                assert_eq!(turn.words, [7, 0]);
                assert_eq!(turn.wakes, 1);
                assert_eq!(a.page.live(), 1);
                assert_eq!(peer.words, [71, 72]);
                assert_eq!(b.page.live(), 1);
                assert_eq!(a.served.load(Ordering::Relaxed), 2 * (round + 1));
                assert_eq!(a.refused.load(Ordering::Relaxed), 2 * (round + 1));
                assert_eq!(b.served.load(Ordering::Relaxed), 0);
                assert_eq!(b.refused.load(Ordering::Relaxed), 0);
                a.page.reap(entry).unwrap();
                assert!(a.zone.live(turn.child.as_ref().unwrap().0).is_none());
            }
            assert_eq!(
                peer.syscall(220, [FLAGS & !0x100, 0xdead0000, 0, 0, 0, 0]),
                dispatch::CompletionRoute::Forward
            );
            assert_eq!(peer.words, [71, 72]);
        }
    }
}
