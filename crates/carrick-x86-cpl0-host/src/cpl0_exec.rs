//! The x86 host Exec service (#1093 S4c slice c, on the design accepted on
//! #2149). A native fork child's exec reaches the host as a staged payload;
//! the shared loader resolves and reads its ELF. This service then checks
//! the image, and before the ring arms the exec reserves everything the
//! CPL0 build after the arm consumes (slice d): the exact fork-stock tables
//! (`image_frame_demand`), the data frames under boot's inventory
//! transaction, and the image rows in the successor's closed reservation
//! root. Every refusal up to here leaves the predecessor as it was.
//!
//! Contention is "not now", never an errno: when the stock cannot grant the
//! tables because a holder (a pending fork, a live child) has them, nothing
//! stays reserved, and the owned operation is kept with the stock release
//! it observed ([`ParkedX86Exec`]); once the holder returns tables, one
//! probe hands the operation back to rerun.
//!
//! The service takes the host's exec lock order
//! ([`carrick_hal::exec_lock_order::ExecCrossingOrder`]): preparations, then
//! the successor's root, then the fork stock, never nested.
use super::*;
use carrick_abi::{LINUX_E2BIG, LINUX_ENOEXEC, LINUX_ENOMEM, LINUX_ENOSYS, LinuxErrno};
use carrick_core_abi::service::{ExecArgumentCharge, ExecSuccessorBacking, ExecSuccessorEntry};
use carrick_core_abi::successor_image::{ImageRow, ImageStack};
use carrick_el1::isa::x86_initial_mm::{
    ImageFrameDemand, InitialMmError, InitialStackSpec, build_initial_stack, image_frame_demand,
};
use carrick_el1::memory::reservations::{
    NoRootWait, Refusal, X86Cpl0Root, X86Cpl0RootReleaseVenue,
};
use carrick_hal::exec_lock_order::ExecCrossingOrder;
use carrick_hal::fork_stock::{
    ChildAddressTags, ForkStock, ForkStockServiceError, StockRelease, SuccessorTables,
};
use carrick_mem::elf::{ElfProgram, SegmentPerms};
use carrick_mem::x86_initial_image::{X86InitialImage, X86InitialRegion, prepare_x86_elf};
use std::collections::BTreeMap;

/// One page-rounded PT_LOAD region holding its own initialized bytes.
#[derive(Debug)]
struct ExecRegion {
    start: u64,
    end: u64,
    initialized_offset: u64,
    file_bytes: Vec<u8>,
    perms: SegmentPerms,
}

/// A successor image the host has loaded and checked: what the CPL0 build
/// maps, the strings its stack carries, where it enters, and what it costs.
#[derive(Debug)]
pub struct X86ExecImage {
    regions: Vec<ExecRegion>,
    executable_region_count: usize,
    entry: u64,
    executable_entry: u64,
    interpreter_base: u64,
    phdr: u64,
    phent: u16,
    phnum: u16,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    stack_pointer: u64,
    demand: ImageFrameDemand,
}

impl X86ExecImage {
    /// The execve(2) argument check, which Linux makes before it looks at
    /// the image: E2BIG (7) when argv and envp exceed the shared
    /// [`ExecArgumentCharge`]. The loader runs it again after a shebang
    /// added its interpreter's strings.
    pub fn check_arguments(argv: &[Vec<u8>], env: &[Vec<u8>]) -> Result<(), LinuxErrno> {
        ExecArgumentCharge::of_strings(argv.iter().chain(env).map(Vec::as_slice))
            .map(|_| ())
            .map_err(|_| LINUX_E2BIG)
    }

    /// Check a parsed program as the successor of an exec. ENOEXEC (8) for
    /// an image the x86 editor cannot map (wrong machine, unmapped program
    /// headers, an entry outside executable memory, rows the shared
    /// successor validator refuses); E2BIG (7) for arguments past Linux's
    /// charge. Arguments that fit Linux but not the stack the editor builds
    /// are a carrier limit, left unrouted (ENOSYS), never a false E2BIG.
    pub fn from_program(
        program: &ElfProgram<'_>,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<Self, LinuxErrno> {
        Self::check_arguments(&argv, &env)?;
        let image = prepare_x86_elf(program).map_err(|_| LINUX_ENOEXEC)?;
        let argv_bytes: Vec<&[u8]> = argv.iter().map(Vec::as_slice).collect();
        let env_bytes: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
        // The stack pointer does not depend on AT_RANDOM's bytes, only on
        // where they sit, so the build after the arm (with fresh carrier
        // randomness) lands on the one sealed here.
        let stack = build_initial_stack(&InitialStackSpec {
            entry: image.executable_entry,
            interpreter_base: image.interpreter_base,
            phdr: image.phdr,
            phent: image.phent,
            phnum: image.phnum,
            argv: &argv_bytes,
            envp: &env_bytes,
            random: [0; 16],
            stack_top: INITIAL_STACK_TOP,
            stack_size: INITIAL_STACK_SIZE,
        })
        .map_err(|error| match error {
            InitialMmError::StackTooLarge => LINUX_ENOSYS,
            _ => LINUX_ENOEXEC,
        })?;
        let rows = x86_image_rows(&image);
        let stack_row = ImageStack {
            top: UserVa::new(INITIAL_STACK_TOP),
            size: carrick_guest_arch::GuestLen::new(INITIAL_STACK_SIZE),
        };
        carrick_core_abi::successor_image::validate_image_rows(
            &rows,
            image.executable_region_count,
            UserVa::new(image.entry),
            stack_row,
            carrick_core_abi::successor_image::ImageGeometry::X86_64,
        )
        .map_err(|_| LINUX_ENOEXEC)?;
        let demand = image_frame_demand(&rows, stack_row).ok_or(LINUX_ENOEXEC)?;
        Ok(Self {
            regions: image
                .regions
                .iter()
                .map(|region| ExecRegion {
                    start: region.start,
                    end: region.end,
                    initialized_offset: region.initialized_offset,
                    file_bytes: region.file_bytes.to_vec(),
                    perms: region.perms,
                })
                .collect(),
            executable_region_count: image.executable_region_count,
            entry: image.entry,
            executable_entry: image.executable_entry,
            interpreter_base: image.interpreter_base,
            phdr: image.phdr,
            phent: image.phent,
            phnum: image.phnum,
            argv,
            env,
            stack_pointer: stack.rsp,
            demand,
        })
    }

    /// The image as boot's loader describes one, borrowing these bytes.
    pub fn initial_image(&self) -> X86InitialImage<'_> {
        X86InitialImage {
            entry: self.entry,
            executable_entry: self.executable_entry,
            interpreter_base: self.interpreter_base,
            phdr: self.phdr,
            phent: self.phent,
            phnum: self.phnum,
            regions: self
                .regions
                .iter()
                .map(|region| X86InitialRegion {
                    start: region.start,
                    end: region.end,
                    initialized_offset: region.initialized_offset,
                    file_bytes: &region.file_bytes,
                    perms: region.perms,
                })
                .collect(),
            executable_region_count: self.executable_region_count,
        }
    }

    pub fn rows(&self) -> Vec<ImageRow> {
        x86_image_rows(&self.initial_image())
    }

    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    pub fn env(&self) -> &[Vec<u8>] {
        &self.env
    }

    /// The tables and data frames the CPL0 build takes for this image.
    pub fn demand(&self) -> ImageFrameDemand {
        self.demand
    }

    /// Where the successor enters, as the manifest seals it.
    pub fn entry(&self) -> ExecSuccessorEntry {
        ExecSuccessorEntry {
            entry: UserVa::new(self.entry),
            stack_pointer: UserVa::new(self.stack_pointer),
        }
    }
}

/// The owned operation of one exec preparation: the checked image and the
/// closed successor the ring published for it.
#[derive(Debug)]
pub struct X86ExecRequest {
    pub image: Box<X86ExecImage>,
    pub successor: ReservationMm,
    pub root_generation: NonZeroU64,
}

/// The data frames of one successor under boot's inventory transaction.
pub trait X86ExecData: Send + 'static {
    /// The grants in the order the build takes them.
    fn grants(&self) -> &[X86InitialBootGrant];
}

/// The carrier's supply of zeroed private data frames.
pub trait X86ExecFrames {
    type Data: X86ExecData;
    /// Stage `pages` frames owned by `owner`, all or nothing.
    fn stage(
        &mut self,
        pages: usize,
        owner: carrick_hal::GuestFrameOwner,
    ) -> Result<Self::Data, TrapError>;
    /// Return frames no guest descriptor has named.
    fn release(&mut self, data: Self::Data) -> Result<(), TrapError>;
}

/// A successor's reserved carrier resources, retained from before the arm
/// until slice d's adoption consumes them or its cancellation returns them.
#[derive(Debug)]
pub struct X86ExecPreparation<D> {
    request: X86ExecRequest,
    /// In the order the build takes them; the first is the root.
    tables: SuccessorTables,
    data: D,
}

impl<D: X86ExecData> X86ExecPreparation<D> {
    pub fn request(&self) -> &X86ExecRequest {
        &self.request
    }

    pub fn tables(&self) -> &[RootGpa] {
        self.tables.pages()
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    /// What the manifest seals: the root the build will produce (the first
    /// reserved table) under x86's one untagged identity, and the entry.
    pub fn seal(&self) -> Option<(ExecSuccessorBacking, ExecSuccessorEntry)> {
        Some((
            ExecSuccessorBacking {
                root: *self.tables.pages().first()?,
                asid: carrick_guest_arch::Asid::x86_untagged(),
                asid_generation: self.request.root_generation,
            },
            self.request.image.entry(),
        ))
    }
}

impl<D> core::fmt::Debug for X86ExecPreparations<D> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("X86ExecPreparations")
            .field("successors", &self.prepared.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The carrier's retained exec preparations, one per closed successor.
pub struct X86ExecPreparations<D> {
    prepared: BTreeMap<u64, X86ExecPreparation<D>>,
}

impl<D> Default for X86ExecPreparations<D> {
    fn default() -> Self {
        Self {
            prepared: BTreeMap::new(),
        }
    }
}

impl<D: X86ExecData> X86ExecPreparations<D> {
    pub fn get(&self, successor: ReservationMm) -> Option<&X86ExecPreparation<D>> {
        self.prepared.get(&successor.raw())
    }

    pub fn len(&self) -> usize {
        self.prepared.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prepared.is_empty()
    }

    /// Take a preparation out of custody (adoption or cancellation).
    pub fn take(&mut self, successor: ReservationMm) -> Option<X86ExecPreparation<D>> {
        self.prepared.remove(&successor.raw())
    }
}

/// Not now: an exec whose tables a holder has. Owns the operation and the
/// stock release it observed before the refused reservation.
#[derive(Debug)]
#[must_use]
pub struct ParkedX86Exec {
    request: X86ExecRequest,
    observed: StockRelease,
}

impl ParkedX86Exec {
    /// Probe once: the operation back to rerun if the holder has returned
    /// tables since the refusal, else still parked.
    pub fn probe<T: ChildAddressTags, C>(
        self,
        stock: &ForkStock<T, C>,
    ) -> Result<X86ExecRequest, Self> {
        if stock.released_since(self.observed) {
            Ok(self.request)
        } else {
            Err(self)
        }
    }

    pub fn successor(&self) -> ReservationMm {
        self.request.successor
    }
}

/// The service's answer before the arm.
#[derive(Debug)]
#[must_use]
pub enum X86ExecStage {
    /// Reserved, imported and retained; seal the manifest from
    /// [`X86ExecPreparation::seal`].
    Staged(ExecSuccessorBacking, ExecSuccessorEntry),
    /// Not now; see [`ParkedX86Exec`]. Nothing is reserved.
    Parked(ParkedX86Exec),
    /// A pre-arm refusal the exec returns (the predecessor runs on), with
    /// nothing reserved. The successor's root refused its rows: ENOMEM, as
    /// the AArch64 service answers the same refusal.
    Refused(LinuxErrno),
}

/// The successor's closed reservation root: its rows are imported, or the
/// import is aborted, with the root lock held only for that.
struct SuccessorRoot<'z> {
    roots: &'z X86Cpl0Reservations,
    zone: &'z X86Cpl0Zone,
    successor: ReservationMm,
}

impl SuccessorRoot<'_> {
    fn locked<R>(
        &self,
        edit: impl FnOnce(&mut X86Cpl0Root<'_>) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        let index = self
            .zone
            .spaces
            .find(self.successor.raw())
            .ok_or(Refusal::Stale)?;
        // Nothing waits on a closed successor's root; a delivery here would
        // be a live waiter this service has no authority to release.
        let woke = core::cell::Cell::new(false);
        let deliver = |_: &X86Cpl0Zone,
                       _: Waker,
                       owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {
            let (_, effects) = owned.deliver_handbacks(&mut |_| woke.set(true));
            if effects != carrick_sched_core::WakeEffects::default() {
                woke.set(true);
            }
        };
        let release = SpaceReleaseVenue {
            zone: self.zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &deliver,
            ),
        };
        let result = X86Cpl0RootReleaseVenue::new(self.roots, release)?
            .lock(index.index(), self.successor, &NoRootWait)
            .and_then(|mut model| {
                if model.mm() != self.successor || model.is_admitted() {
                    return Err(Refusal::Stale);
                }
                edit(&mut model)
            });
        if woke.get() {
            return Err(Refusal::Stale);
        }
        result
    }

    fn import(&self, image: &X86ExecImage) -> Result<(), Refusal> {
        self.locked(|model| {
            let imported = import_x86_image_rows(model, &image.initial_image(), INITIAL_STACK_TOP)
                .and_then(|()| {
                    // The stack the build writes is private memory the carrier
                    // built, as boot's is; boot inserts it after admission, a
                    // successor imports it before.
                    model.import_with(
                        ReservationRange::new(
                            INITIAL_STACK_TOP - INITIAL_STACK_SIZE,
                            INITIAL_STACK_TOP,
                        )
                        .ok_or(Refusal::Invalid)?,
                        carrick_el1_abi::ReservationProtection::READ_WRITE,
                        carrick_el1_abi::ReservationNodeFlags::PRIVATE
                            .union(carrick_el1_abi::ReservationNodeFlags::GROWSDOWN),
                    )
                });
            if let Err(refusal) = imported {
                model.abort_import()?;
                return Err(refusal);
            }
            Ok(())
        })
    }

    fn abort(&self) -> Result<(), Refusal> {
        self.locked(|model| model.abort_import())
    }
}

fn root_fault(refusal: Refusal) -> TrapError {
    fail(format!("exec successor root custody: {refusal:?}"))
}

/// Stage `request` on the stopped `cpu`: check its successor is not already
/// prepared, import its rows into the closed successor root, reserve its
/// exact tables from the fork stock, then stage its data frames, and retain
/// the result in `preparations`. A Busy root is a broken invariant, not
/// contention: the successor is closed, and its only other owner (the
/// ring's successor slot) is parked in this very service call.
#[allow(clippy::too_many_arguments)]
pub fn stage_x86_exec<T, C, F>(
    cpu: carrick_guest_arch::CpuId,
    request: X86ExecRequest,
    preparations: &mut X86ExecPreparations<F::Data>,
    stock: &mut ForkStock<T, C>,
    frames: &mut F,
    roots: &X86Cpl0Reservations,
    zone: &X86Cpl0Zone,
) -> Result<X86ExecStage, TrapError>
where
    T: ChildAddressTags + 'static,
    C: 'static,
    F: X86ExecFrames,
{
    let root = SuccessorRoot {
        roots,
        zone,
        successor: request.successor,
    };
    let demand = request.image.demand();
    // Observed before the probe, so a return that lands after the refusal
    // is never missed.
    let observed = stock.table_release();
    let (released, admitted) = ExecCrossingOrder::on_stopped(cpu, preparations, stock)
        .preparations(|preparations| preparations.get(request.successor).is_none());
    if !admitted {
        return Err(fail("exec successor already prepared"));
    }
    let (rooted, imported) = released.root_release(|| root.import(&request.image));
    match imported {
        Ok(()) => {}
        Err(refusal @ (Refusal::Busy | Refusal::Stale)) => return Err(root_fault(refusal)),
        Err(_) => return Ok(X86ExecStage::Refused(LINUX_ENOMEM)),
    }
    let (bound, ()) = rooted.bind_zone(|| ());
    let reserved = bound.fork_stock(|stock| stock.reserve_successor_tables(demand.tables));
    let tables = match reserved {
        Ok(tables) => tables,
        Err(ForkStockServiceError::SuccessorTableCapacity) => {
            root.abort().map_err(root_fault)?;
            return Ok(X86ExecStage::Parked(ParkedX86Exec { request, observed }));
        }
        Err(error) => {
            root.abort().map_err(root_fault)?;
            return Err(fail(format!("exec successor tables: {error:?}")));
        }
    };
    let owner = carrick_hal::GuestFrameOwner {
        native_mm: MmGeneration::new(
            NonZeroU64::new(request.successor.raw()).ok_or_else(|| fail("exec successor MM"))?,
        ),
        root_generation: ContextGeneration::new(request.root_generation),
    };
    let data = match frames.stage(demand.data, owner) {
        Ok(data) => data,
        Err(error) => {
            stock.return_successor_tables(tables);
            root.abort().map_err(root_fault)?;
            return Err(error);
        }
    };
    let preparation = X86ExecPreparation {
        request,
        tables,
        data,
    };
    let (backing, entry) = preparation
        .seal()
        .ok_or_else(|| fail("exec successor without a root table"))?;
    preparations
        .prepared
        .insert(preparation.request.successor.raw(), preparation);
    Ok(X86ExecStage::Staged(backing, entry))
}

/// Return a retained preparation no build has used: its tables to the
/// stock, its frames to the carrier, and its rows out of the closed root.
pub fn release_x86_exec<T, C, F>(
    preparation: X86ExecPreparation<F::Data>,
    stock: &mut ForkStock<T, C>,
    frames: &mut F,
    roots: &X86Cpl0Reservations,
    zone: &X86Cpl0Zone,
) -> Result<X86ExecRequest, TrapError>
where
    T: ChildAddressTags,
    F: X86ExecFrames,
{
    let X86ExecPreparation {
        request,
        tables,
        data,
    } = preparation;
    stock.return_successor_tables(tables);
    frames.release(data)?;
    SuccessorRoot {
        roots,
        zone,
        successor: request.successor,
    }
    .abort()
    .map_err(root_fault)?;
    Ok(request)
}

#[cfg(test)]
#[path = "cpl0_exec/tests.rs"]
mod tests;
