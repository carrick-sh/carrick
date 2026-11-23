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
//! it observed ([`StockParked`]). The caller's wake is enrolled on that
//! release under the same stock phase that refused, before its one probe;
//! the holder's table return delivers it, and one probe then hands the
//! operation back to rerun.
//!
//! The preparations, their receipts (reserved when the ring's ticket is
//! claimed), the parked rows and the settlement route belong to the neutral
//! exec owner ([`carrick_hal::exec_owner::ExecPreparations`], #2305), the
//! same owner the HVF carrier uses. This module keeps x86's mechanics: the
//! image, the reserved tables and frames, the CPL0 build and its replay.
//!
//! The service takes the host's exec lock order
//! ([`carrick_hal::exec_lock_order::ExecCrossingOrder`]): preparations, then
//! the successor's root, then the fork stock, never nested; each phase sees
//! only its owner's state, for that phase alone (#2192).
use super::*;
use carrick_abi::{LINUX_E2BIG, LINUX_ENOEXEC, LINUX_ENOMEM, LINUX_ENOSYS, LinuxErrno};
use carrick_core_abi::service::{
    ExecAdoptionReceipt, ExecArgumentCharge, ExecBuildSource, ExecSuccessorBacking,
    ExecSuccessorEntry, ServiceOrigin,
};
use carrick_core_abi::successor_image::{ImageRow, ImageStack};
pub use carrick_el1::isa::x86_initial_mm::ImageFrameDemand;
use carrick_el1::isa::x86_initial_mm::{
    InitialMmError, InitialStackSpec, build_initial_stack, image_frame_demand,
};
use carrick_el1::memory::reservations::{
    NoRootWait, Refusal, X86Cpl0Root, X86Cpl0RootReleaseVenue,
};
use carrick_guest_arch::{ExecutionGeneration, TaskIdentity, TaskSerial};
use carrick_hal::exec_lock_order::{Exclusive, ExecCrossingOrder};
use carrick_hal::exec_owner::{
    ExecParkWake, ExecPreparations, ExecRetained, ExecRetireReason, ExecRetired, ExecSettleLane,
    ExecSettleRefusal, ExecSettlement, ParkedProbe, SettledExec, StockParked,
};
use carrick_hal::fork_stock::GrantExecution;
use carrick_hal::fork_stock::{
    ChildAddressTags, ForkStock, ForkStockServiceError, StockReleaseWake, SuccessorTables,
};
use carrick_hal::guest_arch_binding::GuestArchBinding;
use carrick_mem::elf::{ElfProgram, SegmentPerms};
use carrick_mem::x86_initial_image::{X86InitialImage, X86InitialRegion, prepare_x86_elf};

/// One page-rounded PT_LOAD region holding its own initialized bytes.
#[derive(::core::fmt::Debug)]
struct ExecRegion {
    start: u64,
    end: u64,
    initialized_offset: u64,
    file_bytes: Vec<u8>,
    perms: SegmentPerms,
}

/// A successor image the host has loaded and checked: what the CPL0 build
/// maps, the strings its stack carries, where it enters, and what it costs.
#[derive(::core::fmt::Debug)]
pub struct X86ExecImage {
    regions: Vec<ExecRegion>,
    executable_region_count: usize,
    has_vdso: bool,
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
    executable: Option<Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>>,
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
        let (stack_pointer, demand) = Self::image_placement(&image, &argv, &env)?;
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
            has_vdso: false,
            entry: image.entry,
            executable_entry: image.executable_entry,
            interpreter_base: image.interpreter_base,
            phdr: image.phdr,
            phent: image.phent,
            phnum: image.phnum,
            argv,
            env,
            stack_pointer,
            demand,
            executable: None,
        })
    }

    fn image_placement(
        image: &X86InitialImage<'_>,
        argv: &[Vec<u8>],
        env: &[Vec<u8>],
    ) -> Result<(u64, ImageFrameDemand), LinuxErrno> {
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
            vdso: image.vdso_base().map(UserVa::new),
        })
        .map_err(|error| match error {
            InitialMmError::StackTooLarge => LINUX_ENOSYS,
            _ => LINUX_ENOEXEC,
        })?;
        let rows = x86_image_rows(image);
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
        Ok((stack.rsp, demand))
    }

    fn attach_vdso(&mut self, clock: carrick_mem::vdso::X86NativeVvar) -> Result<(), LinuxErrno> {
        let base = self.regions.len();
        if self.has_vdso || base + 2 > carrick_core_abi::X86_INITIAL_MAX_REGIONS {
            return Ok(());
        }
        let vvar = clock.bytes();
        let vdso = carrick_mem::vdso::x8664_vdso_image_bytes();
        let Ok(image) = self.initial_image().with_vdso(&vvar, &vdso) else {
            // An ELF can occupy those addresses. It still executes without
            // advertising the overlay in its auxiliary vector.
            return Ok(());
        };
        let (stack_pointer, demand) = Self::image_placement(&image, &self.argv, &self.env)?;
        let [vvar, vdso] = &image.regions[base..] else {
            return Err(LINUX_ENOEXEC);
        };
        let regions = [vvar, vdso].map(|region| ExecRegion {
            start: region.start,
            end: region.end,
            initialized_offset: region.initialized_offset,
            file_bytes: region.file_bytes.to_vec(),
            perms: region.perms,
        });
        self.regions.extend(regions);
        self.has_vdso = true;
        self.stack_pointer = stack_pointer;
        self.demand = demand;
        Ok(())
    }

    /// Retain the loader's executable through parking, cancellation and adoption.
    pub fn with_executable(
        mut self,
        executable: Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>,
    ) -> Self {
        self.executable = Some(executable);
        self
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
            has_vdso: self.has_vdso,
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

    /// The CPL0 build's inputs for this image over `tables` and `data`.
    fn build_inputs<'a>(
        &'a self,
        regions: &'a [carrick_el1::isa::x86_exec_build::ExecBuildRegion<'a>],
        tables: &'a [RootGpa],
        data: &'a [X86InitialBootGrant],
        random: [u8; 16],
        mm_key: NonZeroU64,
        generation: NonZeroU64,
    ) -> carrick_el1::isa::x86_exec_build::ExecBuildInputs<'a> {
        carrick_el1::isa::x86_exec_build::ExecBuildInputs {
            regions,
            executable_region_count: self.executable_region_count,
            entry: self.entry,
            executable_entry: self.executable_entry,
            interpreter_base: self.interpreter_base,
            has_vdso: self.has_vdso,
            phdr: self.phdr,
            phent: self.phent,
            phnum: self.phnum,
            argv: &self.argv,
            env: &self.env,
            tables,
            data,
            stack_top: INITIAL_STACK_TOP,
            stack_size: INITIAL_STACK_SIZE,
            random,
            mm_key,
            generation,
        }
    }

    fn build_regions(&self) -> Vec<carrick_el1::isa::x86_exec_build::ExecBuildRegion<'_>> {
        self.regions
            .iter()
            .map(|region| carrick_el1::isa::x86_exec_build::ExecBuildRegion {
                start: region.start,
                end: region.end,
                initialized_offset: region.initialized_offset,
                file_bytes: &region.file_bytes,
                permissions: u64::from(region.perms.read)
                    | (u64::from(region.perms.write) << 1)
                    | (u64::from(region.perms.execute) << 2),
            })
            .collect()
    }

    /// The protections of the page at `va`: its region's, or the stack's.
    fn page_permissions(&self, va: u64) -> Option<carrick_guest_arch::EditPermissions> {
        if let Some(region) = self
            .regions
            .iter()
            .find(|region| region.start <= va && va < region.end)
        {
            return Some(carrick_guest_arch::EditPermissions {
                readable: region.perms.read,
                writable: region.perms.write,
                executable: region.perms.execute,
                user: true,
            });
        }
        (INITIAL_STACK_TOP - INITIAL_STACK_SIZE..INITIAL_STACK_TOP)
            .contains(&va)
            .then_some(carrick_guest_arch::EditPermissions {
                readable: true,
                writable: true,
                executable: false,
                user: true,
            })
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
#[derive(::core::fmt::Debug)]
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
    /// Write `bytes` from the start of a staged extent's frames.
    fn write(&mut self, data: &Self::Data, bytes: &[u8]) -> Result<(), TrapError>;
    /// Read `len` bytes from the start of a staged extent's frames.
    fn read(&self, data: &Self::Data, len: usize) -> Result<Vec<u8>, TrapError>;
    /// Zero reserved table pages a cancelled build may have written, before
    /// they return to the stock (whose pages are zero).
    fn clear_tables(&mut self, tables: &[RootGpa]) -> Result<(), TrapError>;
}

/// A successor's reserved carrier resources: the staged data of one row of
/// the carrier's exec owner, from before the arm until the adoption consumes
/// them or a cancellation returns them.
#[derive(::core::fmt::Debug)]
pub struct X86ExecPreparation<D> {
    request: X86ExecRequest,
    /// In the order the build takes them; the first is the root.
    tables: SuccessorTables,
    data: D,
    /// The staged build extent (#2235) and the bytes this service encoded
    /// before the image area: the records and the publication area, which
    /// authenticate the build's results at adoption.
    build: D,
    build_source: ExecBuildSource,
    encoded: Vec<u8>,
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

    pub fn build(&self) -> &D {
        &self.build
    }

    /// What the manifest seals: the root the build will produce (the first
    /// reserved table) under x86's one untagged identity, the entry, and
    /// the staged extent the build reads.
    pub fn seal(&self) -> Option<(ExecSuccessorBacking, ExecSuccessorEntry, ExecBuildSource)> {
        Some((
            ExecSuccessorBacking {
                root: *self.tables.pages().first()?,
                asid: carrick_guest_arch::Asid::x86_untagged(),
                asid_generation: self.request.root_generation,
            },
            self.request.image.entry(),
            self.build_source,
        ))
    }
}

/// The service's answer before the arm.
#[derive(::core::fmt::Debug)]
#[must_use]
pub enum X86ExecStage {
    /// Reserved, imported and staged on the claimed row; seal the manifest
    /// from [`X86ExecPreparation::seal`].
    Staged(ExecSuccessorBacking, ExecSuccessorEntry, ExecBuildSource),
    /// Not now; see [`StockParked`]. Nothing is reserved, and the claimed
    /// row keeps its receipt.
    Parked(StockParked<X86ExecRequest>),
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

/// Stage `request` on the stopped `cpu` for the claimed row `receipt`:
/// check the row asked for this successor and no row has staged it, import
/// its rows into the closed successor root, reserve its exact tables from
/// the fork stock, then stage its data frames, and stage the result on the
/// row. When a holder has the stock, `wake` is enrolled on its release
/// ([`StockParked`]); it is dropped otherwise. A Busy root is a broken
/// invariant, not contention: the successor is closed, and its only other
/// owner (the ring's successor slot) is parked in this very service call.
#[allow(clippy::too_many_arguments)]
pub fn stage_x86_exec<T, C, F, P, A>(
    cpu: carrick_guest_arch::CpuId,
    receipt: ExecAdoptionReceipt,
    request: X86ExecRequest,
    preparations: &mut ExecPreparations<X86ExecPreparation<F::Data>, P, A>,
    stock: &mut ForkStock<T, C>,
    frames: &mut F,
    roots: &X86Cpl0Reservations,
    zone: &X86Cpl0Zone,
    wake: StockReleaseWake,
    random: [u8; 16],
) -> Result<X86ExecStage, TrapError>
where
    T: ChildAddressTags,
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
    let (released, admitted) =
        ExecCrossingOrder::on_stopped(cpu, Exclusive(&mut *preparations), Exclusive(&mut *stock))
            .preparations(|preparations| preparations.stageable(receipt, request.successor));
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
    // Enrolled under the phase that refused, before its one probe, so the
    // holder's return cannot land between the refusal and the enrolment.
    let reserved = bound.fork_stock(|stock| {
        let reserved = stock.reserve_successor_tables(demand.tables);
        if let Err(ForkStockServiceError::SuccessorTableCapacity) = reserved {
            stock.enrol_release(observed, wake);
        }
        reserved
    });
    let tables = match reserved {
        Ok(tables) => tables,
        Err(ForkStockServiceError::SuccessorTableCapacity) => {
            root.abort().map_err(root_fault)?;
            return Ok(X86ExecStage::Parked(StockParked::new(request, observed)));
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
    let (build, build_source, encoded) =
        match stage_build(&request, tables.pages(), &data, frames, owner, random) {
            Ok(staged) => staged,
            Err(error) => {
                frames.release(data)?;
                stock.return_successor_tables(tables);
                root.abort().map_err(root_fault)?;
                return Err(error);
            }
        };
    let preparation = X86ExecPreparation {
        request,
        tables,
        data,
        build,
        build_source,
        encoded,
    };
    let (backing, entry, build_source) = preparation
        .seal()
        .ok_or_else(|| fail("exec successor without a root table"))?;
    preparations
        .stage(receipt, preparation)
        .map_err(|(error, _)| fail(format!("exec successor staging: {error:?}")))?;
    Ok(X86ExecStage::Staged(backing, entry, build_source))
}

/// Stage the build extent for `request` over its reserved `tables` and
/// `data` grants: one private extent the successor's owner holds, encoded
/// by the shared layout ([`carrick_el1::isa::x86_exec_build`]).
fn stage_build<F: X86ExecFrames>(
    request: &X86ExecRequest,
    tables: &[RootGpa],
    data: &F::Data,
    frames: &mut F,
    owner: carrick_hal::GuestFrameOwner,
    random: [u8; 16],
) -> Result<(F::Data, ExecBuildSource, Vec<u8>), TrapError> {
    use carrick_el1::isa::x86_exec_build::{encode_exec_build, exec_build_pages};
    let mm = NonZeroU64::new(request.successor.raw()).ok_or_else(|| fail("exec successor MM"))?;
    let regions = request.image.build_regions();
    let inputs = request.image.build_inputs(
        &regions,
        tables,
        data.grants(),
        random,
        mm,
        request.root_generation,
    );
    let pages =
        exec_build_pages(&inputs).map_err(|error| fail(format!("exec build extent: {error:?}")))?;
    let build = frames.stage(pages as usize, owner)?;
    let encoded = build
        .grants()
        .first()
        .ok_or_else(|| fail("exec build extent base"))
        .and_then(|base| {
            encode_exec_build(FrameGpa::new(base.gpa), &inputs)
                .map_err(|error| fail(format!("exec build encoding: {error:?}")))
        })
        .and_then(|encoded| {
            if encoded.source.pages.get() != pages {
                return Err(fail("exec build extent size"));
            }
            frames.write(&build, &encoded.bytes)?;
            Ok(encoded)
        });
    match encoded {
        Ok(mut encoded) => {
            encoded.bytes.truncate(encoded.results_len);
            Ok((build, encoded.source, encoded.bytes))
        }
        Err(error) => {
            frames.release(build)?;
            Err(error)
        }
    }
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
        build,
        ..
    } = preparation;
    stock.return_successor_tables(tables);
    frames.release(data)?;
    frames.release(build)?;
    SuccessorRoot {
        roots,
        zone,
        successor: request.successor,
    }
    .abort()
    .map_err(root_fault)?;
    Ok(request)
}

/// Cancel a sealed preparation whose build may have run: zero and return
/// its tables, and return its data frames and build extent. The successor's
/// root is the ring's: its exec slot retires it after this crossing.
pub fn cancel_x86_exec<T, C, F>(
    preparation: X86ExecPreparation<F::Data>,
    stock: &mut ForkStock<T, C>,
    frames: &mut F,
) -> Result<X86ExecRequest, TrapError>
where
    T: ChildAddressTags,
    F: X86ExecFrames,
{
    let X86ExecPreparation {
        request,
        tables,
        data,
        build,
        ..
    } = preparation;
    frames.clear_tables(tables.pages())?;
    stock.return_successor_tables(tables);
    frames.release(data)?;
    frames.release(build)?;
    Ok(request)
}

/// Apply the exec owner's carrier-exit verdict (#2799) to the rows it retired:
/// a staged successor's tables, data frames and build extent go back exactly
/// as a ring cancellation (a sealed row) or a refusal (an unsealed one)
/// returns them. A claimed or parked row holds no carrier frames. Returns the
/// rows retired.
pub fn release_x86_execs_at_carrier_exit<T, C, F, P, A>(
    retired: Vec<ExecRetired<X86ExecPreparation<F::Data>, P, A>>,
    stock: &mut ForkStock<T, C>,
    frames: &mut F,
    roots: &X86Cpl0Reservations,
    zone: &X86Cpl0Zone,
) -> Result<usize, TrapError>
where
    T: ChildAddressTags,
    F: X86ExecFrames,
{
    let rows = retired.len();
    for row in retired {
        let ExecRetained::Staged(preparation) = row.held else {
            continue;
        };
        if row.retirement.sealed {
            cancel_x86_exec(preparation, stock, frames)?;
        } else {
            release_x86_exec(preparation, stock, frames, roots, zone)?;
        }
    }
    Ok(rows)
}

/// A successor's data frames on the carrier: one private extent, its
/// frames' identities bound per page under boot's inventory transaction.
pub struct CarrierExecData {
    inventory: InitialInventory,
    grants: Vec<X86InitialBootGrant>,
    handle: BackingHandle,
}

impl X86ExecData for CarrierExecData {
    fn grants(&self) -> &[X86InitialBootGrant] {
        &self.grants
    }
}

/// The carrier's frame supply: fresh GPAs from the dynamic grant window,
/// each extent backed privately and staged in the frame inventory.
struct CarrierExecFrames<'a, M: CarrierMemoryIo> {
    vm: &'a mut CarrierMemory<M>,
    next: &'a mut FrameGpa,
    inventory: &'a Arc<dyn PhysicalFrameInventory>,
    rollback_fault: &'a Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
}

impl<M: CarrierMemoryIo> X86ExecFrames for CarrierExecFrames<'_, M> {
    type Data = CarrierExecData;

    fn stage(
        &mut self,
        pages: usize,
        owner: carrick_hal::GuestFrameOwner,
    ) -> Result<CarrierExecData, TrapError> {
        let len = u64::try_from(pages)
            .ok()
            .and_then(|pages| pages.checked_mul(4096))
            .filter(|len| *len != 0)
            .ok_or_else(|| fail("exec successor data length"))?;
        let base = *self.next;
        *self.next = FrameGpa::new(
            base.raw()
                .checked_add(len)
                .ok_or_else(|| fail("exec successor GPA exhausted"))?,
        );
        let (mut inventory, grants) = InitialInventory::stage(
            Arc::clone(self.rollback_fault),
            Arc::clone(self.inventory),
            (0..pages as u64).map(|page| FrameGpa::new(base.raw() + page * 4096)),
            0,
            4096,
            owner,
        )?;
        let identity = inventory
            .frames()
            .first()
            .ok_or_else(|| fail("exec successor frame identity"))?
            .1;
        let extent =
            BackingExtent::private(base, len as usize).map_err(|error| fail(error.to_string()))?;
        let handle = self
            .vm
            .prepare(
                &[PreparedBacking {
                    extent: Arc::new(extent),
                    identity,
                }],
                &mut inventory,
            )
            .map_err(|error| fail(error.to_string()))?[0];
        if let Err(error) = self.vm.bind_frame_identities(handle, inventory.frames()) {
            // SAFETY: the extent was prepared just above; no descriptor of
            // any MM has named it.
            unsafe { self.vm.cancel_prepared(&[handle], &mut inventory) }
                .map_err(|error| fail(error.to_string()))?;
            return Err(fail(error.to_string()));
        }
        Ok(CarrierExecData {
            inventory,
            grants,
            handle,
        })
    }

    fn release(&mut self, mut data: CarrierExecData) -> Result<(), TrapError> {
        // SAFETY: only an unadopted preparation is released: no published
        // descriptor names these frames (an unadopted build's never-installed
        // root is discarded with them).
        unsafe { self.vm.cancel_prepared(&[data.handle], &mut data.inventory) }
            .map_err(|error| fail(error.to_string()))
    }

    fn write(&mut self, data: &CarrierExecData, bytes: &[u8]) -> Result<(), TrapError> {
        let base = data
            .grants
            .first()
            .ok_or_else(|| fail("exec extent base"))?
            .gpa;
        if bytes.len() > data.grants.len() * 4096 {
            return Err(fail("exec extent write past its frames"));
        }
        self.vm
            .write(FrameGpa::new(base), bytes)
            .map_err(|error| fail(error.to_string()))
    }

    fn read(&self, data: &CarrierExecData, len: usize) -> Result<Vec<u8>, TrapError> {
        carrier_exec_read(self.vm, data, len)
    }

    fn clear_tables(&mut self, tables: &[RootGpa]) -> Result<(), TrapError> {
        let zero = [0u8; 4096];
        tables.iter().try_for_each(|table| {
            self.vm
                .write(table.address(), &zero)
                .map_err(|error| fail(error.to_string()))
        })
    }
}

fn carrier_exec_read<M: CarrierMemoryIo>(
    vm: &CarrierMemory<M>,
    data: &CarrierExecData,
    len: usize,
) -> Result<Vec<u8>, TrapError> {
    let base = data
        .grants
        .first()
        .ok_or_else(|| fail("exec extent base"))?
        .gpa;
    if len > data.grants.len() * 4096 {
        return Err(fail("exec extent read past its frames"));
    }
    vm.read(FrameGpa::new(base), len)
        .map_err(|error| fail(error.to_string()))
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    fn exec_tables(ram: &GuestRam) -> Result<(&X86Cpl0Reservations, &X86Cpl0Zone), TrapError> {
        let roots = ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            )
            .ok_or_else(|| fail("exec reservation table"))?;
        let zone = ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("exec zone"))?;
        // SAFETY: boot initialized both aligned records in the retained
        // metadata window, which `ram` keeps alive.
        Ok(unsafe {
            (
                &*roots.cast::<X86Cpl0Reservations>(),
                &*zone.cast::<X86Cpl0Zone>(),
            )
        })
    }

    /// Attach this carrier's clock overlay (the vvar and vDSO regions boot
    /// mapped for the initial image) to a successor. The Exec service does
    /// this to every image before it reserves, so the demand it stages is
    /// the image's own plus the overlay's.
    fn attach_clock_overlay(&self, image: &mut X86ExecImage) -> Result<(), LinuxErrno> {
        match self.clock_vvar {
            Some(clock) => image.attach_vdso(clock),
            None => Ok(()),
        }
    }

    /// The host Exec service on the stopped `cpu` for the claimed row
    /// `receipt`; see [`stage_x86_exec`].
    pub(crate) fn stage_native_exec(
        &mut self,
        cpu: carrick_guest_arch::CpuId,
        receipt: ExecAdoptionReceipt,
        mut request: X86ExecRequest,
        wake: StockReleaseWake,
        random: [u8; 16],
    ) -> Result<X86ExecStage, TrapError> {
        if let Err(errno) = self.attach_clock_overlay(&mut request.image) {
            return Ok(X86ExecStage::Refused(errno));
        }
        let ram = Arc::clone(&self.ram);
        let (roots, zone) = Self::exec_tables(&ram)?;
        let mut frames = CarrierExecFrames {
            vm: &mut self._vm,
            next: &mut self.anonymous_next_gpa,
            inventory: &self.frame_inventory,
            rollback_fault: &self.initial_rollback_fault,
        };
        stage_x86_exec(
            cpu,
            receipt,
            request,
            &mut self.exec_owner,
            &mut self.fork_stock,
            &mut frames,
            roots,
            zone,
            wake,
            random,
        )
    }

    /// Retire the row `receipt` for `reason` and return its unused
    /// preparation; see [`release_x86_exec`].
    pub(crate) fn release_native_exec(
        &mut self,
        receipt: ExecAdoptionReceipt,
        reason: ExecRetireReason,
    ) -> Result<X86ExecRequest, TrapError> {
        let retired = self
            .exec_owner
            .retire(receipt, reason)
            .map_err(|error| fail(format!("exec successor retirement: {error:?}")))?;
        let ExecRetained::Staged(preparation) = retired.held else {
            return Err(fail("exec successor not prepared"));
        };
        let ram = Arc::clone(&self.ram);
        let (roots, zone) = Self::exec_tables(&ram)?;
        let mut frames = CarrierExecFrames {
            vm: &mut self._vm,
            next: &mut self.anonymous_next_gpa,
            inventory: &self.frame_inventory,
            rollback_fault: &self.initial_rollback_fault,
        };
        release_x86_exec(preparation, &mut self.fork_stock, &mut frames, roots, zone)
    }

    /// Retire every exec row the run left unadopted (#2799) and return what
    /// each held; see [`release_x86_execs_at_carrier_exit`]. Call only once
    /// every CPU lane has stopped. Returns the rows retired.
    pub(crate) fn retire_native_execs_at_carrier_exit(&mut self) -> Result<usize, TrapError> {
        // The tables first: a carrier without them keeps its rows.
        let ram = Arc::clone(&self.ram);
        let (roots, zone) = Self::exec_tables(&ram)?;
        let retired = self.exec_owner.retire_at_carrier_exit();
        let mut frames = CarrierExecFrames {
            vm: &mut self._vm,
            next: &mut self.anonymous_next_gpa,
            inventory: &self.frame_inventory,
            rollback_fault: &self.initial_rollback_fault,
        };
        release_x86_execs_at_carrier_exit(retired, &mut self.fork_stock, &mut frames, roots, zone)
    }
}

/// What a parked row of the carrier's exec owner resumes with: the claimed
/// request whose ticket stays outstanding, and its checked image.
pub(in crate::cpl0_boot) type NativeExecContinuation = (
    Box<anonymous_owner::native_service::PendingNativeExec>,
    X86ExecRequest,
);

/// The carrier's exec owner: the neutral owner over x86's staged successors.
/// A run root's row carries its loader's [`RootExecLoad`] (#2142).
pub(in crate::cpl0_boot) type X86ExecOwner =
    ExecPreparations<X86ExecPreparation<CarrierExecData>, NativeExecContinuation, RootExecLoad>;

/// One fork-stock predecessor receipt that is still owned by an adopted exec.
/// Its exec-owner receipt binds the physical custody to the exact settlement
/// that may make it release-permitted; slot absence alone cannot move it.
struct AdoptedExecPredecessor {
    adoption: ExecAdoptionReceipt,
    stock: carrick_hal::fork_stock::ExecPredecessorReceipt<()>,
}

/// The x86 carrier's two typed predecessor-custody phases. Generic quarantine
/// draining can inspect only `release_permitted`; successful exec-owner
/// settlement is the sole transition out of `adopted`.
#[derive(::core::default::Default)]
pub(in crate::cpl0_boot) struct ExecPredecessorCustody {
    adopted: Vec<AdoptedExecPredecessor>,
    release_permitted: Vec<carrick_hal::fork_stock::ExecPredecessorReceipt<()>>,
}

impl ExecPredecessorCustody {
    pub(in crate::cpl0_boot) fn adopt(
        &mut self,
        adoption: ExecAdoptionReceipt,
        stock: carrick_hal::fork_stock::ExecPredecessorReceipt<()>,
    ) {
        debug_assert!(!self.adopted.iter().any(|owned| {
            owned.adoption == adoption
                || owned.stock.predecessor() == stock.predecessor()
                || owned.stock.successor() == stock.successor()
        }));
        self.adopted
            .push(AdoptedExecPredecessor { adoption, stock });
    }

    /// Spend the exact exec-owner settlement authority once, moving only its
    /// matching fork-stock receipt into the phase a generic drain may release.
    pub(in crate::cpl0_boot) fn permit_release(&mut self, settled: SettledExec) -> bool {
        let Some(index) = self.adopted.iter().position(|owned| {
            owned.adoption == settled.receipt
                && owned.stock.predecessor() == settled.predecessor
                && owned.stock.successor() == settled.successor
        }) else {
            return false;
        };
        let owned = self.adopted.swap_remove(index);
        self.release_permitted.push(owned.stock);
        true
    }

    #[cfg(test)]
    pub(in crate::cpl0_boot) fn adopted_len(&self) -> usize {
        self.adopted.len()
    }

    #[cfg(test)]
    pub(in crate::cpl0_boot) fn release_permitted_len(&self) -> usize {
        self.release_permitted.len()
    }
}

/// What the run root's loader resolved for the Kernel's half of its exec
/// (the executable identity the root's `/proc` reports). The carrier never
/// reads it: it rides the exec owner's row from the Exec arm through the
/// adoption to the root's settlement, where the executor's root exec
/// transaction takes it back (#2142).
pub type RootExecLoad = Box<dyn std::any::Any + Send>;

/// One native exec the carrier's loader served: the image the CPL0 build
/// maps and, for the run root's exec only, its [`RootExecLoad`].
pub struct NativeExecLoad {
    pub image: X86ExecImage,
    pub root: Option<RootExecLoad>,
}

/// The run root's settled exec (#2142). The ring has committed its
/// successor and parked this CPU on the maintenance root; this lane's
/// guest entry is refused until the executor commits the Kernel half and
/// retargets the root's loaded custody, consuming this.
#[must_use = "a root exec settlement owns the run root's custody move; dropping it leaves its CPU refusing guest entry"]
pub struct RootExecSettled {
    settlement: carrick_hal::exec_owner::RootExecSettlement,
    successor: AddressContext<RootGpa>,
    /// The ring's execution generation of the root thread it switched to
    /// the successor: exec advances it.
    execution: ExecutionGeneration,
    mm: carrick_hal::exec_owner::AuthenticatedExecMm,
    load: RootExecLoad,
    state: Option<carrick_hal::threaded::X86TaskCpuStateV1>,
}

impl RootExecSettled {
    pub(crate) fn with_state(
        mut self: Box<Self>,
        state: carrick_hal::threaded::X86TaskCpuStateV1,
    ) -> Self {
        self.state = Some(state);
        *self
    }

    /// The stopped CPU's state in the successor's MM and root generation:
    /// the successor's first task state.
    pub fn state(&self) -> Option<&carrick_hal::threaded::X86TaskCpuStateV1> {
        self.state.as_ref()
    }

    /// The ring-issued successor MM the adoption authenticated: the only
    /// MM the Kernel's half of this exec may install.
    pub fn issued_mm(&self) -> &carrick_hal::exec_owner::AuthenticatedExecMm {
        &self.mm
    }

    /// The successor's address context: its MM, root and the ring's root
    /// generation.
    pub fn successor(&self) -> AddressContext<RootGpa> {
        self.successor
    }

    /// The ring's execution generation of the successor's thread: what a
    /// forward from the successor authenticates against.
    pub fn execution(&self) -> ExecutionGeneration {
        self.execution
    }

    /// The adopted exec's receipt, predecessor and successor MMs.
    pub fn settled(&self) -> carrick_hal::exec_owner::SettledExec {
        self.settlement.settled()
    }

    /// Take the loader's Kernel half; the settlement stays owed.
    pub fn take_load(&mut self) -> RootExecLoad {
        std::mem::replace(&mut self.load, Box::new(()))
    }

    /// Consume the settlement once the root's custody has moved, with the
    /// authenticated MM the Kernel's half installs.
    pub fn consume(
        self,
    ) -> (
        carrick_hal::exec_owner::SettledExec,
        carrick_hal::exec_owner::AuthenticatedExecMm,
    ) {
        (self.settlement.consume(), self.mm)
    }
}

/// What one [`carrick_el1_abi::NATIVE_EXEC_PORT`] crossing settled. A
/// settlement moves the stopped task's registered CR3 from the predecessor's
/// root to the successor's.
pub(in crate::cpl0_boot) enum NativeExecCrossing {
    Answered,
    Settled {
        successor: GuestArchBinding,
        predecessor: Option<RootGpa>,
    },
    /// The run root's exec: its custody moves only through the executor.
    RootSettled(Box<RootExecSettled>),
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    fn exec_frames(&mut self) -> CarrierExecFrames<'_, M> {
        CarrierExecFrames {
            vm: &mut self._vm,
            next: &mut self.anonymous_next_gpa,
            inventory: &self.frame_inventory,
            rollback_fault: &self.initial_rollback_fault,
        }
    }

    fn exec_zone(&self) -> Result<&X86Cpl0Zone, TrapError> {
        Ok(Self::exec_tables(&self.ram)?.1)
    }

    /// Finish a claimed exec once the carrier's loader has run: a loader
    /// errno is the exec's pre-arm refusal; a loaded image is staged
    /// (reserved, imported, extent encoded) and its manifest sealed, or
    /// parked on the fork stock's release.
    pub(in crate::cpl0_boot) fn finish_native_exec<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        pending: Box<anonymous_owner::native_service::PendingNativeExec>,
        loaded: Result<NativeExecLoad, LinuxErrno>,
    ) -> Result<(), TrapError> {
        if self.physical_execution(lease)?.context != pending.execution.context {
            return Err(fail("native exec completion context changed"));
        }
        self.drain_fork_quarantine(pending.execution)?;
        match loaded {
            Err(errno) => self.fail_native_exec(lease.cpu, pending, errno),
            Ok(NativeExecLoad { image, root }) => {
                // Only the run root's exec carries the Kernel's half, and
                // the root's always does.
                let origin = pending.ticket.request().identity.birth.origin;
                match (origin, root) {
                    (ServiceOrigin::Initial, Some(load)) => self
                        .exec_owner
                        .attach(pending.receipt, load)
                        .map_err(|_| fail("native root exec load attachment"))?,
                    (ServiceOrigin::Descendant, None) => {}
                    _ => return Err(fail("native exec load names another lineage")),
                }
                let request = X86ExecRequest {
                    image: Box::new(image),
                    successor: pending.successor,
                    root_generation: pending.root_generation,
                };
                self.stage_and_seal(lease.cpu, pending, request)
            }
        }
    }

    fn stage_and_seal(
        &mut self,
        cpu: carrick_guest_arch::CpuId,
        pending: Box<anonymous_owner::native_service::PendingNativeExec>,
        request: X86ExecRequest,
    ) -> Result<(), TrapError> {
        let (woken, wake) = ExecParkWake::new();
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| fail(format!("exec random: {error}")))?;
        let receipt = pending.receipt;
        match self.stage_native_exec(cpu, receipt, request, wake, random)? {
            X86ExecStage::Staged(backing, entry, build) => {
                self.seal_native_exec(cpu, pending, backing, entry, build)
            }
            X86ExecStage::Parked(parked) => {
                // The ticket stays outstanding: the ring's continuation is
                // parked on it until the rerun seals or refuses.
                self.exec_owner
                    .park(receipt, parked.map(|request| (pending, request)), woken)
                    .map_err(|(error, _)| fail(format!("native exec park: {error:?}")))
            }
            X86ExecStage::Refused(errno) => self.fail_native_exec(cpu, pending, errno),
        }
    }

    /// Probe each parked exec once: a cancelled one is acknowledged and
    /// retires; one whose enrolled release fired and found returned tables
    /// reruns its staging. Called after every crossing that can return stock
    /// tables.
    pub(in crate::cpl0_boot) fn probe_parked_execs(
        &mut self,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        for receipt in self.exec_owner.parked() {
            let probe =
                self.exec_owner
                    .probe_parked(receipt, &self.fork_stock, |(pending, _)| {
                        pending
                            .ticket
                            .cancellation_requested()
                            .map_err(|_| fail("parked native exec ticket changed"))
                    })?;
            match probe {
                ParkedProbe::Absent | ParkedProbe::Still => {}
                ParkedProbe::Cancelled((pending, _), _) => {
                    let anonymous_owner::native_service::PendingNativeExec { ticket, key, .. } =
                        *pending;
                    self.acknowledge_native_exec(cpu, key, || {
                        ticket
                            .complete(false)
                            .map_err(|_| fail("parked native exec cancellation acknowledgment"))
                    })?;
                }
                ParkedProbe::Rerun(_, (pending, request)) => {
                    self.stage_and_seal(cpu, pending, request)?
                }
            }
        }
        Ok(())
    }

    fn acknowledge_native_exec(
        &self,
        cpu: carrick_guest_arch::CpuId,
        key: carrick_sched_core::object_wait::ObjectWaitKey,
        acknowledge: impl FnOnce() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let zone = self.exec_zone()?;
        let completion = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| self.complete_object_wake(cpu, owned);
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &completion)
            .map_err(|_| fail("native exec acknowledgment queue"))?;
        acknowledge()?;
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(
                carrick_sched_core::SlotId::new(cpu.raw() as u8),
                &mut effects,
            )
            .map_err(|_| fail("native exec acknowledgment wake"))?;
        drop(queue);
        if effects.queued_own || effects.owes_host_boundary() {
            self.task(cpu).linux.mark_pending_host_work();
        }
        let sink = self.carrier_zone_wake()?;
        for target in effects.sgi_slots() {
            sink.resched(target);
        }
        if sink.take_undelivered().is_some() {
            return Err(fail("native exec reschedule not delivered"));
        }
        Ok(())
    }

    /// A pre-arm refusal: the exec returns `errno` and the caller runs on.
    /// ENOSYS is the carrier's counted refusal.
    fn fail_native_exec(
        &mut self,
        cpu: carrick_guest_arch::CpuId,
        pending: Box<anonymous_owner::native_service::PendingNativeExec>,
        errno: LinuxErrno,
    ) -> Result<(), TrapError> {
        let request = pending.ticket.request();
        if errno == LINUX_ENOSYS
            && let carrick_core_abi::service::ServiceOperation::Exec { payload, .. } =
                request.operation
        {
            let pointer = self.native_service_pointer(
                pending.execution.context,
                carrick_guest_arch::KernelVa::new(self.binding(cpu).counters_address),
                size_of::<carrick_el1_abi::Counters>(),
                align_of::<carrick_el1_abi::Counters>(),
            )?;
            // SAFETY: the exact stopped binding authenticates the retained
            // counter region.
            unsafe { &*pointer.cast::<carrick_el1_abi::Counters>() }.record_refusal(
                payload.ordinal(),
                request.identity.birth.origin,
                carrick_el1_abi::RefusalVenue::Carrier,
            );
        }
        let failure = carrick_core_abi::service::ServiceFailureCode::new(errno.get() as u32)
            .ok_or_else(|| fail("native exec failure code"))?;
        // Refused before the seal: the row retires and nothing past it was
        // owed.
        let retired = self
            .exec_owner
            .retire(pending.receipt, ExecRetireReason::Refused)
            .map_err(|error| fail(format!("native exec refusal: {error:?}")))?;
        if !matches!(retired.held, ExecRetained::Claimed) {
            return Err(fail("native exec refused with a staged successor"));
        }
        let anonymous_owner::native_service::PendingNativeExec { ticket, key, .. } = *pending;
        self.acknowledge_native_exec(cpu, key, || {
            ticket
                .complete_failure(failure)
                .map_err(|_| fail("native exec failure acknowledgment"))
        })
    }

    /// Seal the staged successor's manifest with the receipt its row
    /// reserved at claim and the build extent, then publish it on the exact
    /// ticket. A ring that cancelled meanwhile gets no manifest, and the
    /// preparation returns.
    fn seal_native_exec(
        &mut self,
        cpu: carrick_guest_arch::CpuId,
        pending: Box<anonymous_owner::native_service::PendingNativeExec>,
        backing: ExecSuccessorBacking,
        entry: ExecSuccessorEntry,
        build: ExecBuildSource,
    ) -> Result<(), TrapError> {
        let identity = pending.ticket.request().identity;
        let receipt = pending.receipt;
        let pointer = self.native_service_pointer(
            pending.execution.context,
            pending.manifest,
            size_of::<carrick_core_abi::service::ExecSuccessorManifest>(),
            align_of::<carrick_core_abi::service::ExecSuccessorManifest>(),
        )?;
        // SAFETY: the outstanding ticket retains the ring's aligned reply box.
        let proposed =
            unsafe { *pointer.cast::<carrick_core_abi::service::ExecSuccessorManifest>() };
        let sealed = proposed
            .seal_with_build(identity, receipt, backing, entry, Some(build))
            .filter(|sealed| {
                sealed.open(identity, receipt).is_some_and(|view| {
                    view.successor_mm == pending.successor
                        && view.root_generation == pending.root_generation
                })
            })
            .ok_or_else(|| fail("native exec manifest seal"))?;
        let claim = self
            .exec_owner
            .seal(receipt)
            .map_err(|error| fail(format!("native exec preparation seal: {error:?}")))?;
        if claim.identity() != identity || claim.successor() != pending.successor {
            return Err(fail("native exec preparation sealed for another request"));
        }
        let anonymous_owner::native_service::PendingNativeExec { ticket, key, .. } = *pending;
        let mut cancelled = false;
        self.acknowledge_native_exec(cpu, key, || {
            match ticket.publish_exec_prepared(receipt, (), |_, ()| {
                // SAFETY: the exact ticket retains this pinned, aligned reply
                // until the release-store completion that follows.
                unsafe {
                    pointer
                        .cast::<carrick_core_abi::service::ExecSuccessorManifest>()
                        .write(sealed)
                };
            }) {
                Ok(()) => Ok(()),
                Err((_, ticket, ())) => {
                    cancelled = true;
                    ticket
                        .complete(false)
                        .map_err(|_| fail("native exec cancelled acknowledgment"))
                }
            }
        })?;
        if cancelled {
            self.release_native_exec(receipt, ExecRetireReason::PublishCancelled)?;
        }
        Ok(())
    }

    /// One [`carrick_el1_abi::NATIVE_EXEC_PORT`] crossing on the stopped CPU
    /// of `lane`.
    pub(in crate::cpl0_boot) fn service_native_exec<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        lane: ExecSettleLane,
    ) -> Result<NativeExecCrossing, TrapError> {
        let operation = lease.io.get_gpr(X86Reg::Rdi)?;
        let address = lease.io.get_gpr(X86Reg::Rax)?;
        let crossing = match operation {
            carrick_el1_abi::GRANT_OP_EXEC_ADOPT => {
                self.adopt_native_exec(lease, address)?;
                NativeExecCrossing::Answered
            }
            carrick_el1_abi::GRANT_OP_EXEC_CANCEL => {
                self.cancel_native_exec(lease, address)?;
                NativeExecCrossing::Answered
            }
            carrick_el1_abi::GRANT_OP_EXEC_SETTLE => {
                self.settle_native_exec(lease, address, lane)?
            }
            _ => return Err(fail("native exec crossing operation")),
        };
        self.probe_parked_execs(lease.cpu)?;
        Ok(crossing)
    }

    fn adopt_native_exec<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        address: u64,
    ) -> Result<(), TrapError> {
        let execution = self.physical_execution(lease)?;
        // SAFETY: the adoption record consists of eight initialized u64s.
        let (physical, mut record) = unsafe {
            self.read_stack_record::<carrick_el1_abi::NativeExecAdoption, I>(
                lease,
                execution.context,
                address,
            )
        }?;
        let request = record
            .claim()
            .ok_or_else(|| fail("native exec adoption record"))?;
        if self.adopt_prepared(execution, request.receipt(), request.manifest())? {
            request.accept();
        } else {
            request.refuse();
        }
        // SAFETY: the record is a fully initialized array of eight u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<carrick_el1_abi::NativeExecAdoption>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|error| fail(error.to_string()))
    }

    /// Authenticate the sealed preparation `receipt` names against the
    /// stopped predecessor, its manifest and its build's results, then move
    /// physical custody: the successor's root and published frames, its
    /// closed space's root identity, and the fork stock's child (whose
    /// predecessor custody waits for the settlement). False: refused, with
    /// nothing changed.
    fn adopt_prepared(
        &mut self,
        execution: GrantExecution,
        receipt: ExecAdoptionReceipt,
        manifest_address: carrick_guest_arch::KernelVa,
    ) -> Result<bool, TrapError> {
        use carrick_el1::isa::x86_exec_build::read_exec_build_results;
        let Some((claim, preparation)) = self.exec_owner.sealed(receipt) else {
            return Ok(false);
        };
        if !claim.names_execution(self.fork_stock.carrier(), execution) {
            return Ok(false);
        }
        let identity = claim.identity();
        let successor = claim.successor();
        let predecessor = ReservationMm::new(execution.binding.mm.raw())
            .ok_or_else(|| fail("exec predecessor MM"))?;
        let pointer = self.native_service_pointer(
            execution.context,
            manifest_address,
            size_of::<carrick_core_abi::service::ExecSuccessorManifest>(),
            align_of::<carrick_core_abi::service::ExecSuccessorManifest>(),
        )?;
        // SAFETY: the adopter retains its aligned sealed manifest through
        // this synchronous crossing.
        let manifest =
            unsafe { *pointer.cast::<carrick_core_abi::service::ExecSuccessorManifest>() };
        let Some(view) = manifest.open(identity, receipt) else {
            return Ok(false);
        };
        let (backing, entry, source) = preparation
            .seal()
            .ok_or_else(|| fail("exec preparation without a root"))?;
        if view.successor_mm != successor
            || view.root != backing.root
            || view.root_generation != preparation.request().root_generation
            || view.entry != entry.entry
            || view.stack_pointer != entry.stack_pointer
            || view.build != Some(source)
        {
            return Ok(false);
        }
        let current = carrier_exec_read(&self._vm, preparation.build(), preparation.encoded.len())?;
        let Some(results) = read_exec_build_results(
            &preparation.encoded,
            &current,
            source,
            backing.root,
            entry.stack_pointer.raw(),
        ) else {
            return Ok(false);
        };
        let zone = self.exec_zone()?;
        let Some(index) = zone.spaces.find(successor.raw()) else {
            return Ok(false);
        };
        let root_raw = backing.root.address().raw();
        if zone
            .spaces
            .closed_root_identity(index, successor.raw())
            .is_some()
            || !zone
                .spaces
                .bind_initial_root(index, successor.raw(), root_raw, root_raw)
        {
            return Ok(false);
        }
        // The point of no return: the ring's crossing record accepts below,
        // and every step from here is the carrier's own invariant.
        let adoption = self
            .exec_owner
            .adopt(receipt, predecessor)
            .map_err(|error| fail(format!("exec preparation adoption: {error:?}")))?;
        if adoption.mm.successor() != successor {
            return Err(fail("exec adoption named another successor"));
        }
        let preparation = adoption.data;
        let X86ExecPreparation {
            mut request,
            tables,
            mut data,
            build,
            ..
        } = preparation;
        let mm = NonZeroU64::new(successor.raw()).ok_or_else(|| fail("exec successor MM"))?;
        let context = AddressContext {
            root: backing.root,
            mm: MmGeneration::new(mm),
            generation: ContextGeneration::new(request.root_generation),
        };
        self.publish_built_successor(&request, context, tables.pages(), &mut data, &results)?;
        self.exec_frames().release(build)?;
        let origin = adoption.mm.origin();
        match (origin, adoption.attachment) {
            (ServiceOrigin::Initial, Some(load)) => {
                if self.root_exec_load.replace((adoption.mm, load)).is_some() {
                    return Err(fail("a second root exec adopted before the first settled"));
                }
            }
            (ServiceOrigin::Descendant, None) => {}
            _ => return Err(fail("exec adoption load names another lineage")),
        }
        let used = self
            .fork_stock
            .take_built_successor_tables(tables, results.tables_used)
            .map_err(|_| fail("exec successor table use"))?;
        // SAFETY: the ring's slot published this exact closed successor
        // incarnation before its crossing; the sealed manifest binds it to
        // this receipt and the stopped predecessor, as on AArch64.
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                self.fork_stock.carrier(),
                successor,
                request.root_generation,
            )
        };
        let mut sources = carrick_hal::fork_stock::ForkHostBackingCustody::default();
        if let Some(executable) = request.image.executable.take() {
            sources.bind_executable(executable);
        }
        // The run root's boot-built MM is no stock child: the stock's root
        // form takes it (#2142). A root that already exec'd runs a successor
        // the stock holds, which leaves like a child's.
        let form = match origin {
            ServiceOrigin::Initial if self.fork_stock.child_owner(predecessor).is_none() => {
                carrick_hal::fork_stock::ExecPredecessorForm::Root
            }
            _ => carrick_hal::fork_stock::ExecPredecessorForm::Child,
        };
        let replaced = self
            .fork_stock
            .replace_for_exec_with_tables(form, execution, handle, backing.root, sources, used)
            .map_err(|(error, _)| fail(format!("exec successor stock custody: {error:?}")))?;
        self.exec_predecessors.adopt(receipt, replaced);
        // The data extent is now the successor's: its frames are published.
        drop(data);
        Ok(true)
    }

    /// Replay the build's publications into the carrier's descriptor model
    /// and commit its data frames, exactly as boot does for the root.
    fn publish_built_successor(
        &mut self,
        request: &X86ExecRequest,
        context: AddressContext<RootGpa>,
        tables: &[RootGpa],
        data: &mut CarrierExecData,
        results: &carrick_el1::isa::x86_exec_build::ExecBuildResults,
    ) -> Result<(), TrapError> {
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan,
        };
        let mm = context.mm.raw();
        let linked = results
            .publications
            .iter()
            .try_fold(1usize, |count, publication| {
                if publication.revision != carrick_el1_abi::GuestMmuPublication::REVISION
                    || publication.outcome != carrick_el1_abi::GuestMmuPublication::APPLIED
                    || publication.mm_key != mm.get()
                    || publication.root_gpa != context.root.address().raw()
                    || publication.generation != context.generation.raw().get()
                    || publication.span_len != 4096
                {
                    return None;
                }
                count.checked_add(publication.tables_linked as usize)
            })
            .ok_or_else(|| fail("exec successor publication receipts"))?;
        let copy_tables = carrick_mmu_core::x86::copy_window::cow_copy_table_frames(
            &self._vm.words(),
            context.root,
        )
        .map_err(|_| fail("exec successor private copy branch"))?;
        if linked + copy_tables.len() != results.tables_used
            || tables.get(linked..results.tables_used) != Some(&copy_tables[..])
        {
            return Err(fail("exec successor table receipts"));
        }
        self._vm
            .install_root(mm, context)
            .map_err(|error| fail(error.to_string()))?;
        data.inventory
            .expect_publications(results.publications.len());
        let mut used = 1usize;
        for (publication, grant) in results.publications.iter().zip(data.grants.iter()) {
            let permissions = request
                .image
                .page_permissions(publication.span_va)
                .ok_or_else(|| fail("exec successor publication outside image and stack"))?;
            let backing = BackingIdentity {
                frame_id: NonZeroU64::new(grant.frame_id).ok_or_else(|| fail("frame identity"))?,
                mapping_id: NonZeroU64::new(grant.mapping_id)
                    .ok_or_else(|| fail("mapping identity"))?,
                owner_generation: NonZeroU64::new(grant.owner_generation)
                    .ok_or_else(|| fail("owner generation"))?,
                inventory_revision: NonZeroU64::new(grant.inventory_revision)
                    .ok_or_else(|| fail("inventory revision"))?,
            };
            let next = used
                .checked_add(publication.tables_linked as usize)
                .ok_or_else(|| fail("exec successor table receipt"))?;
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: mm,
                    generation: context.generation.raw(),
                },
                root: context.root,
                op: DescriptorOp::Prepare {
                    span: PageSpan::new(publication.span_va, 4096),
                    output: FrameGpa::new(grant.gpa),
                    permissions: carrick_mmu_core::x86::descriptor_txn::Permissions {
                        writable: permissions.writable,
                        executable: permissions.executable,
                        user: true,
                    },
                    resident: PageSpan::new(publication.span_va, 4096),
                    backing,
                },
                tables: tables
                    .get(used..next)
                    .ok_or_else(|| fail("exec successor table receipt count"))?,
            };
            self._vm
                .publish(&txn, *publication, &mut data.inventory)
                .map_err(|error| fail(error.to_string()))?;
            used = next;
        }
        data.inventory.finish()
    }

    fn cancel_native_exec<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        address: u64,
    ) -> Result<(), TrapError> {
        let execution = self.physical_execution(lease)?;
        // SAFETY: the cancellation record consists of eight initialized u64s.
        let (physical, mut record) = unsafe {
            self.read_stack_record::<carrick_el1_abi::NativeExecCancellation, I>(
                lease,
                execution.context,
                address,
            )
        }?;
        let receipt = record
            .request()
            .ok_or_else(|| fail("native exec cancellation record"))?;
        let carrier = self.fork_stock.carrier();
        let owned = self
            .exec_owner
            .sealed(receipt)
            .is_some_and(|(claim, _)| claim.predecessor_is(carrier, execution));
        let accepted = match owned {
            true => {
                let (preparation, _, _) = self
                    .exec_owner
                    .cancel(receipt)
                    .map_err(|error| fail(format!("exec preparation cancel: {error:?}")))?;
                let mut frames = CarrierExecFrames {
                    vm: &mut self._vm,
                    next: &mut self.anonymous_next_gpa,
                    inventory: &self.frame_inventory,
                    rollback_fault: &self.initial_rollback_fault,
                };
                cancel_x86_exec(preparation, &mut self.fork_stock, &mut frames)?;
                record.accept()
            }
            false => record.refuse(),
        };
        if !accepted {
            return Err(fail("native exec cancellation reply"));
        }
        // SAFETY: the record is a fully initialized array of eight u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<carrick_el1_abi::NativeExecCancellation>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|error| fail(error.to_string()))
    }

    /// The ring switched its slot to the successor and parked this CPU on
    /// the maintenance root. The exec owner routes the settlement first: a
    /// root exec on a `lane` without the root's custody is refused before
    /// anything changes, and a short commit-effects word is refused. Then
    /// register the successor as the stopped task's translation, and release
    /// the predecessor's stock and physical custody (or defer that release
    /// to the next quarantine drain).
    fn settle_native_exec<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        address: u64,
        lane: ExecSettleLane,
    ) -> Result<NativeExecCrossing, TrapError> {
        let live = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)? & !0xfff))
            .ok_or_else(|| fail("exec settlement root alignment"))?;
        if self.maintenance_root != Some(live) {
            return Err(fail("exec settlement outside the maintenance root"));
        }
        let task = self.task(lease.cpu);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("exec settlement MM"))?;
        let context = self
            ._vm
            .root(mm)
            .ok_or_else(|| fail("exec settlement successor root"))?;
        // Only the record's root of translation is the maintenance root's.
        let stack = AddressContext {
            root: live,
            ..context
        };
        // SAFETY: the settlement record consists of eight initialized u64s.
        let (physical, mut record) = unsafe {
            self.read_stack_record::<carrick_el1_abi::NativeExecSettlement, I>(
                lease, stack, address,
            )
        }?;
        let (predecessor, successor, effects) = record
            .request()
            .ok_or_else(|| fail("native exec settlement record"))?;
        let route = if successor.raw() == mm.get() {
            self.exec_owner
                .settle(predecessor, successor, effects, lane)
        } else {
            Err(ExecSettleRefusal::Unknown)
        };
        let mut root = None;
        let known = match route {
            Ok(ExecSettlement::Child(settlement)) => {
                if !self.exec_predecessors.permit_release(settlement) {
                    return Err(fail("exec settlement without its predecessor custody"));
                }
                true
            }
            Ok(ExecSettlement::Root(settlement)) => {
                if !self.exec_predecessors.permit_release(settlement.settled()) {
                    return Err(fail("exec settlement without its predecessor custody"));
                }
                // The executor consumes the root's settlement: it commits
                // the Kernel half and moves the root's loaded custody.
                let (mm, load) = match self.root_exec_load.take() {
                    Some((mm, load)) if mm.successor() == successor => (mm, load),
                    _ => return Err(fail("root exec settlement without its adopted load")),
                };
                root = Some(RootExecSettled {
                    settlement,
                    successor: context,
                    execution: ExecutionGeneration::new(
                        NonZeroU64::new(binding.generation.raw())
                            .ok_or_else(|| fail("root exec settlement generation"))?,
                    ),
                    mm,
                    load,
                    state: None,
                });
                true
            }
            // Handed back unchanged; the ring's handback is #2142 R3's.
            Ok(ExecSettlement::NotHere) => false,
            Err(_) => false,
        };
        let predecessor_root = NonZeroU64::new(predecessor.raw())
            .and_then(|mm| self._vm.root(mm))
            .map(|context| context.root);
        if known {
            self.settle_exec_predecessors()?;
            record.accept();
        } else {
            record.refuse();
        }
        // SAFETY: the record is a fully initialized array of eight u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<carrick_el1_abi::NativeExecSettlement>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|error| fail(error.to_string()))?;
        if !known {
            return Ok(NativeExecCrossing::Answered);
        }
        if let Some(root) = root {
            return Ok(NativeExecCrossing::RootSettled(Box::new(root)));
        }
        let task = TaskIdentity {
            carrier: carrick_guest_arch::CarrierGeneration::new(self._vm.identity().nonzero()),
            task: TaskSerial::new(
                NonZeroU64::new(binding.task.raw()).ok_or_else(|| fail("exec settlement task"))?,
            ),
            execution: ExecutionGeneration::new(
                NonZeroU64::new(binding.generation.raw())
                    .ok_or_else(|| fail("exec settlement generation"))?,
            ),
        };
        Ok(NativeExecCrossing::Settled {
            successor: GuestArchBinding::x86(task, context),
            predecessor: predecessor_root,
        })
    }

    /// Release every post-settlement exec predecessor no slot still runs: its
    /// tables zeroed back to the stock and its frames, residency and CR3
    /// released like a reclaimed child's. An adopted but unsettled receipt is
    /// not visible here. One whose release cannot run yet (its space not yet
    /// unpublished) stays for the next drain.
    pub(in crate::cpl0_boot) fn settle_exec_predecessors(&mut self) -> Result<(), TrapError> {
        let zone = anonymous_owner::retained_cow_zone(&self.ram)?;
        let installed: Vec<u64> = (0..carrick_x86::cpl0_entry::CPL0_CPU_COUNT)
            .filter_map(|slot| u8::try_from(slot).ok())
            .map(|slot| zone.installed_space(carrick_sched_core::SlotId::new(slot)))
            .collect();
        let returns = anonymous_owner::retained_reservations(&self.ram)?;
        let inventory = Arc::clone(&self.frame_inventory);
        let zero = [0u8; 4096];
        for receipt in core::mem::take(&mut self.exec_predecessors.release_permitted) {
            let Some(absence) = carrick_hal::fork_stock::SlotAbsence::scan(
                receipt.predecessor(),
                installed.iter().copied(),
            ) else {
                self.exec_predecessors.release_permitted.push(receipt);
                continue;
            };
            let memory = std::cell::RefCell::new(&mut self._vm);
            let supplied = std::cell::RefCell::new(&mut self.cow_supplied);
            let settled = self.fork_stock.settle_exec_predecessor(
                &mut carrick_hal::fork_stock::NoTableLedger,
                receipt,
                absence,
                |tables| {
                    let mut memory = memory.borrow_mut();
                    tables
                        .iter()
                        .all(|page| memory.write(page.address(), &zero).is_ok())
                },
                |_, absence| {
                    anonymous_owner::release_retired_child(
                        &mut memory.borrow_mut(),
                        &*inventory,
                        absence,
                        anonymous_owner::ChildRelease::Retired {
                            returns,
                            zone,
                            supplied: &mut supplied.borrow_mut(),
                        },
                    )
                    .is_ok()
                },
            );
            if settled.is_err() {
                self.exec_predecessors.release_permitted.push(receipt);
            }
        }
        Ok(())
    }
}

impl<M: CarrierMemoryIo> BootstrapCustody<M> {
    /// The host Exec service on the stopped `cpu` (#1093 S4c slice c) for
    /// the claimed row `receipt`; `wake` is enrolled on the stock's release
    /// if the exec parks.
    pub fn stage_native_exec(
        &mut self,
        cpu: carrick_guest_arch::CpuId,
        receipt: ExecAdoptionReceipt,
        request: X86ExecRequest,
        wake: StockReleaseWake,
        random: [u8; 16],
    ) -> Result<X86ExecStage, TrapError> {
        self.0
            .stage_native_exec(cpu, receipt, request, wake, random)
    }

    /// Probe a woken parked exec once against this carrier's fork stock.
    pub fn probe_parked_exec(
        &self,
        parked: StockParked<X86ExecRequest>,
    ) -> Result<X86ExecRequest, StockParked<X86ExecRequest>> {
        parked.probe(&self.0.fork_stock)
    }

    /// Refuse the unsealed row `receipt` and return its preparation whole.
    pub fn release_native_exec(
        &mut self,
        receipt: ExecAdoptionReceipt,
    ) -> Result<X86ExecRequest, TrapError> {
        self.0
            .release_native_exec(receipt, ExecRetireReason::Refused)
    }

    /// The reserved tables and data grants of a retained preparation.
    pub fn native_exec_reservation(
        &self,
        successor: ReservationMm,
    ) -> Option<(Vec<RootGpa>, Vec<X86InitialBootGrant>)> {
        let (_, preparation) = self.0.exec_owner.staged_for(successor)?;
        Some((
            preparation.tables().to_vec(),
            preparation.data().grants().to_vec(),
        ))
    }

    /// Reusable fork-stock table pages.
    pub fn fork_table_stock(&self) -> usize {
        self.0.fork_stock.table_stock().len()
    }

    /// Waiters enrolled on the fork stock's release and not yet woken.
    pub fn fork_stock_release_waiters(&self) -> usize {
        self.0.fork_stock.release_waiters()
    }

    /// Publish the closed, unadmitted successor root the ring publishes
    /// before it asks for an exec (`prepare_closed_exec_successor_slot`),
    /// returning its root generation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_publish_exec_successor(
        &mut self,
        successor: ReservationMm,
    ) -> Result<NonZeroU64, TrapError> {
        let ram = Arc::clone(&self.0.ram);
        let (roots, zone) = Cpl0HostCustody::<M>::exec_tables(&ram)?;
        let layout = carrick_el1_linux::exec_successor::successor_layout()
            .map_err(|error| fail(format!("successor layout: {error:?}")))?;
        let index = zone
            .spaces
            .publish_closed_with_layout(
                successor.raw(),
                0,
                0,
                layout.heap.start(),
                layout.arena.start(),
            )
            .ok_or_else(|| fail("successor space"))?;
        if !zone.spaces.mark_initial_bindable(index) {
            return Err(fail("successor space bindable"));
        }
        roots
            .publish(index.index(), successor, layout)
            .map_err(|error| fail(format!("successor root: {error:?}")))?;
        SuccessorRoot {
            roots,
            zone,
            successor,
        }
        .locked(|model| Ok(NonZeroU64::new(model.incarnation().raw())))
        .map_err(root_fault)?
        .ok_or_else(|| fail("successor root generation"))
    }

    /// Claim an exec for `successor` as the ring's ticket would, on behalf
    /// of a synthetic descendant of this carrier, reserving its receipt.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_claim_exec(
        &mut self,
        successor: ReservationMm,
        root_generation: NonZeroU64,
    ) -> Result<ExecAdoptionReceipt, TrapError> {
        use carrick_core_abi::service::{ServiceBirth, ServiceIdentity};
        use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
        let one = NonZeroU64::MIN;
        let identity = ServiceIdentity {
            birth: ServiceBirth {
                origin: ServiceOrigin::Descendant,
                process: TaskKey {
                    id: TaskId::from_registry_allocation(
                        core::num::NonZeroI32::MIN.saturating_abs(),
                    ),
                    serial: TaskSerial::from_registry_allocation(one),
                },
                thread: carrick_core_abi::EntryThreadGeneration::from_raw(1),
                record: carrick_sched_core::RecordRef {
                    id: carrick_sched_core::RecordId::from_raw(1)
                        .ok_or_else(|| fail("fixture record"))?,
                    incarnation: 1,
                },
                // SAFETY: a fixture identity naming the successor's own MM; it
                // authorizes no memory operation and no ring ticket names it.
                mm: unsafe {
                    carrick_el1_abi::El1MmHandle::from_admitted_owner(
                        self.0.fork_stock.carrier(),
                        successor,
                        root_generation,
                    )
                },
            },
            execution: carrick_core_abi::SnapshotGeneration::from_raw(1),
            sequence: one,
        };
        self.0
            .exec_owner
            .claim(identity, successor, root_generation)
            .map(|claim| claim.receipt())
            .map_err(|error| fail(format!("fixture exec claim: {error:?}")))
    }

    /// What the Exec service would reserve for `image` on this carrier: its
    /// demand after the same overlay attachment `stage_native_exec` makes.
    /// A test that sizes fork-stock pressure asks here, so it never restates
    /// what the carrier adds to a successor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_staged_exec_demand(
        &self,
        mut image: X86ExecImage,
    ) -> Result<ImageFrameDemand, LinuxErrno> {
        self.0.attach_clock_overlay(&mut image)?;
        Ok(image.demand())
    }

    /// Hold all but `left` stock tables, as a live holder (a pending fork,
    /// live children) would.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_hold_fork_stock(&mut self, left: usize) -> Result<SuccessorTables, TrapError> {
        let count = self.fork_table_stock().saturating_sub(left);
        self.0
            .fork_stock
            .reserve_successor_tables(count)
            .map_err(|error| fail(format!("hold fork stock: {error:?}")))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_release_fork_stock(&mut self, held: SuccessorTables) {
        self.0.fork_stock.return_successor_tables(held);
    }
}

#[cfg(test)]
#[path = "cpl0_exec/tests.rs"]
mod tests;
