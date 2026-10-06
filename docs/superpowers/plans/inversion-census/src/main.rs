//! Documentation audit script. Reads immutable git blobs; never edits product source.
//! --write regenerates marked prose citations and Appendix A; --check rejects drift.
//! This lexical + syntax inventory does not establish compiled reachability or
//! instruction equivalence. The planned product asm-block-diff tool is separate.
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt::Write as _,
    fs,
    path::PathBuf,
    process::{Command, ExitCode},
};
use syn::{spanned::Spanned, visit::Visit};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PLAN: &str = "docs/superpowers/plans/2026-10-06-shared-kernel-inversion.md";
const MARKER: &str = "<!-- BEGIN GENERATED APPENDIX A -->";
const S: &str = "0f476ce7afb11609c8261cd1954bbe08263548b3";
const O6: &str = "3fd7862be859e106cdfa27ec183fea9cf66ccf63";
const R: &str = "0feb7c7b0f7ad99b3c85aac146e65d52c64904da";
const PATTERNS: &[(&str, &str)] = &[
    (
        "T — trap/frame",
        r#"\b(?:get|set|read|write)_(?:reg|sys_reg|esr|elr|spsr|far|pc)\b|\b(?:TrapFrame|NativeFrame|Aarch64SyscallFrame|Aarch64Exit|EntryEvent|ESR|ELR|SPSR|FAR|SVC_LEN|DESCRIPTOR_DRAIN_ESR|MM_PORTAL_[A-Z_]*ESR)\b|\b(?:esr|elr|spsr|far)\b|\.(?:x|gpr)\b|\b(?:x|gpr):|Reg::(?:X|PC|CPSR)|\b(?:rip|rflags|rax|rcx|r11|rsp)\b"#,
    ),
    (
        "C — context/TLS",
        r#"\b(?:get|set)_(?:fpcr|fpsr|vreg|guest_sp)\b|\b(?:ThreadCtx|Aarch64VcpuSnapshot|NativeContext|XsaveArea|ContextBinding|FPCR|FPSR|TPIDR[A-Z_]*|SP_EL0|CONTEXTIDR_EL1|Xsave|XSTATE_MASK|XSAVE_BYTES)\b|\b(?:sp_el0|tpidr_el0|tpidrro_el0|contextidr_el1|fpsr|fpcr|pstate|fs_base|gs_base)\b|\b(?:xsave|xrstor|swapgs|eret|iretq)\b|carrick_el1_fpsimd"#,
    ),
    (
        "D — descriptors/geometry",
        r#"carrick_mmu_core::aarch64|\baarch64::|\b(?:PageTableManager|PageTableError|LeafAccess|El1PrivateLeafState|TTBR_BADDR_MASK|TTBR_BADDR|PTE_[A-Z_]*|SubstrateGpa|PrimaryTableWords|HardwareDescriptorTxnApplier|HardwareAnonymous[A-Za-z]+Editor|Aarch64CowMmu|Aarch64Mmu|X86Mmu)\b|\b(?:ttbr\w*|asid|cr3|pcid)\b|\b(?:sctlr|tcr|mair|ttbr)[A-Za-z_0-9]*\b|\b(?:indices|table_window|terminal_descriptor|classify_stage1_range|retired_page|descriptor_word|descriptor_bits)\b"#,
    ),
    (
        "L — TLB/coherence",
        r#"\b(?:tlbi|dsb|dmb|isb|invlpg|mfence|sfence|lfence)\b|\b(?:icache|invalidate_asid|invalidate_tlb|broadcast_asid|flush_tlb|invalidate_page|publish_executable|sync_to_host)\b|Reg::(?:DC|IC)|resume_invalidation"#,
    ),
    (
        "I — interrupt/clock",
        r#"\b(?:daif\w*|cntv\w*|cntfrq\w*|cntp\w*|mpidr\w*|sgi\w*|intid|wfi|cli|sti|hlt|rdtsc|rdmsr|wrmsr)\b|\b(?:GIC_[A-Z_]+|ICC_[A-Z0-9_]+|APIC_[A-Z_]+|MPIDR_EL1|CNT[A-Z0-9_]+|DAIF|IrqGuard|InterruptFrame)\b|s3_0_c12|own_sgi_target|send_sgi|ack_irq|end_irq|wait_for_interrupt|read_current_sp|disable_irq_save|restore_irq"#,
    ),
    (
        "H — host transport",
        r#"\bhvc\b|\b(?:HVC_[A-Z_]+|Hvc[A-Za-z_]*|SVC_HVC_[A-Z_]+|[A-Z_]*PORT|[A-Z_]*DOORBELL[A-Z_]*)\b|\bdoorbell\b|\bout dx|mailbox_capture|run_el1_service_call|EL1_HYPERCALL|MaintenanceDone"#,
    ),
    (
        "U — user copy/fixup",
        r#"\b(?:ldtr\w*|sttr\w*|par_el1|HardwareValidator|HardwareUserWord|MemoryValidator|UserWord|fixup_pc|copy_to_user_guarded|copy_from_user_guarded|terminal_descriptor_permits_el0|readable_bytes|writable_bytes)\b|\bat s1e|\bfixup\b"#,
    ),
    (
        "B — boot/control layout",
        r#"\b(?:EL1_[A-Z_]*(?:BASE|SIZE|OFFSET|ADDR)|KERNEL_[A-Z_]*(?:BASE|SIZE)|ImageHeader|IMAGE_HEADER_[A-Z_]+|ImageAbiError|CARRICK_EL1_ABI_HASH|EL0_TRAMPOLINE[A-Z_]*|TPIDR_EL1|VBAR_EL1|SCTLR_EL1|TCR_EL1|MAIR_EL1)\b|Reg::(?:VBAR|SCTLR|TCR|MAIR)|\b(?:boot|install_root|set_translation|install_context)\b"#,
    ),
    (
        "W — ISA binding/cfg",
        r#"target_arch\s*=\s*"(?:aarch64|x86_64)"|\b(?:Aarch64Vmm|Aarch64Vcpu|Aarch64EngineCore|Aarch64TaskEngineState|Aarch64TaskRuntimeProjection|Aarch64ResidentTaskMetadata|Aarch64Reg|SysReg|Reg|HardwareCpu|ThreadCpu|X86Register)\b|use carrick_aarch64|crate::esr|pub mod esr|asm!|global_asm!"#,
    ),
];

const ANCHORS: &[(&str, &str, &str, &str)] = &[
    (
        "arch-types",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "pub trait ArchTypes {",
    ),
    (
        "entry-trait",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "arch_trait!(EntryArch, EntryBackend {",
    ),
    (
        "mmu-trait",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "arch_trait!(MmuArch, MmuBackend {",
    ),
    (
        "irq-trait",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "arch_trait!(InterruptArch, InterruptBackend {",
    ),
    (
        "crossing-trait",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "arch_trait!(CrossingArch, CrossingBackend {",
    ),
    (
        "kernel-trait",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "pub trait KernelArch:",
    ),
    (
        "snapshot",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "pub struct NativeEntrySnapshot<'a, F> {",
    ),
    (
        "irq-token",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "pub struct InterruptAck<I> {",
    ),
    (
        "host-ticket",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "pub struct RequestToken<T> {",
    ),
    (
        "root-gpa",
        "S",
        "crates/carrick-guest-arch/src/lib.rs",
        "pub struct RootGpa(FrameGpa);",
    ),
    (
        "cfg-exclusions",
        "S",
        "crates/carrick-el1/src/lib.rs",
        "pub mod cow;",
    ),
    (
        "cfg-personality",
        "S",
        "crates/carrick-el1/src/personality/mod.rs",
        "pub mod dispatch;",
    ),
    (
        "allocator",
        "S",
        "crates/carrick-el1/src/alloc.rs",
        "pub struct MetadataStorage {",
    ),
    (
        "allocator-lock",
        "S",
        "crates/carrick-el1/src/alloc.rs",
        "pub use crate::substrate::sched::hw::{IrqGuard, disable_irq_save, restore_irq};",
    ),
    (
        "allocator-irq",
        "S",
        "crates/carrick-el1/src/alloc.rs",
        "pub fn ensure_bootstrap_admitted(&self) {",
    ),
    (
        "spinlock",
        "S",
        "crates/carrick-el1/src/lock.rs",
        "pub fn lock(&self)",
    ),
    (
        "irq-save",
        "S",
        "crates/carrick-el1/src/sched/hw.rs",
        "pub fn disable_irq_save()",
    ),
    (
        "irq-restore",
        "S",
        "crates/carrick-el1/src/sched/hw.rs",
        "pub fn restore_irq(",
    ),
    (
        "fatal-leaf",
        "S",
        "crates/carrick-el1/src/sched/hw.rs",
        "pub(crate) fn fatal_entry_binding()",
    ),
    (
        "identity",
        "S",
        "crates/carrick-el1/src/sched.rs",
        ".store(id.generation, Ordering::Release);",
    ),
    (
        "scheduler",
        "S",
        "crates/carrick-el1/src/sched.rs",
        "pub struct Sched<'a, C: ThreadCpu, U: UserWord> {",
    ),
    (
        "sched-result",
        "S",
        "crates/carrick-el1/src/sched.rs",
        "self.task.linux.orig_arg0.store(ctx.x[0], Ordering::Relaxed);",
    ),
    (
        "child-context",
        "S",
        "crates/carrick-el1/src/personality/lifecycle.rs",
        "    ctx.x[0] = 0;",
    ),
    (
        "o6-child",
        "O6",
        "crates/carrick-el1/src/personality/lifecycle.rs",
        "ctx.x[0] = context.result.raw() as u64;",
    ),
    (
        "replay",
        "S",
        "crates/carrick-el1/src/personality/ipc.rs",
        "OperationResumePc::new(frame.elr.wrapping_sub(linux::SVC_LEN))",
    ),
    (
        "threadctx",
        "S",
        "crates/carrick-sched-core/src/lib.rs",
        "pub struct ThreadCtx {",
    ),
    (
        "zone-record",
        "S",
        "crates/carrick-sched-core/src/lib.rs",
        "pub struct ZoneRecord {",
    ),
    (
        "record-context",
        "S",
        "crates/carrick-sched-core/src/lib.rs",
        "ctx: UnsafeCell<ThreadCtx>,",
    ),
    (
        "zone-tables",
        "S",
        "crates/carrick-sched-core/src/lib.rs",
        "pub struct ZoneTables {",
    ),
    (
        "parked-copy",
        "S",
        "crates/carrick-sched-core/src/lib.rs",
        "let ctx = unsafe { *record.ctx_mut() };",
    ),
    (
        "trap-frame",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "pub struct TrapFrame {",
    ),
    (
        "current-task",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "pub struct CurrentTask {",
    ),
    (
        "layout-hash",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "pub const EL1_ABI_LAYOUT_HASH: u64 = {",
    ),
    (
        "hash-assert",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "const _: () = assert!(EL1_ABI_LAYOUT_HASH ==",
    ),
    (
        "image-header",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "pub struct ImageHeader {",
    ),
    (
        "metadata-mailbox",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "pub struct MetadataGrantMailbox {",
    ),
    (
        "delegated-file",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "pub struct DelegatedFile {",
    ),
    (
        "delegated-inotify",
        "S",
        "crates/carrick-el1-abi/src/lib.rs",
        "pub struct DelegatedInotify {",
    ),
    (
        "lifecycle-page",
        "S",
        "crates/carrick-el1-abi/src/thread_lifecycle.rs",
        "pub struct ThreadLifecyclePage {",
    ),
    (
        "lifecycle-version",
        "S",
        "crates/carrick-el1-abi/src/thread_lifecycle.rs",
        "pub const THREAD_LIFECYCLE_PROTOCOL_VERSION:",
    ),
    (
        "control-slot",
        "S",
        "crates/carrick-el1-abi/src/thread_lifecycle.rs",
        "pub struct ThreadControlSlot {",
    ),
    (
        "pool-entry",
        "S",
        "crates/carrick-el1-abi/src/thread_lifecycle.rs",
        "pub struct PoolEntry {",
    ),
    (
        "entry-ref",
        "S",
        "crates/carrick-el1-abi/src/thread_lifecycle.rs",
        "pub struct EntryRef {",
    ),
    (
        "portal-slots",
        "S",
        "crates/carrick-el1-abi/src/mm_portal.rs",
        "pub struct MmPortalSlots {",
    ),
    (
        "descriptor-slots",
        "S",
        "crates/carrick-el1-abi/src/descriptor_txn.rs",
        "pub struct DescriptorTxnSlots {",
    ),
    (
        "copy-table",
        "S",
        "crates/carrick-el1-abi/src/service_copy.rs",
        "pub struct ServiceCopyTable {",
    ),
    (
        "native-mailbox",
        "S",
        "crates/carrick-aarch64/src/mailbox.rs",
        "pub use carrick_mem::memory::Aarch64SyscallMailbox;",
    ),
    (
        "mailbox-version",
        "S",
        "crates/carrick-aarch64/src/mailbox.rs",
        "pub const AARCH64_SYSCALL_MAILBOX_VERSION:",
    ),
    (
        "host-zone",
        "S",
        "crates/carrick-runtime/src/vcpu_loop/zone.rs",
        ") -> Result<ThreadCtx, RuntimeError> {",
    ),
    (
        "host-zone-apply",
        "S",
        "crates/carrick-runtime/src/vcpu_loop/zone.rs",
        "    ctx: &mut ThreadCtx,",
    ),
    (
        "host-crash",
        "S",
        "crates/carrick-runtime/src/vcpu_loop/crash.rs",
        "let registers = file.registers;",
    ),
    (
        "host-snapshot",
        "S",
        "crates/carrick-aarch64/src/vmm.rs",
        "pub struct Aarch64VcpuSnapshot {",
    ),
    (
        "native-context",
        "S",
        "crates/carrick-x86/src/cpl0_scheduler.rs",
        "pub struct NativeContext {",
    ),
    (
        "xsave",
        "S",
        "crates/carrick-x86/src/cpl0_scheduler.rs",
        "pub const XSAVE_BYTES:",
    ),
    (
        "cr3-install",
        "S",
        "crates/carrick-x86/src/cpl0_scheduler.rs",
        "pub unsafe fn install_root(",
    ),
    (
        "xcr0",
        "S",
        "crates/carrick-vmm-kvm/src/carrier_interrupts.rs",
        "return Err(fail(\"CPL0 requires qualified XCR0=7\"));",
    ),
    (
        "o6-xcr0",
        "O6",
        "crates/carrick-vmm-kvm/src/carrier_interrupts.rs",
        "return Err(fail(\"CPL0 requires qualified XCR0=7\"));",
    ),
    (
        "noallocation",
        "S",
        "crates/carrick-x86-cpl0/src/entry.rs",
        "struct NoAllocation;",
    ),
    (
        "cpl0-adapter",
        "S",
        "crates/carrick-x86-cpl0/src/entry.rs",
        "#[path = \"../../carrick-x86/src/cpl0_entry.rs\"]",
    ),
    (
        "x86-frame",
        "S",
        "crates/carrick-x86/src/cpl0_entry.rs",
        "pub struct NativeFrame {",
    ),
    (
        "image-bound",
        "S",
        "crates/carrick-el1/link.ld",
        "ASSERT(_image_end <= _image_start + 0x100000,",
    ),
    (
        "guarded-copy",
        "S",
        "crates/carrick-el1/src/file.rs",
        "pub(crate) unsafe fn copy_from_user_guarded",
    ),
    (
        "validator",
        "S",
        "crates/carrick-el1/src/file.rs",
        "fn writable_bytes(&self, user_va: u64, len: usize) -> usize {",
    ),
    (
        "fault",
        "S",
        "crates/carrick-el1/src/fault.rs",
        "pub fn dispatch_fault_with_regions",
    ),
    (
        "owner-mmu",
        "S",
        "crates/carrick-mmu-core/src/owner_mmu.rs",
        "pub trait OwnerMmu",
    ),
    (
        "owner-grant",
        "S",
        "crates/carrick-mmu-core/src/owner_mmu.rs",
        "pub trait OwnerGrantMmu",
    ),
    (
        "core-completion",
        "S",
        "crates/carrick-core-abi/src/entry.rs",
        "pub struct EntryCompletion",
    ),
    (
        "linux-epoll",
        "S",
        "crates/carrick-abi/src/lib.rs",
        "pub struct LinuxX8664EpollEvent {",
    ),
    (
        "arm-epoll",
        "S",
        "crates/carrick-el1/src/personality/ipc/epoll.rs",
        "const EVENT_BYTES: usize = 16;",
    ),
];

fn git(args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn revision(tag: &str) -> Result<&'static str> {
    match tag {
        "S" => Ok(S),
        "O6" => Ok(O6),
        "R" => Ok(R),
        _ => Err(format!("unknown revision {tag}").into()),
    }
}
fn blob(rev: &str, path: &str) -> Result<String> {
    git(&["show", &format!("{rev}:{path}")])
}
fn retained(line: &str) -> bool {
    !line.trim().is_empty() && !line.trim_start().starts_with("//")
}
fn compact(sites: &BTreeSet<usize>) -> String {
    let mut runs = Vec::new();
    let mut iter = sites.iter().copied();
    let Some(mut first) = iter.next() else {
        return String::new();
    };
    let mut last = first;
    for line in iter {
        if line == last + 1 {
            last = line;
        } else {
            runs.push(if first == last {
                first.to_string()
            } else {
                format!("{first}–{last}")
            });
            first = line;
            last = line;
        }
    }
    runs.push(if first == last {
        first.to_string()
    } else {
        format!("{first}–{last}")
    });
    runs.join(", ")
}
#[derive(Default)]
struct Assembly(Vec<(usize, usize)>);
impl<'ast> Visit<'ast> for Assembly {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "asm" || s.ident == "global_asm")
        {
            self.0
                .push((node.span().start().line, node.span().end().line));
        }
        syn::visit::visit_macro(self, node);
    }
}
fn render(document: &str) -> Result<String> {
    let head = document
        .split_once(MARKER)
        .ok_or("missing generated appendix marker")?
        .0;
    let mut citations = BTreeMap::new();
    let mut rows = String::new();
    for &(key, tag, path, needle) in ANCHORS {
        let source = blob(revision(tag)?, path)?;
        let found: Vec<_> = source
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(needle))
            .collect();
        if found.len() != 1 {
            return Err(format!(
                "anchor {key}: expected exactly one {needle:?} in {tag}:{path}, got {}",
                found.len()
            )
            .into());
        }
        let line = found[0].0 + 1;
        let citation = format!("`{tag}:{path}:{line}`");
        if citations.insert(key, citation.clone()).is_some() {
            return Err(format!("duplicate anchor {key}").into());
        }
        writeln!(
            rows,
            "| {key} | {citation} | `{}` |",
            found[0].1.trim().replace('|', "&#124;").replace('`', "'")
        )?;
    }
    let cite_rx = Regex::new(r"<!-- cite:([a-z0-9-]+) -->(?:`[^`]*`)?")?;
    let mut rendered_head = String::new();
    let mut end = 0;
    let mut used = BTreeSet::new();
    for found in cite_rx.captures_iter(head) {
        let complete = found.get(0).ok_or("missing complete citation match")?;
        let key = found.get(1).ok_or("missing citation key")?.as_str();
        let citation = citations
            .get(key)
            .ok_or_else(|| format!("unknown citation key {key}"))?;
        rendered_head.push_str(&head[end..complete.start()]);
        write!(rendered_head, "<!-- cite:{key} -->{citation}")?;
        used.insert(key);
        end = complete.end();
    }
    rendered_head.push_str(&head[end..]);
    let patterns: Vec<_> = PATTERNS
        .iter()
        .map(|(key, value)| Regex::new(value).map(|rx| (*key, rx)))
        .collect::<std::result::Result<_, _>>()?;
    let scopes = [
        "carrick-el1",
        "carrick-el1-abi",
        "carrick-aarch64",
        "carrick-x86",
        "carrick-x86-cpl0",
        "carrick-sched-core",
        "carrick-guest-arch",
    ];
    let counted = [
        "carrick-el1",
        "carrick-el1-abi",
        "carrick-aarch64",
        "carrick-core",
        "carrick-core-abi",
        "carrick-personality-linux",
        "carrick-sched-core",
        "carrick-mmu-core",
        "carrick-guest-arch",
        "carrick-x86",
        "carrick-x86-cpl0",
        "carrick-el1-image",
    ];
    let paths = git(&["ls-tree", "-r", "--name-only", S, "crates"])?;
    let mut census: BTreeMap<&str, BTreeMap<String, BTreeSet<usize>>> = BTreeMap::new();
    let mut union: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut blocks = 0;
    for path in paths.lines().filter(|p| p.ends_with(".rs")) {
        let Some(package) = path
            .strip_prefix("crates/")
            .and_then(|p| p.split_once("/src/"))
            .map(|(pkg, _)| pkg)
        else {
            continue;
        };
        if !counted.contains(&package) {
            continue;
        }
        let source = blob(S, path)?;
        let lines: Vec<_> = source.lines().collect();
        *counts.entry(package).or_default() += lines.iter().filter(|s| retained(s)).count();
        if !scopes.contains(&package) {
            continue;
        }
        for (index, line) in lines.iter().enumerate().filter(|(_, s)| retained(s)) {
            for (group, rx) in &patterns {
                if rx.is_match(line) {
                    census
                        .entry(group)
                        .or_default()
                        .entry(path.to_owned())
                        .or_default()
                        .insert(index + 1);
                    union.entry(path.to_owned()).or_default().insert(index + 1);
                }
            }
        }
        let syntax = syn::parse_file(&source).map_err(|e| format!("parse {path}: {e}"))?;
        let mut assembly = Assembly::default();
        assembly.visit_file(&syntax);
        for (first, last) in assembly.0 {
            if first == 0 || last > lines.len() {
                return Err(format!("invalid asm span {path}:{first}–{last}").into());
            }
            blocks += 1;
            let body = lines[first - 1..last].join("\n");
            let mut groups: Vec<_> = patterns
                .iter()
                .filter(|(group, rx)| !group.starts_with('W') && rx.is_match(&body))
                .map(|(group, _)| *group)
                .collect();
            if groups.is_empty() {
                groups.push(PATTERNS[0].0);
            }
            for line in (first..=last).filter(|line| retained(lines[line - 1])) {
                for group in &groups {
                    census
                        .entry(group)
                        .or_default()
                        .entry(path.to_owned())
                        .or_default()
                        .insert(line);
                }
                union.entry(path.to_owned()).or_default().insert(line);
            }
        }
    }
    let mut out = rendered_head;
    writeln!(
        out,
        "{MARKER}\n\n## Appendix A: regenerated source census and citation anchors\n"
    )?;
    writeln!(
        out,
        "Generated by the committed Rust audit script `docs/superpowers/plans/inversion-census/src/main.rs`. All census sites are at S; semantic anchor rows explicitly select S or O6. The script reads immutable git blobs, resolves each prose anchor from a unique source string, parses asm macro spans with syn (including operands/options), and refuses a missing or ambiguous anchor. This is a conservative lexical inventory plus full native-item spans, not proof of reachability, complete indirect hardware semantics, or machine-code equivalence. Inclusive runs enumerate individual physical source lines. Tests/cfg branches are included. MMU-core's existing ISA modules are audited as whole native items below, without extra relocation credit.\n"
    )?;
    writeln!(
        out,
        "### Source totals\n\n| Crate | Retained src Rust lines | Distinct ISA-site hits |\n| --- | ---: | ---: |"
    )?;
    for pkg in counted {
        let hits: usize = union
            .iter()
            .filter(|(p, _)| p.starts_with(&format!("crates/{pkg}/")))
            .map(|(_, s)| s.len())
            .sum();
        let hit_cell = if scopes.contains(&pkg) {
            hits.to_string()
        } else {
            "not scanned".to_owned()
        };
        writeln!(
            out,
            "| {pkg} | {} | {hit_cell} |",
            counts
                .get(pkg)
                .ok_or_else(|| format!("missing count {pkg}"))?
        )?;
    }
    let arm: usize = scopes[..3]
        .iter()
        .map(|pkg| counts.get(pkg).copied().unwrap_or_default())
        .sum();
    writeln!(
        out,
        "\nThree-crate ARM denominator: **{arm}**. Fully parsed asm macro invocations in the seven scanned packages: **{blocks}**. Blank lines and trimmed `//` prefixes are excluded; block-comment prefixes and Rust dereference assignments are retained. Build scripts and integration tests are outside src and excluded.\n"
    )?;
    if arm != 49_580 {
        return Err(format!("owner denominator drift: {arm}").into());
    }
    writeln!(
        out,
        "### Semantic anchors (generated, including prose citations)\n\n| Key | Citation | Matched source line |\n| --- | --- | --- |\n{rows}"
    )?;
    for (group, _) in PATTERNS {
        writeln!(
            out,
            "### {group}\n\n| Pinned source path (S) | Line sites (inclusive runs) |\n| --- | --- |"
        )?;
        for (path, sites) in census
            .get(group)
            .ok_or_else(|| format!("empty concern {group}"))?
        {
            writeln!(out, "| `{path}` | {} |", compact(sites))?;
        }
        writeln!(out)?;
    }
    writeln!(
        out,
        "### Whole native items and substrate projections\n\nThese full-file spans also cover constant encodings, arithmetic and failure paths without a lexical ISA spelling. Counts above do not add them a second time.\n\n| Concern | Complete native/source span at S |\n| --- | --- |"
    )?;
    for (group, suffix) in [
        ("Trap", "carrick-aarch64/src/esr.rs"),
        ("Context", "carrick-el1/src/sched/aarch64_context.rs"),
        ("Context", "carrick-x86/src/arch_context.rs"),
        ("Trap", "carrick-x86/src/cpl0_entry.rs"),
        ("Context/root", "carrick-x86/src/cpl0_scheduler.rs"),
        ("Coherence", "carrick-aarch64/src/icache.rs"),
        ("Interrupt", "carrick-x86/src/interrupts.rs"),
        ("Boot/transport", "carrick-el1/src/entry.rs"),
        ("Boot/transport", "carrick-x86-cpl0/src/entry.rs"),
        ("Native fixture", "carrick-x86-cpl0/src/progress.rs"),
        ("Boot", "carrick-el1/link.ld"),
        ("MMU contracts", "carrick-mmu-core/src/owner_mmu.rs"),
        ("Descriptor", "carrick-mmu-core/src/aarch64.rs"),
        (
            "Descriptor",
            "carrick-mmu-core/src/aarch64/descriptor_txn.rs",
        ),
        (
            "Descriptor",
            "carrick-mmu-core/src/aarch64/descriptor_txn/copy_window.rs",
        ),
        (
            "Descriptor/COW",
            "carrick-mmu-core/src/aarch64/descriptor_txn/guest_cow.rs",
        ),
        (
            "Descriptor/fork",
            "carrick-mmu-core/src/aarch64/owner_fork.rs",
        ),
        ("Descriptor", "carrick-mmu-core/src/x86/mod.rs"),
        ("Descriptor", "carrick-mmu-core/src/x86/descriptor_txn.rs"),
        ("Descriptor", "carrick-mmu-core/src/x86/owner_mmu.rs"),
    ] {
        let path = format!("crates/{suffix}");
        writeln!(
            out,
            "| {group} | `{path}:1–{}` |",
            blob(S, &path)?.lines().count()
        )?;
    }
    writeln!(out, "\n<!-- END GENERATED APPENDIX A -->")?;
    println!(
        "resolved {} unique source anchors; {} used in prose; {} concern groups; {blocks} asm blocks; ARM denominator {arm}",
        citations.len(),
        used.len(),
        PATTERNS.len()
    );
    Ok(out)
}
#[allow(
    clippy::disallowed_methods,
    reason = "Standalone documentation audit: read the caller-selected plan, never guest/product files"
)]
fn read_document(path: &std::path::Path) -> Result<String> {
    Ok(fs::read_to_string(path)?)
}
#[allow(
    clippy::disallowed_methods,
    reason = "Standalone documentation audit: --write explicitly authorizes regeneration of the caller-selected plan"
)]
fn write_document(path: &std::path::Path, text: &str) -> Result<()> {
    Ok(fs::write(path, text)?)
}
fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("use --check or --write, optionally --document PATH")?;
    let path = match args.next().as_deref() {
        None => PathBuf::from(PLAN),
        Some("--document") => PathBuf::from(args.next().ok_or("missing --document path")?),
        _ => return Err("unexpected argument".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    if mode != "--check" && mode != "--write" {
        return Err("use --check or --write".into());
    }
    let current = read_document(&path)?;
    let generated = render(&current)?;
    if mode == "--write" {
        write_document(&path, &generated)?;
        println!("regenerated {}", path.display());
    } else if current != generated {
        return Err(format!(
            "{} has stale citations/Appendix A; run --write",
            path.display()
        )
        .into());
    } else {
        println!("citations and Appendix A match immutable source inputs");
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("inversion-census: {e}");
            ExitCode::FAILURE
        }
    }
}
