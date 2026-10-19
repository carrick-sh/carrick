//! Worst-case ring stack depth from a built ring image.
//!
//! The stable toolchain has no `-Z emit-stack-sizes`, so the audit reads the
//! image the build produced: `llvm-objdump` disassembly plus the ELF's loaded
//! data words. Every function's frame is the sum of its stack-pointer
//! decrements (pre-indexed stores and `sub sp` on AArch64, `push`, `sub rsp`
//! and `and rsp` on x86_64, including stack-probe targets). The call graph is
//! every direct and tail call. An indirect call is never guessed: each
//! function that makes one must be named by an [`IndirectRule`], whose budget
//! is charged at that call. Each recursive cycle must be named by a
//! [`RecursionRule`] with an iteration bound. Anything unnamed fails.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::elf::ElfData;

/// The two ring instruction sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    /// Stack bytes a call itself consumes before the callee's prologue.
    const fn call_overhead(self) -> u64 {
        match self {
            // `bl` leaves the return address in x30.
            Self::Aarch64 => 0,
            // `call` pushes the return address.
            Self::X86_64 => 8,
        }
    }
}

/// One function of a ring image.
#[derive(Clone, Debug)]
pub struct Function {
    /// The demangled symbol exactly as `llvm-objdump --demangle` prints it.
    pub raw: String,
    /// [`Function::raw`] with Rust's legacy escapes decoded and the hash and
    /// LLVM suffixes removed: what rules match.
    pub name: String,
    pub start: u64,
    pub end: u64,
    /// Bytes this function's own prologue takes from the stack.
    pub frame: u64,
    /// Direct and tail callees (indices into [`Image::functions`]).
    pub calls: BTreeSet<usize>,
    /// Indirect calls and indirect tail calls (jump tables excluded).
    pub indirect_calls: usize,
    /// Branch targets outside every function.
    pub stray_targets: Vec<u64>,
    /// Stack adjustments by a register amount, which no static bound covers.
    pub dynamic_adjustments: Vec<String>,
    /// Whether the function touches its frame page by page as it grows it
    /// (LLVM inline stack probes), so it cannot step over a guard.
    pub probes: bool,
    /// Whether the image takes this function's address (a data word, or an
    /// `adrp`/`add`, `adr` or `lea [rip]` in code): a possible target of
    /// every indirect call.
    pub address_taken: bool,
}

/// A parsed ring image.
#[derive(Clone, Debug)]
pub struct Image {
    pub arch: Arch,
    pub functions: Vec<Function>,
}

/// Decode Rust's legacy symbol escapes and drop the `::h<hash>` and
/// ` (.llvm.N)` suffixes, leaving a stable, readable path.
pub fn normalize(raw: &str) -> String {
    let mut name = raw;
    if let Some(index) = name.find(" (.llvm.") {
        name = &name[..index];
    }
    if let Some(index) = name.rfind("::h")
        && name[index + 3..].len() == 16
        && name[index + 3..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        name = &name[..index];
    }
    let mut decoded = name.to_owned();
    for (escape, plain) in [
        ("$LT$", "<"),
        ("$GT$", ">"),
        ("$u20$", " "),
        ("$C$", ","),
        ("$RF$", "&"),
        ("$BP$", "*"),
        ("$LP$", "("),
        ("$RP$", ")"),
        ("$u27$", "'"),
        ("$u5b$", "["),
        ("$u5d$", "]"),
        ("$u7b$", "{"),
        ("$u7d$", "}"),
        ("$u7e$", "~"),
        ("$SP$", "@"),
        ("..", "::"),
    ] {
        decoded = decoded.replace(escape, plain);
    }
    decoded
        .strip_prefix("_<")
        .map(|rest| format!("<{rest}"))
        .unwrap_or(decoded)
}

fn parse_header(line: &str) -> Option<(u64, &str)> {
    let line = line.trim_end();
    let body = line.strip_suffix(">:")?;
    let (address, name) = body.split_once(" <")?;
    if address.is_empty() || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((u64::from_str_radix(address, 16).ok()?, name))
}

fn parse_instruction(line: &str) -> Option<(u64, &str)> {
    let (address, rest) = line.split_once(':')?;
    let address = address.trim();
    if address.is_empty() || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let text = rest.trim();
    if text.is_empty() {
        return None;
    }
    Some((u64::from_str_radix(address, 16).ok()?, text))
}

fn split_instruction(text: &str) -> (&str, &str) {
    let text = text.split("//").next().unwrap_or(text).trim();
    match text.split_once(char::is_whitespace) {
        Some((mnemonic, operands)) => (mnemonic, operands.trim()),
        None => (text, ""),
    }
}

/// An immediate in `#0x1f`, `#31`, `0x1f` or `-0x40` form.
fn immediate(token: &str) -> Option<i128> {
    let token = token.trim().trim_start_matches('#');
    let (negative, digits) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) => i128::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<i128>().ok()?,
    };
    Some(if negative { -value } else { value })
}

/// The first hexadecimal address operand of a branch (`0x...`).
fn branch_target(operands: &str) -> Option<u64> {
    operands
        .split([',', ' ', '\t'])
        .find_map(|token| token.strip_prefix("0x"))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

/// The `# 0x...` address llvm-objdump annotates on a `[rip + disp]` operand.
fn rip_slot(operands: &str) -> Option<u64> {
    let (_, comment) = operands.split_once('#')?;
    branch_target(comment.trim())
}

/// `sub <reg>, <base>, #imm[, lsl #12]` amount, if this is that form.
fn aarch64_sub_amount(operands: &str, destination: &str, base: &str) -> Option<u64> {
    let mut parts = operands.split(',').map(str::trim);
    if parts.next()? != destination || parts.next()? != base {
        return None;
    }
    let amount = immediate(parts.next()?)?;
    let shifted = match parts.next() {
        None => amount,
        Some("lsl #12") => amount << 12,
        Some(_) => return None,
    };
    u64::try_from(shifted).ok()
}

/// AArch64 frame: pre-indexed stores to SP plus `sub sp` or, when LLVM
/// probes and realigns through x9, the x9 target plus the realignment slack.
/// The same counting rule `carrick-el1-image` pinned for #338, over the
/// whole body so a shrink-wrapped prologue is not missed.
fn aarch64_frame(body: &[(u64, &str)], dynamic: &mut Vec<String>) -> u64 {
    // x9 is LLVM's probe/realign target. Between `sub x9, sp, #N` and the
    // end of its probe loop (`cmp sp, x9`) or realignment (`and sp, x9`),
    // the loop's `sub sp, sp, #4096` steps are part of N; a residual
    // `sub sp, sp, #R` after the loop is counted again.
    let mut frame = 0_u64;
    let mut aligned = false;
    let mut in_probe = false;
    let mut alignment = 64_u64;
    for (_, text) in body {
        let (mnemonic, operands) = split_instruction(text);
        if (mnemonic == "stp" || mnemonic == "str")
            && let Some((_, rest)) = operands.split_once("[sp, #-")
            && rest.ends_with("]!")
            && let Some(amount) = immediate(rest.trim_end_matches("]!"))
            && let Ok(amount) = u64::try_from(amount)
        {
            frame = frame.saturating_add(amount);
            continue;
        }
        if mnemonic == "sub" {
            if let Some(amount) = aarch64_sub_amount(operands, "x9", "sp") {
                aligned = true;
                in_probe = true;
                frame = frame.saturating_add(amount);
            } else if in_probe && let Some(amount) = aarch64_sub_amount(operands, "x9", "x9") {
                frame = frame.saturating_add(amount);
            } else if !in_probe && let Some(amount) = aarch64_sub_amount(operands, "sp", "sp") {
                frame = frame.saturating_add(amount);
            } else if operands.starts_with("sp, sp, x") || operands.starts_with("sp, sp, w") {
                dynamic.push((*text).to_owned());
            }
            continue;
        }
        if mnemonic == "cmp" && operands == "sp, x9" {
            in_probe = false;
        }
        if mnemonic == "and" && operands.starts_with("sp, x9, ") {
            in_probe = false;
        }
        if mnemonic == "and"
            && let Some(mask) = operands.strip_prefix("sp, x9, ")
            && let Some(mask) = immediate(mask)
            && let Ok(mask) = u64::try_from(mask & i128::from(u64::MAX))
        {
            alignment = alignment.max((!mask).saturating_add(1));
        }
    }
    if aligned {
        frame = frame.saturating_add(alignment - 1);
    }
    frame
}

/// x86_64 frame: pushes, `sub rsp` (unrolled probes included) and `and rsp`
/// realignment slack. The return address is charged by the caller's edge.
fn x86_frame(body: &[(u64, &str)], dynamic: &mut Vec<String>) -> u64 {
    // LLVM's large-frame probe loop: `mov r11, rsp; sub r11, N; L: sub rsp,
    // 0x1000; mov qword ptr [rsp], 0; cmp rsp, r11; jne L`. N is the frame;
    // the loop's page step is not counted again.
    let mut frame = 0_u64;
    let mut probe_base = false;
    let mut in_probe_loop = false;
    for (_, text) in body {
        let (mnemonic, operands) = split_instruction(text);
        let starts_probe = mnemonic == "mov" && operands == "r11, rsp";
        match mnemonic {
            "push" => frame = frame.saturating_add(8),
            "sub" => {
                if let Some(amount) = operands.strip_prefix("rsp, ") {
                    match immediate(amount).and_then(|value| u64::try_from(value).ok()) {
                        Some(_) if in_probe_loop => {}
                        Some(value) => frame = frame.saturating_add(value),
                        None => dynamic.push((*text).to_owned()),
                    }
                } else if probe_base && let Some(amount) = operands.strip_prefix("r11, ") {
                    match immediate(amount).and_then(|value| u64::try_from(value).ok()) {
                        Some(value) => {
                            frame = frame.saturating_add(value);
                            in_probe_loop = true;
                        }
                        None => dynamic.push((*text).to_owned()),
                    }
                }
            }
            "cmp" if operands == "rsp, r11" => in_probe_loop = false,
            "and" => {
                if let Some(mask) = operands.strip_prefix("rsp, ")
                    && let Some(mask) = immediate(mask)
                    && mask < 0
                {
                    frame = frame.saturating_add(u64::try_from(-mask - 1).unwrap_or(0));
                }
            }
            _ => {}
        }
        probe_base = starts_probe;
    }
    frame
}

/// Whether the AArch64 `br`/`blr` at `index` dispatches through a jump table
/// (`adr base; ...; add reg, base, offset; br reg`) rather than calling.
fn aarch64_jump_table(body: &[(u64, &str)], index: usize, register: &str) -> bool {
    let window = &body[index.saturating_sub(8)..index];
    window.iter().any(|(_, text)| {
        let (mnemonic, operands) = split_instruction(text);
        if mnemonic != "add" {
            return false;
        }
        let mut parts = operands.split(',').map(str::trim);
        if parts.next() != Some(register) {
            return false;
        }
        let Some(base) = parts.next() else {
            return false;
        };
        window.iter().any(|(_, prior)| {
            let (mnemonic, operands) = split_instruction(prior);
            mnemonic == "adr" && operands.split(',').next().map(str::trim) == Some(base)
        })
    })
}

/// Whether the x86_64 `jmp` at `index` is a jump-table dispatch: a scaled
/// table operand, or a register computed from a `movsxd` table entry.
fn x86_jump_table(body: &[(u64, &str)], index: usize, operands: &str) -> bool {
    if operands.contains("*") && operands.contains('[') {
        return true;
    }
    let register = operands.trim_start_matches("notrack").trim();
    let window = &body[index.saturating_sub(8)..index];
    window.iter().any(|(_, text)| {
        let (mnemonic, operands) = split_instruction(text);
        mnemonic == "movsxd" && operands.starts_with(register)
    })
}

struct RawFunction<'a> {
    raw: &'a str,
    start: u64,
    body: Vec<(u64, &'a str)>,
}

impl Image {
    /// Parse `llvm-objdump -d --demangle` output (Intel syntax on x86_64).
    /// `data` resolves x86_64 calls through linker-filled `[rip + disp]`
    /// slots; without it they count as indirect.
    pub fn parse(arch: Arch, disassembly: &str, data: Option<&ElfData>) -> Result<Self, String> {
        let mut raw_functions: Vec<RawFunction<'_>> = Vec::new();
        let mut in_text = false;
        for line in disassembly.lines() {
            if line.starts_with("Disassembly of section") {
                in_text = true;
                continue;
            }
            if !in_text {
                continue;
            }
            if let Some((start, raw)) = parse_header(line) {
                raw_functions.push(RawFunction {
                    raw,
                    start,
                    body: Vec::new(),
                });
                continue;
            }
            if let Some(instruction) = parse_instruction(line)
                && let Some(function) = raw_functions.last_mut()
            {
                function.body.push(instruction);
            }
        }
        if raw_functions.is_empty() {
            return Err("disassembly lists no functions".to_owned());
        }
        raw_functions.sort_by_key(|function| function.start);
        let starts: Vec<u64> = raw_functions
            .iter()
            .map(|function| function.start)
            .collect();
        let mut by_start = BTreeMap::new();
        for (index, start) in starts.iter().enumerate() {
            by_start.insert(*start, index);
        }
        let ends: Vec<u64> = raw_functions
            .iter()
            .enumerate()
            .map(|(index, function)| {
                starts.get(index + 1).copied().unwrap_or_else(|| {
                    function
                        .body
                        .last()
                        .map_or(function.start, |(address, _)| address + 4)
                })
            })
            .collect();
        let containing = |address: u64| -> Option<usize> {
            let index = starts
                .partition_point(|start| *start <= address)
                .checked_sub(1)?;
            (address < ends[index]).then_some(index)
        };
        let mut functions = Vec::with_capacity(raw_functions.len());
        for (index, function) in raw_functions.iter().enumerate() {
            let (start, end) = (function.start, ends[index]);
            let mut dynamic = Vec::new();
            let frame = match arch {
                Arch::Aarch64 => aarch64_frame(&function.body, &mut dynamic),
                Arch::X86_64 => x86_frame(&function.body, &mut dynamic),
            };
            let mut calls = BTreeSet::new();
            let mut indirect_calls = 0;
            let mut stray_targets = Vec::new();
            let edge = |target: u64, calls: &mut BTreeSet<usize>, strays: &mut Vec<u64>| {
                if (start..end).contains(&target) && target != start {
                    return;
                }
                match containing(target) {
                    Some(callee) => {
                        calls.insert(callee);
                    }
                    None => strays.push(target),
                }
            };
            for (position, (_, text)) in function.body.iter().enumerate() {
                let (mnemonic, operands) = split_instruction(text);
                match arch {
                    Arch::Aarch64 => match mnemonic {
                        "bl" | "b" | "cbz" | "cbnz" | "tbz" | "tbnz" => {
                            if let Some(target) = branch_target(operands) {
                                edge(target, &mut calls, &mut stray_targets);
                            }
                        }
                        _ if mnemonic.starts_with("b.") => {
                            if let Some(target) = branch_target(operands) {
                                edge(target, &mut calls, &mut stray_targets);
                            }
                        }
                        "blr" | "br" => {
                            let register = operands.trim();
                            if !aarch64_jump_table(&function.body, position, register) {
                                indirect_calls += 1;
                            }
                        }
                        _ => {}
                    },
                    Arch::X86_64 => {
                        let is_call = mnemonic == "call";
                        let is_jump = mnemonic == "jmp" || mnemonic.starts_with('j');
                        if !is_call && !is_jump {
                            continue;
                        }
                        if operands.starts_with("0x") {
                            if let Some(target) = branch_target(operands) {
                                edge(target, &mut calls, &mut stray_targets);
                            }
                            continue;
                        }
                        if operands.contains("[rip") {
                            let resolved = rip_slot(operands)
                                .and_then(|slot| data.and_then(|data| data.word_at(slot)))
                                .and_then(|target| by_start.get(&target).copied());
                            match resolved {
                                Some(callee) => {
                                    calls.insert(callee);
                                }
                                None => indirect_calls += 1,
                            }
                            continue;
                        }
                        if !is_call && x86_jump_table(&function.body, position, operands) {
                            continue;
                        }
                        indirect_calls += 1;
                    }
                }
            }
            functions.push(Function {
                raw: function.raw.to_owned(),
                name: normalize(function.raw),
                start,
                end,
                frame,
                calls,
                indirect_calls,
                stray_targets,
                dynamic_adjustments: dynamic,
                address_taken: false,
                probes: function.body.iter().any(|(_, text)| {
                    let (mnemonic, operands) = split_instruction(text);
                    match arch {
                        Arch::Aarch64 => {
                            (mnemonic == "str" || mnemonic == "ldr")
                                && operands.starts_with("xzr, [sp")
                        }
                        Arch::X86_64 => mnemonic == "mov" && operands == "qword ptr [rsp], 0x0",
                    }
                }),
            });
        }
        // Every address the image materializes: a target of indirect calls.
        let mut taken = BTreeSet::new();
        for function in &raw_functions {
            let mut pages: BTreeMap<String, u64> = BTreeMap::new();
            for (_, text) in &function.body {
                let (mnemonic, operands) = split_instruction(text);
                let mut parts = operands.split(',').map(str::trim);
                let destination = parts.next().unwrap_or_default().to_owned();
                let address = match (arch, mnemonic) {
                    (Arch::Aarch64, "adrp") => {
                        if let Some(page) = parts.next().and_then(branch_target) {
                            pages.insert(destination, page);
                        }
                        None
                    }
                    (Arch::Aarch64, "adr") => parts.next().and_then(branch_target),
                    (Arch::Aarch64, "add") => {
                        let base = parts.next().and_then(|base| pages.get(base).copied());
                        let offset = parts
                            .next()
                            .and_then(immediate)
                            .and_then(|offset| u64::try_from(offset).ok());
                        base.zip(offset)
                            .map(|(base, offset)| base.wrapping_add(offset))
                    }
                    (Arch::X86_64, "lea") if operands.contains("[rip") => rip_slot(operands),
                    (Arch::X86_64, "mov" | "movabs") => parts
                        .next()
                        .and_then(immediate)
                        .and_then(|value| u64::try_from(value).ok()),
                    _ => None,
                };
                if let Some(index) = address.and_then(|address| by_start.get(&address)) {
                    taken.insert(*index);
                }
            }
        }
        if let Some(data) = data {
            for word in data.words() {
                if let Some(index) = by_start.get(&word) {
                    taken.insert(*index);
                }
            }
        }
        for index in taken {
            functions[index].address_taken = true;
        }
        Ok(Self { arch, functions })
    }

    fn find_exact(&self, name: &str) -> Option<usize> {
        self.functions
            .iter()
            .position(|function| function.raw == name || function.name == name)
    }
}

/// A function pinned to its own frame ceiling (the #338 exit-frame pins).
#[derive(Clone, Copy, Debug)]
pub struct NamedCeiling {
    /// Substring of the demangled symbol, as `llvm-objdump` prints it.
    pub symbol: &'static str,
    pub ceiling: u64,
    /// A required pin fails when no function matches.
    pub required: bool,
}

/// One function of a recursive cycle and the most activations of it that
/// can be live on one stack.
#[derive(Clone, Copy, Debug)]
pub struct RecursionMember {
    /// Substring of the member's normalized name.
    pub pattern: &'static str,
    pub max_live: u64,
}

/// A recursive cycle with reviewed activation bounds. The cycle costs each
/// member's frame times its bound.
#[derive(Clone, Copy, Debug)]
pub struct RecursionRule {
    pub members: &'static [RecursionMember],
    pub why: &'static str,
}

/// Functions whose indirect calls are reviewed: each indirect call from a
/// function whose normalized name contains `caller` is charged `budget`.
#[derive(Clone, Copy, Debug)]
pub struct IndirectRule {
    pub caller: &'static str,
    pub budget: u64,
    pub why: &'static str,
}

/// What a ring image must satisfy.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub arch: Arch,
    /// Exact symbols where the ring is entered on a fresh per-CPU stack.
    pub entries: &'static [&'static str],
    /// Bytes each entry chain may use with every recursive cycle live once:
    /// exceeding it is a statically certain overflow.
    pub stack_budget: u64,
    /// Ratchet on each entry chain with every recursive cycle at its
    /// reviewed bound. It may only decrease, toward `stack_budget`; beyond
    /// the usable stack the guard page faults at run time.
    pub bounded_ceiling: u64,
    /// Ratchet on each entry chain with every indirect call resolved to the
    /// deepest address-taken function (each recursion once). May only
    /// decrease, toward `stack_budget`.
    pub resolved_ceiling: u64,
    /// The same with every recursion at its bound; may only decrease.
    pub resolved_bounded_ceiling: u64,
    /// The unmapped guard below each stack: a larger frame must probe it.
    pub guard: u64,
    /// Ceiling for every function's own frame in the image.
    pub function_ceiling: u64,
    pub named_ceilings: &'static [NamedCeiling],
    pub recursion: &'static [RecursionRule],
    pub indirect: &'static [IndirectRule],
}

/// One step of an entry's deepest chain.
#[derive(Clone, Debug)]
pub enum Link {
    Call {
        name: String,
        frame: u64,
    },
    Recursion {
        members: Vec<String>,
        iterations: u64,
        bytes: u64,
    },
    Indirect {
        caller: String,
        rule: &'static str,
        budget: u64,
    },
}

/// How an entry chain counts recursion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    /// Every recursive cycle live once: the overflow is statically certain.
    Certain,
    /// Every recursive cycle at its rule's activation bound.
    Bounded,
}

/// How an entry chain charges indirect calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Each indirect call costs its `IndirectRule` budget.
    Declared,
    /// Each indirect call costs the larger of its budget and the deepest
    /// address-taken function's own (declared) chain: every function whose
    /// address the image takes is a possible target.
    Resolved,
}

/// One entry's worst case.
#[derive(Clone, Debug)]
pub struct EntryDepth {
    pub entry: String,
    pub kind: Depth,
    pub resolution: Resolution,
    pub depth: u64,
    pub budget: u64,
    pub chain: Vec<Link>,
}

/// A failed audit condition.
#[derive(Clone, Debug)]
pub enum Violation {
    FunctionCeiling {
        name: String,
        frame: u64,
        ceiling: u64,
    },
    NamedCeiling {
        symbol: &'static str,
        name: String,
        frame: u64,
        ceiling: u64,
    },
    MissingNamedCeiling {
        symbol: &'static str,
    },
    MissingEntry {
        entry: &'static str,
    },
    UnknownRecursion {
        members: Vec<String>,
    },
    UnknownIndirect {
        caller: String,
        sites: usize,
    },
    StrayBranch {
        caller: String,
        target: u64,
    },
    DynamicStackAdjustment {
        caller: String,
        instruction: String,
    },
    UnprobedFrame {
        name: String,
        frame: u64,
        guard: u64,
    },
    EntryBudget(EntryDepth),
}

/// The audit's result: every entry's worst case and every violation.
#[derive(Clone, Debug)]
pub struct Report {
    pub arch: Arch,
    /// Address-taken functions: the possible targets of every indirect call.
    pub indirect_targets: usize,
    /// The deepest address-taken target's own chain, per depth kind.
    pub deepest_target: Vec<(Depth, String, u64)>,
    /// Usable stack bytes per entry chain.
    pub stack_budget: u64,
    pub entries: Vec<EntryDepth>,
    pub largest_frame: Option<(String, u64)>,
    pub reachable: usize,
    pub violations: Vec<Violation>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for Link {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call { name, frame } => write!(formatter, "{frame:#7x}  {name}"),
            Self::Recursion {
                members,
                iterations,
                bytes,
            } => write!(
                formatter,
                "{bytes:#7x}  recursion x{iterations}: {}",
                members.join(" <-> ")
            ),
            Self::Indirect {
                caller,
                rule,
                budget,
            } => write!(
                formatter,
                "{budget:#7x}  indirect call from {caller} (rule `{rule}`)"
            ),
        }
    }
}

impl fmt::Display for EntryDepth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "{} ({}, {}): worst case {} of {} bytes ({} bytes headroom)",
            self.entry,
            match self.kind {
                Depth::Certain => "each recursion once",
                Depth::Bounded => "recursion at its bound",
            },
            match self.resolution {
                Resolution::Declared => "indirect calls at their budgets",
                Resolution::Resolved => "indirect calls resolved to every address-taken target",
            },
            self.depth,
            self.budget,
            self.budget as i128 - self.depth as i128
        )?;
        let mut total = 0_u64;
        for link in &self.chain {
            total = total.saturating_add(match link {
                Link::Call { frame, .. } => *frame,
                Link::Recursion { bytes, .. } => *bytes,
                Link::Indirect { budget, .. } => *budget,
            });
            writeln!(formatter, "    {total:#7x} {link}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FunctionCeiling {
                name,
                frame,
                ceiling,
            } => write!(
                formatter,
                "ring function frame {frame:#x} exceeds the per-function ceiling {ceiling:#x}: {name}"
            ),
            Self::NamedCeiling {
                symbol,
                name,
                frame,
                ceiling,
            } => write!(
                formatter,
                "EL1 exit frame {symbol}: {frame:#x} exceeds {ceiling:#x} ({name})"
            ),
            Self::MissingNamedCeiling { symbol } => {
                write!(formatter, "missing EL1 exit frame {symbol}")
            }
            Self::MissingEntry { entry } => {
                write!(formatter, "ring entry {entry} is not in the image")
            }
            Self::UnknownRecursion { members } => write!(
                formatter,
                "recursion with no RecursionRule bound: {}",
                members.join(" <-> ")
            ),
            Self::UnknownIndirect { caller, sites } => write!(
                formatter,
                "{sites} indirect call(s) with no IndirectRule budget in {caller}"
            ),
            Self::StrayBranch { caller, target } => write!(
                formatter,
                "branch from {caller} to {target:#x}, outside every function"
            ),
            Self::DynamicStackAdjustment {
                caller,
                instruction,
            } => write!(
                formatter,
                "unbounded stack adjustment `{instruction}` in {caller}"
            ),
            Self::UnprobedFrame { name, frame, guard } => write!(
                formatter,
                "frame {frame:#x} is larger than the {guard:#x}-byte guard and never probes it: {name}"
            ),
            Self::EntryBudget(depth) => write!(formatter, "ring stack budget exceeded by {depth}"),
        }
    }
}

/// Tarjan's strongly connected components over `nodes`, iteratively.
fn components(image: &Image, nodes: &BTreeSet<usize>) -> Vec<Vec<usize>> {
    #[derive(Clone, Copy)]
    struct State {
        index: usize,
        low: usize,
        on_stack: bool,
    }
    let mut state: BTreeMap<usize, State> = BTreeMap::new();
    let mut stack = Vec::new();
    let mut result = Vec::new();
    let mut next = 0;
    for &root in nodes {
        if state.contains_key(&root) {
            continue;
        }
        let mut work: Vec<(usize, Vec<usize>)> = Vec::new();
        state.insert(
            root,
            State {
                index: next,
                low: next,
                on_stack: true,
            },
        );
        next += 1;
        stack.push(root);
        work.push((root, image.functions[root].calls.iter().copied().collect()));
        while let Some((node, pending)) = work.last_mut() {
            let node = *node;
            if let Some(child) = pending.pop() {
                if !nodes.contains(&child) {
                    continue;
                }
                match state.get(&child).copied() {
                    None => {
                        state.insert(
                            child,
                            State {
                                index: next,
                                low: next,
                                on_stack: true,
                            },
                        );
                        next += 1;
                        stack.push(child);
                        work.push((
                            child,
                            image.functions[child].calls.iter().copied().collect(),
                        ));
                    }
                    Some(child_state) if child_state.on_stack => {
                        if let Some(entry) = state.get_mut(&node) {
                            entry.low = entry.low.min(child_state.index);
                        }
                    }
                    Some(_) => {}
                }
                continue;
            }
            work.pop();
            let Some(node_state) = state.get(&node).copied() else {
                continue;
            };
            if let Some((parent, _)) = work.last()
                && let Some(parent_state) = state.get_mut(parent)
            {
                parent_state.low = parent_state.low.min(node_state.low);
            }
            if node_state.low == node_state.index {
                let mut component = Vec::new();
                while let Some(member) = stack.pop() {
                    if let Some(entry) = state.get_mut(&member) {
                        entry.on_stack = false;
                    }
                    component.push(member);
                    if member == node {
                        break;
                    }
                }
                result.push(component);
            }
        }
    }
    result
}

/// Audit `image` against `policy`.
pub fn audit(image: &Image, policy: &Policy) -> Report {
    let mut violations = Vec::new();
    let overhead = image.arch.call_overhead();

    let largest_frame = image
        .functions
        .iter()
        .max_by_key(|function| function.frame)
        .map(|function| (function.name.clone(), function.frame));
    for function in &image.functions {
        if function.frame > policy.function_ceiling {
            violations.push(Violation::FunctionCeiling {
                name: function.name.clone(),
                frame: function.frame,
                ceiling: policy.function_ceiling,
            });
        }
    }
    for function in &image.functions {
        if function.frame > policy.guard && !function.probes {
            violations.push(Violation::UnprobedFrame {
                name: function.name.clone(),
                frame: function.frame,
                guard: policy.guard,
            });
        }
    }
    for pin in policy.named_ceilings {
        let mut found = false;
        for function in image
            .functions
            .iter()
            .filter(|f| f.raw.contains(pin.symbol))
        {
            found = true;
            if function.frame == 0 || function.frame > pin.ceiling {
                violations.push(Violation::NamedCeiling {
                    symbol: pin.symbol,
                    name: function.name.clone(),
                    frame: function.frame,
                    ceiling: pin.ceiling,
                });
            }
        }
        if pin.required && !found {
            violations.push(Violation::MissingNamedCeiling { symbol: pin.symbol });
        }
    }

    let mut roots = Vec::new();
    for entry in policy.entries {
        match image.find_exact(entry) {
            Some(index) => roots.push(index),
            None => violations.push(Violation::MissingEntry { entry }),
        }
    }
    // Every address-taken function is a possible target of every indirect
    // call, so each is audited as an entry of its own (and covered by the
    // same recursion and indirect-call rules).
    // A policy with no entries (the pins-only clippy policy) audits no chain.
    let targets: Vec<usize> = (0..image.functions.len())
        .filter(|index| !policy.entries.is_empty() && image.functions[*index].address_taken)
        .collect();
    let mut reachable = BTreeSet::new();
    let mut work = roots.clone();
    work.extend(targets.iter().copied());
    while let Some(node) = work.pop() {
        if reachable.insert(node) {
            work.extend(image.functions[node].calls.iter().copied());
        }
    }
    for &node in &reachable {
        let function = &image.functions[node];
        for target in &function.stray_targets {
            violations.push(Violation::StrayBranch {
                caller: function.name.clone(),
                target: *target,
            });
        }
        for instruction in &function.dynamic_adjustments {
            violations.push(Violation::DynamicStackAdjustment {
                caller: function.name.clone(),
                instruction: instruction.clone(),
            });
        }
    }

    // Charge each function's indirect calls from its rule.
    let mut indirect_budget: BTreeMap<usize, (u64, &'static str)> = BTreeMap::new();
    for &node in &reachable {
        let function = &image.functions[node];
        if function.indirect_calls == 0 {
            continue;
        }
        match policy
            .indirect
            .iter()
            .find(|rule| function.name.contains(rule.caller))
        {
            Some(rule) => {
                indirect_budget.insert(node, (rule.budget, rule.caller));
            }
            None => violations.push(Violation::UnknownIndirect {
                caller: function.name.clone(),
                sites: function.indirect_calls,
            }),
        }
    }

    // Condense cycles; a cycle costs its bound times all its members' frames.
    let mut component_of = BTreeMap::new();
    let mut component_cost = Vec::new();
    let all = components(image, &reachable);
    for (id, members) in all.iter().enumerate() {
        for member in members {
            component_of.insert(*member, id);
        }
        let recursive =
            members.len() > 1 || image.functions[members[0]].calls.contains(&members[0]);
        if !recursive {
            component_cost.push(None);
            continue;
        }
        let names: Vec<String> = members
            .iter()
            .map(|member| image.functions[*member].name.clone())
            .collect();
        let bound = |rule: &RecursionRule, name: &str| {
            rule.members
                .iter()
                .find(|member| name.contains(member.pattern))
                .map(|member| member.max_live)
        };
        let rule = policy
            .recursion
            .iter()
            .find(|rule| names.iter().all(|name| bound(rule, name).is_some()));
        match rule {
            Some(rule) => {
                let mut bytes = 0_u64;
                let mut iterations = 0_u64;
                for member in members {
                    let function = &image.functions[*member];
                    let live = bound(rule, &function.name).unwrap_or(1);
                    iterations = iterations.max(live);
                    bytes = bytes.saturating_add((function.frame + overhead).saturating_mul(live));
                }
                component_cost.push(Some((iterations, bytes)));
            }
            None => {
                violations.push(Violation::UnknownRecursion { members: names });
                component_cost.push(Some((1, 0)));
            }
        }
    }

    let once: Vec<u64> = all
        .iter()
        .map(|members| {
            members.iter().fold(0_u64, |sum, member| {
                sum.saturating_add(image.functions[*member].frame + overhead)
            })
        })
        .collect();
    let compute = |kind: Depth, charge: &dyn Fn(usize) -> Option<u64>| {
        // Deepest chain per component, children first (Tarjan emits them first).
        let mut depth = vec![0_u64; all.len()];
        let mut next_hop: Vec<Option<Hop>> = vec![None; all.len()];
        for (id, members) in all.iter().enumerate() {
            let own = match (component_cost[id], kind) {
                (None, _) => image.functions[members[0]].frame,
                (Some(_), Depth::Certain) => once[id],
                (Some((_, bytes)), Depth::Bounded) => bytes.max(once[id]),
            };
            let mut best = 0_u64;
            let mut hop = None;
            for member in members {
                for callee in &image.functions[*member].calls {
                    let Some(&callee_id) = component_of.get(callee) else {
                        continue;
                    };
                    if callee_id == id {
                        continue;
                    }
                    let candidate = depth[callee_id].saturating_add(overhead);
                    if candidate > best {
                        best = candidate;
                        hop = Some(Hop::Call(*callee));
                    }
                }
                if let Some(bytes) = charge(*member) {
                    let candidate = bytes.saturating_add(overhead);
                    if candidate > best {
                        best = candidate;
                        hop = Some(Hop::Indirect(*member));
                    }
                }
            }
            depth[id] = own.saturating_add(best);
            next_hop[id] = hop;
        }
        (depth, next_hop)
    };

    let mut entries = Vec::new();
    let mut deepest_target = Vec::new();
    for kind in [Depth::Certain, Depth::Bounded] {
        // Declared budgets first: what each address-taken target's own
        // chain needs when its indirect calls are charged their rules.
        let declared = |member: usize| indirect_budget.get(&member).map(|(budget, _)| *budget);
        let (target_depth, target_hops) = compute(kind, &declared);
        let deepest = targets
            .iter()
            .filter_map(|target| {
                component_of
                    .get(target)
                    .map(|id| (target_depth[*id], *target))
            })
            .max();
        let target_max = deepest.map_or(0, |(bytes, _)| bytes);
        if let Some((bytes, target)) = deepest {
            deepest_target.push((kind, image.functions[target].name.clone(), bytes));
        }
        // Then every indirect call is charged the larger of its rule and the
        // deepest address-taken target, whose chain follows in the report.
        let resolved = |member: usize| {
            indirect_budget
                .get(&member)
                .map(|(budget, _)| (*budget).max(target_max))
        };
        let (resolved_depth, resolved_hops) = compute(kind, &resolved);

        for resolution in [Resolution::Declared, Resolution::Resolved] {
            let (depth, next_hop) = match resolution {
                Resolution::Declared => (&target_depth, &target_hops),
                Resolution::Resolved => (&resolved_depth, &resolved_hops),
            };
            for &root in &roots {
                let Some(&id) = component_of.get(&root) else {
                    continue;
                };
                let mut chain = Vec::new();
                let mut current = Some(Hop::Call(root));
                let mut hops = next_hop;
                let mut steps = 0;
                while let Some(hop) = current.take() {
                    steps += 1;
                    if steps > 2 * all.len() + 2 {
                        break;
                    }
                    let lead = if chain.is_empty() { 0 } else { overhead };
                    match hop {
                        Hop::Indirect(caller) => {
                            let rule = indirect_budget.get(&caller).map_or("", |(_, rule)| *rule);
                            let budget = indirect_budget
                                .get(&caller)
                                .map_or(0, |(budget, _)| *budget);
                            match deepest {
                                // The target's own chain is the deeper charge.
                                Some((bytes, target))
                                    if resolution == Resolution::Resolved
                                        && bytes > budget
                                        && std::ptr::eq(hops, &resolved_hops) =>
                                {
                                    chain.push(Link::Indirect {
                                        caller: image.functions[caller].name.clone(),
                                        rule,
                                        budget: overhead,
                                    });
                                    hops = &target_hops;
                                    current = Some(Hop::Call(target));
                                }
                                _ => chain.push(Link::Indirect {
                                    caller: image.functions[caller].name.clone(),
                                    rule,
                                    budget: budget + overhead,
                                }),
                            }
                        }
                        Hop::Call(function) => {
                            let Some(&component) = component_of.get(&function) else {
                                break;
                            };
                            match component_cost[component] {
                                Some((iterations, bytes)) => chain.push(Link::Recursion {
                                    members: all[component]
                                        .iter()
                                        .map(|member| image.functions[*member].name.clone())
                                        .collect(),
                                    iterations: if kind == Depth::Certain {
                                        1
                                    } else {
                                        iterations
                                    },
                                    bytes: lead
                                        + if kind == Depth::Certain {
                                            once[component]
                                        } else {
                                            bytes.max(once[component])
                                        },
                                }),
                                None => chain.push(Link::Call {
                                    name: image.functions[function].name.clone(),
                                    frame: image.functions[function].frame + lead,
                                }),
                            }
                            current = hops[component];
                        }
                    }
                }
                let budget = match (kind, resolution) {
                    (Depth::Certain, Resolution::Declared) => policy.stack_budget,
                    (Depth::Bounded, Resolution::Declared) => policy.bounded_ceiling,
                    (Depth::Certain, Resolution::Resolved) => policy.resolved_ceiling,
                    (Depth::Bounded, Resolution::Resolved) => policy.resolved_bounded_ceiling,
                };
                let entry = EntryDepth {
                    entry: image.functions[root].name.clone(),
                    kind,
                    resolution,
                    depth: depth[id],
                    budget,
                    chain,
                };
                if entry.depth > budget {
                    violations.push(Violation::EntryBudget(entry.clone()));
                }
                entries.push(entry);
            }
        }
    }

    Report {
        arch: image.arch,
        stack_budget: policy.stack_budget,
        entries,
        indirect_targets: targets.len(),
        deepest_target,
        largest_frame,
        reachable: reachable.len(),
        violations,
    }
}

#[derive(Clone, Copy, Debug)]
enum Hop {
    Call(usize),
    Indirect(usize),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const ENTRY: &[&str] = &["entry"];

    fn policy(arch: Arch) -> Policy {
        Policy {
            arch,
            entries: ENTRY,
            stack_budget: 0x1000,
            bounded_ceiling: 0x1000,
            resolved_ceiling: 0x1000,
            resolved_bounded_ceiling: 0x1000,
            guard: 0x1000,
            function_ceiling: 0x800,
            named_ceilings: &[],
            recursion: &[],
            indirect: &[],
        }
    }

    fn image(arch: Arch, text: &str) -> Image {
        let disassembly = format!("\nDisassembly of section .text:\n\n{text}");
        Image::parse(arch, &disassembly, None).expect("synthetic image parses")
    }

    fn function<'a>(image: &'a Image, name: &str) -> &'a Function {
        image
            .functions
            .iter()
            .find(|function| function.name == name)
            .expect("function present")
    }

    #[test]
    fn aarch64_frames_count_pre_indexed_stores_sub_sp_and_probe_targets() {
        let image = image(
            Arch::Aarch64,
            "0000000000001000 <entry>:\n\
             \x20   1000:\tstp\tx29, x30, [sp, #-0x20]!\n\
             \x20   1004:\tsub\tsp, sp, #0x1, lsl #12   // =0x1000\n\
             \x20   1008:\tstr\txzr, [sp]\n\
             \x20   100c:\tsub\tsp, sp, #0x40\n\
             \x20   1010:\tret\n\
             \n\
             0000000000001100 <realigned>:\n\
             \x20   1100:\tstp\tx29, x30, [sp, #-0x10]!\n\
             \x20   1104:\tsub\tx9, sp, #0xc0\n\
             \x20   1108:\tand\tsp, x9, #0xffffffffffffffc0\n\
             \x20   110c:\tret\n",
        );
        let entry = function(&image, "entry");
        assert_eq!(entry.frame, 0x20 + 0x1000 + 0x40);
        assert!(entry.probes);
        assert_eq!(function(&image, "realigned").frame, 0x10 + 0xc0 + 63);
    }

    #[test]
    fn aarch64_frames_count_a_residual_after_the_probe_loop() {
        let image = image(
            Arch::Aarch64,
            "0000000000001000 <entry>:\n\
             \x20   1000:\tstp\tx29, x30, [sp, #-0x40]!\n\
             \x20   1004:\tsub\tx9, sp, #0x20, lsl #12  // =0x20000\n\
             \x20   1008:\tsub\tsp, sp, #0x1, lsl #12   // =0x1000\n\
             \x20   100c:\tcmp\tsp, x9\n\
             \x20   1010:\tstr\txzr, [sp]\n\
             \x20   1014:\tb.ne\t0x1008 <entry+0x8>\n\
             \x20   1018:\tsub\tsp, sp, #0x40\n\
             \x20   101c:\tret\n",
        );
        // The pre-index, the loop target, the residual, realignment slack.
        assert_eq!(function(&image, "entry").frame, 0x40 + 0x20000 + 0x40 + 63);
    }

    #[test]
    fn x86_frames_count_the_probe_loop_target_once() {
        let image = image(
            Arch::X86_64,
            "ffffffff80001000 <entry>:\n\
             ffffffff80001000:\tpush\trbp\n\
             ffffffff80001001:\tmov\trbp, rsp\n\
             ffffffff80001004:\tpush\trbx\n\
             ffffffff80001005:\tmov\tr11, rsp\n\
             ffffffff80001008:\tsub\tr11, 0x10000\n\
             ffffffff8000100f:\tsub\trsp, 0x1000\n\
             ffffffff80001016:\tmov\tqword ptr [rsp], 0x0\n\
             ffffffff8000101e:\tcmp\trsp, r11\n\
             ffffffff80001021:\tjne\t0xffffffff8000100f <entry+0xf>\n\
             ffffffff80001023:\tsub\trsp, 0x10\n\
             ffffffff80001027:\tret\n",
        );
        let entry = function(&image, "entry");
        assert_eq!(entry.frame, 16 + 0x10000 + 0x10);
        assert!(entry.probes);
    }

    #[test]
    fn an_oversized_frame_fails_its_ceiling_and_its_entry_chain() {
        let image = image(
            Arch::Aarch64,
            "0000000000001000 <entry>:\n\
             \x20   1000:\tstp\tx29, x30, [sp, #-0x10]!\n\
             \x20   1004:\tbl\t0x1100 <record>\n\
             \x20   1008:\tret\n\
             \n\
             0000000000001100 <record>:\n\
             \x20   1100:\tstp\tx29, x30, [sp, #-0x10]!\n\
             \x20   1104:\tsub\tsp, sp, #0x1, lsl #12\n\
             \x20   1108:\tret\n",
        );
        let report = audit(&image, &policy(Arch::Aarch64));
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            Violation::FunctionCeiling { name, frame: 0x1010, .. } if name == "record"
        )));
        // An unprobed frame wider than the guard could step over it.
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            Violation::UnprobedFrame { name, .. } if name == "record"
        )));
        let certain = report
            .entries
            .iter()
            .find(|entry| entry.kind == Depth::Certain)
            .expect("certain depth");
        assert_eq!(certain.depth, 0x1020);
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            Violation::EntryBudget(depth) if depth.kind == Depth::Certain && depth.depth == 0x1020
        )));
    }

    #[test]
    fn unnamed_recursion_and_indirect_calls_fail_and_named_ones_are_charged() {
        let text = "0000000000001000 <entry>:\n\
             \x20   1000:\tstp\tx29, x30, [sp, #-0x10]!\n\
             \x20   1004:\tbl\t0x1100 <walk>\n\
             \x20   1008:\tblr\tx8\n\
             \x20   100c:\tadr\tx10, 0x1010 <entry+0x10>\n\
             \x20   1010:\tadd\tx10, x10, x11, lsl #2\n\
             \x20   1014:\tbr\tx10\n\
             \n\
             0000000000001100 <walk>:\n\
             \x20   1100:\tstp\tx29, x30, [sp, #-0x80]!\n\
             \x20   1104:\tbl\t0x1100 <walk>\n\
             \x20   1108:\tret\n";
        let image = image(Arch::Aarch64, text);
        assert_eq!(
            function(&image, "entry").indirect_calls,
            1,
            "jump tables are not calls"
        );
        let report = audit(&image, &policy(Arch::Aarch64));
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            Violation::UnknownRecursion { members } if members == &["walk".to_owned()]
        )));
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            Violation::UnknownIndirect { caller, sites: 1 } if caller == "entry"
        )));

        const RECURSION: &[RecursionRule] = &[RecursionRule {
            members: &[RecursionMember {
                pattern: "walk",
                max_live: 4,
            }],
            why: "test",
        }];
        const INDIRECT: &[IndirectRule] = &[IndirectRule {
            caller: "entry",
            budget: 0x100,
            why: "test",
        }];
        let named = Policy {
            recursion: RECURSION,
            indirect: INDIRECT,
            ..policy(Arch::Aarch64)
        };
        let report = audit(&image, &named);
        assert!(report.passed(), "{:?}", report.violations);
        let depth = |kind| {
            report
                .entries
                .iter()
                .find(|entry| entry.kind == kind)
                .map(|entry| entry.depth)
        };
        // The entry, then the deeper of the walk (one or four frames) and the
        // indirect budget.
        assert_eq!(depth(Depth::Certain), Some(0x10 + 0x100));
        assert_eq!(depth(Depth::Bounded), Some(0x10 + 4 * 0x80));
    }

    /// #369 review P1: an indirect call is charged the deepest function
    /// whose address the image takes, not only its declared budget.
    #[test]
    fn indirect_calls_resolve_to_the_deepest_address_taken_function() {
        let image = image(
            Arch::Aarch64,
            "0000000000001000 <entry>:\n\
             \x20   1000:\tstp\tx29, x30, [sp, #-0x10]!\n\
             \x20   1004:\tadr\tx8, 0x1100 <deep>\n\
             \x20   1008:\tblr\tx8\n\
             \x20   100c:\tret\n\
             \n\
             0000000000001100 <deep>:\n\
             \x20   1100:\tstp\tx29, x30, [sp, #-0x10]!\n\
             \x20   1104:\tsub\tsp, sp, #0x7f0\n\
             \x20   1108:\tret\n",
        );
        assert!(function(&image, "deep").address_taken);
        assert!(!function(&image, "entry").address_taken);
        const INDIRECT: &[IndirectRule] = &[IndirectRule {
            caller: "entry",
            budget: 0x100,
            why: "test",
        }];
        let policy = Policy {
            indirect: INDIRECT,
            ..policy(Arch::Aarch64)
        };
        let report = audit(&image, &policy);
        let depth = |resolution| {
            report
                .entries
                .iter()
                .find(|entry| {
                    entry.entry == "entry"
                        && entry.kind == Depth::Certain
                        && entry.resolution == resolution
                })
                .map(|entry| entry.depth)
        };
        assert_eq!(depth(Resolution::Declared), Some(0x10 + 0x100));
        assert_eq!(depth(Resolution::Resolved), Some(0x10 + 0x800));
        assert_eq!(report.indirect_targets, 1);
    }

    #[test]
    fn legacy_symbols_normalize_to_stable_paths() {
        assert_eq!(
            normalize(
                "_$LT$carrick_core..mm..A$LT$P$C$G$GT$$u20$as$u20$carrick_core..B$GT$::f::h0123456789abcdef"
            ),
            "<carrick_core::mm::A<P,G> as carrick_core::B>::f"
        );
        assert_eq!(normalize("memset (.llvm.123)"), "memset");
    }
}
