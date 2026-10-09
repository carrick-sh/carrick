//! Release EL1 stack budget from emitted frame sizes and linked direct calls.
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

// The 12 KiB mapped stack retains 2 KiB for interrupt frames and indirect
// calls that the linked direct-call graph cannot resolve.
const LIMIT: u64 = 10 * 1024;
const VECTOR_FRAME: u64 = 288; // TrapFrame, asserted in carrick-el1-abi.

#[derive(clap::Args, Debug, Clone)]
pub struct El1StackArgs {
    #[arg(long)]
    pub image: PathBuf,
}

#[derive(Default)]
struct Function {
    name: String,
    calls: Vec<u64>,
}

fn output(program: &Path, args: &[&str]) -> Result<String, String> {
    let result = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    if !result.status.success() {
        return Err(format!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    String::from_utf8(result.stdout).map_err(|e| e.to_string())
}

fn names_in_entry(names: &str) -> Vec<&str> {
    let mut depth = 0isize;
    let mut start = 0usize;
    let mut result = Vec::new();
    for (at, ch) in names.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => {
                result.push(names[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    result.push(names[start..].trim());
    result
}

fn parse_sizes(raw: &str) -> Result<HashMap<String, u64>, String> {
    let mut sizes = HashMap::new();
    let mut pending = None;
    for line in raw.lines() {
        let line = line.trim();
        if let Some(names) = line
            .strip_prefix("Functions: [")
            .and_then(|line| line.strip_suffix(']'))
        {
            pending = Some(names);
        } else if let (Some(names), Some(size)) = (pending.take(), line.strip_prefix("Size: 0x")) {
            let size = u64::from_str_radix(size, 16).map_err(|e| e.to_string())?;
            for name in names_in_entry(names) {
                sizes.insert(name.to_owned(), size);
            }
        }
    }
    if sizes.is_empty() {
        return Err("EL1 image has no emitted stack sizes".into());
    }
    Ok(sizes)
}

fn parse_calls(raw: &str) -> HashMap<u64, Function> {
    let mut functions = HashMap::<u64, Function>::new();
    let mut current = None;
    for line in raw.lines() {
        if let Some((address, rest)) = line.split_once(" <")
            && let Some(name) = rest.strip_suffix(">:")
            && let Ok(address) = u64::from_str_radix(address, 16)
        {
            functions.insert(
                address,
                Function {
                    name: name.to_owned(),
                    calls: Vec::new(),
                },
            );
            current = Some(address);
            continue;
        }
        let Some(address) = current else { continue };
        let mut words = line.split_ascii_whitespace();
        if let Some(at) = words.position(|word| word == "bl")
            && at >= 2
            && let Some(target) = words.next().and_then(|word| word.strip_prefix("0x"))
            && let Ok(target) = u64::from_str_radix(target, 16)
        {
            functions.entry(address).or_default().calls.push(target);
        }
    }
    functions
}

fn terminal_without_emitted_size(name: &str, calls: &[u64]) -> bool {
    // These are linked compiler-rt leaves or diverging panic paths. A new
    // missing symbol fails the audit instead of silently receiving zero.
    (calls.is_empty()
        && matches!(
            name,
            "memcpy" | "memmove" | "memset" | "memcmp" | "OUTLINED_FUNCTION_0"
        ))
        || name.starts_with("core::panicking::")
        || name.starts_with("core::option::unwrap_failed")
        || name.starts_with("core::slice::index::slice_index_fail")
        || name.starts_with("alloc::alloc::handle_alloc_error")
        || name.starts_with("alloc::raw_vec::handle_error")
        || name.starts_with("alloc::raw_vec::capacity_overflow")
}

fn recursive_limit(name: &str) -> Option<usize> {
    // AArch64 stage-1 has four table levels. The cloned signal-action map
    // has at most 64 keys, within four BTree levels.
    if name.contains("carrick_core::mm::fork::copy_table")
        || name.contains("carrick_core::mm::fork::copy_entry")
        || name.contains("carrick_core::mm::fork::census_entry")
        || name.contains("clone_subtree::<carrick_signal_core::policy::Signal")
    {
        Some(4)
    } else {
        None
    }
}

fn peak(
    address: u64,
    functions: &HashMap<u64, Function>,
    sizes: &HashMap<String, u64>,
    active: &mut Vec<u64>,
) -> Result<(u64, Vec<String>), String> {
    let function = functions
        .get(&address)
        .ok_or(format!("missing call target {address:#x}"))?;
    let repeated = active
        .iter()
        .filter(|candidate| **candidate == address)
        .count();
    if repeated != 0 {
        let limit = recursive_limit(&function.name)
            .ok_or(format!("unbounded EL1 recursion: {}", function.name))?;
        if repeated >= limit {
            return Ok((0, Vec::new()));
        }
    }
    let frame = match sizes.get(&function.name) {
        Some(frame) => *frame,
        None if terminal_without_emitted_size(&function.name, &function.calls) => 0,
        None => return Err(format!("missing EL1 stack size: {}", function.name)),
    };
    if !sizes.contains_key(&function.name) {
        return Ok((0, Vec::new()));
    }
    active.push(address);
    let mut deepest = (0, Vec::new());
    for child in &function.calls {
        if functions.contains_key(child) {
            let candidate = peak(*child, functions, sizes, active)?;
            if candidate.0 > deepest.0 {
                deepest = candidate;
            }
        }
    }
    active.pop();
    deepest.1.insert(0, format!("{frame:5} {}", function.name));
    Ok((frame + deepest.0, deepest.1))
}

pub fn run(args: El1StackArgs, writer: &mut impl Write) -> Result<(), String> {
    let sysroot = output(Path::new("rustc"), &["--print", "sysroot"])?;
    let version = output(Path::new("rustc"), &["-vV"])?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc did not report a host triple")?;
    let llvm = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin");
    let image = args.image.to_str().ok_or("non-UTF-8 EL1 image path")?;
    let sizes = parse_sizes(&output(
        &llvm.join("llvm-readobj"),
        &["-C", "--stack-sizes", image],
    )?)?;
    let functions = parse_calls(&output(
        &llvm.join("llvm-objdump"),
        &["--demangle", "--disassemble", image],
    )?);
    let roots: Vec<_> = functions
        .iter()
        .filter(|(_, f)| f.name.contains("ProcessNative<") && f.name.ends_with("::fork"))
        .collect();
    if roots.len() != 1 {
        return Err(format!(
            "expected one AArch64 owner fork, found {}",
            roots.len()
        ));
    }
    let fork = peak(*roots[0].0, &functions, &sizes, &mut Vec::new())?;
    let dispatch = *sizes
        .get("carrick_el1::personality::dispatch::dispatch_syscall")
        .ok_or("missing dispatch frame")?;
    let entry = *sizes
        .get("carrick_el1_syscall")
        .ok_or("missing EL1 entry frame")?;
    let total = fork.0 + dispatch + entry + VECTOR_FRAME;
    writeln!(writer, "EL1 fork stack: fork={} dispatch={dispatch} entry={entry} vector={VECTOR_FRAME} total={total} budget={LIMIT}", fork.0).map_err(|e| e.to_string())?;
    for frame in &fork.1 {
        writeln!(writer, "{frame}").map_err(|e| e.to_string())?;
    }
    if total > LIMIT {
        return Err(format!(
            "EL1 fork path exceeds {LIMIT} bytes by {}",
            total - LIMIT
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_keep_each_emitted_frame_size() {
        let sizes = parse_sizes("Functions: [one, <two<a, b>>::call]\nSize: 0x20\n")
            .expect("valid emitted sizes");
        assert_eq!(sizes.get("one"), Some(&32));
        assert_eq!(sizes.get("<two<a, b>>::call"), Some(&32));
    }

    #[test]
    fn unknown_recursion_fails_closed() {
        let functions = HashMap::from([(
            1,
            Function {
                name: "unbounded".into(),
                calls: vec![1],
            },
        )]);
        let sizes = HashMap::from([("unbounded".into(), 16)]);
        assert!(
            peak(1, &functions, &sizes, &mut Vec::new())
                .expect_err("recursive stack path must be refused")
                .contains("unbounded EL1 recursion")
        );
    }
}
