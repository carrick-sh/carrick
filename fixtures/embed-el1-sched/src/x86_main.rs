//! Native x86 entry for the same ARM lifecycle and IPC workload modules.
#[allow(dead_code)]
mod fixture_common;
use fixture_common::*;
#[allow(dead_code)]
mod ipc;
#[allow(dead_code)]
mod threads;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let number =
        |i: usize, default: usize| args.get(i).and_then(|v| v.parse().ok()).unwrap_or(default);
    let rc = match args.get(1).map(String::as_str).unwrap_or("") {
        "thread-spawn-slope" => threads::spawn_slope(number(2, 8), number(3, 2)),
        "fork-storm" => threads::fork_storm(number(2, 1)),
        "exit-group-storm" => threads::exit_group_storm(number(2, 1)),
        "exec-storm" => threads::exec_storm(number(2, 1), &args[0]),
        "exec-storm-child" => threads::exec_storm_child(),
        "mask-storm" => threads::mask_storm(number(2, 32)),
        "futex-flood" => threads::futex_flood(number(2, 32)),
        "ipc-processes" => ipc::processes(
            args.get(2).map(String::as_str).unwrap_or("pipe"),
            number(3, 1),
            number(4, 128),
        ),
        _ => {
            eprintln!("unknown x86 scenario");
            2
        }
    };
    std::process::exit(rc);
}
