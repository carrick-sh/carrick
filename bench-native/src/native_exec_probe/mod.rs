mod report;

use report::{ProbeReport, Status};

pub fn run_from_env() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage());
    };

    if args.next().is_some() {
        return Err(usage());
    }

    match command.as_str() {
        "page-size" => Err("page-size probe is implemented in Task 2".to_string()),
        "fixed-map" => Err("fixed-map probe is implemented in Task 2".to_string()),
        "execmem" => Err("execmem probe is implemented in Task 3".to_string()),
        "brk-trap" => Err("brk-trap probe is implemented in Task 4".to_string()),
        "branch-gateway" => Err("branch-gateway probe is implemented in Task 5".to_string()),
        "fault-discriminator" => {
            Err("fault-discriminator probe is implemented in Task 6".to_string())
        }
        "all" => run_all(),
        _ => Err(usage()),
    }
}

fn run_all() -> Result<(), String> {
    Err("all probe is implemented after the individual probes exist".to_string())
}

fn print_one(report: ProbeReport) -> Result<(), String> {
    let failed = report.status() == Status::Fail;
    report.print();
    if failed {
        Err("native execution feasibility probe failed".to_string())
    } else {
        Ok(())
    }
}

fn usage() -> String {
    "usage: native_exec_probe page-size|fixed-map|execmem|brk-trap|branch-gateway|fault-discriminator|all".to_string()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
