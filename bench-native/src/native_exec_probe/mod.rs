#![allow(dead_code)]

mod execmem;
mod fault;
mod mapping;
mod report;
mod trap;

use execmem::execmem;
use fault::fault_discriminator;
use mapping::{fixed_map_child, page_size};
use report::{ProbeReport, Status};
use trap::{branch_gateway, brk_trap};

pub fn run_from_env() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage());
    };

    if args.next().is_some() {
        return Err(usage());
    }

    match command.as_str() {
        "page-size" => print_one(page_size()?),
        "fixed-map" => print_one(fixed_map_child()?),
        "execmem" => print_one(execmem()?),
        "brk-trap" => print_one(brk_trap()?),
        "branch-gateway" => print_one(branch_gateway()?),
        "fault-discriminator" => print_one(fault_discriminator()?),
        "all" => run_all(),
        _ => Err(usage()),
    }
}

fn run_all() -> Result<(), String> {
    let reports = [
        page_size()?,
        fixed_map_child()?,
        execmem()?,
        brk_trap()?,
        branch_gateway()?,
        fault_discriminator()?,
    ];

    let failed = reports.iter().any(|report| report.status() == Status::Fail);
    for report in reports {
        report.print();
    }

    if failed {
        Err("native execution feasibility probe failed".to_string())
    } else {
        Ok(())
    }
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
