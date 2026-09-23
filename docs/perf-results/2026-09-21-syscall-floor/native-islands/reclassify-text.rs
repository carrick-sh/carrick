//! Static comparison against the recovered DSR decoder. Never executes code.
use anyhow::{Context, Result, ensure};
use carrick_dsr_aarch64::{
    decode,
    types::{InstAction, MemoryClass, MemoryVirtualization},
};
use carrick_guest_mem::GuestVa;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn hex(site: &Value, key: &str) -> Result<u64> {
    let value = site[key].as_str().context("missing hex site value")?;
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}

#[expect(
    clippy::disallowed_methods,
    reason = "Offline operator-selected diagnostic JSON; no guest path or execution"
)]
fn load_input(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

fn label(action: InstAction) -> (String, bool) {
    match action {
        InstAction::Unsupported { op, .. } => (format!("unsupported.{op:?}"), false),
        InstAction::Memory(access) => (
            format!("memory.{:?}.{:?}", access.class, access.virtualization),
            access.class != MemoryClass::Unsupported
                && access.virtualization != MemoryVirtualization::Unsupported,
        ),
        InstAction::Sensitive(exit) => {
            let detail = format!("{:?}", exit.kind);
            (
                format!("sensitive.{}", detail.split('(').next().unwrap_or(&detail)),
                true,
            )
        }
        InstAction::Direct(exit) => (format!("direct.{:?}", exit.kind), true),
        InstAction::Indirect(exit) => (format!("indirect.{:?}", exit.kind), true),
        other => {
            let detail = format!("{other:?}");
            (
                detail.split([' ', '(']).next().unwrap_or(&detail).into(),
                true,
            )
        }
    }
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: reclassify-text AUDIT.json")?;
    let input: Value = serde_json::from_slice(&load_input(&path)?)?;
    ensure!(
        input["schema"] == "native-slice-static-text-coverage-v1",
        "unexpected input schema"
    );
    let mut results = Vec::new();
    for symbol in input["symbols"].as_array().context("missing symbols")? {
        let sites = symbol["instructions"]
            .as_array()
            .context("missing instructions")?;
        let mut classes = BTreeMap::<String, usize>::new();
        let mut rejected = Vec::new();
        for site in sites {
            let word = u32::try_from(hex(site, "word")?)?;
            let address = GuestVa(hex(site, "address")?);
            match decode::classify(word, address) {
                Ok(action) => {
                    let (class, supported) = label(action);
                    *classes.entry(class.clone()).or_default() += 1;
                    if !supported {
                        rejected.push(json!({"site": site, "reason": class}));
                    }
                }
                Err(error) => {
                    *classes.entry("decode-error".into()).or_default() += 1;
                    rejected.push(json!({"site": site, "reason": error.to_string()}));
                }
            }
        }
        results.push(json!({
            "symbol": symbol["symbol"],
            "instruction_sites": sites.len(),
            "actions": classes,
            "rejected_sites_count": rejected.len(),
            "rejected_sites": rejected,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "dsr-static-decoder-coverage-v1",
            "input": path,
            "limitation": "Decoder actions only, not current-MM emission, executable authority, native execution, branch linking, atomic ordering or measured coverage. Sensitive actions may require helpers or region fusion. No guest code is executed.",
            "symbols": results,
        }))?
    );
    Ok(())
}
