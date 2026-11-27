//! `carrick debug zonedump`: one carrier's in-guest scheduler zone state.
//!
//! Every source prints the same census, written by the shared
//! `ZoneTables::write_census` and `CurrentTask::write_census`: the zone's
//! slots, idle and queued maps, futex buckets and object wait queues (head,
//! tail, epoch), every record in use (claim, tid, mm, and a parked record's
//! saved syscall number and arguments), and each slot's current task and
//! service notice.
//!
//! - `--run-id`: a live carrier, through its run-scoped debug endpoint (the
//!   non-aborting capture; ARM HVF and x86 KVM).
//! - `--post-mortem`: a capture file written by `carrick debug capture`,
//!   `carrick debug abort` or a deadline capture.
//! - `--region`: a raw image of an ARM EL1 region from its first byte, for
//!   a cored or stopped carrier (for example lldb's `memory read --force
//!   --binary` of `carrick_el1_abi::EL1_REGION_HOST_PTR` for
//!   `EL1_REGION_SIZE` bytes). The layout comes from `carrick-el1-abi`.

use anyhow::{Context, Result};
use std::path::Path;

/// Where the zone state comes from.
pub(crate) enum ZoneSource<'a> {
    Live(&'a str),
    PostMortem(&'a Path),
    Region(&'a Path),
}

pub(crate) fn run_zonedump(source: ZoneSource<'_>) -> Result<()> {
    let text = match source {
        ZoneSource::Live(run_id) => {
            let capture = carrick_kernel::kernel::debug::capture(run_id)
                .map_err(|error| anyhow::anyhow!("{error}"))
                .with_context(|| format!("capture live run {run_id}"))?;
            render_capture(&capture)?
        }
        ZoneSource::PostMortem(path) => {
            let bytes = read_input(path)?;
            let capture: carrick_kernel::kernel::debug::PostMortem = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse post-mortem {}", path.display()))?;
            render_capture(&capture)?
        }
        ZoneSource::Region(path) => render_region(path)?,
    };
    print!("{text}");
    Ok(())
}

/// The one host file read of this diagnostic: a capture or region image the
/// operator named.
fn read_input(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read {}", path.display()))
}

/// The zone sections of one capture (`PostMortem::zone_report`).
fn render_capture(capture: &carrick_kernel::kernel::debug::PostMortem) -> Result<String> {
    capture.zone_report().ok_or_else(|| {
        anyhow::anyhow!(
            "the capture carries no zone state (no in-guest scheduler zone was installed)"
        )
    })
}

/// A heap value of `T` copied from `size_of::<T>()` bytes of `image` at
/// `offset`.
///
/// # Safety
/// `T` must be a shared-memory ABI type for which every byte pattern is a
/// valid value (atomics and plain words), as the EL1 region's types are:
/// the guest writes them, and the host already reads them in place.
unsafe fn read_abi<T>(image: &[u8], offset: u64) -> Result<Box<T>> {
    let layout = std::alloc::Layout::new::<T>();
    anyhow::ensure!(layout.size() != 0, "zero-sized ABI read");
    let source = usize::try_from(offset)
        .ok()
        .and_then(|start| image.get(start..start.checked_add(layout.size())?))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "read {} bytes at region offset {offset:#x}: image is {} bytes",
                layout.size(),
                image.len()
            )
        })?;
    // SAFETY: nonzero layout.
    let ptr = unsafe { std::alloc::alloc(layout) };
    anyhow::ensure!(!ptr.is_null(), "allocate {} bytes", layout.size());
    // SAFETY: `ptr` owns `layout.size()` bytes; the copy initializes all of
    // them, and any byte pattern is a valid T (caller contract).
    unsafe {
        std::ptr::copy_nonoverlapping(source.as_ptr(), ptr, layout.size());
        Ok(Box::from_raw(ptr.cast::<T>()))
    }
}

type CurrentTasks = [carrick_el1_abi::CurrentTask; carrick_el1_abi::EL1_STACK_SLOTS as usize];

/// Decode an ARM EL1 region image through the ABI types.
fn render_region(path: &Path) -> Result<String> {
    let image = read_input(path)?;
    let needed = carrick_el1_abi::EL1_ZONE_OFFSET
        + std::mem::size_of::<carrick_el1_abi::ZoneTables>() as u64;
    let len = image.len() as u64;
    anyhow::ensure!(
        len >= needed,
        "region image {} is {len:#x} bytes; the zone ends at {needed:#x} (EL1_ZONE_OFFSET {:#x}), so it is not a whole EL1 region",
        path.display(),
        carrick_el1_abi::EL1_ZONE_OFFSET
    );
    // SAFETY: both are EL1-region ABI types made of atomics and plain words.
    let zone: Box<carrick_el1_abi::ZoneTables> =
        unsafe { read_abi(&image, carrick_el1_abi::EL1_ZONE_OFFSET)? };
    // SAFETY: as above.
    let tasks: Box<CurrentTasks> =
        unsafe { read_abi(&image, carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET)? };
    let mut out = format!("region: {}\n", path.display());
    zone.write_census(&mut out)
        .map_err(|_| anyhow::anyhow!("format the zone census"))?;
    carrick_el1_abi::write_current_tasks_census(&tasks[..], &mut out)
        .map_err(|_| anyhow::anyhow!("format the current-task census"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn bytes_of<T>(value: &T) -> &[u8] {
        // SAFETY: reading the initialized bytes of a live value.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(value).cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        }
    }

    #[test]
    fn region_image_reads_zone_records_and_service_notices_through_the_abi_layout() {
        use carrick_el1_abi::{EL1_CURRENT_TASKS_OFFSET, EL1_ZONE_OFFSET, SlotId};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("region.bin");
        // A whole region image, sparse except for the two tables.
        let mut file = std::fs::File::create(&path).unwrap();
        let zeros = vec![0u8; std::mem::size_of::<carrick_el1_abi::ZoneTables>()];
        // SAFETY: zero is the valid empty zone.
        let zone: Box<carrick_el1_abi::ZoneTables> = unsafe { read_abi(&zeros, 0).unwrap() };
        drop(zeros);
        zone.enter_idle(SlotId::new(2), false, &carrick_el1_abi::OwedPasses::new());
        let tasks: [carrick_el1_abi::CurrentTask; 2] = [
            carrick_el1_abi::CurrentTask::new(),
            carrick_el1_abi::CurrentTask::new(),
        ];
        tasks[1]
            .execution
            .task
            .store(17, std::sync::atomic::Ordering::Relaxed);
        file.seek(SeekFrom::Start(EL1_CURRENT_TASKS_OFFSET))
            .unwrap();
        file.write_all(bytes_of(&tasks)).unwrap();
        file.seek(SeekFrom::Start(EL1_ZONE_OFFSET)).unwrap();
        file.write_all(bytes_of(&*zone)).unwrap();
        drop(file);
        let text = render_region(&path).unwrap();
        assert!(
            text.contains("zone maps: idle_slots=[2] queued_slots=[]"),
            "{text}"
        );
        assert!(
            text.contains("el1 task slot 1: tid=17 ")
                && text.contains("service_notice=empty")
                && !text.contains("el1 task slot 0:"),
            "{text}"
        );
        // A truncated image is refused by name, not decoded as zeros.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(EL1_ZONE_OFFSET)
            .unwrap();
        let error = render_region(&path).unwrap_err().to_string();
        assert!(error.contains("not a whole EL1 region"), "{error}");
    }
}
