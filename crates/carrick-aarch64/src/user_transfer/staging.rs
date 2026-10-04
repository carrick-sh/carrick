//! Select and retain every physical output page before admitting any permit.
use super::*;
use carrick_guest_mem::{
    GuestWriteRange, MemoryPrepareError, MemorySupplyRequest, PreparedGuestWrite,
};

pub fn prepare_write<'a, V: Aarch64Vmm, C: TransferCustody + ?Sized>(
    engine: &'a Aarch64EngineCore<V>,
    custody: &C,
    slots: &'a MmPortalSlots,
    target: TransferTarget,
    ranges: &[GuestWriteRange],
) -> Result<Box<dyn PreparedGuestWrite + 'a>, MemoryPrepareError>
where
    C::Pin: 'a,
{
    let bounded =
        carrick_guest_mem::PreparedStreamRanges::new(ranges).map_err(MemoryPrepareError::Limit)?;
    let ranges = bounded.ranges();
    let mut pages = Vec::new();
    for (output, range) in ranges.iter().enumerate() {
        let mut offset = 0;
        while offset < range.len() {
            let va = range.address().raw() + offset as u64;
            let len = (range.len() - offset)
                .min(carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize - (va as usize & 4095));
            pages.push(
                stage_page(
                    engine,
                    custody,
                    slots,
                    target,
                    va,
                    len,
                    output,
                    offset,
                    PortalTransferIntent::UserWrite,
                    None,
                )
                .map_err(|error| {
                    MemoryPrepareError::Fault(carrick_guest_mem::MemoryError::HostMap(
                        error.to_string(),
                    ))
                })??,
            );
            offset += len;
        }
    }
    // All potentially blocking physical work is over before this loan and
    // the first semantic permit. A later refusal cancels all earlier permits.
    Ok(Box::new(prepared::PreparedWrite::prepare_current(
        engine,
        slots,
        ranges.to_vec(),
        pages,
    )?))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stage_page<V: Aarch64Vmm, C: TransferCustody + ?Sized>(
    engine: &Aarch64EngineCore<V>,
    custody: &C,
    slots: &MmPortalSlots,
    target: TransferTarget,
    va: u64,
    len: usize,
    output: usize,
    offset: usize,
    intent: PortalTransferIntent,
    fork_sequence: Option<NonZeroU64>,
) -> Result<Result<prepared::RetainedWritePage<C::Pin>, MemoryPrepareError>, TrapError> {
    let service = engine.transfer_service_loan()?;
    Ok(stage_with_loan(
        service,
        custody,
        slots,
        target,
        va,
        len,
        output,
        offset,
        intent,
        fork_sequence,
    ))
}

#[allow(clippy::too_many_arguments)]
fn stage_with_loan<V: Aarch64Vmm, C: TransferCustody + ?Sized>(
    mut service: crate::engine::TransferServiceLoan<'_, V>,
    custody: &C,
    slots: &MmPortalSlots,
    target: TransferTarget,
    va: u64,
    len: usize,
    output: usize,
    offset: usize,
    intent: PortalTransferIntent,
    fork_sequence: Option<NonZeroU64>,
) -> Result<prepared::RetainedWritePage<C::Pin>, MemoryPrepareError> {
    let region = carrick_el1_abi::get_el1_region_host_ptr();
    if region == 0
        || slots as *const MmPortalSlots as usize
            != region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize
        || custody.carrier() != target.handle.carrier()
        || !slots.bind_carrier(target.handle.carrier())
    {
        carrick_fatal::carrick_fatal!(
            "aarch64::prepared_copy",
            "selection carrier custody mismatch"
        );
    }
    let executable = service
        .slot()
        .ok()
        .and_then(|slot| slots.executable(slot))
        .unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "selection has no exact executor slot"
            )
        });
    let mut frame = TrapFrame {
        esr: carrick_el1_abi::MM_PORTAL_SELECT_ESR,
        ..TrapFrame::default()
    };
    frame.x[1] = target.handle.carrier().get();
    frame.x[2] = target.handle.mm().raw();
    frame.x[3] = target.handle.incarnation().get();
    frame.x[4] = va;
    frame.x[5] = len as u64;
    frame.x[6] = intent.encode();
    frame.x[7] = offset as u64;
    frame.x[19] = fork_sequence.map_or(0, NonZeroU64::get);
    let frame = run_selected_service(&mut service, frame, target, fork_sequence, &mut || {
        executable.handle(|request| custody.publish_executable(target, request))
    })
    .unwrap_or_else(|error| {
        carrick_fatal::carrick_fatal!(
            "aarch64::prepared_copy",
            "selection service failed: {error}"
        )
    });
    // Physical retention/revocation is not licensed by execution custody.
    drop(service);
    let nz = |value| {
        NonZeroU64::new(value).unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!("aarch64::prepared_copy", "zero owner receipt identity")
        })
    };
    if frame.x[0] == 11 && frame.x[14] == 3 {
        let cause = carrick_el1_abi::PortalWaitCause::decode(frame.x[16]).unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!("aarch64::prepared_copy", "invalid owner wait cause")
        });
        // SAFETY: this exact target was served under exclusive carrier CPU custody.
        let observed = unsafe {
            carrick_el1_abi::PortalOwnerWait::from_owner(target.handle, cause, frame.x[17])
        };
        return Err(if cause == carrick_el1_abi::PortalWaitCause::Metadata {
            MemoryPrepareError::Supply(MemorySupplyRequest::Metadata {
                operation: PortalOperation {
                    carrier: target.handle.carrier(),
                    mm: target.handle.mm(),
                    incarnation: target.handle.incarnation(),
                    sequence: nz(frame.x[8]),
                },
                observed,
            })
        } else {
            MemoryPrepareError::OwnerWait(observed)
        });
    }
    if frame.x[0] == 11 && matches!(frame.x[14], 1 | 2) {
        let window = carrick_el1_abi::PortalGrantWindow {
            operation: PortalOperation {
                carrier: target.handle.carrier(),
                mm: target.handle.mm(),
                incarnation: target.handle.incarnation(),
                sequence: nz(frame.x[8]),
            },
            generation: carrick_el1_abi::ReservationGeneration::new(frame.x[9]).unwrap_or_else(
                || {
                    carrick_fatal::carrick_fatal!(
                        "aarch64::prepared_copy",
                        "invalid supply generation"
                    )
                },
            ),
            range: carrick_el1_abi::ReservationRange::new(frame.x[10], frame.x[11]).unwrap_or_else(
                || carrick_fatal::carrick_fatal!("aarch64::prepared_copy", "invalid supply range"),
            ),
            protection: carrick_el1_abi::ReservationProtection::from_bits(frame.x[12])
                .unwrap_or_else(|| {
                    carrick_fatal::carrick_fatal!(
                        "aarch64::prepared_copy",
                        "invalid supply permissions"
                    )
                }),
            fault_page: frame.x[13],
            fork_sequence,
            host_backing: if frame.x[16] == 0 {
                None
            } else {
                Some(carrick_el1_abi::HostBackingIdentity::new(
                    nz(frame.x[16]),
                    nz(frame.x[17]),
                    frame.x[18],
                ))
            },
        };
        return Err(MemoryPrepareError::Supply(if frame.x[14] == 2 {
            MemorySupplyRequest::Cow(window)
        } else {
            MemorySupplyRequest::Grant(window)
        }));
    }
    if frame.x[0] == 3 {
        return Err(MemoryPrepareError::Fault(
            carrick_guest_mem::MemoryError::OwnerRetired(target.handle),
        ));
    }
    if frame.x[0] == 14 {
        return Err(MemoryPrepareError::Fault(
            carrick_guest_mem::MemoryError::OutOfBounds {
                address: va,
                length: len,
            },
        ));
    }
    if frame.x[0] != 0 {
        return Err(MemoryPrepareError::Fault(
            carrick_guest_mem::MemoryError::HostMap(format!(
                "selection omitted exact suspension receipt: errno={} tag={}",
                frame.x[0], frame.x[14]
            )),
        ));
    }
    let selected = PortalSelectedData {
        ipa: frame.x[10],
        executable: frame.x[15] == 1,
        root_generation: nz(frame.x[9]),
        offset: offset as u64,
    };
    let retry = carrick_el1_abi::PortalWaitCause::decode(frame.x[16])
        .filter(|cause| *cause == carrick_el1_abi::PortalWaitCause::Reservations)
        .map(|cause| {
            // SAFETY: this exact authenticated selection returned its pre-probe revision.
            unsafe {
                carrick_el1_abi::PortalOwnerWait::from_owner(target.handle, cause, frame.x[17])
            }
        });
    let pin = retain_selected(custody.retain(selected, len, intent), retry)?;
    if let Some(wait) = pin.pending() {
        return Err(MemoryPrepareError::Physical(wait));
    }
    let operation = PortalOperation {
        carrier: target.handle.carrier(),
        mm: target.handle.mm(),
        incarnation: target.handle.incarnation(),
        sequence: nz(frame.x[8]),
    };
    let mut request = PortalTransferRequest::new(
        operation,
        PortalByteRange::new(va, len as u64).unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!("aarch64::prepared_copy", "invalid staged range")
        }),
        intent,
        selected,
        pin.identity(),
    )
    .unwrap_or_else(|| {
        carrick_fatal::carrick_fatal!(
            "aarch64::prepared_copy",
            "invalid physical staging identity"
        )
    });
    request.fork_sequence = fork_sequence;
    Ok(prepared::RetainedWritePage {
        request,
        pin,
        output,
        offset,
    })
}

fn retain_selected<P>(
    result: Result<Option<P>, TrapError>,
    observed: Option<carrick_el1_abi::PortalOwnerWait>,
) -> Result<P, MemoryPrepareError> {
    result
        .map_err(|error| {
            MemoryPrepareError::Fault(carrick_guest_mem::MemoryError::HostMap(error.to_string()))
        })?
        .ok_or_else(|| {
            observed.map_or_else(
                || {
                    MemoryPrepareError::Fault(carrick_guest_mem::MemoryError::HostMap(
                        "selection omitted recheck authority".into(),
                    ))
                },
                MemoryPrepareError::OwnerWait,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_physical_selection_returns_exact_owner_observation() {
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                NonZeroU64::new(1).unwrap(),
                ReservationMm::new(77).unwrap(),
                NonZeroU64::new(3).unwrap(),
            )
        };
        let observed = unsafe {
            carrick_el1_abi::PortalOwnerWait::from_owner(
                handle,
                carrick_el1_abi::PortalWaitCause::Reservations,
                41,
            )
        };
        assert!(matches!(retain_selected::<()>(Ok(None), Some(observed)),
            Err(MemoryPrepareError::OwnerWait(wait)) if wait == observed));
        assert!(matches!(
            retain_selected::<()>(
                Err(TrapError::Hypervisor("physical failure".into())),
                Some(observed)
            ),
            Err(MemoryPrepareError::Fault(
                carrick_guest_mem::MemoryError::HostMap(_)
            ))
        ));
    }
}
