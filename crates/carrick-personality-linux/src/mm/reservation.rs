//! Linux placement, remap and byte-brk interpretation over one borrowed owner guard.
use super::LinuxReservationPolicy;
use carrick_core_abi::*;

pub(super) fn place<M: ReservationPolicyAccess>(
    root: &mut M,
    placement: Placement,
    len: GuestLen,
) -> Result<ReservationRange, Refusal> {
    let len = len.raw();
    if !root.is_admitted() {
        return Err(Refusal::Stale);
    }
    if len == 0
        || matches!(placement, Placement::Fixed(addr) | Placement::NoReplace(addr) if !addr.is_multiple_of(4096))
    {
        return Err(Refusal::Invalid);
    }
    let len = len
        .checked_add(4095)
        .map(|v| v & !4095)
        .ok_or(Refusal::Limit)?;
    let address = match placement {
        Placement::Fixed(addr) | Placement::NoReplace(addr) => addr,
        Placement::Anywhere => root
            .first_fit(GuestLen::new(len))
            .ok_or(Refusal::Limit)?
            .raw(),
        Placement::Hint(addr) => {
            let addr = addr & !4095;
            match addr
                .checked_add(len)
                .and_then(|end| ReservationRange::new(addr, end))
            {
                Some(r) if root.in_layout(r) => {
                    if root
                        .next_range(UserVa::new(addr))
                        .is_none_or(|n| n.start() >= r.end())
                    {
                        addr
                    } else {
                        root.first_fit(GuestLen::new(len))
                            .ok_or(Refusal::Limit)?
                            .raw()
                    }
                }
                // Linux honours a free hint anywhere; the host serves
                // out-of-arena hints (Go's 0xc000000000 probe) with alias
                // VAs. Relocating here would give a second answer.
                _ => return Err(Refusal::ForeignMapping),
            }
        }
    };
    let end = address.checked_add(len).ok_or(Refusal::Limit)?;
    let range = ReservationRange::new(address, end).ok_or(Refusal::Invalid)?;
    if matches!(placement, Placement::NoReplace(_))
        && root
            .next_range(UserVa::new(address))
            .is_some_and(|n| n.start() < range.end())
    {
        return Err(Refusal::Collision);
    }
    Ok(range)
}

pub(super) fn mmap<M: ReservationPolicyAccess>(
    root: &mut M,
    placement: Placement,
    len: GuestLen,
    prot: ReservationProtection,
) -> Result<Decision, Refusal> {
    let len = len.raw();
    if root.has_pending_edit() || root.fork_pending() {
        return Err(Refusal::Busy);
    }
    let range = place(root, placement, GuestLen::new(len))?;
    let address = range.start();
    root.propose(
        range,
        prot,
        ReservationOperation::Prepare,
        UserVa::new(address),
        UserVa::new(root.layout().brk),
        false,
        None,
        ReservationNodeFlags::ANONYMOUS_PRIVATE,
    )
}

pub(super) fn mremap<M: ReservationPolicyAccess>(
    root: &mut M,
    source: ReservationRange,
    new_len: GuestLen,
    target: MoveTarget,
) -> Result<Decision, Refusal> {
    let new_len = new_len.raw();
    let backing = root
        .mapping(UserVa::new(source.start()))
        .and_then(|mapping| {
            mapping.host_backing.and_then(|source_backing| {
                source_backing.advance(source.start() - mapping.range.start())
            })
        });
    let decision = mremap_inner(root, source, new_len, target)?;
    if let (Some(backing), Decision::Work(request)) = (backing, decision)
        && matches!(
            request.operation,
            ReservationOperation::Prepare | ReservationOperation::Move
        )
    {
        let result = root.pending_result().ok_or(Refusal::Stale)?;
        let backing = if result.raw() == source.start() && request.range.start() == source.end() {
            backing.advance(source.len()).ok_or(Refusal::Invalid)?
        } else {
            backing
        };
        if backing.advance(request.range.len()).is_none() {
            root.refuse(request)?;
            return Err(Refusal::Invalid);
        }
        root.write_pending_backing(backing)?;
    }
    Ok(decision)
}

fn mremap_inner<M: ReservationPolicyAccess>(
    root: &mut M,
    source: ReservationRange,
    new_len: u64,
    target: MoveTarget,
) -> Result<Decision, Refusal> {
    if !root.is_admitted() {
        return Err(Refusal::Stale);
    }
    if root.has_pending_edit() || root.fork_pending() {
        return Err(Refusal::Busy);
    }
    let fixed = match target {
        MoveTarget::Fixed(address) | MoveTarget::KeepSource(Some(address)) => Some(address),
        _ => None,
    };
    if new_len == 0 || fixed.is_some_and(|address| !address.is_multiple_of(4096)) {
        return Err(Refusal::Invalid);
    }
    let new_len = new_len
        .checked_add(4095)
        .map(|v| v & !4095)
        .ok_or(Refusal::Limit)?;
    let keep_source = matches!(target, MoveTarget::KeepSource(_));
    if keep_source && new_len != source.len() {
        return Err(Refusal::Invalid);
    }
    let node = root.run_covering(source).ok_or(Refusal::Hole)?;
    if !LinuxReservationPolicy::root_editable(&node) {
        return Err(Refusal::ForeignMapping);
    }
    let prot = LinuxReservationPolicy::protection(&node);
    let flags = LinuxReservationPolicy::flags(&node);
    let brk = root.layout().brk;
    let (operation, moved) = if keep_source {
        (ReservationOperation::Prepare, None)
    } else {
        (ReservationOperation::Move, Some(source))
    };
    if let Some(address) = fixed {
        let range = address
            .checked_add(new_len)
            .and_then(|end| ReservationRange::new(address, end))
            .ok_or(Refusal::Invalid)?;
        if range.start() < source.end() && source.start() < range.end() {
            return Err(Refusal::Invalid);
        }
        return root.propose(
            range,
            prot,
            operation,
            UserVa::new(address),
            UserVa::new(brk),
            false,
            moved,
            flags,
        );
    }
    if !keep_source {
        if new_len <= source.len() {
            if new_len == source.len() {
                return Ok(Decision::Complete(source.start()));
            }
            let tail = ReservationRange::new(source.start() + new_len, source.end())
                .ok_or(Refusal::Invalid)?;
            return root.propose(
                tail,
                ReservationProtection::NONE,
                ReservationOperation::Retire,
                UserVa::new(source.start()),
                UserVa::new(brk),
                false,
                None,
                ReservationNodeFlags::EMPTY,
            );
        }
        let extension = source
            .start()
            .checked_add(new_len)
            .and_then(|end| ReservationRange::new(source.end(), end))
            .filter(|r| root.in_layout(*r));
        let free = extension.is_some_and(|r| {
            root.next_range(UserVa::new(r.start()))
                .is_none_or(|n| n.start() >= r.end())
        });
        if let Some(extension) = extension.filter(|_| free) {
            return root.propose(
                extension,
                prot,
                ReservationOperation::Prepare,
                UserVa::new(source.start()),
                UserVa::new(brk),
                false,
                None,
                flags,
            );
        }
        if target == MoveTarget::InPlace {
            return Err(Refusal::Limit);
        }
    }
    let address = root
        .first_fit(GuestLen::new(new_len))
        .ok_or(Refusal::Limit)?
        .raw();
    let range = ReservationRange::new(address, address + new_len).ok_or(Refusal::Invalid)?;
    root.propose(
        range,
        prot,
        operation,
        UserVa::new(address),
        UserVa::new(brk),
        false,
        moved,
        flags,
    )
}

pub(super) fn brk<M: ReservationPolicyAccess>(
    root: &mut M,
    requested: UserVa,
) -> Result<Decision, Refusal> {
    let requested = requested.raw();
    if !root.is_admitted() {
        return Err(Refusal::Stale);
    }
    if root.has_pending_edit() || root.fork_pending() {
        return Err(Refusal::Busy);
    }
    let old = root.layout().brk;
    let heap = root.layout().heap;
    if requested == 0 || requested < heap.start() || requested > heap.end() {
        return Ok(Decision::Complete(old));
    }
    let old_end = old.checked_add(4095).ok_or(Refusal::Invalid)? & !4095;
    let new_end = requested.checked_add(4095).ok_or(Refusal::Invalid)? & !4095;
    if old_end == new_end {
        if old != requested {
            root.set_byte_break(UserVa::new(requested))?;
        }
        return Ok(Decision::Complete(requested));
    }
    if new_end > old_end
        && root
            .next_range(UserVa::new(old_end))
            .is_some_and(|n| n.start() < new_end)
    {
        return Ok(Decision::Complete(old));
    }
    let range = ReservationRange::new(old_end.min(new_end), old_end.max(new_end))
        .ok_or(Refusal::Invalid)?;
    let (prot, op) = if new_end > old_end {
        (
            ReservationProtection::READ_WRITE,
            ReservationOperation::Prepare,
        )
    } else {
        (ReservationProtection::NONE, ReservationOperation::Retire)
    };
    match root.propose(
        range,
        prot,
        op,
        UserVa::new(requested),
        UserVa::new(requested),
        false,
        None,
        ReservationNodeFlags::ANONYMOUS_PRIVATE,
    ) {
        Err(Refusal::Limit | Refusal::ForeignMapping) => Ok(Decision::Complete(old)),
        result => result,
    }
}
