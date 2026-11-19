use super::*;

#[test]
fn decodes_el0_counter_register_traps() {
    let cntfrq = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
        | AARCH64_SYS64_ISS_SYS_CNTFRQ
        | (1 << AARCH64_SYS64_ISS_RT_SHIFT);
    let cntvct = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
        | AARCH64_SYS64_ISS_SYS_CNTVCT
        | (2 << AARCH64_SYS64_ISS_RT_SHIFT);

    assert_eq!(
        decode_el0_sys64_read(cntfrq),
        Some((1, El0SysRegRead::CntfrqEl0))
    );
    assert_eq!(
        decode_el0_sys64_read(cntvct),
        Some((2, El0SysRegRead::CntvctEl0))
    );
    // CTR_EL0 / DCZID_EL0 — the cache-geometry reads glibc 2.41 does at
    // startup. The faulting `mrs x1, ctr_el0` observed from python:3.12-slim
    // was ESR_EL1=0x6232c021 (EC=0x18, Rt=1): decode it directly.
    assert_eq!(
        decode_el0_sys64_read(0x6232c021),
        Some((1, El0SysRegRead::CtrEl0))
    );
    let dczid = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
        | AARCH64_SYS64_ISS_SYS_DCZID
        | (3 << AARCH64_SYS64_ISS_RT_SHIFT);
    assert_eq!(
        decode_el0_sys64_read(dczid),
        Some((3, El0SysRegRead::DczidEl0))
    );
    assert_eq!(decode_el0_sys64_read(0), None);
}
