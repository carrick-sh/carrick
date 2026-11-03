//! x86-64-v3 instruction witnesses through the production block entry (#1439).
#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use carrick_softcpu_x86::{
    ExtentRecord, ExtentTable, FrameGpa, LinearPlacement, MmioHoles, OwnerGeneration, RootGpa,
    SoftCpu, SoftCpuExit, SoftMmuMemory, reg,
};
use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Register};
use std::sync::atomic::{AtomicU64, Ordering};

// Four-level identity map for a single executable/data page. As in level0,
// AtomicU64 backing supplies aligned storage for architectural page entries.
struct Memory {
    _backing: Vec<AtomicU64>,
    placement: LinearPlacement,
    extents: ExtentTable,
}
impl Memory {
    fn new() -> Self {
        let backing: Vec<_> = (0..(0x7000 / 8)).map(|_| AtomicU64::new(0)).collect();
        let base = (backing.as_ptr() as usize + 4095) & !4095;
        // SAFETY: allocation has alignment padding and owns all six mapped pages.
        let placement = unsafe { LinearPlacement::new(base, 0x6000, MmioHoles::empty()) }.unwrap();
        let mut extents = ExtentTable::new().unwrap();
        assert!(extents.install(ExtentRecord::new(
            FrameGpa::new(0),
            0x6000,
            OwnerGeneration::FIRST
        )));
        extents.set_root_generation(
            RootGpa::page_aligned(FrameGpa::new(0)).unwrap(),
            OwnerGeneration::FIRST,
        );
        let mem = Self {
            _backing: backing,
            placement,
            extents,
        };
        for (offset, entry) in [
            (0, 0x1007),
            (0x1000, 0x2007),
            (0x2000, 0x3007),
            (0x3020, 0x4007),
        ] {
            // SAFETY: aligned entry lies in the owned page-table allocation.
            unsafe { &*((base + offset) as *const AtomicU64) }.store(entry, Ordering::Relaxed);
        }
        mem
    }
    fn write(&mut self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= 4096);
        // SAFETY: destination is the mapped data page, disjoint from page tables.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (self.placement.base_host_addr() + 0x4000 + offset) as *mut u8,
                data.len(),
            );
        }
    }
}
// SAFETY: owned initialized aligned storage remains alive and stationary;
// execution and direct writes are synchronous with no concurrent references.
unsafe impl SoftMmuMemory for Memory {
    fn placement(&self) -> &LinearPlacement {
        &self.placement
    }
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        &mut self.extents
    }
}
fn fixture() -> (SoftCpu, Memory) {
    assert!(
        std::is_x86_feature_detected!("avx2"),
        "v3 witness requires native AVX2"
    );
    assert!(
        std::is_x86_feature_detected!("fma"),
        "v3 witness requires native FMA"
    );
    assert!(
        std::is_x86_feature_detected!("f16c"),
        "v3 witness requires native F16C"
    );
    assert!(
        std::is_x86_feature_detected!("aes"),
        "crypto witness requires native AES"
    );
    assert!(
        std::is_x86_feature_detected!("pclmulqdq"),
        "crypto witness requires native PCLMULQDQ"
    );
    assert!(std::is_x86_feature_detected!("bmi1"));
    assert!(std::is_x86_feature_detected!("bmi2"));
    assert!(std::is_x86_feature_detected!("lzcnt"));
    assert!(std::is_x86_feature_detected!("movbe"));
    let mem = Memory::new();
    let mut cpu = SoftCpu::with_cpuid_view(
        mem.extents(),
        Box::new(carrick_x86::GuestCpuidView::default()),
    )
    .unwrap();
    cpu.context_mut().xcr0 = 7;
    (cpu, mem)
}
fn execute(cpu: &mut SoftCpu, mem: &mut Memory, insn: Instruction) -> SoftCpuExit {
    let mut encoder = Encoder::new(64);
    encoder.encode(&insn, 0x4000).unwrap();
    let mut bytes = encoder.take_buffer();
    bytes.extend_from_slice(&[0xeb, 0]);
    mem.write(0, &bytes);
    cpu.context_mut().rip = 0x4000;
    cpu.step_block(mem).unwrap()
}
fn run(cpu: &mut SoftCpu, mem: &mut Memory, insn: Instruction) {
    assert!(
        matches!(execute(cpu, mem, insn), SoftCpuExit::Continue { .. }),
        "{:?}",
        insn.code()
    );
}
fn mxcsr(cpu: &mut SoftCpu, value: u32) {
    cpu.context_mut().fxsave.0[24..28].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn bmi1_results_and_defined_flags() {
    let (mut cpu, mut mem) = fixture();
    for (code, input, expected, flags) in [
        (Code::VEX_Blsi_r64_rm64, 0u64, 0u64, 0x40u64),
        (Code::VEX_Blsi_r64_rm64, 0x58, 8, 1),
        (Code::VEX_Blsmsk_r64_rm64, 0, u64::MAX, 0x81),
        (Code::VEX_Blsr_r64_rm64, 0, 0, 0x41),
        (Code::VEX_Blsr_r64_rm64, 0x58, 0x50, 0),
        (Code::Tzcnt_r64_rm64, 0, 64, 1),
        (Code::Tzcnt_r64_rm64, 1, 0, 0x40),
        (Code::Lzcnt_r64_rm64, 0, 64, 1),
        (Code::Lzcnt_r64_rm64, 1 << 63, 0, 0x40),
    ] {
        cpu.context_mut().gpr[reg::RCX] = input;
        cpu.context_mut().rflags = 0xad7;
        run(
            &mut cpu,
            &mut mem,
            Instruction::with2(code, Register::RAX, Register::RCX).unwrap(),
        );
        assert_eq!(cpu.context().gpr[reg::RAX], expected, "{code:?}");
        let mask = if matches!(code, Code::Tzcnt_r64_rm64 | Code::Lzcnt_r64_rm64) {
            0x41
        } else {
            0x8c1
        };
        assert_eq!(cpu.context().rflags & mask, flags, "{code:?}");
    }
    for (code, a, b, expected) in [
        (Code::VEX_Andn_r64_r64_rm64, 0xf0, 0xff, 0xf),
        (Code::VEX_Bextr_r64_rm64_r64, 0xabcd, 0x0804, 0xbc),
    ] {
        cpu.context_mut().gpr[reg::RCX] = a;
        cpu.context_mut().gpr[reg::RDX] = b;
        run(
            &mut cpu,
            &mut mem,
            Instruction::with3(code, Register::RAX, Register::RCX, Register::RDX).unwrap(),
        );
        assert_eq!(cpu.context().gpr[reg::RAX], expected, "{code:?}");
        assert_eq!(cpu.context().rflags & 0x841, 0, "{code:?}");
    }
}
#[test]
fn bmi2_results_and_flag_preservation() {
    let (mut cpu, mut mem) = fixture();
    for (code, a, b, expected) in [
        (Code::VEX_Pdep_r64_r64_rm64, 0xb, 0x55, 0x45),
        (Code::VEX_Pext_r64_r64_rm64, 0x45, 0x55, 0xb),
        (Code::VEX_Shlx_r64_rm64_r64, 3, 4, 48),
        (Code::VEX_Shrx_r64_rm64_r64, 0x80, 4, 8),
        (
            Code::VEX_Sarx_r64_rm64_r64,
            0xfffffffffffffff0,
            2,
            0xfffffffffffffffc,
        ),
    ] {
        cpu.context_mut().gpr[reg::RCX] = a;
        cpu.context_mut().gpr[reg::RDX] = b;
        cpu.context_mut().rflags = 0xad7;
        run(
            &mut cpu,
            &mut mem,
            Instruction::with3(code, Register::RAX, Register::RCX, Register::RDX).unwrap(),
        );
        assert_eq!(cpu.context().gpr[reg::RAX], expected, "{code:?}");
        assert_eq!(cpu.context().rflags & 0x8d5, 0x8d5, "{code:?}");
    }
    cpu.context_mut().gpr[reg::RCX] = 0x1234;
    cpu.context_mut().gpr[reg::RDX] = 8;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with3(
            Code::VEX_Bzhi_r64_rm64_r64,
            Register::RAX,
            Register::RCX,
            Register::RDX,
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RAX], 0x34);
    assert_eq!(cpu.context().rflags & 0x8c1, 0);
    cpu.context_mut().gpr[reg::RCX] = u64::MAX;
    cpu.context_mut().gpr[reg::RDX] = 2;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with3(
            Code::VEX_Mulx_r64_r64_rm64,
            Register::RAX,
            Register::RBX,
            Register::RCX,
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RAX], 1);
    assert_eq!(cpu.context().gpr[reg::RBX], u64::MAX - 1);
    cpu.context_mut().gpr[reg::RCX] = 0x1234;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with3(
            Code::VEX_Rorx_r64_rm64_imm8,
            Register::RAX,
            Register::RCX,
            8u32,
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RAX], 0x3400000000000012);
}
#[test]
fn movbe_load_and_store() {
    let (mut cpu, mut mem) = fixture();
    mem.write(0x800, &0x0123456789abcdefu64.to_le_bytes());
    cpu.context_mut().gpr[reg::RDI] = 0x4800;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(
            Code::Movbe_r64_m64,
            Register::RAX,
            MemoryOperand::with_base(Register::RDI),
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RAX], 0xefcdab8967452301);
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(
            Code::Movbe_m64_r64,
            MemoryOperand::with_base(Register::RDI),
            Register::RAX,
        )
        .unwrap(),
    );
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RBX,
            MemoryOperand::with_base(Register::RDI),
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RBX], 0x0123456789abcdef);
}
#[test]
fn fma_fuses_and_respects_guest_rounding() {
    let (mut cpu, mut mem) = fixture();
    // (1+2^-23)*(1-2^-23)-1 = -2^-46, lost by separate multiply/add.
    cpu.context_mut().write_xmm(0, u128::from(0x3f800001u32));
    cpu.context_mut()
        .write_xmm(1, u128::from((-1f32).to_bits()));
    cpu.context_mut().write_xmm(2, u128::from(0x3f7ffffeu32));
    run(
        &mut cpu,
        &mut mem,
        Instruction::with3(
            Code::VEX_Vfmadd132ss_xmm_xmm_xmmm32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap(),
    );
    assert_eq!(
        cpu.context().read_xmm(0) as u32,
        (-2f32.powi(-46)).to_bits()
    );
    for (mode, expected) in [
        (0, 0x3f800000),
        (1, 0x3f800000),
        (2, 0x3f800001),
        (3, 0x3f800000),
    ] {
        mxcsr(&mut cpu, 0x1f80 | (mode << 13));
        cpu.context_mut().write_xmm(0, u128::from(1f32.to_bits()));
        cpu.context_mut()
            .write_xmm(1, u128::from(2f32.powi(-24).to_bits()));
        cpu.context_mut().write_xmm(2, u128::from(1f32.to_bits()));
        run(
            &mut cpu,
            &mut mem,
            Instruction::with3(
                Code::VEX_Vfmadd132ss_xmm_xmm_xmmm32,
                Register::XMM0,
                Register::XMM1,
                Register::XMM2,
            )
            .unwrap(),
        );
        assert_eq!(
            cpu.context().read_xmm(0) as u32,
            expected,
            "rounding {mode}"
        );
    }
}
#[test]
fn f16c_immediate_and_mxcsr_rounding() {
    let (mut cpu, mut mem) = fixture();
    for (mode, expected) in [(0, 0x3c00), (1, 0x3c00), (2, 0x3c01), (3, 0x3c00)] {
        for immediate in [mode, 4] {
            // Deliberately disagree: imm8[2]=0 must ignore MXCSR.RC.
            let csr_mode = if immediate == 4 { mode } else { (mode + 2) % 4 };
            mxcsr(&mut cpu, 0x1f80 | (csr_mode << 13));
            cpu.context_mut()
                .write_xmm(1, u128::from((1f32 + 2f32.powi(-11)).to_bits()));
            run(
                &mut cpu,
                &mut mem,
                Instruction::with3(
                    Code::VEX_Vcvtps2ph_xmmm64_xmm_imm8,
                    Register::XMM0,
                    Register::XMM1,
                    immediate,
                )
                .unwrap(),
            );
            assert_eq!(cpu.context().read_xmm(0) as u16, expected);
        }
    }
    cpu.context_mut().write_xmm(1, 0x3c00);
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(
            Code::VEX_Vcvtph2ps_xmm_xmmm64,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().read_xmm(0) as u32, 1f32.to_bits());
}

fn hex(s: &str) -> u128 {
    let bytes: Vec<_> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    u128::from_le_bytes(bytes.try_into().unwrap())
}
#[test]
fn aes_fips197_encrypt_decrypt_legacy_and_vex() {
    // FIPS 197 Appendix B/C AES-128 key schedule and known-answer block.
    let keys = [
        "000102030405060708090a0b0c0d0e0f",
        "d6aa74fdd2af72fadaa678f1d6ab76fe",
        "b692cf0b643dbdf1be9bc5006830b3fe",
        "b6ff744ed2c2c9bf6c590cbf0469bf41",
        "47f7f7bc95353e03f96c32bcfd058dfd",
        "3caaa3e8a99f9deb50f3af57adf622aa",
        "5e390f7df7a69296a7553dc10aa31f6b",
        "14f9701ae35fe28c440adf4d4ea9c026",
        "47438735a41c65b9e016baf4aebf7ad2",
        "549932d1f08557681093ed9cbe2c974e",
        "13111d7fe3944a17f307a78b4d2b30c5",
    ]
    .map(hex);
    let plaintext = hex("00112233445566778899aabbccddeeff");
    let ciphertext = hex("69c4e0d86a7b0430d8cdb78070b4c55a");
    for vex in [false, true] {
        let (mut cpu, mut mem) = fixture();
        cpu.context_mut().write_xmm(0, plaintext ^ keys[0]);
        cpu.context_mut().ymm_hi128.fill(0x71);
        for (round, key) in keys.iter().enumerate().skip(1) {
            cpu.context_mut().write_xmm(1, *key);
            let insn = if vex {
                Instruction::with3(
                    if round == 10 {
                        Code::VEX_Vaesenclast_xmm_xmm_xmmm128
                    } else {
                        Code::VEX_Vaesenc_xmm_xmm_xmmm128
                    },
                    Register::XMM0,
                    Register::XMM0,
                    Register::XMM1,
                )
            } else {
                Instruction::with2(
                    if round == 10 {
                        Code::Aesenclast_xmm_xmmm128
                    } else {
                        Code::Aesenc_xmm_xmmm128
                    },
                    Register::XMM0,
                    Register::XMM1,
                )
            }
            .unwrap();
            run(&mut cpu, &mut mem, insn);
        }
        assert_eq!(cpu.context().read_xmm(0), ciphertext, "vex={vex}");
        assert_eq!(
            &cpu.context().ymm_hi128[..16],
            &[if vex { 0 } else { 0x71 }; 16]
        );
        cpu.context_mut().write_xmm(0, ciphertext ^ keys[10]);
        for round in (0..10).rev() {
            cpu.context_mut().write_xmm(1, keys[round]);
            if round != 0 {
                run(
                    &mut cpu,
                    &mut mem,
                    Instruction::with2(
                        if vex {
                            Code::VEX_Vaesimc_xmm_xmmm128
                        } else {
                            Code::Aesimc_xmm_xmmm128
                        },
                        Register::XMM1,
                        Register::XMM1,
                    )
                    .unwrap(),
                );
            }
            let insn = if vex {
                Instruction::with3(
                    if round == 0 {
                        Code::VEX_Vaesdeclast_xmm_xmm_xmmm128
                    } else {
                        Code::VEX_Vaesdec_xmm_xmm_xmmm128
                    },
                    Register::XMM0,
                    Register::XMM0,
                    Register::XMM1,
                )
            } else {
                Instruction::with2(
                    if round == 0 {
                        Code::Aesdeclast_xmm_xmmm128
                    } else {
                        Code::Aesdec_xmm_xmmm128
                    },
                    Register::XMM0,
                    Register::XMM1,
                )
            }
            .unwrap();
            run(&mut cpu, &mut mem, insn);
        }
        assert_eq!(cpu.context().read_xmm(0), plaintext);
        cpu.context_mut().write_xmm(1, 0);
        run(
            &mut cpu,
            &mut mem,
            Instruction::with3(
                if vex {
                    Code::VEX_Vaeskeygenassist_xmm_xmmm128_imm8
                } else {
                    Code::Aeskeygenassist_xmm_xmmm128_imm8
                },
                Register::XMM0,
                Register::XMM1,
                1u32,
            )
            .unwrap(),
        );
        assert_eq!(
            cpu.context().read_xmm(0),
            hex("63636363626363636363636362636363")
        );
    }
}
#[test]
fn pclmul_known_polynomial_all_lane_selectors() {
    let (mut cpu, mut mem) = fixture();
    for vex in [false, true] {
        for selector in [0u32, 1, 16, 17] {
            let a = [0x8000000000000001u64, 0x123456789abcdef0];
            let b = [3u64, 0xfedcba9876543210];
            let lhs = a[(selector & 1) as usize];
            let rhs = b[((selector >> 4) & 1) as usize];
            let expected = (0..64)
                .filter(|bit| (rhs >> bit) & 1 != 0)
                .fold(0u128, |value, bit| value ^ (u128::from(lhs) << bit));
            cpu.context_mut()
                .write_xmm(0, u128::from(a[0]) | (u128::from(a[1]) << 64));
            cpu.context_mut()
                .write_xmm(1, u128::from(b[0]) | (u128::from(b[1]) << 64));
            let insn = if vex {
                Instruction::with4(
                    Code::VEX_Vpclmulqdq_xmm_xmm_xmmm128_imm8,
                    Register::XMM0,
                    Register::XMM0,
                    Register::XMM1,
                    selector,
                )
            } else {
                Instruction::with3(
                    Code::Pclmulqdq_xmm_xmmm128_imm8,
                    Register::XMM0,
                    Register::XMM1,
                    selector,
                )
            }
            .unwrap();
            run(&mut cpu, &mut mem, insn);
            assert_eq!(
                cpu.context().read_xmm(0),
                expected,
                "vex={vex} selector={selector}"
            );
        }
    }
}

#[test]
fn scalar_extensions_ignore_vector_controls_and_preserve_partial_registers() {
    let (mut cpu, mut mem) = fixture();
    cpu.context_mut().cr0 |= 12;
    cpu.context_mut().cr4 &= !((1 << 18) | (1 << 9));
    cpu.context_mut().xcr0 = 3;
    cpu.context_mut().gpr[reg::RCX] = 0x58;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(Code::VEX_Blsi_r64_rm64, Register::RAX, Register::RCX).unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RAX], 8);
    cpu.context_mut().gpr[reg::RAX] = 0x123456789abcdef0;
    cpu.context_mut().gpr[reg::RCX] = 1;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(Code::Lzcnt_r16_rm16, Register::AX, Register::CX).unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RAX], 0x123456789abc000f);
    mem.write(0x800, &[0x12, 0x34]);
    cpu.context_mut().gpr[reg::RDI] = 0x4800;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(
            Code::Movbe_r16_m16,
            Register::AX,
            MemoryOperand::with_base(Register::RDI),
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().gpr[reg::RAX], 0x123456789abc1234);
    cpu.context_mut().gpr[reg::RCX] = u64::MAX;
    cpu.context_mut().gpr[reg::RDX] = 2;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with3(
            Code::VEX_Mulx_r64_r64_rm64,
            Register::RAX,
            Register::RAX,
            Register::RCX,
        )
        .unwrap(),
    );
    assert_eq!(
        cpu.context().gpr[reg::RAX],
        1,
        "aliased MULX keeps high product"
    );
}
#[test]
fn f16c_suppresses_alignment_check_for_unaligned_m64() {
    let (mut cpu, mut mem) = fixture();
    cpu.context_mut().cr0 |= 1 << 18;
    cpu.context_mut().rflags |= 1 << 18;
    mem.write(0x801, &0x3c00u64.to_le_bytes());
    cpu.context_mut().gpr[reg::RDI] = 0x4801;
    run(
        &mut cpu,
        &mut mem,
        Instruction::with2(
            Code::VEX_Vcvtph2ps_xmm_xmmm64,
            Register::XMM0,
            MemoryOperand::with_base(Register::RDI),
        )
        .unwrap(),
    );
    assert_eq!(cpu.context().read_xmm(0) as u32, 1f32.to_bits());
    run(
        &mut cpu,
        &mut mem,
        Instruction::with3(
            Code::VEX_Vcvtps2ph_xmmm64_xmm_imm8,
            MemoryOperand::with_base(Register::RDI),
            Register::XMM0,
            0u32,
        )
        .unwrap(),
    );
}
#[test]
fn legacy_crypto_control_and_alignment_faults_are_atomic() {
    use carrick_softcpu_x86::X86Exception;
    for code in [
        Code::Aesenc_xmm_xmmm128,
        Code::Aesdec_xmm_xmmm128,
        Code::Aesimc_xmm_xmmm128,
    ] {
        for mode in 0..4 {
            let (mut cpu, mut mem) = fixture();
            cpu.context_mut().write_xmm(0, 0x1234);
            cpu.context_mut().gpr[reg::RDI] = 0x4800;
            let expected = match mode {
                0 => {
                    cpu.context_mut().cr0 |= 4;
                    X86Exception::invalid_opcode(0x4000)
                }
                1 => {
                    cpu.context_mut().cr4 &= !(1 << 9);
                    X86Exception::invalid_opcode(0x4000)
                }
                2 => {
                    cpu.context_mut().cr0 |= 8;
                    X86Exception::device_not_available(0x4000)
                }
                _ => {
                    cpu.context_mut().gpr[reg::RDI] += 1;
                    X86Exception::general_protection(0x4000, 0)
                }
            };
            assert_eq!(
                execute(
                    &mut cpu,
                    &mut mem,
                    Instruction::with2(
                        code,
                        Register::XMM0,
                        MemoryOperand::with_base(Register::RDI)
                    )
                    .unwrap()
                ),
                SoftCpuExit::Exception(expected),
                "{code:?} mode {mode}"
            );
            assert_eq!(cpu.context().read_xmm(0), 0x1234);
        }
    }
}

#[test]
fn fma_all_vex_orders_precisions_and_lane_widths() {
    let (mut cpu, mut mem) = fixture();
    let mut failures = Vec::new();
    let mut population = 0;
    for code in Code::values() {
        let name = format!("{code:?}");
        if !name.starts_with("VEX_Vfm") && !name.starts_with("VEX_Vfnm") {
            continue;
        }
        if !["132", "213", "231"]
            .iter()
            .any(|order| name.contains(order))
        {
            continue;
        }
        let scalar = name.contains("ss_") || name.contains("sd_");
        let double = name.contains("pd_") || name.contains("sd_");
        let wide = name.contains("_ymm_");
        let registers = if wide {
            [Register::YMM0, Register::YMM1, Register::YMM2]
        } else {
            [Register::XMM0, Register::XMM1, Register::XMM2]
        };
        let insn = Instruction::with3(code, registers[0], registers[1], registers[2]).unwrap();
        for (index, value) in [2f64, 3f64, 5f64].into_iter().enumerate() {
            let lane = if double {
                value.to_le_bytes().to_vec()
            } else {
                (value as f32).to_le_bytes().to_vec()
            };
            let bytes: Vec<_> = lane.iter().copied().cycle().take(32).collect();
            cpu.context_mut()
                .write_xmm(index, u128::from_le_bytes(bytes[..16].try_into().unwrap()));
            cpu.context_mut().ymm_hi128[index * 16..index * 16 + 16].copy_from_slice(&bytes[16..]);
        }
        let exit = execute(&mut cpu, &mut mem, insn);
        population += 1;
        if !matches!(exit, SoftCpuExit::Continue { .. }) {
            failures.push(format!("{name}: {exit:?}"));
            continue;
        }
        let (product, addend) = if name.contains("132") {
            (10f64, 3f64)
        } else if name.contains("213") {
            (6f64, 5f64)
        } else {
            (15f64, 2f64)
        };
        let count = if scalar {
            1
        } else {
            (if wide { 32 } else { 16 }) / if double { 8 } else { 4 }
        };
        let mut result = cpu.context().read_xmm(0).to_le_bytes().to_vec();
        result.extend_from_slice(&cpu.context().ymm_hi128[..16]);
        for lane in 0..count {
            let subtract = if name.contains("addsub") {
                lane % 2 == 0
            } else if name.contains("subadd") {
                lane % 2 != 0
            } else {
                name.contains("sub")
            };
            let expected = if name.contains("Vfnm") {
                -product
            } else {
                product
            } + if subtract { -addend } else { addend };
            let actual = if double {
                f64::from_le_bytes(result[lane * 8..lane * 8 + 8].try_into().unwrap())
            } else {
                f64::from(f32::from_le_bytes(
                    result[lane * 4..lane * 4 + 4].try_into().unwrap(),
                ))
            };
            if actual != expected {
                failures.push(format!("{name} lane {lane}: {actual} != {expected}"));
            }
        }
    }
    assert_eq!(population, 96, "all 96 VEX FMA instruction forms");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn bmi32_register_and_memory_forms_zero_extend_and_publish_flags() {
    let (mut cpu, mut mem) = fixture();
    let mut failures = Vec::new();
    // (code, source, control/mask, expected result, defined flag mask/value).
    let rows = [
        (Code::VEX_Blsi_r32_rm32, 0x58u32, 0, 8u32, 0x8c1u64, 1u64),
        (Code::VEX_Blsmsk_r32_rm32, 0x58, 0, 15, 0x8c1, 0),
        (Code::VEX_Blsr_r32_rm32, 0x58, 0, 0x50, 0x8c1, 0),
        (Code::Tzcnt_r32_rm32, 0x58, 0, 3, 0x41, 0),
        (Code::Lzcnt_r32_rm32, 0x58, 0, 25, 0x41, 0),
        (Code::VEX_Bextr_r32_rm32_r32, 0xabcd, 0x0804, 0xbc, 0x841, 0),
        (Code::VEX_Bzhi_r32_rm32_r32, 0x1234, 8, 0x34, 0x8c1, 0),
        (Code::VEX_Shlx_r32_rm32_r32, 3, 4, 48, 0x8d5, 0x8d5),
        (Code::VEX_Shrx_r32_rm32_r32, 0x80, 4, 8, 0x8d5, 0x8d5),
        (
            Code::VEX_Sarx_r32_rm32_r32,
            0xfffffff0,
            2,
            0xfffffffc,
            0x8d5,
            0x8d5,
        ),
        (Code::VEX_Andn_r32_r32_rm32, 0xf0, 0xff, 0xf, 0x8c1, 0),
        (Code::VEX_Pdep_r32_r32_rm32, 0xb, 0x55, 0x45, 0x8d5, 0x8d5),
        (Code::VEX_Pext_r32_r32_rm32, 0x45, 0x55, 0xb, 0x8d5, 0x8d5),
    ];
    for (code, a, b, expected, mask, flags) in rows {
        for memory in [false, true] {
            let name = format!("{code:?}");
            let source_last = name.contains("_r32_r32_rm32");
            let three = source_last || name.contains("_rm32_r32");
            cpu.context_mut().gpr[reg::RAX] = u64::MAX;
            cpu.context_mut().gpr[reg::RCX] = u64::from(a);
            cpu.context_mut().gpr[reg::RDX] = u64::from(b);
            cpu.context_mut().gpr[reg::RDI] = 0x4800;
            cpu.context_mut().rflags = 0xad7;
            mem.write(0x800, &if source_last { b } else { a }.to_le_bytes());
            let operand = MemoryOperand::with_base(Register::RDI);
            let insn = match (three, source_last, memory) {
                (false, _, false) => Instruction::with2(code, Register::EAX, Register::ECX),
                (false, _, true) => Instruction::with2(code, Register::EAX, operand),
                (true, _, false) => {
                    Instruction::with3(code, Register::EAX, Register::ECX, Register::EDX)
                }
                (true, true, true) => {
                    Instruction::with3(code, Register::EAX, Register::ECX, operand)
                }
                (true, false, true) => {
                    Instruction::with3(code, Register::EAX, operand, Register::EDX)
                }
            }
            .unwrap();
            let exit = execute(&mut cpu, &mut mem, insn);
            if !matches!(exit, SoftCpuExit::Continue { .. }) {
                failures.push(format!("{name} memory={memory}: {exit:?}"));
                continue;
            }
            if cpu.context().gpr[reg::RAX] != u64::from(expected)
                || cpu.context().rflags & mask != flags
            {
                failures.push(format!("{name} memory={memory}: result={:x} flags={:x}; expected {expected:x}/{flags:x}",cpu.context().gpr[reg::RAX],cpu.context().rflags&mask));
            }
        }
    }
    for memory in [false, true] {
        cpu.context_mut().gpr[reg::RCX] = u64::from(u32::MAX);
        cpu.context_mut().gpr[reg::RDX] = 2;
        cpu.context_mut().gpr[reg::RDI] = 0x4800;
        mem.write(0x800, &u32::MAX.to_le_bytes());
        let mul = if memory {
            Instruction::with3(
                Code::VEX_Mulx_r32_r32_rm32,
                Register::EAX,
                Register::EBX,
                MemoryOperand::with_base(Register::RDI),
            )
        } else {
            Instruction::with3(
                Code::VEX_Mulx_r32_r32_rm32,
                Register::EAX,
                Register::EBX,
                Register::ECX,
            )
        }
        .unwrap();
        let exit = execute(&mut cpu, &mut mem, mul);
        if !matches!(exit, SoftCpuExit::Continue { .. }) {
            failures.push(format!("MULX32 memory={memory}: {exit:?}"));
        } else {
            assert_eq!(cpu.context().gpr[reg::RAX], 1);
            assert_eq!(cpu.context().gpr[reg::RBX], 0xfffffffe);
        }
        let ror = if memory {
            Instruction::with3(
                Code::VEX_Rorx_r32_rm32_imm8,
                Register::EAX,
                MemoryOperand::with_base(Register::RDI),
                7u32,
            )
        } else {
            Instruction::with3(
                Code::VEX_Rorx_r32_rm32_imm8,
                Register::EAX,
                Register::ECX,
                7u32,
            )
        }
        .unwrap();
        let exit = execute(&mut cpu, &mut mem, ror);
        if !matches!(exit, SoftCpuExit::Continue { .. }) {
            failures.push(format!("RORX32 memory={memory}: {exit:?}"));
        } else {
            assert_eq!(cpu.context().gpr[reg::RAX], u64::from(u32::MAX));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unadvertised_extensions_raise_ud_with_enabled_avx_state() {
    use carrick_softcpu_x86::X86ExceptionVector;
    let (mut cpu, mut mem) = fixture();
    assert_eq!(cpu.context().xcr0, 7);
    let mut failures = Vec::new();
    for (name, bytes) in [
        ("VAES-256", &[0xc4, 0xe2, 0x75, 0xdc, 0xc2][..]),
        ("VPCLMULQDQ-256", &[0xc4, 0xe3, 0x75, 0x44, 0xc2, 0][..]),
        ("AVX-VNNI", &[0xc4, 0xe2, 0x75, 0x50, 0xc2][..]),
        ("SHA", &[0x0f, 0x38, 0xcb, 0xc1][..]),
        ("ADX", &[0x66, 0x48, 0x0f, 0x38, 0xf6, 0xc1][..]),
    ] {
        mem.write(0, bytes);
        cpu.context_mut().rip = 0x4000;
        let before = cpu.context().gpr;
        let exit = cpu.step_block(&mut mem);
        if !matches!(exit, Ok(SoftCpuExit::Exception(e))
            if e.vector == X86ExceptionVector::InvalidOpcode)
        {
            failures.push(format!("{name}: {exit:?}"));
        }
        assert_eq!(cpu.context().gpr, before, "{name}");
        assert_eq!(cpu.context().rip, 0x4000, "{name}");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn installed_view_gates_each_extension_before_memory_or_state_mutation() {
    use carrick_softcpu_x86::{CpuidAuthority, CpuidRegs, GuestCpuidView, X86ExceptionVector};
    struct Without {
        leaf: u32,
        bit: u32,
    }
    impl CpuidAuthority for Without {
        fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidRegs {
            let mut out = GuestCpuidView::default().cpuid(leaf, subleaf);
            if leaf == self.leaf && subleaf == 0 {
                if leaf == 7 {
                    out.ebx &= !self.bit;
                } else {
                    out.ecx &= !self.bit;
                }
            }
            out
        }
    }
    for (leaf, bit, bytes) in [
        (1, 1 << 28, &[0xc5, 0xf0, 0x58, 0xc2][..]),
        (7, 1 << 5, &[0xc5, 0xf5, 0xfe, 0xc2][..]),
        (1, 1 << 28, &[0xc4, 0xe2, 0x71, 0x98, 0xc2][..]),
        (1, 1 << 28, &[0xc4, 0xe2, 0x79, 0x13, 0xc1][..]),
        (1, 1 << 28, &[0xc4, 0xe2, 0x71, 0xdc, 0xc2][..]),
        (1, 1 << 28, &[0xc4, 0xe3, 0x71, 0x44, 0xc2, 0][..]),
        (7, 1 << 3, &[0xc4, 0xe2, 0x70, 0xf2, 0xc2][..]),
        (7, 1 << 8, &[0xc4, 0xe2, 0x73, 0xf5, 0xc2][..]),
        (1, 1 << 12, &[0xc4, 0xe2, 0x71, 0x98, 0xc2][..]),
        (1, 1 << 29, &[0xc4, 0xe2, 0x79, 0x13, 0xc1][..]),
        (1, 1 << 22, &[0x0f, 0x38, 0xf0, 0x07][..]),
        (1, 1 << 25, &[0x66, 0x0f, 0x38, 0xdc, 0xc1][..]),
        (1, 1 << 25, &[0xc4, 0xe2, 0x71, 0xdc, 0xc2][..]),
        (1, 1 << 1, &[0x66, 0x0f, 0x3a, 0x44, 0xc1, 0][..]),
        (1, 1 << 1, &[0xc4, 0xe3, 0x71, 0x44, 0xc2, 0][..]),
    ] {
        let (mut cpu, mut mem) = fixture();
        // Build once under the full view, then replace it: cached leaves must
        // still obey the live authority on the next production entry.
        mem.write(0, &[bytes, &[0xeb, 0]].concat());
        cpu.context_mut().gpr[reg::RDI] = 0x4800;
        cpu.context_mut().rip = 0x4000;
        assert!(matches!(
            cpu.step_block(&mut mem).unwrap(),
            SoftCpuExit::Continue { .. }
        ));
        cpu.set_cpuid_view(Box::new(Without { leaf, bit })).unwrap();
        cpu.context_mut().rip = 0x4000;
        cpu.context_mut().gpr[reg::RDI] = 0x8000; // unmapped
        cpu.context_mut().cr0 |= 8; // #UD must also precede #NM
        let gpr = cpu.context().gpr;
        let fp = cpu.context().fxsave.0;
        let ymm = cpu.context().ymm_hi128;
        assert!(
            matches!(cpu.step_block(&mut mem).unwrap(), SoftCpuExit::Exception(e)
            if e.vector == X86ExceptionVector::InvalidOpcode),
            "{leaf:x}/{bit:x}: {bytes:x?}"
        );
        assert_eq!(cpu.context().gpr, gpr);
        assert_eq!(cpu.context().fxsave.0, fp);
        assert_eq!(cpu.context().ymm_hi128, ymm);
    }
}
