use carrick_softcpu_aarch64::{A64Class, classify};

#[test]
fn census_top_twenty() {
    // Regression inputs from the issue's dated measurement, not an inventory
    // used by the decoder or by the real-image coverage assertion.
    for word in [
        0xd5033f5f, 0x9ac82428, 0xd4200020, 0xdac01108, 0x9ac82129, 0x9ac82128, 0xdac01129,
        0x1ac92109, 0x9ac9254a, 0xdac0114a, 0x9ac92149, 0xdac002c8, 0x1ac82128, 0xdac00268,
        0x9ac82528, 0xdac00308, 0x1ac92508, 0x9acd21cd, 0x1ac82528, 0x9ada2108,
    ] {
        assert_ne!(classify(word), A64Class::Unknown, "{word:08x}");
    }
}

#[test]
fn allocated_family_leaves() {
    for sf in [0, 1 << 31] {
        for op in 8..=11 {
            for registers in [0, 31 | (30 << 5) | (29 << 16)] {
                let word = sf | 0x1ac00000 | (op << 10) | registers;
                assert_ne!(classify(word), A64Class::Unknown, "{word:08x}");
            }
        }
        for op in 0..=5 {
            if sf == 0 && op == 3 {
                continue;
            }
            let word = sf | 0x5ac00000 | (op << 10) | (30 << 5) | 31;
            assert_ne!(classify(word), A64Class::Unknown, "{word:08x}");
        }
    }
    for imm in [0, 1, 0x8000, 0xffff] {
        assert_ne!(classify(0xd4200000 | (imm << 5)), A64Class::Unknown);
    }
    for crm in 0..16 {
        assert_ne!(classify(0xd503305f | (crm << 8)), A64Class::Unknown);
    }
    // AT: base stage-1/stage-1+2 translations and PAN forms.
    for (op1, crm, op2) in [
        (0, 8, 0),
        (0, 8, 1),
        (0, 8, 2),
        (0, 8, 3),
        (4, 8, 0),
        (4, 8, 1),
        (4, 8, 4),
        (4, 8, 5),
        (4, 8, 6),
        (4, 8, 7),
        (6, 8, 0),
        (6, 8, 1),
        (0, 9, 0),
        (0, 9, 1),
    ] {
        for rt in [0, 17, 31] {
            let word = 0xd5087000 | (op1 << 16) | (crm << 8) | (op2 << 5) | rt;
            assert_ne!(classify(word), A64Class::Unknown, "{word:08x}");
        }
    }
    for crm in [3, 7] {
        for op2 in [1, 2, 3, 5, 7] {
            for rt in [0, 17, 31] {
                let word = 0xd5088000 | (crm << 8) | (op2 << 5) | rt;
                assert_ne!(classify(word), A64Class::Unknown, "{word:08x}");
            }
        }
    }
}

#[test]
fn neighboring_unallocated_leaves() {
    for word in [
        0x5ac00c00, 0xdac08000, 0xdac10000, 0xdac01800, 0x1ac03000, 0x3ac02000, 0x5ac02000,
        0xd4200001, 0xd503305e, 0xd503307f, 0xd5087880, 0xd5097800, 0xd50c7840, 0xd5087940,
        0xd5088220, 0xd5098720, 0xd5088780, 0xd5088760,
    ] {
        assert_eq!(classify(word), A64Class::Unknown, "{word:08x}");
    }
}
