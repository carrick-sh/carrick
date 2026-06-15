/* ABI-correct wrapper for hv_vcpu_set_simd_fp_reg.
 *
 * Apple's `hv_simd_fp_uchar16_t` is `__attribute__((ext_vector_type(16)))
 * uint8_t` — a 16-byte SIMD vector passed BY VALUE in a vector (V) register per
 * AAPCS64. The Rust `applevisor-sys` binding (without the nightly `simd-nightly`
 * feature) types that by-value parameter as `u128`, which Rust passes in a
 * general-purpose register pair — the wrong register class — so the kernel
 * reads junk and the SIMD register ends up zeroed. Passing the vector type
 * across `extern "C"` from Rust requires the nightly-only `simd_ffi` feature, so
 * we do the call from C instead, where the vector ABI is correct on stable.
 *
 * The 16 register bytes arrive by pointer (a plain GP-register argument);
 * we reconstruct the vector and forward to the kernel.
 */

#include <stdint.h>
#include <string.h>

typedef uint64_t hv_vcpu_t;
typedef int32_t hv_return_t;
typedef uint32_t hv_simd_fp_reg_t;
typedef __attribute__((ext_vector_type(16))) uint8_t hv_simd_fp_uchar16_t;

/* Resolved at link time from Hypervisor.framework (already linked by
 * applevisor-sys). */
extern hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg,
                                           hv_simd_fp_uchar16_t value);

hv_return_t carrick_set_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg,
                                    const uint8_t *bytes) {
  hv_simd_fp_uchar16_t value;
  memcpy(&value, bytes, 16);
  return hv_vcpu_set_simd_fp_reg(vcpu, reg, value);
}
