#!/bin/sh
# Compile the no_std vDSO getrandom blob (vdso_getrandom_blob.rs) to a FLAT,
# ZERO-RELOCATION aarch64 binary and print the bytes (+ the __kernel_getrandom
# offset) for embedding into crates/carrick-mem/src/vdso.rs. The shared crypto
# core is host-tested in carrick-mem; this only produces the embeddable blob.
#
# Requires: rustc + `rustup target add aarch64-unknown-none` and the llvm-tools
# component (`rustup component add llvm-tools`, which ships rust-lld + llvm-*).
set -e
cd "$(dirname "$0")"
SRC="vdso_getrandom_blob.rs"
OUT="${OUT:-/tmp/vdso-getrandom}"
mkdir -p "$OUT"

rustup target add aarch64-unknown-none >/dev/null 2>&1 || true
rustup component add llvm-tools >/dev/null 2>&1 || true
BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin"
LLD="$BIN/rust-lld"
OBJCOPY="$BIN/llvm-objcopy"
NM="$BIN/llvm-nm"
READELF="$BIN/llvm-readelf"

# 1. compile to a PIC relocatable object. function-sections lets the linker
#    script place __kernel_getrandom first (offset 0).
rustc --target aarch64-unknown-none --edition 2021 \
  -C panic=abort -C relocation-model=pic -C opt-level=2 -C lto=false \
  -C target-feature=+crt-static \
  --emit=obj --crate-type=lib "$SRC" -o "$OUT/blob.o"

# 2. link to a flat binary: one contiguous segment, __kernel_getrandom first,
#    gc unused helpers, discard unwind/metadata. Resolves all internal
#    adrp/add (rodata) + bl (mem*) references PC-relative within the blob.
cat > "$OUT/flat.ld" <<'LD'
ENTRY(__kernel_getrandom)
SECTIONS {
  . = 0;
  .text : {
    *(.text.__kernel_getrandom)
    *(.text*)
  }
  .rodata : { *(.rodata*) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) *(.llvm*) *(.ARM.*) }
}
LD
"$LLD" -flavor gnu -T "$OUT/flat.ld" --gc-sections -o "$OUT/blob.elf" "$OUT/blob.o"

# 3. ZERO-RELOCATION gate — a flat blob with any relocation is not embeddable.
relocs=$("$READELF" -r "$OUT/blob.elf" 2>/dev/null | grep -cE 'R_AARCH64' || true)
if [ "$relocs" != "0" ]; then
  echo "FATAL: blob has $relocs relocation(s) — not position-independent:" >&2
  "$READELF" -r "$OUT/blob.elf" >&2
  exit 1
fi

# 4. extract the flat bytes; __kernel_getrandom MUST be at offset 0 (the linker
#    script orders it first) so vdso.rs can point the symbol at the blob start.
"$OBJCOPY" -O binary "$OUT/blob.elf" "$OUT/blob.bin"
off=$("$NM" "$OUT/blob.elf" | awk '/ __kernel_getrandom$/ {print $1}')
if [ "$off" != "0000000000000000" ]; then
  echo "FATAL: __kernel_getrandom not at offset 0 (got 0x$off)" >&2
  exit 1
fi
# 5. install the flat blob next to vdso.rs, which include_bytes!()'s it.
DST="../../carrick-mem/src/vdso_getrandom_blob.bin"
cp -f "$OUT/blob.bin" "$DST"
echo "OK: $(wc -c < "$DST") bytes, __kernel_getrandom @ 0x0, zero relocations -> $DST"
