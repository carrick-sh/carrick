#!/usr/bin/env bash
# Sweep stage-1 MMU configurations via the repro binary + lldb sysreg dump.
# Usage:
#   ./scripts/stage1_sweep.sh <label> [KEY=value ...]
# Example:
#   ./scripts/stage1_sweep.sh "ap=00 default rest" REPRO_AP=00
set -euo pipefail

label="$1"; shift
env_args=()
for kv in "$@"; do env_args+=("$kv"); done

REPRO=./target/release/examples/stage1_repro

env "${env_args[@]+${env_args[@]}}" "$REPRO" 1>/dev/null 2>/dev/null &
PID=$!
sleep 1

# Dump key sys regs + PC via HVF C API. Use simple eval expressions so the
# values come back through the lldb result printer (no need for printf).
out=$(lldb -p "$PID" --batch \
  -o 'expr -- unsigned long _v=0; (int)hv_vcpu_get_reg(0, 31, &_v); _v' \
  -o 'expr -- unsigned long _v=0; (int)hv_vcpu_get_sys_reg(0, 0xc290, &_v); _v' \
  -o 'expr -- unsigned long _v=0; (int)hv_vcpu_get_sys_reg(0, 0xc300, &_v); _v' \
  -o 'expr -- unsigned long _v=0; (int)hv_vcpu_get_sys_reg(0, 0xc201, &_v); _v' \
  -o 'expr -- unsigned long _v=0; (int)hv_vcpu_get_sys_reg(0, 0xc200, &_v); _v' \
  -o 'process detach' 2>/dev/null | grep -E '\$' )
kill -9 "$PID" 2>/dev/null || true
wait 2>/dev/null || true

pc=$(echo "$out" | sed -n '1s/.*= //p')
esr=$(echo "$out" | sed -n '2s/.*= //p')
far=$(echo "$out" | sed -n '3s/.*= //p')
elr=$(echo "$out" | sed -n '4s/.*= //p')
spsr=$(echo "$out" | sed -n '5s/.*= //p')

ec=$(( (esr >> 26) & 0x3f ))
ifsc=$(( esr & 0x3f ))

verdict="HANG"
[ "$ec" = "22" ] && verdict="HVC-OK"     # 0x16 = 22 dec
[ "$ec" = "33" ] && verdict="IAB-SE-IFSC=$(printf 0x%x $ifsc)"  # 0x21 = 33
[ "$ec" = "32" ] && verdict="IAB-LE-IFSC=$(printf 0x%x $ifsc)"  # 0x20 = 32

printf "%-40s PC=0x%-6x ESR=0x%-8x EC=0x%-2x  FAR=0x%-6x  → %s\n" \
  "$label" "$pc" "$esr" "$ec" "$far" "$verdict"
