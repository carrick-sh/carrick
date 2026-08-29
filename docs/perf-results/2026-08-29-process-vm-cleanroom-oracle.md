# Process-vm clean-room oracle receipt — 2026-08-29

This Docker-only measurement establishes the Task 8 process-vm contracts
without consulting Linux kernel source. It ran without Carrick or another guest
lane running concurrently.

## Exact environment

- Image: `gcc:14-bookworm`
- Image ID and digest:
  `sha256:5e927c284bf55a7dc796262e311a0703344f62f41f5621eb56843111b1d37e15`
- Platform: native `linux/arm64`; container reported `aarch64`
- Compiler: `gcc (GCC) 14.3.0`
- Probe source SHA-256:
  `a55420f37666aaa09b84d6787c43fa1488e56917ffd5e3a72c3eb51540be03e4`
- Source: [`2026-08-29-process-vm-cleanroom-oracle/process_vm_oracle_cleanroom.c`](2026-08-29-process-vm-cleanroom-oracle/process_vm_oracle_cleanroom.c)

## Command

```sh
docker run --rm --platform linux/arm64 -v /tmp:/work -w /work \
  gcc:14-bookworm sh -c \
  'gcc -O2 -Wall -Wextra -o process_vm_oracle_cleanroom \
  process_vm_oracle_cleanroom.c && ./process_vm_oracle_cleanroom'
```

## Exact output

```text
read_remote_midfault rc=4096 errno=0
read_remote_midfault_bytes first=66 last=66
write_remote_midfault rc=4096 errno=0
write_remote_midfault_bytes first=87 last=87
read_local_midfault rc=4096 errno=0
write_local_midfault rc=4096 errno=0
both_counts_zero_missing rc=0 errno=0
both_counts_zero_bad_flags rc=-1 errno=22
local_total_zero_bad_remote_array_missing rc=0 errno=0
remote_total_zero_missing rc=0 errno=0
bad_local_array_remote_count_zero_missing rc=-1 errno=14
valid_vectors_missing rc=-1 errno=3
```

## Task 8 contracts established

- A fault inside one remote iovec preserves and returns the exact 4096-byte
  prefix for both read and write.
- A fault inside one local iovec likewise preserves and returns 4096 bytes.
- Invalid nonzero flags win over a zero-byte transfer with `EINVAL`.
- After flags and local-iovec import, a zero local total returns zero without
  importing the remote array or resolving the PID.
- A zero remote total returns zero without resolving the PID.
- A nonzero invalid local iovec array returns `EFAULT` even when the remote
  count is zero.
- With nonempty valid vectors, a missing PID returns `ESRCH`.

Permission policy, target exec/exit races, and extreme total lengths remain
separate oracle questions; this receipt does not claim them.
