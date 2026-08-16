# Carrick Documentation Index

This directory contains technical design documents, architectural overviews, HAL/ABI specifications, diagnostic guides, and benchmark records for the Carrick project.

---

## 🏛 Architecture & Foundations

- **[`architecture-overview.md`](architecture-overview.md)** — High-level architecture of Carrick: execution lanes, kernel graph, VFS/rootfs, process models, and syscall translation.
- **[`hal.md`](hal.md)** — Hardware Abstraction Layer (HAL): platform-neutral contracts separating host/VMM backends (HVF, KVM, bhyve, NVMM).
- **[`namespaces-design.md`](namespaces-design.md)** — Linux PID, mount, IPC, user, and network namespace emulation inside host Darwin/BSD environments.
- **[`support-matrix.md`](support-matrix.md)** — Auto-rendered Linux syscall compatibility and conformance status matrix across architectures.
- **[`syscalls-emulation-map.md`](syscalls-emulation-map.md)** — Canonical AArch64 and x86_64 Linux syscall dispatch map with emulation coverage levels.

---

## 🔧 Subsystems & Implementation Design

- **[`fs-host-capstd-amplification.md`](fs-host-capstd-amplification.md)** — Host filesystem passthrough via `cap-std`, case-sensitivity amplification, and APFS clone mechanics.
- **[`syscall-shim-design.md`](syscall-shim-design.md)** — In-guest syscall acceleration shim and fast-path interception.
- **[`rosetta.md`](rosetta.md)** & **[`rosetta-binfmt.md`](rosetta-binfmt.md)** — Apple Silicon Linux x86_64 translation via Rosetta.
- **[`bhyve-shared-memory.md`](bhyve-shared-memory.md)** — Shared memory and guest physical address translation on FreeBSD/bhyve.
- **[`ptrace-darwin-design.md`](ptrace-darwin-design.md)** — `ptrace(2)` emulation design on macOS/Darwin.
- **[`network-provider-roadmap.md`](network-provider-roadmap.md)** — Sockets, AF_NETLINK, epoll multiplexing, and network device abstraction roadmap.

---

## 🔬 Testing, Conformance & Diagnostics

- **[`conformance-testing.md`](conformance-testing.md)** — Differential conformance testing framework against native ARM64 Docker oracle.
- **[`conformance-coverage.md`](conformance-coverage.md)** — Conformance coverage tiers, test harnesses (LTP, CPython, Node.js, Go), and regression tracking.
- **[`diagnostics-and-debugging.md`](diagnostics-and-debugging.md)** — Guide to in-process USDT probes, `carrick trace` (DTrace), `carrick_lldb.py`, and the lock-free event ring.

---

## ⚡ Performance, JIT & Binary Patching

- **[`dynamic-syscall-rewriter.md`](dynamic-syscall-rewriter.md)** — Dynamic Syscall Rewriter (DSR) architecture, block planning, instruction caches, and Darwin JIT execution.
- **[`perf-results/`](perf-results/)** — Benchmark results, wall-time audits, allocation census logs, and profile records.

---

## 📁 Subdirectories & Historical Records

- **[`archive/`](archive/)** — Historical campaign diaries, early build decomposition plans, and milestone evidence documents.
- **[`superpowers/`](superpowers/)** — Agent capability specifications, task plans, and architectural design reviews.
- **[`ltp-baseline/`](ltp-baseline/)**, **[`cpython-baseline/`](cpython-baseline/)**, **[`nodejs-baseline/`](nodejs-baseline/)** — Reference oracle baseline recordings for test suites.
