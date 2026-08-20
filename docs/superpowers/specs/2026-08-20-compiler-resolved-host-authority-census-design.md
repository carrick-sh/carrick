# Compiler-Resolved Host-Authority Census Design

**Status:** approved successor design under the standing phase approval  
**Supersedes:** the lexical scanner portion of Phase 0 Task 2 in
`docs/superpowers/plans/2026-08-19-trustworthy-authority-baseline.md`  
**Does not supersede:** the authority model or closure gates in
`docs/superpowers/specs/2026-08-19-authority-enforced-kernel-closure-design.md`

## Problem

Phase 0 must freeze every reviewed use of a host facility that can influence a
guest answer, host target, authorized backing object, or authenticated carrier.
The first implementation attempted to recover Rust name resolution, cfg
selection, module reachability, and call syntax in Python. Five repair rounds
proved that architecture fail-open: valid cfg items could erase production
siblings, aliases and function values could evade the census, standalone-bin
reachability could waive library code, and an omitted operation such as
`libc::waitpid` remained invisible.

A security drift gate may be incomplete by declared scope, but it may not
pretend to resolve Rust while silently missing valid Rust. Phase 0 therefore
uses the compiler's resolved program as its source of callsite truth.

## Decision

Use pinned Clippy `disallowed-methods` diagnostics as the authoritative
callsite census. Run every declared product configuration with
`--force-warn clippy::disallowed_methods --message-format=json`, normalize the
compiler diagnostics, and compare them with a checked structured review
inventory.

`--force-warn` is load-bearing. Ordinary `#[expect]` annotations remain useful
as source breadcrumbs and keep the normal `just clippy` gate readable, but
they cannot suppress the census. The pinned Clippy 1.96 feasibility probe
confirmed that forced diagnostics resolve direct calls, imported aliases,
reexports, Rust and libc function-item captures, local and dependency macros,
and `libc::waitpid`.

The census never parses Rust source to decide what a call means. It parses only
Cargo/Clippy JSON diagnostics and checked JSON configuration.

## Components

### Watched-operation catalog

`clippy.toml` contains explicit fully qualified operations and stable catalog
IDs. Invalid paths are errors, not ignored entries. The initial catalog covers
the existing host-identity, process-control, filesystem, network, thread, and
HVF operations and adds the breaker omissions, including `libc::waitpid` and
the actual `OpenOptions::open` operation rather than only builder creation.

The catalog also names escape hatches that could bypass a method catalog:
`libc::syscall`, dynamic symbol lookup, inline assembly, local `extern`
redeclarations, and direct FFI to equivalent host APIs. A small deny-style
source gate rejects those constructs outside explicitly reviewed boundary
modules. This gate detects only unmistakable escape-hatch syntax; it does not
attempt name resolution.

Catalog completeness is a declared Phase 0 boundary. Phase 1 replaces this
enumeration with a typed host-capability facade and denies raw host operations
outside it.

### Product build matrix

`scripts/migrate/host-authority-build-matrix.json` declares every package,
target kind, feature set, target triple, and cfg profile whose compiled code is
part of the product. The collector executes exactly that matrix and records the
pinned `rustc` and Clippy identities in its receipt.

The canonical macOS/HVF arm64 slice is mandatory locally. Linux, FreeBSD, and
NetBSD slices use the repository's existing platform check environments. A
partial local run is allowed only as a named partial check and cannot update or
bless the complete inventory. Test-only path modules and standalone probe bins
are outside the product matrix; compiler target selection, not a handwritten
reachability parser, excludes them.

### Diagnostic collector

The replacement checker launches Cargo/Clippy for each requested matrix slice,
requires successful compilation, accepts only JSON messages, and extracts
`clippy::disallowed_methods` diagnostics. Each normalized row contains:

- stable catalog operation ID and compiler-reported canonical operation;
- primary source file, byte/line/column span, and macro expansion callsite;
- the set of product matrix profiles in which the site is reachable;
- a stable review ID;
- classification, structured evidence, and rationale.

Rows are deduplicated by compiler identity and expansion callsite across matrix
slices. Ambiguous diagnostics, duplicate identities, unknown operations,
missing matrix slices, compiler failure, malformed JSON, new rows, removed
rows, and unreviewed rows fail closed. Refreshing the inventory never carries a
review onto a changed operation or callsite.

### Review model

Classifications remain:

- `forbidden_semantic`: the result or target contributes to a guest-visible
  answer, identity, signal, wait, liveness decision, or host target selected by
  guest state;
- `declared_backing`: the call accesses one named capability-resolved backing
  root, object, wire endpoint, page, or hardware clock;
- `declared_substrate`: the call acts only on one authenticated carrier-owned
  thread, vCPU, or helper resource and cannot accept a guest identity;
- `legacy_unreachable`: not valid for product diagnostics. Product-matrix
  exclusion replaces this waiver, so a compiled product row cannot be marked
  unreachable.

Structured evidence prevents empty and schema-wrong reviews; human review
establishes semantic truth. Phase 0 documentation must not claim that prose or
JSON validation proves a classification. Current host waits and liveness sites
are reviewed under the strict rule that any result feeding guest waitability,
exit status, record reclamation, or CLI-visible container state is
`forbidden_semantic`.

### Source breadcrumbs

Reviewed sites may use a narrow macro or expression-level
`#[expect(clippy::disallowed_methods, reason = "HA-...")]` breadcrumb. The
review ID must exist in the checked inventory. Expectations are not the census
and are never trusted for completeness because the forced diagnostic run
overrides them.

No function-, module-, or crate-wide allow/expect is accepted for a watched
operation. A focused test proves that a broad expectation still produces every
forced diagnostic and therefore cannot hide drift.

## Failure and update behavior

The normal gate is read-only. A refresh writes a candidate inventory with new
rows marked `unreviewed`; it never blesses classifications. Complete inventory
updates require every mandatory matrix slice and matching tool identities.
Partial runs may compare their own slices but cannot delete rows from other
profiles or rewrite the canonical artifact.

Compiler diagnostics are treated as an interface. If a pinned toolchain update
changes diagnostic shape or canonical names, the gate fails and requires a
reviewed catalog/migration change.

## Red-first verification

A checked fixture workspace exercises:

- direct, aliased, reexported, function-item, and macro-generated calls;
- `libc::waitpid` and `OpenOptions::open`;
- product feature/target cfg differences;
- a broad `#[expect]` that forced warnings must pierce;
- an operation retarget, new call, removed call, duplicate ID, unknown
  operation, missing slice, malformed diagnostic, and invalid evidence;
- escape hatches such as `libc::syscall` and local host FFI declarations.

The first test records the complete compiler diagnostic set before the
collector exists. Subsequent tests require new diagnostics to become
`unreviewed`, reviewed diagnostics to pass, stale rows to fail, and partial
matrix results to remain unable to bless the canonical inventory.

## Non-goals

- This is not Phase 1 type-level capability enforcement.
- It does not prove that a human-authored classification is semantically true.
- It does not inspect arbitrary dependency internals; dependency wrappers are
  a separate trust surface.
- It does not make cross-platform completeness claims from a macOS-only run.

## Alternatives rejected

- **rust-analyzer/SCIP:** useful as an audit cross-check, but its batch CLI is
  explicitly unstable, cfg/target control is less direct, and it adds a
  protobuf consumer without a native deny mechanism.
- **Another regex, Semgrep, `syn`, or token parser:** syntax alone cannot
  reproduce DefId resolution, reexports, function values, cfg, and Cargo target
  reachability.
- **Custom rustc/Dylint lint:** strongest bespoke semantics, but nightly and
  compiler-internal coupling are disproportionate for the Phase 0 census.

## Exit criteria

The replacement is acceptable only when the adversarial fixture is green, the
canonical macOS/HVF product slice produces a fully reviewed inventory, forced
diagnostics pierce source expectations, current `waitpid` and guest-liveness
sites are present and correctly classified, the ordinary typed-domain and
Clippy gates remain green, and documentation labels cross-platform slices not
run locally as pending rather than complete.
