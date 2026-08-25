# Task 1 report — exact legacy LTP closure protocols

## Status

Completed. The closure-mode LTP parser now recognizes the three requested
source-specific legacy protocols without broadening the regression-mode parser.

## Files changed

- `crates/carrick-conformance/src/parsers/ltp.rs`
- `.superpowers/sdd/current-plan/task-1-report.md` (this required report)

## RED evidence

Before adding production parsing, I added three literal-receipt tests. Each
names the production mutation it catches in its doc comment. The transcripts
come from `target/conformance/raw/fill-14443-d06` through `d10` and use the
20260529 source protocol shapes; no mocks were used.

Command:

```sh
env RUSTC_WRAPPER= cargo test -p carrick-conformance closure_parses_only_
```

Result: exit 101; all three new tests failed for the expected reason: the old
closure parser returned `SuiteOutcome::None` with no identities for complete
`fcntl11`, `setfsuid04`, and `fcntl01` transcripts.

The first attempt without `RUSTC_WRAPPER=` was blocked before compilation by
the local `sccache` permission error; it did not count as RED evidence.

## GREEN evidence

After the parser implementation and formatting, the same focused command
passed: 3 passed, 0 failed, 159 filtered out, exit 0.

The package has no library target, so the brief's literal command was attempted
and recorded:

```sh
env RUSTC_WRAPPER= cargo test -p carrick-conformance --lib
```

Result: exit 101, `error: no library targets found in package
\`carrick-conformance\``. The supported equivalent was then run:

```sh
env RUSTC_WRAPPER= cargo test -p carrick-conformance
```

Result: 162 passed, 0 failed, exit 0.

Formatting and whitespace checks also passed:

```sh
env RUSTC_WRAPPER= cargo fmt --all
git diff --check -- crates/carrick-conformance/src/parsers/ltp.rs
```

No Docker, Carrick guest, or `carrick-cli` build was run.

## Self-review

- The new dispatch executes only in closure mode, leaving modern, old-API,
  summary reconciliation, timeout handling, and regression parsing unchanged.
- `fcntl11` requires one tmpdir banner and ordered Enter/Exit pairs for blocks
  1 through 9. Unknown, duplicate, reordered, missing, and unmatched lines
  fail closed to `SuiteOutcome::None`; an in-block `TFAIL`/`TBROK` changes that
  exact block identity from OK.
- `setfsuid04` requires exactly the source-observable two deny markers, two
  restored-root success markers, and the terminal TPASS. Any missing, reordered,
  extra, terminal-failure, or nonzero transcript returns None rather than
  guessing an identity.
- `fcntl01` is keyed specifically to its TCID and its source's only successful
  tmpdir transcript. It emits the single stable identity on clean success and
  maps recognized TFAIL/TBROK to that same identity; unrelated or nonzero
  no-verdict output remains None.

## Blockers / concerns

- There is no `carrick-conformance` library target; the requested `--lib`
  command cannot run. The executable-target package suite passed instead.
- The worktree's git fsmonitor socket reports an IPC error on status/diff calls,
  but direct diffs show only the scoped parser file before the required report
  and commit.
- Commit: `fix(conformance): parse legacy ltp closure protocols` (the final
  local commit containing this report; resolve its exact hash with
  `git rev-parse HEAD`).

## Fix round 1/5 — tmpdir ordering and fcntl01 failure coverage

Base: `049730d0`.

### Files changed

- `crates/carrick-conformance/src/parsers/ltp.rs`
- `.superpowers/sdd/current-plan/task-1-report.md` (this appended evidence)

### RED evidence

I added a mutation assertion derived from the `fill-14443-d08/d09` `fcntl11`
receipts: move the tmpdir TINFO line after the completed block-9 pair. It must
be non-cacheable because the banner is not the first protocol line.

```sh
env RUSTC_WRAPPER= cargo test -p carrick-conformance \
  closure_parses_only_complete_fcntl11_block_protocols
```

Result: exit 101, 0 passed / 1 failed. The unmodified parser incorrectly
returned Success with all nine block identities, which proves the test catches
the reviewed mutation.

The requested realistic `fcntl01` tmpdir-plus-TFAIL and tmpdir-plus-TBROK
coverage was added to the existing source-protocol test. The base parser
already handled those two-line failure transcripts, so those added assertions
were green coverage rather than a new red condition.

### GREEN evidence

After requiring the `fcntl11` tmpdir banner to be the first nonblank line:

```sh
env RUSTC_WRAPPER= cargo test -p carrick-conformance closure_parses_only_
env RUSTC_WRAPPER= cargo test -p carrick-conformance
env RUSTC_WRAPPER= cargo fmt --all -- --check
git diff --check
```

Results: focused parser tests 3 passed / 0 failed (exit 0); full package suite
162 passed / 0 failed (exit 0); format and diff checks passed (exit 0).

### Self-review

- `fcntl11` consumes its required tmpdir line before all marker parsing, so a
  late or duplicate banner is an unknown protocol line and returns None.
- The `fcntl01` tests now cover the real tmpdir banner followed by either
  TFAIL or TBROK, with the same stable identity and the appropriate failure
  outcome.
- No Docker, Carrick guest, `carrick-cli` build, or unrelated source file was
  touched.

### Concerns

- Commit: pending the requested narrow fix commit.
