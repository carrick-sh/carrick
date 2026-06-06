# Homebrew distribution for carrick

**Date:** 2026-06-06
**Status:** Approved (brainstorming) — ready for implementation plan
**Goal:** `brew install --HEAD carrick` from a public tap, building from source and
ad-hoc codesigning the binary with the Hypervisor.framework entitlement on the
user's machine.

## Background / constraints

- The binary is `carrick`, built from the workspace member `crates/carrick-cli`
  (workspace version `0.1.0`, edition 2024, license `Apache-2.0 OR MIT`).
- carrick needs the `com.apple.security.hypervisor` entitlement to use
  Hypervisor.framework. `cargo build` strips the macOS signature, and an
  unsigned binary fails every guest run with `HV_DENIED (0xfae94007)`. The repo
  already ships the entitlement plist at `scripts/entitlements.plist` and signs
  ad-hoc in `scripts/build-signed.sh` (`codesign --force --sign - --entitlements
  scripts/entitlements.plist`).
- On Apple Silicon, Homebrew ad-hoc signs binaries it installs but does **not**
  add custom entitlements. The formula must therefore re-sign with the
  hypervisor entitlement so the installed binary can run guests.
- carrick runs aarch64 Linux guests via HVF → **Apple Silicon only**.
- `carrick-sh/carrick` is currently **private**; `Cargo.lock` is committed.

## Decisions (from brainstorming)

| Decision | Choice |
| --- | --- |
| Distribution | Build from source; make `carrick-sh/carrick` **public** |
| Tap repo | `carrick-sh/homebrew-carrick` (tap name `carrick-sh/carrick`) |
| Versioning | **HEAD-only** (no version tag yet) — `brew install --HEAD carrick` |
| Formula location | Canonical in the tap repo only (no mirror in main, to avoid drift) |
| Signing | Ad-hoc `codesign` with `scripts/entitlements.plist` during install |

Out of scope: prebuilt bottles, version tags / release CI, auto-bump workflows.
A future stable tag would enable bare `brew install carrick` (no `--HEAD`).

## Architecture

### 1. Tap repo `carrick-sh/homebrew-carrick` (new, public)

Contains `Formula/carrick.rb`. Install UX:

```sh
brew tap carrick-sh/carrick
brew install --HEAD carrick
# or, one-liner:
brew install --HEAD carrick-sh/carrick/carrick
```

### 2. Formula `Formula/carrick.rb`

```ruby
class Carrick < Formula
  desc "Run Linux binaries on macOS via Apple's Hypervisor.framework"
  homepage "https://github.com/carrick-sh/carrick"
  license any_of: ["Apache-2.0", "MIT"]
  head "https://github.com/carrick-sh/carrick.git", branch: "main"

  depends_on "rust" => :build
  depends_on arch: :arm64        # Apple Silicon only (aarch64 HVF guests)

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/carrick-cli")
    # cargo strips the macOS signature; HVF needs the hypervisor entitlement.
    system "codesign", "--force", "--sign", "-",
           "--entitlements", "scripts/entitlements.plist", bin/"carrick"
  end

  def caveats
    <<~EOS
      carrick is ad-hoc codesigned with com.apple.security.hypervisor at install
      time so it can use Hypervisor.framework. Apple Silicon macOS only.
    EOS
  end

  test do
    # `--help` exits 0; adjust the matcher to carrick's actual help banner.
    assert_match(/carrick|Usage/, shell_output("#{bin}/carrick --help"))
  end
end
```

- `std_cargo_args(path: "crates/carrick-cli")` → `--locked --root <prefix>
  --path crates/carrick-cli`, installing the `carrick` bin into `<prefix>/bin`.
- `depends_on arch: :arm64` rejects Intel installs cleanly (HVF aarch64 guests
  require Apple Silicon). Formulae are macOS-only by default on this tap.

### 3. Signing step (the crux — verified empirically)

The entitlement re-sign uses the in-tree plist:

```sh
codesign --force --sign - --entitlements scripts/entitlements.plist <bin>
```

Open question resolved during implementation by **local testing, not
assumption**: whether signing in `install` survives Homebrew's own
post-install ARM ad-hoc signing, or whether it must move to `post_install`.
Acceptance check after a local `brew install`:

1. `codesign -d --entitlements - "$(brew --prefix)/bin/carrick"` shows
   `com.apple.security.hypervisor`.
2. `carrick run <image> /bin/true` (or equivalent) does **not** fail with
   `HV_DENIED`.

If `install`-time signing is stripped, move the `codesign` call to
`post_install` (which runs after relocation/linking) and re-verify.

### 4. Make `carrick-sh/carrick` public

Required so Homebrew can anonymously `git clone` the repo for `--HEAD` builds.
Done via `gh repo edit carrick-sh/carrick --visibility public --accept-visibility-change-consequences` (or the GitHub UI). Consequential and
hard to reverse — confirmed with the user at execution time.

### 5. README install section (main repo)

Add an "Install (Homebrew)" section to `README.md`:

```markdown
## Install

Apple Silicon macOS only.

    brew tap carrick-sh/carrick
    brew install --HEAD carrick

carrick is ad-hoc codesigned with the Hypervisor.framework entitlement during
install so it can run Linux guests.
```

## Components & responsibilities

| Unit | Purpose | Depends on |
| --- | --- | --- |
| `carrick-sh/homebrew-carrick` / `Formula/carrick.rb` | Build-from-source + entitlement signing recipe | public `carrick-sh/carrick`, `rust`, `scripts/entitlements.plist` |
| `carrick-sh/carrick` (public) | Source the formula clones for `--HEAD` | — |
| `README.md` install section | User-facing install instructions | the tap |

## Testing / verification

- Author the formula, test locally with the installed Homebrew before publishing:
  `brew install --HEAD <local-or-ssh formula>` → run `brew test carrick` and the
  two acceptance checks in §3 (entitlement present + no HV_DENIED).
- `brew audit --new --formula Formula/carrick.rb` (style/lint) — fix audit
  findings except those inherent to a HEAD-only / arch-gated formula.

## Execution prerequisites & gated actions

1. Verify `cargo install --path crates/carrick-cli --locked` builds the `carrick`
   bin from a clean checkout.
2. **Gated (confirm at execution):** make `carrick-sh/carrick` public.
3. **Gated (confirm at execution):** create public `carrick-sh/homebrew-carrick`
   and push `Formula/carrick.rb`.
4. Commit the README install section to `carrick-sh/carrick`.

## Future (not now)

- Cut a `v0.1.0` tag + stable `url`/`sha256` so bare `brew install carrick`
  works without `--HEAD`.
- Optional prebuilt bottles / release CI / auto-bump for fast installs.
