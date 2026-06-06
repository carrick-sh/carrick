# Homebrew Tap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `brew install --HEAD carrick` from a public `carrick-sh/homebrew-carrick` tap that builds carrick from source and ad-hoc codesigns it with the Hypervisor.framework entitlement on the user's machine.

**Architecture:** A HEAD-only Homebrew formula compiles `crates/carrick-cli` with `cargo`, then re-signs the binary with `scripts/entitlements.plist` (Homebrew's automatic ARM ad-hoc signing drops custom entitlements). The carrick source repo is made public so Homebrew can clone it; the formula lives only in the tap repo.

**Tech Stack:** Homebrew (Ruby formula), Rust/cargo, macOS `codesign`, `gh` CLI.

**Spec:** `docs/superpowers/specs/2026-06-06-homebrew-tap-design.md`

**Conventions for this plan:**
- Run from the carrick checkout at `/Volumes/CaseSensitive/carrick` unless stated.
- "Test" steps here are `brew`/`codesign`/`carrick` invocations (no Rust unit tests apply to a packaging recipe); each task's acceptance check IS its test.
- Two steps are **GATED**: making the repo public and creating the tap repo. Confirm with the user before running those exact commands.

---

### Task 1: Dry-run the formula's build+sign logic outside Homebrew

Validates that `std_cargo_args`' underlying command builds the `carrick` bin and that the entitlement signs cleanly — before involving brew or the network.

**Files:** none (verification only).

- [ ] **Step 1: Build the bin exactly as the formula will**

```sh
rm -rf /tmp/carrick-formula-test
cargo install --path crates/carrick-cli --locked --root /tmp/carrick-formula-test
```
Expected: compiles and writes `/tmp/carrick-formula-test/bin/carrick`.

- [ ] **Step 2: Apply the entitlement sign**

```sh
codesign --force --sign - --entitlements scripts/entitlements.plist /tmp/carrick-formula-test/bin/carrick
```
Expected: `replacing existing signature` (or silent success), exit 0.

- [ ] **Step 3: Verify the entitlement is present**

```sh
codesign -d --entitlements - /tmp/carrick-formula-test/bin/carrick 2>&1 | grep -A1 hypervisor
```
Expected: shows `com.apple.security.hypervisor`.

- [ ] **Step 4: Verify the signed bin runs a guest (no HV_DENIED)**

```sh
/tmp/carrick-formula-test/bin/carrick run ubuntu:24.04 /bin/echo brew-ok
```
Expected: prints `brew-ok`; NOT `HV_DENIED (0xfae94007)`. (If it pulls an image first, that's fine.)

If any step fails, stop — the formula recipe itself needs revisiting before continuing.

---

### Task 2: GATED — make `carrick-sh/carrick` public

Required so Homebrew can anonymously `git clone` the repo for `--HEAD`.

**Files:** none (GitHub repo setting).

- [ ] **Step 1: Confirm with the user, then flip visibility**

Confirm explicitly (hard to reverse). Then:
```sh
gh repo edit carrick-sh/carrick --visibility public --accept-visibility-change-consequences
```

- [ ] **Step 2: Verify public**

```sh
gh repo view carrick-sh/carrick --json visibility -q .visibility
```
Expected: `public`.

---

### Task 3: Author the formula and test it locally via Homebrew

**Files:**
- Create: `/tmp/homebrew-carrick/Formula/carrick.rb` (working copy for local testing; published in Task 4)

- [ ] **Step 1: Write the formula**

```sh
mkdir -p /tmp/homebrew-carrick/Formula
```
Create `/tmp/homebrew-carrick/Formula/carrick.rb`:
```ruby
class Carrick < Formula
  desc "Run Linux binaries on macOS via Apple's Hypervisor.framework"
  homepage "https://github.com/carrick-sh/carrick"
  license any_of: ["Apache-2.0", "MIT"]
  head "https://github.com/carrick-sh/carrick.git", branch: "main"

  depends_on "rust" => :build
  depends_on arch: :arm64 # Apple Silicon only (aarch64 HVF guests)

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
    assert_match(/carrick|Usage/i, shell_output("#{bin}/carrick --help"))
  end
end
```

- [ ] **Step 2: Lint the formula**

```sh
brew audit --new --formula /tmp/homebrew-carrick/Formula/carrick.rb || true
brew style /tmp/homebrew-carrick/Formula/carrick.rb || true
```
Expected: review output. Fix any non-inherent findings (style nits, missing fields). HEAD-only / arch-gated warnings are acceptable; note them.

- [ ] **Step 3: Install from the local formula (the real test)**

```sh
brew install --HEAD --formula /tmp/homebrew-carrick/Formula/carrick.rb
```
Expected: clones carrick `main`, `cargo install` builds (several minutes), install completes. If it fails because a previous `carrick` is installed, `brew uninstall carrick` first.

- [ ] **Step 4: Verify the entitlement survived Homebrew's signing**

```sh
codesign -d --entitlements - "$(brew --prefix)/bin/carrick" 2>&1 | grep -A1 hypervisor
```
Expected: shows `com.apple.security.hypervisor`.

**If it is MISSING:** Homebrew re-signed after `install` and stripped it. Move the codesign into `post_install` instead of `install`:
```ruby
  def install
    system "cargo", "install", *std_cargo_args(path: "crates/carrick-cli")
    (buildpath/"entitlements.plist").write \
      (buildpath/"scripts/entitlements.plist").read
    pkgshare.install "scripts/entitlements.plist"
  end

  def post_install
    system "codesign", "--force", "--sign", "-",
           "--entitlements", pkgshare/"entitlements.plist", bin/"carrick"
  end
```
Then `brew reinstall --HEAD --formula /tmp/homebrew-carrick/Formula/carrick.rb` and re-run Step 4 until the entitlement is present. (Keep whichever of `install`-time or `post_install` signing actually persists.)

- [ ] **Step 5: Verify the brew-installed bin runs a guest**

```sh
brew test carrick
"$(brew --prefix)/bin/carrick" run ubuntu:24.04 /bin/echo brew-tap-ok
```
Expected: `brew test` passes; the run prints `brew-tap-ok` with no `HV_DENIED`.

---

### Task 4: GATED — create the public tap repo and publish the formula

**Files:**
- Create (in new repo `carrick-sh/homebrew-carrick`): `Formula/carrick.rb`, `README.md`

- [ ] **Step 1: Confirm with the user, then create the repo**

```sh
gh repo create carrick-sh/homebrew-carrick --public \
  --description "Homebrew tap for carrick"
```

- [ ] **Step 2: Populate and push**

```sh
cd /tmp/homebrew-carrick
git init -b main
cp /tmp/homebrew-carrick/Formula/carrick.rb Formula/carrick.rb  # already there; ensure final version
cat > README.md <<'EOF'
# Homebrew tap for carrick

    brew tap carrick-sh/carrick
    brew install --HEAD carrick

Apple Silicon macOS only. carrick is ad-hoc codesigned with the
Hypervisor.framework entitlement during install.
EOF
git add Formula/carrick.rb README.md
git commit -m "Add carrick formula (HEAD-only, build-from-source + HVF entitlement signing)"
git remote add origin git@github.com:carrick-sh/homebrew-carrick.git
git push -u origin main
```
Return to the carrick checkout afterward: `cd /Volumes/CaseSensitive/carrick`.

- [ ] **Step 3: Test the published tap end-to-end**

```sh
brew uninstall carrick 2>/dev/null || true
brew untap carrick-sh/carrick 2>/dev/null || true
brew tap carrick-sh/carrick
brew install --HEAD carrick
codesign -d --entitlements - "$(brew --prefix)/bin/carrick" 2>&1 | grep hypervisor
"$(brew --prefix)/bin/carrick" run ubuntu:24.04 /bin/echo tap-published-ok
```
Expected: tap resolves, install succeeds, entitlement present, run prints `tap-published-ok`.

---

### Task 5: Add the install section to the carrick README

**Files:**
- Modify: `README.md` (carrick repo)

- [ ] **Step 1: Add an Install section**

Insert after the status banner (around `README.md:11`, before the first `---` divider or the first content section):
```markdown
## Install

Apple Silicon macOS only.

```sh
brew tap carrick-sh/carrick
brew install --HEAD carrick
```

carrick is ad-hoc codesigned with the `com.apple.security.hypervisor`
entitlement during install so it can run Linux guests via Hypervisor.framework.
```

- [ ] **Step 2: Commit**

```sh
git add README.md
git commit -m "docs(readme): add Homebrew install instructions"
```
(The pre-commit hook runs `cargo fmt --check`; a README-only change passes.)

- [ ] **Step 3: Push carrick main** (confirm with user if pushing is desired)

```sh
git push origin main
```

---

## Self-review notes

- Spec coverage: tap repo (Task 4), formula build+sign (Task 3), make-public (Task 2), README (Task 5), local verification incl. entitlement + HV_DENIED checks (Tasks 1,3,4), brew audit (Task 3 Step 2). All spec sections mapped.
- Empirical signing decision (install vs post_install) is handled in Task 3 Step 4 with the concrete fallback formula — not left as a TODO.
- HEAD-only is consistent throughout (`brew install --HEAD carrick`). A future stable tag (out of scope) would drop `--HEAD`.
