# gh-aw dispatch spike (#644)

Recommendation: **keep #634 for subscription-backed dispatch**; retain gh-aw
as a bounded Copilot experiment. A later hybrid could replace engine setup,
sandboxing, output validation and transcript parsing, but adopting stock gh-aw
now would lose the owner's Codex/Claude/Antigravity login path. This is a source
and compilation spike, **not a successful live dispatch or billing trial**.
The director owns publication and the live trial under this task's no-push rule.

Research date: 2026-10-18. Read [#644][644], [#634 including owner comments][634]
and root `AGENTS.md`. Evidence below is from GitHub's gh-aw repository and its
[documentation site][site] only. Source links target **v0.92.0**, commit
`a68f5a9436d2a014dbd1d1d48ff86c4bdec7424a`; they describe that version,
not an assumed future API. Installed with:

```sh
gh extension install github/gh-aw --pin v0.92.0
gh aw version # gh aw version v0.92.0
```

The [v0.92.0 release][release] is immutable and non-prerelease. Checked the
historical billing retirement: [merged upstream PR #30698][retirement] and
[its README notice][old-readme] retire **0.68.4 through 0.71.3**. Both affected
release lookups now return “release not found”. v0.92.0 is outside that range.
The current README also retires **0.83.3–<0.85.4** for a separate security bug
([README][readme], lines 34–35). A newer version number alone is no security
review; recheck advisories before the director enables a trial.

## 1. Authentication and what the owner already pays for

These are supported stock-engine paths, not claims about everything a vendor's
standalone CLI could do. A copied login file is not an API key.

| Engine | Supported authentication in this release | Can the personal subscription login replace an API key? |
|---|---|---|
| `copilot` | `COPILOT_GITHUB_TOKEN`: user-owned fine-grained PAT, Account → Copilot Requests → Read. Alternatively `permissions.copilot-requests: write` uses the Actions token with centralized organization Copilot billing. | **The Copilot entitlement can be used via PAT**; copying a CLI login is unnecessary. OAuth `gho_` tokens and App tokens are not supported as the inference secret. The ordinary `GITHUB_TOKEN` alone is insufficient for the personal-seat path. |
| `claude` | `ANTHROPIC_API_KEY`; Anthropic workload identity federation (WIF) is another supported path. | **No supported subscription login.** Docs explicitly say `CLAUDE_CODE_OAUTH_TOKEN` is ignored and Teams/Max subscription OAuth is unsupported. Restoring the Claude login file is not a documented alternative. |
| `codex` | `CODEX_API_KEY`, then `OPENAI_API_KEY`; Azure Entra OIDC is also supported. | **No supported `auth.json` subscription path.** The compiler selects provider secrets; AWF configures a Responses proxy with `env_key = CODEX_API_KEY`. `CODEX_HOME` changes the config directory, not that authentication contract. |
| `gemini` | `GEMINI_API_KEY`, or Google WIF with the Vertex AI backend. | **No supported Gemini/Antigravity personal OAuth token path.** Source validates the key unless Google WIF is configured. WIF is cloud workload identity, not subscription login. |

Evidence: [auth reference][auth] lines 133–159, 199–230, 293–309, 385–423;
[provider secret selection][providers] lines 94–124;
[Claude implementation][claude-source] lines 75–119 and 534–558;
[Codex implementation][codex-source] lines 107–149 and 469–491;
[Codex proxy configuration][codex-config] lines 104–145 and 270–275;
[Gemini implementation][gemini-source] lines 91–113 and 317–321.
The Codex/Gemini “no” is an inference from these implemented paths and the
documented auth list, not an empirical rejection using the owner's credentials.

There is a useful additional option: Claude and Codex can use **Copilot
inference**, selected with a `copilot/…` model or GitHub provider; the same PAT
or organization inference permission then applies. This spends Copilot
entitlement, not the owner's separate Claude/Codex subscription. It is subject
to the `agentic-workflows` integration's model availability and policy
([engine reference][engines], lines 14–43; source skip/provider branches above).

Gemini is now deprecated in favor of experimental `agy`. This does **not**
solve our Antigravity OAuth requirement: that engine deliberately selects the
Gemini API-key profile, receives a dummy key behind AWF, and creates a private
home without inherited user auth ([Agy reference][agy], lines 35–56).

**Cost:** do not budget “one premium request per Actions run”. Current upstream
[billing documentation][billing] distinguishes personal PAT entitlements from
organization AIC billing; it gives no fixed premium-request count per run.
Native legacy premium-request observations are not a guaranteed invoice or a
conversion from AIC. Copilot's $40 plan alone does not establish a numeric run
cost from these sources. Record actual provider usage and allowance changes in
the trial; no dollar or premium-request measurement was made here. API-key/WIF
paths use their corresponding provider account, not the personal subscription.

The trial caps the main agent at 5 AIC and threat detection at another 5 AIC;
these are **separate** caps, not a guaranteed $0.10 invoice ceiling. Upstream
uses 1 AIC = $0.01 as its reporting metric ([cost management][cost], line 76).
Detection otherwise defaults to **400 AIC**, independently of the agent limit
([threat detection][threat], lines 102–111 and 170–178). Setup, retries,
artifacts and our VM infrastructure add cost; duration remains unmeasured.

## 2. Runners and bootstrap

Yes: `runs-on: [self-hosted, Linux, X64, carrick-agent]` selects our label.
Use `runs-on-slim` for activation/conclusion/framework jobs, explicit
`safe-outputs.runs-on` for publishing, and
`safe-outputs.threat-detection.runs-on` for detection. All five generated jobs
in this spike select that array. `--require-self-hosted-runners` verifies the
whole graph ([runner reference][runners], lines 8–26, 61–96, 120–154).

**Important observed discrepancy:** despite the documentation's inheritance
claim, the first compilation placed `detection` on `ubuntu-latest` when only
top-level `runs-on` and `runs-on-slim` were set. The explicit detection override
fixed it; the enforcement flag caught it before publication.

Supported agent runners are **Linux with usable Docker**, plus the Actions
runner, git, Bash and download/extraction tools. Generated steps install Node
24 on nonstandard runners, the pinned Copilot CLI and AWF, and pull pinned
sandbox/MCP images. The Copilot installer may need sudo; preflight that path.
See [runner prerequisites][runners], lines 10–26 and 328–356, and the generated
lock file's setup/download steps. No locally installed `gh aw` is needed to
execute the checked-in lock file. Carrick builds additionally need Carrick's
normal toolchain; this fixed task performs none.

ctb-w1 has no Docker, and this task prohibits using it here. Compilation needs
no Docker. Do not disable the sandbox to make this host a trial runner.
Our Mac signed gates remain separate conventional workflows.

gh-aw queues Actions jobs; it does not provision Proxmox VMs. Keep the #634
standing controller, JIT registration, four-clone cap, one job per ephemeral
clone, destruction on every outcome and zero idle workers. This workflow has
five jobs, so one turn can consume several successive fresh clones. Test the
controller against that job graph before treating a workflow as one clone.

## 3. Fit with #634's event and review model

| Requirement | gh-aw capability and remaining Carrick work |
|---|---|
| Label dispatch | Standard `issues: {types: [labeled]}` plus top-level `if`; `names` also filters labels. Keep the exact owner/App and Brief checks. `label_command` removes its label automatically, so it is unsuitable as our persistent tier state. |
| `/agent continue` | Standard `issue_comment` with exact command parsing, or `slash_command: agent` plus a guard requiring argument `continue`. Slash shorthand only requires the command as the first word; it does not implement our subcommand/state policy. Keep branch identity, thread reconstruction and actor admission. |
| Review follow-up | `pull_request_review: {types: [submitted]}` plus `review.state == 'changes_requested'` and owner/App admission. Use `push-to-pull-request-branch` for subsequent turns; creating a new PR each turn is wrong. Same-repo PR checkout is supported. |
| Multi-turn state | New Actions runs can load the GitHub thread and prior artifacts. Copilot's `max-continuations` is an in-run engine feature, not the owner's blocked → comment → new-turn protocol. Preserve durable WIP and exact branch/head checks in #634. |
| Tiers | Keep a fixed label → engine/model/effort allowlist and refuse unknown/conflicting labels before credentials/VM admission. `engine.model` and `engine.config` configure engines; experimental model routing is not our authorization policy. Copilot catalog presence does not guarantee access. |
| Re-route/cancel | Configure one concurrency group across all tiers and turns for an issue; use cancellation only with proven WIP preservation. gh-aw's default issue groups do not cancel, and per-engine concurrency serializes runs unless overridden. Removing a label needs an explicit event/cancel policy. |
| Checks and logs | Actions jobs provide checks, summaries and artifacts. Keep the PR-head `agent` check with ~60-second updates, structured contract, Blocked/In review project transitions, signed-gate routing and merge-queue policy. These are not supplied by a Markdown prompt. |

Evidence: [triggers][triggers] lines 242–254, 395–507;
[command triggers][commands] lines 55–57, 90–99 and 121–135;
[concurrency][concurrency] lines 14–37 and 39–69;
[engine comparison][engines] lines 195–210;
[PR safe outputs][pr-outputs] sections on creation and pushing to a PR branch.
Stock role admission defaults to admin/maintain/write; that is broader than our
owner/App rule. The spike uses `roles: all` **only alongside** a deterministic
exact actor, label, issue-kind and main-ref `if` before activation. Future
comment/review entry points must carry equivalent checks.

**Logs:** gh-aw forwards child stdout/stderr live
([process runner][process-runner], lines 364–395), renders sessions for summaries
([renderer][renderer]), retains stdio/session/usage/patch artifacts
([artifact collector][artifacts], lines 10–65 and 88–133), and supports
`gh aw audit RUN_ID --parse` and `gh aw logs --format markdown`
([audit reference][audit]). This does not prove #634's rendered live tool calls
with command exit codes and periodic PR-head check updates. Keep our renderer
and check updater until those exact properties are demonstrated. Set
`GH_AW_DEFAULT_ARTIFACT_RETENTION_DAYS=30` for the trial if the director wants
#634's retention; [retention precedence][retention-policy] is repo config,
then Actions variable, then artifact defaults. Contract JSON and diff stat
still need explicit production artifacts.

## 4. Security, stability and replacement boundary

Safe outputs separate the agent's read-only GitHub token from a later job with
scoped write permissions. The agent submits structured intents and a patch;
handlers validate and publish them. Draft status is enforced policy,
`allowed-files` is exclusive, protected files have a separate policy, and
output quotas bound writes ([PR safe outputs][pr-outputs], lines 12–56,
136–140 and 645–681). This replaces substantial bespoke publication code,
not review, semantic tests or merge authorization. A draft PR is published
after the agent completes; #634's immediate draft and durable WIP-on-cancel
need additional orchestration.

This spike allows exactly one 1-KB/one-file patch at
`docs/ci/gh-aw-trial.txt`, one draft PR and one issue comment. It disables
issue-closing/fallback and tracking-issue reporting. Threat detection is
explicitly fail-closed (`continue-on-error: false`); upstream's default is
advisory. Agent shell access is broad inside the sandbox. The file policy
restricts the published patch, not every local action or network side effect.

Inference credentials are kept outside the AWF agent process where supported;
other tool tokens and custom steps/MCP services still require review.
[Redaction code][redaction] scans declared secret values, known patterns and
captured masks before artifact upload, and fails on redaction errors. Keep
#634's derived-secret masking and a test that scans **every** uploaded file;
redaction is not proof against encoded/transformed leakage or prompt injection.
Do not map `AGENT_WORKER_TOKEN` into the agent's generic read-token fallback.
Keep the App private key on the Mac and use the protected main-only
`agent-dispatch` environment for injected credentials.

There are concrete preview risks beyond the old billing retirement:
[GHSA-9jxf-w4wc-5g93][token-advisory] describes sandboxed theft of the job token
(fixed v0.91.13); [GHSA-8h78-hpm7-29gg][artifact-advisory] describes CI-trigger
tokens in safe-output artifacts (fixed v0.85.4). v0.92.0 also hardens patch and
bundle byte binding ([release notes][release]). Pin compiler, review generated
YAML and dependency changes, and track advisories. “Non-prerelease” metadata
does not turn the technical preview into a production dispatch guarantee.

**Keep from #634:** subscription refresher and private pinned launcher; tier
and owner/App policy; branch/WIP recovery; four-worker scale-to-zero controller;
rendered live logs/checks/redaction contract; board lifecycle and merge queue;
existing CI and signed gates. **Potential gh-aw replacement after evidence:**
engine installers/harnesses, AWF/tool wiring, validated publication handlers,
and end-of-run transcript/usage collection. Do not fork a stock engine to
silently restore personal OAuth: that creates an auth/security maintenance
surface and does not satisfy the supported-engine trial.

## Reproduction and director's trial

The added `.md` and `.lock.yml` are the only new executable workflow pair.
The compiler also generated `.github/aw/actions-lock.json` (retained for pin
reproducibility) and `.gitattributes` (optional generated-file annotation,
not retained). The only existing config change registers `carrick-agent` with
actionlint; no existing workflow is changed.

```sh
gh aw compile agent-dispatch --require-self-hosted-runners \
  --actionlint --shellcheck --no-check-update
```

Verified locally: compilation with **zero warnings**, all-job self-hosted
runner enforcement, gh-aw's actionlint 1.7.12 (zero issues), shellcheck, stable
recompilation and `git diff --check`. Standalone actionlint initially rejected
`copilot-requests: none` and `queue: max`, although gh-aw's patched validator
accepted them. The source now omits the unnecessary inference permission and
disables optional queue emission; **standalone actionlint also passes**. An
initial lint caught the unregistered custom runner label, now fixed.
No guest/runtime code changed; Docker/HVF/KVM execution and Rust gates were
not run. No secrets were read or installed; no workload or cost was observed.

Director handoff (not executed here):

1. Recheck the pinned release/advisories; provision a **Docker-capable Linux**
   runner with all four labels and the protected main-only environment.
   Supply `COPILOT_GITHUB_TOKEN` through secrets using the documented PAT
   path. Ensure Actions is allowed to create PRs. No subscription auth files
   are needed for this Copilot trial.
2. Publish the pair on a throwaway fork's default `main`, or land this bounded
   experiment after review. Issue events load default-branch workflows; simply
   pushing this work branch will not enable the label trigger. The exact
   owner/App guard must remain intact.
3. Label a throwaway issue `dispatch:copilot`. Confirm one allowed-file draft
   PR and one comment, all jobs on JIT clones, and cleanup/zero idle clones.
   Default `GITHUB_TOKEN` publication does not trigger normal PR CI; keep it
   for this trivial task. Production must supply a separate write-job App/PAT
   strategy ([triggering CI][ci-trigger]).
4. Record run URL, requested/effective model, premium-request/account allowance
   delta where available, main/detector AIC, tokens, queue/setup/agent/total
   duration and artifact links. Inspect rendered and raw logs plus redaction.
   Close the throwaway PR. Do not interpret an unrun workflow as acceptance.
5. A separate personal Codex/Claude/Antigravity subscription trial is **not
   supported by these stock paths**, so it was not fabricated or replaced by
   an API-key run. If adopting Copilot-backed Claude/Codex, trial that billing
   route separately and name it accurately.

[644]: https://github.com/carrick-sh/carrick/issues/644
[634]: https://github.com/carrick-sh/carrick/issues/634
[site]: https://github.github.com/gh-aw/
[release]: https://github.com/github/gh-aw/releases/tag/v0.92.0
[retirement]: https://github.com/github/gh-aw/pull/30698
[old-readme]: https://github.com/github/gh-aw/blob/343ffb640c5f0bf967933e34552b4887e5e6b6a9/README.md#L16-L18
[readme]: https://github.com/github/gh-aw/blob/v0.92.0/README.md#L34
[auth]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/auth.mdx
[providers]: https://github.com/github/gh-aw/blob/v0.92.0/pkg/workflow/llm_provider.go#L94
[claude-source]: https://github.com/github/gh-aw/blob/v0.92.0/pkg/workflow/claude_engine.go#L75
[codex-source]: https://github.com/github/gh-aw/blob/v0.92.0/pkg/workflow/codex_engine.go#L107
[codex-config]: https://github.com/github/gh-aw/blob/v0.92.0/pkg/workflow/codex_config.go#L104
[gemini-source]: https://github.com/github/gh-aw/blob/v0.92.0/pkg/workflow/gemini_engine.go#L91
[engines]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/engines.md
[agy]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/engines/agy.md#L35
[billing]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/billing.md
[cost]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/cost-management.md#L76
[threat]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/threat-detection.md#L102
[runners]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/self-hosted-runners.md
[triggers]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/triggers.md
[commands]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/command-triggers.md
[concurrency]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/concurrency.md
[pr-outputs]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/safe-outputs-pull-requests.md
[process-runner]: https://github.com/github/gh-aw/blob/v0.92.0/actions/setup/js/process_runner.cjs#L364
[renderer]: https://github.com/github/gh-aw/blob/v0.92.0/actions/setup/js/log_parser_format.cjs
[artifacts]: https://github.com/github/gh-aw/blob/v0.92.0/pkg/workflow/compiler_yaml_post_agent.go#L10
[audit]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/audit.md
[retention-policy]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/compiler-enterprise-environment-controls.md#L80
[redaction]: https://github.com/github/gh-aw/blob/v0.92.0/actions/setup/js/redact_secrets.cjs
[token-advisory]: https://github.com/github/gh-aw/security/advisories/GHSA-9jxf-w4wc-5g93
[artifact-advisory]: https://github.com/github/gh-aw/security/advisories/GHSA-8h78-hpm7-29gg
[ci-trigger]: https://github.com/github/gh-aw/blob/v0.92.0/docs/src/content/docs/reference/triggering-ci.mdx
