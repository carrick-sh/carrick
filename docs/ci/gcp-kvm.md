# GCP nested-KVM lane

`kernel-runtime.yml`'s `kvm-tests` job produces the KVM lane's per-SHA
receipt (`xtask accept --profile kvm`, i.e. `just test-kvm` with
`CARRICK_REQUIRE_KVM=1`) on one **ephemeral GCP VM with nested
virtualization** per run. The job itself runs on a hosted `ubuntu-latest`
runner and drives the VM keylessly; there is no self-hosted runner
registration, no PAT and no service-account key. The Willow JIT runner
([willow-pilot.md](willow-pilot.md)) remains as a fallback backend.

This is trusted-ref CI infrastructure for an experimental project, not an
adversarial isolation boundary.

## Flow

```
hosted kvm-tests job                       GCP project carrick-ci-261011
--------------------                       -----------------------------
OIDC token --(WIF provider)--> GCP_CI_SA   (instanceAdmin.v1, actAs VM SA,
                                            objectViewer on the bucket)
scripts/ci/gcp-kvm-run.sh run
  create  kvm-<run>-<attempt>-<sha8> ----> n2-standard-16, nested VMX, debian-13,
          (zone fallback a,b,c,f)          100 GB pd-ssd, VM SA, labels,
                                           max-run-duration 3h -> DELETE
                                           startup script (metadata):
                                             apt deps, user `carrick` in kvm,
                                             rustup + pinned toolchain,
                                             git fetch <exact sha>,
                                             just accept --profile kvm
                                             upload -> gs://<bucket>/<run>/<attempt>/
  wait    poll bucket for DONE | FAILED     receipt.json, accept-logs.tar.gz,
          tail serial port (new lines)      status.json, startup.log, DONE last
  collect receipt -> target/ci-receipts/receipt.json
  trap    delete VM (also an always() step)
upload-artifact receipt-kvm-<sha>-<attempt>  (unchanged name; kvm-gate reads it)
```

The script exits 0 whenever a receipt was collected. Test failures are
recorded in the receipt and judged by the hosted `kvm-gate` job against the
merge-group base, exactly as with Willow. It exits non-zero on a `FAILED`
marker (VM setup failed before `accept` ran), a timeout (default 150 min), a
VM that disappears before writing a marker, or `DONE` without a receipt.

`GCP_KVM_DRY_RUN=1 scripts/ci/gcp-kvm-run.sh` prints every gcloud command and
the generated startup script without running anything;
`scripts/ci/gcp-kvm-run.sh startup-script` prints only the script. The
script header lists every input.

## Trust boundary

- **Who can get GCP credentials.** The workload identity provider
  (`vars.GCP_WIF_PROVIDER`) has an attribute condition admitting only
  repository `carrick-sh/carrick` with ref `refs/heads/main` or
  `refs/heads/gh-readonly-queue/main/*`. Pull-request, fork and branch runs
  cannot mint a token even if they edit the workflow. `kernel-runtime.yml`
  has no `pull_request` trigger, and the job also refuses a dispatch on any
  ref but main.
- **No long-lived secrets.** The job exchanges its GitHub OIDC token
  (`id-token: write`, job-scoped) for a short-lived token of `GCP_CI_SA`.
  Nothing is stored in repository secrets; the identifiers are repository
  `vars`.
- **Controller account (`GCP_CI_SA`).** `roles/compute.instanceAdmin.v1`,
  `iam.serviceAccountUser` on the VM account only (to attach it), and
  `objectViewer` on the receipt bucket (to poll and download).
- **VM account (`GCP_RUNNER_VM_SA`).** No project roles; `objectCreator` on
  the receipt bucket only: it can create objects but not read, list or
  overwrite them. The VM uses `--scopes cloud-platform` so that the IAM roles,
  not scopes, are the bound.
- **Test code cannot use the VM account.** The lane runs as the unprivileged
  user `carrick` (in group `kvm`). An nftables rule rejects that user's TCP
  traffic to the metadata server's HTTP port (`169.254.169.254:80`,
  `[fd20:ce::254]:80`), so test code cannot mint the VM account's token; DNS
  via the metadata resolver still works. Only the root startup script
  uploads.
- **Exact SHA.** The VM fetches `GITHUB_SHA` (merge-group SHAs are fetchable
  by hash while the queue branch exists), checks it out detached, and
  verifies `HEAD` before building. The toolchain comes from that commit's
  `rust-toolchain.toml`; `rustup-init` is checksum-pinned to the same hash
  as the Willow template (`scripts/ci/build-template-debian.sh`).
- **No inbound access.** No SSH keys are installed
  (`block-project-ssh-keys=TRUE`); the controller only reads the serial port
  and the bucket.
- **Deletion backstops.** The script's `EXIT` trap deletes the VM; an
  `if: always()` step deletes it again by name (covers a cancelled job); and
  every VM carries `--max-run-duration=3h --instance-termination-action=DELETE`,
  so GCP deletes it even if GitHub never runs either.

## Cost controls

- One VM per run attempt, deleted at the end of the run. An n2-standard-16
  with a 100 GB pd-ssd costs on the order of $0.80 an hour on demand in us-central1 (check current pricing).
- `--max-run-duration=3h` bounds any one VM; the job's wait bound is 150 min
  and its `timeout-minutes` is 175.
- The project carries a **$300/month budget alert** (Billing, Budgets &
  alerts). It notifies; it does not cap. If it fires, set
  `CARRICK_GCP_KVM` to anything but `true` to stop new VMs (the lane falls
  back to Willow if `CARRICK_SELF_HOSTED_KVM` is `true`).
- The receipt bucket has a 14-day lifecycle rule.
- Concurrent merge-queue entries each create a VM. The regional N2 vCPU
  quota bounds concurrency; a quota error fails the job rather than retrying
  other zones (quota is regional, capacity is zonal).

## Configuration

Repository variables (Settings, Secrets and variables, Actions, Variables):

| Variable | Meaning |
|---|---|
| `CARRICK_GCP_KVM` | `true` enables the GCP backend. |
| `CARRICK_KVM_BACKEND` | `willow` forces the Willow job even when `CARRICK_GCP_KVM` is `true`; unset or `gcp` keeps GCP. |
| `CARRICK_SELF_HOSTED_KVM` | `true` enables the Willow job when GCP is not selected. |
| `GCP_PROJECT`, `GCP_WIF_PROVIDER`, `GCP_CI_SA`, `GCP_RUNNER_VM_SA`, `GCP_RECEIPT_BUCKET` | GCP identifiers (see Trust boundary). |
| `CARRICK_GCP_KVM_MACHINE_TYPE` | Optional; default `n2-standard-16`. Must support nested virtualization (Intel N1/N2/C2/C3-class). |
| `CARRICK_GCP_KVM_ZONES` | Optional comma list; default `us-central1-a,us-central1-b,us-central1-c,us-central1-f`. |

### Switching backends

Exactly one KVM job runs. GitHub job ids cannot be shared, so the GCP job
is `kvm-tests` and the Willow job is `kvm-tests-willow`; their `if:`
conditions are complements of one selection expression:

```
gcp selected = vars.CARRICK_GCP_KVM == 'true' && vars.CARRICK_KVM_BACKEND != 'willow'
```

`kvm-gate` and `trusted-hardware-ok` read the selected job's result with the
same expression, so a skipped selected lane still fails the required check.
Both jobs upload the same artifact name, `receipt-kvm-<sha>-<attempt>`, so
the gate is backend-agnostic. To switch, change the variables; no workflow
edit is needed. Going back to Willow also requires its standing controller
(`ci-scaler standing`) to be running.

## Debugging

- **Job log.** The script streams new serial-console lines (prefixed `  |`)
  while it waits. Everything the startup script prints goes to the serial
  console and to `/var/log/carrick-kvm.log` on the VM.
- **Bucket artifacts.** `gs://carrick-ci-261011-receipts/<run_id>/<attempt>/`
  holds `receipt.json`, `accept-logs.tar.gz` (the `target/el1-gate/<head>/`
  step logs written by `xtask accept`), `status.json` (accept exit status),
  `startup.log`, and `DONE` or `FAILED` (with the log tail). The job also
  uploads them as the `gcp-kvm-logs-<sha>-<attempt>` artifact.
  `gcloud storage ls gs://carrick-ci-261011-receipts/<run_id>/<attempt>/`
- **Live serial output** while the VM exists:
  `gcloud compute instances get-serial-port-output kvm-<run>-<attempt>-<sha8> --zone <zone> --project carrick-ci-261011`
- **Leaked VMs.** `gcloud compute instances list --project carrick-ci-261011 --filter=labels.carrick-lane=kvm`.
  Labels `run-id`, `run-attempt` and `sha` name the owning run. The
  max-run-duration backstop deletes them within three hours regardless.
- **Reproduce the VM side** by printing the startup script
  (`scripts/ci/gcp-kvm-run.sh startup-script` with the required environment)
  and running it as root on a nested-KVM Debian 13 VM.
