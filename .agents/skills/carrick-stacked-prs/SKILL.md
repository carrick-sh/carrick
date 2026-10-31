---
name: carrick-stacked-prs
description: Use when Carrick work depends on another unmerged PR, when splitting a change over the size cap into dependent slices, when a lane must build on another lane's hot file, or when landing several dependent PRs together.
---

# Dependent work as native GitHub stacks

Dependent PRs land as a native GitHub stack (#468). Don't wait for a base
to merge before starting the next slice, and don't fold PRs into a
hand-built landing branch. GitHub references:
[CLI](https://docs.github.com/en/pull-requests/reference/stacked-prs-cli-commands),
[merging](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/merging-stacked-pull-requests).

## When to stack

- A slice needs code from an unmerged PR (for example the #323 signal
  slices, or a fix that builds on an open custody PR).
- One change is over the 4k-line cap and splits into ordered slices.
- A second lane needs a hot file another lane owns (CODEOWNERS): it adds a
  layer on top of the owner's stack instead of carrying a copy.

Don't stack independent work. Ejecting a layer from the merge queue ejects
every layer above it, so unrelated PRs stay separate.

## Shape

- Each layer is one branch (`work/<topic>-<issue>`) and one PR, under the
  size cap, with its own witness and issue link (`Closes #N` or
  `Part of #N`; the `linked-issue` check needs one).
- The stack is linear and in one repository. Each PR's base is the branch
  below it; the bottom layer's base is `main`.
- Build layer branches from GitHub `main` (`git fetch origin main`;
  start from `origin/main`). A host's local `main` may lag, and it may be
  checked out elsewhere.

## Workflow

```bash
gh extension install github/gh-stack          # once per host; gh >= 2.90
git checkout -b work/a-123 origin/main        # bottom layer; commit
git checkout -b work/b-124                    # next layer on top; commit
gh stack init work/a-123 work/b-124           # adopt branches bottom to top
gh stack submit                               # push, open/link the PRs (drafts are fine)
gh stack view                                 # layers, PRs and their state
```

- **One worktree per layer** when different workers own the layers;
  `gh stack` updates the clean worktree that owns each branch. Keep a
  layer's worktree idle while the stack is being rebased.
- **Fixing a lower layer:** commit on that layer's branch, then
  `gh stack rebase` (cascades upward; on conflict resolve, `git add`,
  `gh stack rebase --continue`) and `gh stack push` (force-with-lease per
  branch, not atomic: rerun it if a branch is rejected).
- **Main moved:** `gh stack sync` fetches, rebases the stack onto trunk
  only if needed, and pushes.
- Never `git stash` and never `git add -A` (AGENTS.md); commit WIP instead.

## Gates and landing (director)

1. Review every layer's diff on its own PR. An out-of-fence change in one
   layer is still out of fence.
2. Run the signed gate and `just accept --profile linux-portable` once,
   at the top PR's SHA, in a dedicated detached worktree; the top contains
   every layer. Post the receipt on the top PR and link it from the others.
3. Mark every layer ready and wait for each layer's `ci-ok`. Marking
   ready starts a fresh full CI run on each layer; an older passing `ci-ok`
   doesn't count.
4. **Collapse and land as one PR, never with a merge commit** (owner,
   2026-10-31, #231). Our merge queue (REBASE method) takes a native stack
   one layer per pass. After `gh stack merge`, only the bottom layer is
   built; the layers above sit `UNMERGEABLE` with `head=null` and are
   dropped and rebased when it merges (stack 1029 on 2026-10-29, stack
   1082 on 2026-10-31; #468). So, instead of `gh stack merge`:
   1. Dequeue any queued layer. Dequeuing the bottom one ejects the rest.
   2. `gh stack unstack <stack number>`. This works only while no layer has
      merged or is queued.
   3. `gh pr edit <top> --base main`. The top PR now carries every layer's
      commits.
   4. Rebase the top branch onto the current main tip and push it with the
      normal hook. Check that the rebase changed only what main changed
      since the signed gate's base: the patch-ids of
      `git diff <gated merge> HEAD` and `git diff <gated base> origin/main`
      must match.
   5. When `ci-ok` is green on that exact head, admin-merge it:
      `gh pr merge <top> --admin --rebase`. That skips the merge-group-only
      jobs (`macos-build`, `macos-clippy`, `macos-authority`, the KVM gate),
      so confirm the PR's own CI covered those surfaces first. Without that
      proof, enqueue the top PR as an ordinary PR.
   6. Close the lower PRs with "landed via #top", and close their issues.

   Traps:
   - A bare number is read as a **stack** number first. Stack numbers share
     the PR number range: stack #1120 is the #1061/#1119 stack, not PR
     #1120. Look stacks up with `gh api repos/carrick-sh/carrick/stacks`.
   - Plain `gh pr merge` and admin bypass are refused for a stacked PR,
     which is why step 2 unstacks first.
   - `gh stack modify` is refused while any layer is queued.
5. After landing: remove every layer's branch, worktree and `target/` on
   every host.
