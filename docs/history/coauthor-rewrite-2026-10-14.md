# Co-author history rewrite, 2026-10-14

On 2026-10-14 every commit in carrick-sh/carrick was rewritten once to normalize
`Co-Authored-By` trailers: one noreply address per vendor and the `Co-Authored-By`
spelling. Names are unchanged, two worker-VM author identities were fixed, and
every file tree is byte-identical.

`docs/history/coauthor-rewrite-2026-10-14-commit-map.txt` (on this branch only, never merged) maps each old commit SHA to its new SHA
(`old new`, one per line). Resolve any pre-rewrite SHA through it, e.g.:

    git show origin/history/coauthor-rewrite-2026-10-14:docs/history/coauthor-rewrite-2026-10-14-commit-map.txt | grep ^<old-prefix>

Old main `29de4c4e5ff4889f040f092e71ddba4f933ba4e4` became `7419bbe99eb2e7132c179016740c37995f64493f`.
