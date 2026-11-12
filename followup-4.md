# Follow-up 4: fork-child readlinkat is ENOSYS (case_07)

`ln -sf /etc/hostname lnk && readlink lnk` exits 1 with empty stderr on both gate Macs (case_07, run 43246641703, line 544). `ln -s` now works through the venue (`6687c1f85`), but READLINKAT has no `HostFileCall` arm, so `readlink` gets a counted ENOSYS. #2067 assigns readlinkat to #1900 / PR #2084 ("serve native child executable links"). Check whether #2084 covers a plain symlink, not only `/proc/self/exe`. If it doesn't, give readlinkat its own owner.
