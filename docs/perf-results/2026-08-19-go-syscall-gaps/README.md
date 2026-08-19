# `go-syscall` — three rows, two closed

Ranked off the quiet A/B arm, `go-syscall` had 3 diverging rows. Two are fixed
and verified; the third is attributed but not yet fixed.

## FIXED — `TestFchmodat`

    fchmodat2(symlink, AT_SYMLINK_NOFOLLOW)   docker rc=-1 errno=95   carrick rc=0

Linux cannot change a symlink's mode, so `AT_SYMLINK_NOFOLLOW` is not advisory
there — it is `EOPNOTSUPP`. carrick treated the flag as advisory and chmod'd the
link's TARGET, the one thing the caller asked not to happen. Narrow by
construction: on a non-symlink the flag is a no-op on both sides, and plain
`fchmodat` (nr 53) ignores flags entirely on both. Reducer
`reducers/fchmodat-nofollow.py` runs the raw syscalls on both sides.

## FIXED — the `msg_flags` half of `TestSCMCredentials`

    recvmsg(..., MSG_CMSG_CLOEXEC)  docker msg_flags=0x40000000  carrick 0x0

`MSG_CMSG_CLOEXEC` has no macOS equivalent, so the host never reports it back and
the translated flags arrived without it; Linux echoes the caller's request. The
close-on-exec was already applied to the installed fd — only the echo was
missing. Reducer `reducers/recvmsg-cmsg-cloexec.py`.

## OPEN — the payload half of `TestSCMCredentials`

With the echo fixed the test advances from `creds_test.go:110` to `:122`,
"ReadMsgUnix oob bytes don't match". **Attributed by source reading, NOT yet
confirmed differentially** — the confirming Docker run has not been taken because
a carrick gate was occupying the host, and Carrick-vs-Docker concurrency is not
allowed.

The hypothesis, and why it is likely: on a `recvmsg` with `SO_PASSCRED` carrick
APPENDS an `SCM_CREDENTIALS` record built from `peer_ucred(host_fd)`
(`net.rs:2417` -> `carrick_portable::peer_credentials`), which on macOS reads
`xucred` plus a HOST pid. Under HVPatch every guest process is a thread of ONE
carrier, so a host pid is the carrier's for every peer and never a guest pid,
while Linux reports the actual sending process. That is the identity/scope-domain
class `docs/identity-and-scope-domains.md` names: Darwin PID-owned state standing
in for a Linux-process concept.

Next step, in order:

1. Confirm differentially — print the received `ucred` on both sides and compare
   against the sender's guest pid. Do NOT skip this; the payload could also
   differ in the pass-through direction (Linux delivers what the SENDER supplied,
   subject to permission checks, rather than regenerating it).
2. If confirmed, source the ucred from carrick's kernel graph — the guest task
   owning the peer endpoint — instead of the host. `socket_namespace` tracks an
   owner pid for endpoint records but has no per-socket guest-task mapping today.

## OPEN — `TestPrlimitFileLimit`

    helper2 cached rlimit is 43, want 42

A `prlimit` applied to ANOTHER process is not observed by that process's Go
runtime cache. Not investigated further.
