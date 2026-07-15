/*
 * psynch-callers.d — attribute macOS pthread condvar traffic to its Rust
 * caller. Aggregates psynch_cvwait / psynch_cvsignal by user stack across the
 * whole process tree, so we can see WHICH lock/condvar is doing the ~3M ops.
 *
 * Needs a symbolicating build:
 *   RUSTFLAGS="-C force-frame-pointers=yes" CARGO_PROFILE_RELEASE_DEBUG=1 \
 *     ./scripts/build-signed.sh --debug
 *
 * Run: carrick trace --script scripts/dtrace/psynch-callers.d -- run <args>
 */
#pragma D option quiet
#pragma D option ustackframes=48

syscall::psynch_cvwait:entry
/pid == $target || progenyof($target)/
{ @cvwait[ustack(28)] = count(); }

syscall::psynch_cvsignal:entry
/pid == $target || progenyof($target)/
{ @cvsignal[ustack(28)] = count(); }

tick-1s { secs++; }
tick-1s /secs >= 240/ { exit(0); }

END {
	printf("\n==== psynch_cvwait: top 5 caller stacks ====\n");
	trunc(@cvwait, 5);
	printa(@cvwait);
	printf("\n==== psynch_cvsignal: top 5 caller stacks ====\n");
	trunc(@cvsignal, 5);
	printa(@cvsignal);
}
