#!/usr/sbin/dtrace -qs
/*
 * Sample repeated exec startup without enabling high-rate fault/COW probes.
 * Darwin/arm64 profile ABI qualified 2026-09-09: arg0 is kernel PC, arg1
 * user PC; pid/tid name the interrupted thread. User stacks require the
 * repository frame-pointer build. Raw PIE addresses require return-site
 * validation against the exact binary before offline symbolization (see
 * hvpatch-carrier-user-cpu-ranking.d). HVF run samples do not resolve guest CPU.
 *
 * Perturbation: 499 Hz stacks, no USDT probes. Rankings are diagnostic only;
 * accept performance only from separate untraced runs. Require target exit(0),
 * nonzero samples, zero errors/drops and natural completion within 45 seconds.
 * Do not symbolize kernel addresses using a mismatched KDK build.
 */
#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option aggsize=32m

dtrace:::BEGIN
{ started = timestamp; sample_seen = 0; errors = 0; seen = 0; code = -1; bounded = 0; }

profile-499
/(pid == $target || progenyof($target)) && arg1 != 0/
{ sample_seen = 1; @population[0] = count(); @user[ustack(24)] = count(); }

profile-499
/(pid == $target || progenyof($target)) && arg0 != 0/
{ sample_seen = 1; @population[1] = count(); @kernel[stack(24)] = count(); }

syscall::exit:entry
/pid == $target/
{ seen = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{ exit(seen && code == 0 && sample_seen && errors == 0 ? 0 : 2); }

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{
    printf("EXECCPU|summary|sample-seen=%d|errors=%d|seen=%d|code=%d|bounded=%d\n", sample_seen, errors, seen, code, bounded);
    printa("EXECCPU|kernel-mode=%d|samples=%@d\n", @population);
    printa("EXECCPU|user=%k|samples=%@d\n", @user);
    printa("EXECCPU|kernel=%k|samples=%@d\n", @kernel);
}
