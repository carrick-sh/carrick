#!/bin/bash
# Full curated sweep across the four Go-relevant areas. Hardened so a wedged
# guest can't hang it: carrick stdout -> FILE (never a pipe — a hung guest
# holding the pipe survives `timeout` reaping the parent), and guests are
# force-killed before+after each run (they rename argv0 to "carrick:", so a
# plain pkill misses them — use scripts/sudo/kill.sh). Edit the area lists to
# extend coverage; this is a CURATED subset (~192 of 1457 LTP syscall binaries),
# not the full suite — say so when reporting "complete coverage".
#
# See ltp-check.sh for the verdict logic + the interpretation caveats.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
export CARRICK_INSECURE_REGISTRIES="${CARRICK_INSECURE_REGISTRIES:-localhost:5050}"

SIGNALS="rt_sigaction01 rt_sigaction02 rt_sigaction03 rt_sigprocmask01 rt_sigprocmask02 rt_sigsuspend01 rt_sigtimedwait01 rt_sigqueueinfo01 sigaltstack01 sigaltstack02 tgkill01 tgkill02 tgkill03 tkill01 tkill02 kill02 kill03 kill05 kill06 kill07 kill08 kill09 kill10 kill11 kill12 kill13 sigaction01 sigaction02 signal01 signal02 signal03 signal04 signal05 signal06 sigpending02 sigsuspend01 sigsuspend02 sigprocmask01 sighold02 sigrelse01 sigwait01 sigwaitinfo01 sigtimedwait01 pause01 pause02 pause03 abort01"
EPOLL="epoll_create01 epoll_create02 epoll_create1_01 epoll_create1_02 epoll_ctl01 epoll_ctl02 epoll_ctl03 epoll_ctl04 epoll_ctl05 epoll_pwait01 epoll_pwait02 epoll_pwait03 epoll_pwait04 epoll_pwait05 epoll_wait01 epoll_wait02 epoll_wait03 epoll_wait04 epoll_wait05 epoll_wait06 epoll_wait07 eventfd01 eventfd02 eventfd03 eventfd04 eventfd05 eventfd06 eventfd2_01 eventfd2_02 eventfd2_03 pipe01 pipe02 pipe03 pipe04 pipe05 pipe06 pipe07 pipe08 pipe09 pipe10 pipe11 pipe12 pipe13 pipe14 pipe2_01 pipe2_02 pipe2_04 poll01 poll02 ppoll01 pselect01 pselect02 pselect03 select01 select02 select03 select04 fcntl02 fcntl04 fcntl05 fcntl08"
TIMERS="nanosleep01 nanosleep02 nanosleep04 clock_nanosleep01 clock_nanosleep02 clock_nanosleep03 clock_nanosleep04 clock_gettime01 clock_gettime02 clock_gettime03 clock_gettime04 clock_getres01 clock_settime01 clock_settime02 clock_settime03 clock_adjtime01 clock_adjtime02 timer_create01 timer_create02 timer_create03 timer_delete01 timer_delete02 timer_gettime01 timer_settime01 timer_settime02 timer_settime03 timer_getoverrun01 timerfd_create01 timerfd_gettime01 timerfd_settime01 timerfd_settime02 timerfd01 timerfd02 timerfd04 setitimer01 setitimer02 getitimer01 getitimer02 alarm02 alarm03 alarm05 alarm06 alarm07 gettimeofday01 gettimeofday02 time01 times01 times03"
SCHED="sched_getaffinity01 sched_setaffinity01 sched_yield01 gettid01 gettid02 getcpu01 getcpu02 futex_wait01 futex_wait02 futex_wait03 futex_wait04 futex_wait05 futex_wake01 futex_wake02 futex_wake03 futex_wake04 futex_cmp_requeue01 futex_wait_bitset01 clone01 clone02 clone03 clone04 clone05 clone06 clone07 clone08 clone09 clone301 clone302 clone303 set_tid_address01 sched_get_priority_max01 sched_get_priority_min01 sched_getparam01 sched_getscheduler01 sched_rr_get_interval01 sched_setparam01 sched_setscheduler01"

run_area() {
  echo "######## AREA: $1 ########"
  "$HERE/ltp-check.sh" $2 | sed '/^---- /d'
  echo
}
run_area SIGNALS "$SIGNALS"
run_area EPOLL   "$EPOLL"
run_area TIMERS  "$TIMERS"
run_area SCHED   "$SCHED"
echo "ALL DONE"
