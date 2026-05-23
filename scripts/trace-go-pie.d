#pragma D option quiet
#pragma D option strsize=256

typedef struct guest_regs {
	uint64_t pc;
	uint64_t sp;
	uint64_t fp;
	uint64_t lr;
	uint64_t x8;
	uint64_t x0;
	uint64_t stack_guest_base;
	uint64_t stack_host_base;
	uint64_t stack_guest_end;
} guest_regs_t;

dtrace:::BEGIN
{
	printf("go-pie trace started at %Y\n", walltimestamp);
}

carrick*:::vcpu-trap
/pid == $target || progenyof($target)/
{
	this->r = (guest_regs_t *)copyin(arg0, sizeof (guest_regs_t));
	printf("[%d trap ] pc=%#x sp=%#x fp=%#x lr=%#x x8=%d x0=%#x\n",
	    pid, this->r->pc, this->r->sp, this->r->fp, this->r->lr,
	    this->r->x8, this->r->x0);
	@trap_pc[this->r->pc, this->r->lr, this->r->x8] = count();
	@trap_regs[this->r->pc, this->r->sp, this->r->fp, this->r->lr, this->r->x8, this->r->x0] = count();
}

carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
	this->sa = (uint64_t *)copyin(arg2, 48);
	printf("[%d entry] %-20s nr=%-3d args=[%#x, %#x, %#x, %#x, %#x, %#x]\n",
	    pid, copyinstr(arg1), arg0,
	    this->sa[0], this->sa[1], this->sa[2],
	    this->sa[3], this->sa[4], this->sa[5]);
	@entry_args[copyinstr(arg1), arg0,
	    this->sa[0], this->sa[1], this->sa[2],
	    this->sa[3], this->sa[4], this->sa[5]] = count();
}

carrick*:::syscall-return
/pid == $target || progenyof($target)/
{
	printf("[%d ret  ] %-20s nr=%-3d ret=%-12d errno=%d\n",
	    pid, copyinstr(arg1), arg0, (int)arg2, (int)arg3);
	@returns[copyinstr(arg1), (int)arg2, (int)arg3] = count();
	@returns64[copyinstr(arg1), arg2, (int)arg3] = count();
}

carrick*:::unhandled-syscall
/pid == $target || progenyof($target)/
{
	printf("[%d unh  ] %-20s nr=%-3d\n", pid, copyinstr(arg1), arg0);
	@unhandled[copyinstr(arg1)] = count();
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
	printf("[%d exit ] code=%d\n", pid, (int)arg1);
}

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
	printf("[%d sigi ] signum=%d saved_pc=%#x sp=%#x handler=%#x\n",
	    pid, (int)arg0, arg1, arg2, arg3);
	@signal_inject[(int)arg0, arg1, arg2, arg3] = count();
}

carrick*:::signal-restore
/pid == $target || progenyof($target)/
{
	printf("[%d sigr ] saved_pc=%#x sp=%#x magic=%#x\n",
	    pid, arg0, arg1, arg2);
	@signal_restore[arg0, arg1, arg2] = count();
}

carrick*:::mem-watch
/pid == $target || progenyof($target)/
{
	printf("[%d watch] nr=%d addr=%#x value=%#x\n", pid, arg0, arg1, arg2);
	@watch[arg0, arg1, arg2] = count();
}

tick-1s
{
	secs++;
}

tick-1s
/secs >= 12/
{
	exit(0);
}

dtrace:::END
{
	printf("\n--- trap PCs (pc, lr, x8) ---\n");
	printa("  pc=%#x lr=%#x x8=%d %@d\n", @trap_pc);
	printf("\n--- trap regs (pc, sp, fp, lr, x8, x0) ---\n");
	printa("TRAP pc=%#x sp=%#x fp=%#x lr=%#x x8=%d x0=%#x count=%@d\n", @trap_regs);
	printf("\n--- syscall entries (name, nr, args) ---\n");
	printa("ENTRY name=%s nr=%d a0=%#x a1=%#x a2=%#x a3=%#x a4=%#x a5=%#x count=%@d\n", @entry_args);
	printf("\n--- syscall returns (name, ret, errno) ---\n");
	printa("RET name=%s ret=%d errno=%d count=%@d\n", @returns);
	printf("\n--- syscall returns64 (name, ret, errno) ---\n");
	printa("RET64 name=%s ret=%#x errno=%d count=%@d\n", @returns64);
	printf("\n--- signal injections (signum, saved_pc, sp, handler) ---\n");
	printa("SIGI signum=%d saved_pc=%#x sp=%#x handler=%#x count=%@d\n", @signal_inject);
	printf("\n--- signal restores (saved_pc, sp, magic) ---\n");
	printa("SIGR saved_pc=%#x sp=%#x magic=%#x count=%@d\n", @signal_restore);
	printf("\n--- watched guest address (nr, addr, value) ---\n");
	printa("WATCH nr=%d addr=%#x value=%#x count=%@d\n", @watch);
	printf("\n--- unhandled syscalls ---\n");
	printa("UNHANDLED name=%s count=%@d\n", @unhandled);
}
