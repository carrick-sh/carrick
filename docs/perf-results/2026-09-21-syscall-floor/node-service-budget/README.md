# Coarse Node service census

Five successful app-smoke iterations on the frozen discard-retirement candidate.
10,922 begin/argument/end events per category, zero trace errors, root exited,
cleanup returned zero. See raw trace and inputs for artifact and command identity.
The script header was clarified after the run to name arg4 duration_ns; probe
logic is unchanged. inputs.json retains the executed script hash.

Summed service times across five iterations: madvise 367.844 ms, munmap 84.266 ms,
epoll_pwait 54.146 ms, futex 50.131 ms. These instrumented intervals may overlap;
they are neither CPU time nor critical-path time nor predicted removable cost.

app-smoke.js was retrieved from the fixture path in the pinned image named in
inputs.json. It is retained as experimental input, not introduced into product
code. It includes a child Node exec and a worker. The subsequent node-phases
reduction selects child process lifecycle as the next diagnostic target.
