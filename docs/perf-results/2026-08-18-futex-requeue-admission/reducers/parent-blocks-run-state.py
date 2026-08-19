import os, time
# The PARENT blocks; a CHILD observes the parent's /proc state. The parent is
# the root task, whose run-state record the reader does resolve, so this
# isolates the block-guard from the forked-child record-lookup defect.
r, w = os.pipe()
r2, w2 = os.pipe()
kid = os.fork()
if kid == 0:
    time.sleep(1.5)
    ppid = os.getppid()
    try:
        line = open(f"/proc/{ppid}/stat").read()
        import sys; print(f"parent pid={ppid} state={line.split(') ')[1][:1]}  (blocked on pipe read -> want S)", flush=True)
    except Exception as e:
        print("ERR", e, flush=True)
    os.write(w2, b"x")
    os.write(w, b"y")          # release the parent; it holds w too, so EOF never comes
    sys.stdout.flush()
    os._exit(0)
os.close(w2)
os.read(r2, 1)     # wait until the child has sampled us
os.read(r, 1)      # then unblock (never written; child exits and closes w)
os.waitpid(kid, 0)
