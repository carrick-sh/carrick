import multiprocessing

def _check_context(conn):
    conn.send(multiprocessing.get_start_method())

def check_context(ctx, tag):
    r, w = ctx.Pipe(duplex=False)
    p = ctx.Process(target=_check_context, args=(w,))
    p.start()
    w.close()
    try:
        child_method = r.recv()
        r.close(); p.join()
        print(f"{tag}: ok {child_method}", flush=True)
    except EOFError:
        p.join(5)
        print(f"{tag}: EOF exit={p.exitcode}", flush=True)

if __name__ == '__main__':
    # --- test_context body ---
    for method in ('fork', 'spawn', 'forkserver'):
        ctx = multiprocessing.get_context(method)
        check_context(ctx, f"ctx-{method}")
    # --- test_set_get body ---
    multiprocessing.set_forkserver_preload(['__main__', 'test.test_multiprocessing_forkserver'])
    old = multiprocessing.get_start_method()
    for method in ('fork', 'spawn', 'forkserver'):
        multiprocessing.set_start_method(method, force=True)
        check_context(multiprocessing, f"setget-{method}")
    multiprocessing.set_start_method(old, force=True)
