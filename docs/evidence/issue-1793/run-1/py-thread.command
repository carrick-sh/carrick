python3 -c 'import threading; t=threading.Thread(target=lambda: print("thread-ok", flush=True)); t.start(); t.join()'
