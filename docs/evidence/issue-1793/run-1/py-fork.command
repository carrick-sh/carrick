python3 -c 'import os; p=os.fork(); print("child-ok" if p==0 else "parent-ok", flush=True); os._exit(0) if p==0 else os.waitpid(p,0)'
