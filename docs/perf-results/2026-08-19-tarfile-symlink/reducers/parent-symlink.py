#!/usr/bin/env python3
"""RED-FIRST: where does a write through `parent/evil` land?

CPython's test_tarfile.test_parent_symlink builds, inside the extraction dir:
    current -> .
    parent  -> current/..
and then creates `parent/evil`. Linux resolves `parent` by expanding `current`
to the directory holding it, so `current/..` names that directory's PARENT.
"""
import os, shutil, sys, tempfile

base = tempfile.mkdtemp()
dest = os.path.join(base, "outerdir", "dest")
os.makedirs(dest)
os.symlink(".", os.path.join(dest, "current"))
os.symlink("current/..", os.path.join(dest, "parent"))

print("readlink current:", os.readlink(os.path.join(dest, "current")), flush=True)
print("readlink parent :", os.readlink(os.path.join(dest, "parent")), flush=True)
print("realpath parent :", os.path.realpath(os.path.join(dest, "parent")), flush=True)

target = os.path.join(dest, "parent", "evil")
try:
    with open(target, "w") as f:
        f.write("x")
    print("open  parent/evil: OK", flush=True)
except OSError as e:
    print("open  parent/evil: errno=%d %s" % (e.errno, e.strerror), flush=True)

found = []
for root, dirs, files in os.walk(base):
    for name in files:
        found.append(os.path.relpath(os.path.join(root, name), base))
print("files under base:", sorted(found), flush=True)
shutil.rmtree(base, ignore_errors=True)
sys.stdout.flush()
