from pathlib import Path
import subprocess,hashlib,json,os,re
repo=Path.cwd();worker=Path('/Users/tjfontaine/.codex/worktrees/el1-personality-boundary/carrick')
out=repo/'target/el1-completion/namespace-independent';out.mkdir(parents=True,exist_ok=True)
assert not subprocess.check_output(['git','status','--porcelain'],text=True).strip()
paths=['crates/carrick-vfs/src/vfs/rootfs.rs','crates/carrick-vfs/src/fs_backend/host.rs','crates/carrick-vfs/src/vfs/namespace_mutation.rs']
original={p:(repo/p).read_bytes() for p in paths};candidate={p:(worker/p).read_bytes() for p in paths}
for p,b in original.items():
 assert b==subprocess.check_output(['git','show','5d612ffb5:'+p]),p
text=candidate[paths[0]].decode();start=text.index('        fn test_namespace_mutation_work()');end=text.index('\n        }\n',start)+len('\n        }\n');fn=text[start:end]
# Keep the same diagnostic test on both arms, but defer cold assertions until after all measurements are printed.
for begin,stop in [('                    assert_eq!(cold_opens, 0);','                    assert_eq!(warm_dentry_opens, 0, "warm rename opens 0 dir fds");'),('                    assert_eq!(cold_opens, 0);','                    assert_eq!(warm_dentry_opens, 0, "warm unlink opens 0 dir fds");')]:
 if stop not in fn: raise RuntimeError('Unexpected witness shape: '+stop)
 a=fn.index(begin);b=fn.index(stop,a)+len(stop);fn=fn[:a]+fn[b:]
fn=fn.replace('                    continue;','                    assert_eq!(opens, 0, "cold backend opens");\n                    assert_eq!(dentry_opens, 2, "cold two-directory traversal");\n                    continue;')
(out/'witness.rs').write_text(fn)
base=original[paths[0]].decode();marker='    mod serial_host {\n        use super::*;';assert marker in base
base=base.replace(marker,marker+'\n\n        #[cfg(target_os = "macos")]\n        #[test]\n'+fn,1)
needle='    pub fn host_fd_inode_identity(raw_fd: i32) -> Option<InodeIdentity> {\n';assert needle in base
base=base.replace(needle,needle+'        #[cfg(any(test, feature = "test-support"))]\n        crate::fs_backend::host::record_test_host_parent_fstat();\n',1)
cand=text[:start]+fn+text[end:]
cmd=['cargo','test','-p','carrick-vfs','--lib','vfs::rootfs::tests::serial_host::test_namespace_mutation_work','--','--exact','--nocapture'];env=os.environ.copy();env.update(RUSTC_WRAPPER='',RUST_TEST_THREADS='1')
results=[]
try:
 for arm,root,ns in [('base',base,original[paths[2]]),('candidate',cand,candidate[paths[2]])]:
  (repo/paths[0]).write_text(root);(repo/paths[1]).write_bytes(candidate[paths[1]]);(repo/paths[2]).write_bytes(ns)
  hashes={p:hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in paths}
  (out/(arm+'-rootfs.rs')).write_text(root)
  r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  (out/(arm+'.log')).write_bytes(r.stdout)
  results.append({'arm':arm,'command':cmd,'exit_code':r.returncode,'source_sha256':hashes,'witness_sha256':hashlib.sha256(fn.encode()).hexdigest()})
  print(arm,'exit',r.returncode,flush=True)
finally:
 for p,b in original.items():(repo/p).write_bytes(b)
 (out/'results.json').write_text(json.dumps({'base_head':'5d612ffb5','candidate_source_sha256':{p:hashlib.sha256(b).hexdigest() for p,b in candidate.items()},'results':results},indent=2)+'\n')
print('checkout restored',flush=True)
