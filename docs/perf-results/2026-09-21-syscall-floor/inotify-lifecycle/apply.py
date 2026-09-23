from pathlib import Path
import re,shutil,subprocess,hashlib
root=Path.cwd();out=root/'target/lease-cost/inotify-lifecycle'
log=(out/'signed-red.log').read_text();assert 'AssertionError' in log
p=Path(re.search(r'test-signed: FAIL (.*inotify_lifecycle-[^\s]+)',log).group(1));shutil.copy2(p,out/'embed-red')
(out/'embed-red.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'\n')
r=subprocess.run(['codesign','-dvvv','--entitlements',':-',str(out/'embed-red')],capture_output=True);(out/'embed-red.codesign').write_bytes(r.stdout+r.stderr)
p=root/'crates/carrick-kernel/src/inotify.rs';s=p.read_text().replace('use std::cmp::Reverse;\n','').replace('{BinaryHeap, HashMap, HashSet, VecDeque}','{HashMap, HashSet, VecDeque}').replace('    free_wds: BinaryHeap<Reverse<i32>>,\n','').replace('            free_wds: BinaryHeap::new(),\n','')
a=s.index('    /// Allocate the lowest available watch descriptor.');b=s.index('    /// Append one already-encoded',a)
s=s[:a]+'''    /// Advance through positive descriptors without reusing removed watches
    /// until wraparound, matching inotify(7). Pending events retain their wd;
    /// eagerly recycling it can coalesce distinct IN_IGNORED notifications.
    /// Only live descriptors are consulted, never the pending event queue.
    fn alloc_wd(&mut self) -> Result<i32, LinuxErrno> {
        if self.watches.len() >= i32::MAX as usize {
            return Err(LINUX_ENOSPC);
        }
        // At most live-count collisions precede a free slot, including wrap.
        for _ in 0..=self.watches.len() {
            let wd = self.next_wd;
            self.next_wd = wd.checked_add(1).unwrap_or(1);
            if !self.watches.contains_key(&wd) {
                return Ok(wd);
            }
        }
        Err(LINUX_ENOSPC)
    }

'''+s[b:]
old='        let wd = inner.alloc_wd();'
s=s.replace(old,'''        let wd = match inner.alloc_wd() {
            Ok(wd) => wd,
            Err(error) => {
                for native_wd in native_wds {
                    if !inner.native_wd_to_guest.contains_key(&native_wd) {
                        unsafe { libc::inotify_rm_watch(self.inotify_fd, native_wd) };
                    }
                }
                for fd in host_fds { unsafe { libc::close(fd) }; }
                return Err(error);
            }
        };''',1)
s=s.replace(old,'''        let wd = match inner.alloc_wd() {
            Ok(wd) => wd,
            Err(error) => {
                // Closing these owned descriptors also removes their kqueue filters.
                for watch_fd in &watch_fds { unsafe { libc::close(watch_fd.host_fd) }; }
                return Err(error);
            }
        };''',1).replace(old,'        let wd = inner.alloc_wd()?;',1)
s=s.replace('pub(crate) fn add_virtual_watch(&self, mask: u32) -> i32','pub(crate) fn add_virtual_watch(&self, mask: u32) -> Result<i32, LinuxErrno>')
a=s.index('    pub(crate) fn add_virtual_watch');b=s.index('    /// Replace or extend',a);s=s[:a]+s[a:b].replace('        wd\n','        Ok(wd)\n')+s[b:]
s=s.replace('        inner.free_wd(wd);\n','')
s=re.sub(r'(state\.add_virtual_watch\([^;\n]+\))(;)',r'\1.expect("virtual watch")\2',s)
a=s.index('    #[test]',s.index('mod tests'))
s=s[:a]+'''    #[test]
    fn watch_descriptor_wrap_skips_live_watches() {
        let state = InotifyState::new().expect("inotify");
        let first = state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY).unwrap();
        assert_eq!(first, 1);
        state.inner.lock().next_wd = i32::MAX;
        let last = state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY).unwrap();
        assert_eq!(last, i32::MAX);
        assert_eq!(state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY).unwrap(), 2);
        state.rm_watch(first).unwrap();
        state.inner.lock().next_wd = i32::MAX;
        assert_eq!(state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY).unwrap(), 1);
        assert!(state.inner.lock().watches.contains_key(&last));
    }

    #[test]
    fn removed_watch_does_not_name_its_successor() {
        let state = InotifyState::new().expect("inotify");
        let first = state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY).unwrap();
        state.rm_watch(first).unwrap();
        let second = state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY).unwrap();
        assert_ne!(first, second);
        assert_eq!(state.rm_watch(first), Err(LINUX_EINVAL));
        assert!(state.inner.lock().watches.contains_key(&second));
    }

'''+s[a:];p.write_text(s)
p=root/'crates/carrick-kernel/src/dispatch/fs/notify.rs';p.write_text(p.read_text().replace('state.add_virtual_watch(mask)', 'state.add_virtual_watch(mask)?'))
p=root/'crates/carrick-kernel/src/dispatch/net.rs';p.write_text(p.read_text().replace('inotify_state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY);','inotify_state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY).expect("virtual watch");'))
p=root/'crates/carrick-conformance-contract/tests/claims.rs';p.write_text(p.read_text().replace('registry.contracts().len(), 24','registry.contracts().len(), 26'))
