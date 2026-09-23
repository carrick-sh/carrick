# SPDX-License-Identifier: Apache-2.0 OR MIT
# Independent public-ABI diagnostic, no LTP implementation code.
import ctypes as c, os, json, struct
lib=c.CDLL(None,use_errno=True)
lib.inotify_add_watch.argtypes=[c.c_int,c.c_char_p,c.c_uint]
path=('/tmp/carrick-inotify-shape-'+str(os.getpid())).encode()
f=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
for mode in ['churn','serial_full']:
 for n in [1,8,32,128]:
  q=lib.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC); assert q>=0
  ids=[]
  for i in range(n):
   wd=lib.inotify_add_watch(q,path,2);assert wd>=0;ids.append(wd)
   if mode=='serial_full':assert os.write(f,b'x'*64)==64;assert os.lseek(f,0,0)==0
   assert lib.inotify_rm_watch(q,wd)==0
  available=c.c_int(-1);assert lib.ioctl(q,0x541b,c.byref(available))==0
  events=[]
  while True:
   try:data=os.read(q,65536)
   except BlockingIOError:break
   assert data
   pos=0
   while pos<len(data):
    wd,mask,cookie,length=struct.unpack_from('iIII',data,pos);events.append((wd,mask));pos+=16+length
   assert pos==len(data)
  print(json.dumps(dict(mode=mode,n=n,distinct_wds=len(set(ids)),first_wds=ids[:8],queued_bytes=available.value,events=len(events),ignored=sum(m==0x8000 for w,m in events),modify=sum(m==2 for w,m in events))),flush=True)
  os.close(q)
os.close(f);os.unlink(path);print('probe_complete=1',flush=True)
