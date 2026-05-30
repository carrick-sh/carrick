//! Exercises the vDSO getrandom fast path: resolve __kernel_getrandom, query,
//! mmap the opaque state, then 200 getrandom(16) calls. Prints the total bytes
//! (deterministic → MATCHes the oracle); the FAST-path proof is the getrandom(2)
//! syscall count under `carrick trace` (~1 reseed for 200 calls, not 200).
use std::ptr;
const AT_SYSINFO_EHDR: u64 = 33;
unsafe fn r16(p:u64)->u16{ptr::read_unaligned(p as *const u16)} unsafe fn r32(p:u64)->u32{ptr::read_unaligned(p as *const u32)}
unsafe fn r64(p:u64)->u64{ptr::read_unaligned(p as *const u64)} unsafe fn ri64(p:u64)->i64{ptr::read_unaligned(p as *const i64)}
unsafe fn ceq(p:u64,w:&str)->bool{for(i,&b)in w.as_bytes().iter().enumerate(){if *((p+i as u64)as *const u8)!=b{return false}} *((p+w.len()as u64)as*const u8)==0}
unsafe fn sym(w:&str)->u64{let b=libc::getauxval(AT_SYSINFO_EHDR);if b==0{return 0}
 let ph0=r64(b+0x20);let es=r16(b+0x36)as u64;let n=r16(b+0x38)as u64;let mut dy=0u64;
 for i in 0..n{let ph=b+ph0+i*es;if r32(ph)==2{dy=b+r64(ph+16)}} if dy==0{return 0}
 let(mut st,mut str_,mut h)=(0u64,0u64,0u64);let mut d=dy;loop{let t=ri64(d);let v=r64(d+8);
  match t{6=>st=b+v,5=>str_=b+v,4=>h=b+v,_=>{}} if t==0{break} d+=16}
 let nc=if h!=0{r32(h+4)}else{0};if st==0||str_==0{return 0}
 for s in 0..nc as u64{let sy=st+s*24;let nm=r32(sy)as u64;let sh=r16(sy+6);let val=r64(sy+8);
  if nm==0||sh==0{continue} if ceq(str_+nm,w){return b+val}} 0}
#[repr(C)] #[derive(Default)] struct P{size:u32,prot:u32,flags:u32,res:[u32;13]}
type F=unsafe extern "C" fn(*mut u8,usize,u32,*mut u8,usize)->isize;
fn main(){unsafe{
 let a=sym("__kernel_getrandom"); if a==0{println!("resolved=false");println!("loop_total=0");return}
 println!("resolved=true"); let f:F=std::mem::transmute(a);
 let mut p=P::default(); f(ptr::null_mut(),0,0,&mut p as *mut P as *mut u8,usize::MAX);
 let st=libc::mmap(ptr::null_mut(),4096,p.prot as i32,p.flags as i32,-1,0);
 if st==libc::MAP_FAILED{println!("loop_total=0");return}
 let mut total=0i64; let mut buf=[0u8;16];
 for _ in 0..200 { let n=f(buf.as_mut_ptr(),16,0,st as *mut u8,p.size as usize); if n==16{total+=16} }
 println!("loop_total={total}");
}}
