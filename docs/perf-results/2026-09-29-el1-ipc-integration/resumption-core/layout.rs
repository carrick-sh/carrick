use carrick_el1_abi::ipc::*;
use std::mem::{size_of,align_of,offset_of};
fn main(){
 println!("hash={:#x} directory={} fd={} fd_align={} object={} slot={} op={} objects={} operations={}",IPC_LAYOUT_HASH,size_of::<IpcDirectory>(),size_of::<IpcFdCore>(),align_of::<IpcFdCore>(),size_of::<IpcObjectRecord>(),size_of::<IpcOperationSlot>(),size_of::<IpcOperation>(),IPC_OBJECTS,IPC_OPERATIONS);
 println!("op kind={} object={} task={} mm={} buf={} progress={} park={} value={} orig={} nr={}",offset_of!(IpcOperation,kind),offset_of!(IpcOperation,object),offset_of!(IpcOperation,task),offset_of!(IpcOperation,mm),offset_of!(IpcOperation,buf),offset_of!(IpcOperation,progress),offset_of!(IpcOperation,park_seq),offset_of!(IpcOperation,value),offset_of!(IpcOperation,orig_x0),offset_of!(IpcOperation,nr));
 println!("pipe size={} align={} state={} progress={} progress_written={}",size_of::<pipe::PipeRecord>(),align_of::<IpcObjectState>(),size_of::<IpcObjectState>(),size_of::<pipe::WriteProgress>(),offset_of!(pipe::WriteProgress,written));
}
