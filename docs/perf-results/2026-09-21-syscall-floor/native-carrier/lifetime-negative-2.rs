use carrick_kernel::kernel::{KernelContext, objects::ThreadExecutionLease};
use carrick_kernel::kernel::mm_access::CowBroken;
fn transfer(c: &KernelContext, e: ThreadExecutionLease, cow: &mut CowBroken<'_, '_, '_>) {
    let data = c.borrow_current_native_data(&e, cow).unwrap();
    c.thread().yield_from_executor(e).unwrap();
    let _ = data.len();
}
