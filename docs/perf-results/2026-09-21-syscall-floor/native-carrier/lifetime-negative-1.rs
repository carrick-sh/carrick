use carrick_kernel::kernel::{KernelContext, objects::ThreadExecutionLease};
use carrick_kernel::kernel::mm_access::{CowBroken, CurrentNativeData};
fn escape(c: &KernelContext, e: &ThreadExecutionLease, cow: &mut CowBroken<'_, '_, '_>)
    -> CurrentNativeData<'static, 'static, 'static, 'static, 'static> {
    c.borrow_current_native_data(e, cow).unwrap()
}
