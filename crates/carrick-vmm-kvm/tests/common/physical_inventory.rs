//! Upper-layer fixture composition using the real kernel inventory.
pub fn physical_inventory() -> std::sync::Arc<dyn carrick_hal::PhysicalFrameInventory> {
    std::sync::Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new()).physical_projection(
        std::sync::Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new()),
    )
}
