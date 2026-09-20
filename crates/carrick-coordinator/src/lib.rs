//! Host-wide resource coordinator preventing conflicting phases and managing campaign budgets.

mod budget;
mod coordinator;

pub use budget::{BudgetExhausted, CampaignBudget, CampaignState};
pub use coordinator::{Coordinator, CoordinatorError, Lease, LeaseOwner, ResourceClass};
