use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ResourceClass;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignBudget {
    pub max_experiments: usize,
    pub max_elapsed_seconds: u64,
    #[serde(default)]
    pub max_resource_units: HashMap<ResourceClass, usize>,
}

impl Default for CampaignBudget {
    fn default() -> Self {
        Self {
            max_experiments: 20,
            max_elapsed_seconds: 1800, // 30 minutes
            max_resource_units: HashMap::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetExhausted {
    #[error("experiment limit reached: executed {executed} >= limit {limit}")]
    ExperimentLimit { executed: usize, limit: usize },
    #[error("elapsed duration limit reached: {elapsed:?} >= limit {limit:?}")]
    ElapsedLimit { elapsed: Duration, limit: Duration },
    #[error("resource unit limit reached for {resource:?}: used {used} >= limit {limit}")]
    ResourceUnitLimit {
        resource: ResourceClass,
        used: usize,
        limit: usize,
    },
}

#[derive(Debug)]
pub struct CampaignState {
    pub budget: CampaignBudget,
    pub experiments_run: usize,
    pub started_at: Instant,
    pub resource_units: HashMap<ResourceClass, usize>,
}

impl CampaignState {
    pub fn new(budget: CampaignBudget) -> Self {
        Self {
            budget,
            experiments_run: 0,
            started_at: Instant::now(),
            resource_units: HashMap::new(),
        }
    }

    pub fn check_budget(&self) -> Result<(), BudgetExhausted> {
        if self.experiments_run >= self.budget.max_experiments {
            return Err(BudgetExhausted::ExperimentLimit {
                executed: self.experiments_run,
                limit: self.budget.max_experiments,
            });
        }

        let elapsed = self.started_at.elapsed();
        let limit = Duration::from_secs(self.budget.max_elapsed_seconds);
        if elapsed >= limit {
            return Err(BudgetExhausted::ElapsedLimit { elapsed, limit });
        }

        for (resource, &limit) in &self.budget.max_resource_units {
            let used = self.resource_units.get(resource).copied().unwrap_or(0);
            if used >= limit {
                return Err(BudgetExhausted::ResourceUnitLimit {
                    resource: *resource,
                    used,
                    limit,
                });
            }
        }

        Ok(())
    }

    pub fn record_experiment(&mut self) -> Result<(), BudgetExhausted> {
        self.experiments_run += 1;
        self.check_budget()
    }

    pub fn record_resource_unit(&mut self, resource: ResourceClass) -> Result<(), BudgetExhausted> {
        let entry = self.resource_units.entry(resource).or_insert(0);
        *entry += 1;
        self.check_budget()
    }
}
