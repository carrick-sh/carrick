//! Exact task binding for the shared Linux entry dispatcher.
use carrick_el1_abi::CurrentTask;
use carrick_personality_linux::entry::ExecutionBinding;

pub fn execution_binding(task: &CurrentTask) -> ExecutionBinding {
    carrick_core::entry::binding(&task.execution, &task.mm)
}

#[cfg(test)]
mod tests;
