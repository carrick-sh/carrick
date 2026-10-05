//! Fixture-owned injections. Numeric task identities can repeat in independent
//! Kernel fixtures, so admission requires the exact retained task allocation.

use carrick_kernel::kernel::{TaskKey, TaskRef};
use parking_lot::Mutex;
use std::sync::Arc;

struct Entry<T> {
    task: TaskRef,
    key: TaskKey,
    value: Mutex<Option<T>>,
}

pub(crate) struct TaskHookRegistry<T: 'static> {
    entries: Mutex<Vec<Arc<Entry<T>>>>,
}

impl<T> TaskHookRegistry<T> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn install(&'static self, task: &TaskRef, value: T) -> TaskHookGuard<T> {
        let entry = Arc::new(Entry {
            task: Arc::clone(task),
            key: task.key(),
            value: Mutex::new(Some(value)),
        });
        self.entries.lock().push(Arc::clone(&entry));
        TaskHookGuard {
            registry: self,
            entry,
        }
    }

    pub(crate) fn with_task<R>(
        &self,
        task: &TaskRef,
        invoke: impl FnOnce(&mut Option<T>) -> R,
    ) -> Option<R> {
        let entry = self
            .entries
            .lock()
            .iter()
            .find(|entry| entry.key == task.key() && Arc::ptr_eq(&entry.task, task))
            .cloned()?;
        // Never run a callback under the process-wide registry lock.
        Some(invoke(&mut entry.value.lock()))
    }
}

#[must_use = "dropping the guard uninstalls the fixture's injection"]
pub(crate) struct TaskHookGuard<T: 'static> {
    registry: &'static TaskHookRegistry<T>,
    entry: Arc<Entry<T>>,
}

impl<T> Drop for TaskHookGuard<T> {
    fn drop(&mut self) {
        self.entry.value.lock().take();
        self.registry
            .entries
            .lock()
            .retain(|entry| !Arc::ptr_eq(entry, &self.entry));
    }
}
