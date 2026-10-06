//! Neutral one-owner entry completion.
use carrick_core_abi::{EntryCompletion, ExecutionBinding};

pub fn admit(binding: ExecutionBinding) -> Option<EntryCompletion> {
    EntryCompletion::admit(binding)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionError {
    WrongGeneration,
}

/// Consume the sole completion authority after authenticating the same exact
/// execution binding that was admitted.
pub fn complete(
    completion: EntryCompletion,
    current: ExecutionBinding,
) -> Result<(), CompletionError> {
    if completion.binding() == current {
        Ok(())
    } else {
        Err(CompletionError::WrongGeneration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_generation_cannot_complete_admitted_entry() {
        let binding = ExecutionBinding {
            task: 7,
            generation: 11,
            mm: 13,
            thread_generation: 17,
        };
        let completion = EntryCompletion::admit(binding).unwrap();
        assert_eq!(complete(completion, binding), Ok(()));
        let completion = EntryCompletion::admit(binding).unwrap();
        assert_eq!(
            complete(
                completion,
                ExecutionBinding {
                    generation: 12,
                    ..binding
                }
            ),
            Err(CompletionError::WrongGeneration)
        );
    }
}
