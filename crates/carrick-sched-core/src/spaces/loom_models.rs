//! loom models of one space's editor word (#3105): prepared-commit shares
//! against the exact guest editor and a host pause. They drive the
//! production `AddressSpaces` methods on loom atomics; the space has no
//! release venue attached, so these models check admission and exclusion,
//! and the unit tests in `notification.rs` check the release's wake.
//!
//! A share against a host pause isn't modelled here: it is a Dekker pair
//! (the share counts itself, then reads the gate; the pause raises the
//! gate, then reads the word), and loom treats `SeqCst` accesses as
//! `AcqRel`, so it reports that pair as a race C11's single `SeqCst` order
//! rules out (loom's README, "Unsupported features"). A share takes the
//! exact editor's handshake unchanged, and the unit test
//! `a_commit_share_under_a_raised_gate_releases_and_refuses` checks it.
//! Run with `cargo test -p carrick-sched-core --features loom --lib loom_models`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use loom::sync::Arc;
use loom::sync::atomic::AtomicU32;
use loom::thread;
use std::boxed::Box;

const KEY: u64 = 7;

fn model(body: impl Fn() + Send + Sync + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.check(body);
}

fn open_space() -> (Arc<Box<AddressSpaces>>, SpaceIndex) {
    let spaces = AddressSpaces::new();
    let index = spaces.publish_closed(KEY, 0x1_0000, 0x1_0000).unwrap();
    spaces.open(index);
    (Arc::new(Box::new(spaces)), index)
}

fn share(spaces: &AddressSpaces, index: SpaceIndex) -> Option<SpaceCommit<'_>> {
    spaces
        .try_begin_commit::<ThreadCtx>(index, KEY, None)
        .map_err(|refusal| {
            assert!(
                matches!(
                    refusal,
                    EditAdmissionRefusal::Editor | EditAdmissionRefusal::Gate
                ),
                "contention on the editor word is \"not now\", never {refusal:?}"
            );
        })
        .ok()
}

/// Who is inside the space's tables: the low bits count shares (they
/// coexist), and [`EXCLUSIVE`] marks the exact editor.
const EXCLUSIVE: u32 = 1 << 8;

/// Enter the tables as a share (`exclusive` false) or as the exact editor,
/// asserting no conflicting holder is inside; the guard leaves.
fn enter(inside: &AtomicU32, exclusive: bool) -> impl Drop + '_ {
    let before = if exclusive {
        inside.fetch_or(EXCLUSIVE, Ordering::SeqCst)
    } else {
        inside.fetch_add(1, Ordering::SeqCst)
    };
    let conflict = if exclusive {
        before
    } else {
        before & EXCLUSIVE
    };
    assert_eq!(conflict, 0, "holders {before:#x} conflict with this one");
    struct Leave<'a>(&'a AtomicU32, bool);
    impl Drop for Leave<'_> {
        fn drop(&mut self) {
            if self.1 {
                self.0.fetch_and(!EXCLUSIVE, Ordering::SeqCst);
            } else {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
    Leave(inside, exclusive)
}

/// Two shares and the exact editor race for one space. The shares may run
/// together; the editor never runs beside either, and the word ends free
/// with no drain request left behind.
#[test]
fn commit_shares_and_the_exact_editor_never_hold_a_space_together() {
    model(|| {
        let (spaces, index) = open_space();
        let inside = Arc::new(AtomicU32::new(0));
        let sharers: std::vec::Vec<_> = (0..2)
            .map(|_| {
                let (spaces, inside) = (Arc::clone(&spaces), Arc::clone(&inside));
                thread::spawn(move || {
                    if let Some(commit) = share(&spaces, index) {
                        let in_tables = enter(&inside, false);
                        // Leave the tables before the share releases.
                        drop(in_tables);
                        drop(commit);
                    }
                })
            })
            .collect();
        let editor = {
            let (spaces, inside) = (Arc::clone(&spaces), Arc::clone(&inside));
            thread::spawn(move || {
                if let Some(editor) =
                    spaces.try_begin_edit(index, KEY, NonZeroU64::new(11).unwrap())
                {
                    let in_tables = enter(&inside, true);
                    drop(in_tables);
                    drop(editor);
                }
            })
        };
        for sharer in sharers {
            sharer.join().unwrap();
        }
        editor.join().unwrap();
        assert_eq!(spaces.editor_word(index), EditorWord::Free);
        // A drain request never outlives the shares it waited on.
        assert!(share(&spaces, index).is_some());
    });
}

/// The exact editor, refused by a held share, asks the shares to drain, so
/// a new share is refused; the drain request races the last share's
/// release and never outlives it: the word ends free, and the editor then
/// gets in.
#[test]
fn a_drain_request_races_the_last_share_and_never_outlives_it() {
    model(|| {
        let (spaces, index) = open_space();
        // This thread holds the last share and releases it while the others
        // run.
        let held = share(&spaces, index).unwrap();
        let editor = {
            let spaces = Arc::clone(&spaces);
            thread::spawn(move || {
                spaces
                    .try_begin_edit(index, KEY, NonZeroU64::new(11).unwrap())
                    .is_some()
            })
        };
        let latecomer = {
            let spaces = Arc::clone(&spaces);
            thread::spawn(move || share(&spaces, index).is_some())
        };
        drop(held);
        let _ = editor.join().unwrap();
        let _ = latecomer.join().unwrap();
        assert_eq!(spaces.editor_word(index), EditorWord::Free);
        assert!(
            spaces
                .try_begin_edit(index, KEY, NonZeroU64::new(11).unwrap())
                .is_some()
        );
    });
}
