//! Model of the shipping gate and the backend's final check-to-run window.
//! There is no retrying kick. The edge-only counterexample is intentional:
//! this candidate is pending the signed HVF next-entry qualification.
#![allow(clippy::unwrap_used, clippy::panic)]
use carrick_hal::vcpu_run::{RunStateWord, VcpuRunState};
use loom::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    thread,
};

struct Word(AtomicU8);
impl RunStateWord for Word {
    fn load(&self) -> u8 {
        self.0.load(Ordering::SeqCst)
    }
    fn set_bits(&self, bits: u8) -> u8 {
        self.0.fetch_or(bits, Ordering::SeqCst)
    }
    fn clear_bits(&self, bits: u8) {
        self.0.fetch_and(!bits, Ordering::SeqCst);
    }
}
#[derive(Default)]
struct Hardware {
    running: bool,
    cancelled: bool,
}

fn exercise(latched_hardware: bool, observe_shutdown: bool) {
    let mut model = loom::model::Builder::new();
    model.max_threads = 3;
    model.max_branches = 1000;
    model.check(move || {
        let gate = Arc::new(VcpuRunState::with_word(Word(AtomicU8::new(0))));
        let hardware = Arc::new(Mutex::new(Hardware::default()));
        let (stopped_tx, stopped_rx) = loom::sync::mpsc::channel();
        let worker_gate = Arc::clone(&gate);
        let worker_hardware = Arc::clone(&hardware);
        let worker = thread::spawn(move || {
            // One internally handled exit followed by another physical entry.
            let first = worker_gate.enter();
            if observe_shutdown && first.shutdown_requested() {
                stopped_rx.recv().unwrap();
                return true;
            }
            {
                let mut hw = worker_hardware.lock().unwrap();
                hw.running = true;
                if hw.cancelled {
                    drop(hw);
                    stopped_rx.recv().unwrap();
                    return true;
                }
                hw.running = false;
            }
            drop(first);
            let entry = worker_gate.enter();
            if observe_shutdown && entry.shutdown_requested() {
                stopped_rx.recv().unwrap();
                return true;
            }
            worker_hardware.lock().unwrap().running = true;
            // Bounded abstract WFI: inspect the outcome after the one shutdown
            // request, retaining the real entry guard throughout the wait.
            stopped_rx.recv().unwrap();
            worker_hardware.lock().unwrap().cancelled
        });
        let stop_gate = Arc::clone(&gate);
        let stop_hardware = Arc::clone(&hardware);
        let stop = thread::spawn(move || {
            stop_gate.request_shutdown(|| {
                let mut hw = stop_hardware.lock().unwrap();
                if latched_hardware || hw.running {
                    hw.cancelled = true;
                }
            });
            let _ = stopped_tx.send(());
        });
        stop.join().unwrap();
        assert!(
            worker.join().unwrap(),
            "lost shutdown across physical entry"
        );
    });
}

#[test]
fn shutdown_entry_handshake_with_latched_backend() {
    exercise(true, true);
}

#[test]
#[should_panic(expected = "lost shutdown across physical entry")]
fn shutdown_entry_handshake_requires_backend_latch() {
    exercise(false, true);
}

#[test]
#[should_panic(expected = "lost shutdown across physical entry")]
fn shutdown_entry_handshake_rejects_missing_latch_check() {
    exercise(true, false);
}
