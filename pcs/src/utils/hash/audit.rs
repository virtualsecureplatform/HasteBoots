//! Optional process-wide SHA512 Hash-trait output observation, not a bound.
use super::Digest512;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
type Callback = Arc<dyn Fn(Digest512) + Send + Sync>;
struct State {
    enabled: AtomicBool,
    callback: Callback,
}
static ACTIVE: Mutex<Option<Arc<State>>> = Mutex::new(None);

/// Ends an exclusive process-wide output observation scope on drop.
pub struct ObservationGuard(Arc<State>);
impl Drop for ObservationGuard {
    fn drop(&mut self) {
        self.0.enabled.store(false, Ordering::Release);
        let mut active = ACTIVE.lock().unwrap();
        if active
            .as_ref()
            .is_some_and(|state| Arc::ptr_eq(state, &self.0))
        {
            *active = None;
        }
    }
}
/// Observe standard SHA512 Hash-trait outputs on all workers in this process.
/// Direct Digest calls and hash input lengths are not observed. The callback
/// must not recursively perform observed Hash-trait operations.
pub fn observe(
    callback: impl Fn(Digest512) + Send + Sync + 'static,
) -> Result<ObservationGuard, &'static str> {
    let mut active = ACTIVE.lock().unwrap();
    if active.is_some() {
        return Err("SHA512 output observer already active");
    }
    let state = Arc::new(State {
        enabled: AtomicBool::new(true),
        callback: Arc::new(callback),
    });
    *active = Some(Arc::clone(&state));
    Ok(ObservationGuard(state))
}
pub(super) fn record(output: Digest512) {
    let active = ACTIVE.lock().unwrap().clone();
    if let Some(state) = active {
        if state.enabled.load(Ordering::Acquire) {
            (state.callback)(output);
        }
    }
}
