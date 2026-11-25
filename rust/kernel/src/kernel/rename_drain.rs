use super::{Kernel, KernelError};
use parking_lot::{Condvar, Mutex};
use std::time::Duration;

#[derive(Default)]
struct State {
    closing: bool,
    active: usize,
    incomplete: bool,
}

#[derive(Default)]
pub(super) struct RenameDrain {
    state: Mutex<State>,
    idle: Condvar,
}

pub(super) struct AdmittedRename<'a> {
    drain: &'a RenameDrain,
    pub(super) completed: bool,
}

impl Drop for AdmittedRename<'_> {
    fn drop(&mut self) {
        let mut state = self.drain.state.lock();
        state.active -= 1;
        if state.closing {
            state.incomplete |= !self.completed;
            if state.active == 0 {
                self.drain.idle.notify_all();
            }
        }
    }
}

impl RenameDrain {
    pub(super) fn enter(&self) -> Result<AdmittedRename<'_>, KernelError> {
        let mut state = self.state.lock();
        if state.closing {
            return Err(KernelError::WouldBlock("node is draining renames".into()));
        }
        state.active += 1;
        Ok(AdmittedRename {
            drain: self,
            completed: false,
        })
    }
}

impl Kernel {
    /// Close rename admission on this kernel for shutdown. Keep the storage
    /// backend and consensus running until the admitted syscalls finish.
    /// This covers only calls in flight when this process closes admission.
    pub fn drain_renames(&self, timeout: Duration) -> Result<(), KernelError> {
        let mut state = self.renames.state.lock();
        state.closing = true;
        if state.active != 0 {
            tracing::info!(active = state.active, "waiting for in-flight renames");
        }
        self.renames
            .idle
            .wait_while_for(&mut state, |s| s.active != 0, timeout);
        if state.active != 0 || state.incomplete {
            return Err(KernelError::OutcomeUnknown(format!(
                "rename drain incomplete ({} still active, unsuccessful completion: {})",
                state.active, state.incomplete
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::OperationContext;

    #[test]
    fn timed_out_shutdown_keeps_admission_closed_and_can_wait_again() {
        let k = Kernel::new();
        let mut ongoing = k.renames.enter().unwrap();
        assert!(matches!(
            k.drain_renames(Duration::ZERO),
            Err(KernelError::OutcomeUnknown(_))
        ));
        let ctx = OperationContext::new("test", "root", true, None, true);
        assert!(matches!(
            k.sys_rename("/old", "/new", &ctx),
            Err(KernelError::WouldBlock(_))
        ));
        ongoing.completed = true;
        drop(ongoing);
        k.drain_renames(Duration::ZERO).unwrap();
    }

    #[test]
    fn losing_an_admitted_call_during_shutdown_keeps_its_result_unconfirmed() {
        let k = Kernel::new();
        let ongoing = k.renames.enter().unwrap();
        assert!(k.drain_renames(Duration::ZERO).is_err());
        drop(ongoing);
        assert!(matches!(
            k.drain_renames(Duration::ZERO),
            Err(KernelError::OutcomeUnknown(_))
        ));
    }
}
