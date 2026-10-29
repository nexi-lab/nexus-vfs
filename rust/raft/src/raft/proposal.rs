//! Proposal deadlines and retries after a definite pre-submission refusal.

/// Commit budget shared by local proposals, forwarding and forwarded RPCs.
pub(crate) const PROPOSAL_TIMEOUT_SECS: u64 = 10;

#[cfg(all(feature = "grpc", has_protos))]
pub(super) async fn retry_leader_refusals<T, F, Fut>(
    deadline: tokio::time::Instant,
    mut attempt: F,
) -> super::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = super::Result<T>>,
{
    use super::RaftError;
    use std::time::Duration;
    use tokio::time::{sleep, timeout_at, Instant};

    loop {
        let result = timeout_at(deadline, attempt())
            .await
            .map_err(|_| RaftError::Timeout(PROPOSAL_TIMEOUT_SECS))?;
        match result {
            Err(error @ RaftError::NotLeader { .. }) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(error);
                }
                sleep(Duration::from_millis(20).min(remaining)).await;
                if Instant::now() >= deadline {
                    return Err(error);
                }
            }
            result => return result,
        }
    }
}

#[cfg(all(test, feature = "grpc", has_protos))]
mod tests {
    use super::retry_leader_refusals;
    use crate::raft::{Command, FullStateMachine, RaftError, StateMachine};
    use crate::storage::RedbStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::time::Instant;

    fn state(directory: &std::path::Path) -> Arc<Mutex<FullStateMachine>> {
        let store = RedbStore::open(directory.join("state.redb")).unwrap();
        Arc::new(Mutex::new(FullStateMachine::new(&store).unwrap()))
    }

    fn increment(state: &Mutex<FullStateMachine>) {
        let mut state = state.lock().unwrap();
        let index = state.last_applied_index() + 1;
        state
            .apply(
                index,
                &Command::AdjustCounter {
                    key: "/references".into(),
                    delta: 1,
                },
            )
            .unwrap();
    }

    fn count(state: &Mutex<FullStateMachine>) -> i64 {
        let bytes = state
            .lock()
            .unwrap()
            .get_metadata("/references")
            .unwrap()
            .unwrap();
        i64::from_be_bytes(bytes.try_into().unwrap())
    }

    #[tokio::test]
    async fn a_definite_refusal_can_retry_without_duplicating_a_counter() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path());
        let attempts = AtomicUsize::new(0);
        retry_leader_refusals(Instant::now() + Duration::from_secs(5), || async {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(RaftError::NotLeader { leader_hint: None });
            }
            increment(&state);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(count(&state), 1);
    }

    #[tokio::test]
    async fn a_lost_reply_after_applying_a_counter_never_replays_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path());
        let attempts = AtomicUsize::new(0);
        let result: super::super::Result<()> =
            retry_leader_refusals(Instant::now() + Duration::from_secs(5), || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                increment(&state);
                Err(RaftError::Transport("reply lost after commit".into()))
            })
            .await;
        assert!(result.unwrap_err().proposal_outcome_unknown());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(count(&state), 1);
    }

    #[tokio::test]
    async fn exhausted_refusals_keep_their_definite_outcome() {
        let result: super::super::Result<()> =
            retry_leader_refusals(Instant::now() + Duration::from_millis(1), || async {
                Err(RaftError::NotLeader { leader_hint: None })
            })
            .await;
        let error = result.unwrap_err();
        assert!(matches!(error, RaftError::NotLeader { .. }));
        assert!(!error.proposal_outcome_unknown());
    }

    #[tokio::test]
    async fn a_submitted_attempt_keeps_the_shared_deadline_without_replay() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path());
        let attempts = AtomicUsize::new(0);
        let result: super::super::Result<()> =
            retry_leader_refusals(Instant::now() + Duration::from_millis(20), || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                increment(&state);
                std::future::pending().await
            })
            .await;
        assert!(matches!(result, Err(RaftError::Timeout(_))));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(count(&state), 1);
    }
}
