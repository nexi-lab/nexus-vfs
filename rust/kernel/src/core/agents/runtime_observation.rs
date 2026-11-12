//! Read-through engine facts and bounded external observations on one PCB.

use super::{AgentError, AgentInstance, AgentKind, AgentRegistry, AgentState};
use contracts::runtime_status::{
    RuntimeAvailability, RuntimeInventory, RuntimeInventoryScope, RuntimeObservation,
    RuntimePresence, RuntimeStatusUpdate,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use contracts::runtime_status::RuntimeStatusSource;
use contracts::runtime_status::{RuntimeDirectory, RuntimeInstanceId, RuntimeObservationHost};

/// Installed at the concrete host boundary, never a raw-registry syscall escape.
pub type RuntimeDirectoryLookup =
    Arc<dyn Fn(&str, &str) -> Result<RuntimeDirectory, String> + Send + Sync>;

pub struct RuntimeRegistryHost {
    registry: Arc<AgentRegistry>,
    instance: AgentInstance,
    owner: String,
    zone: String,
    lookup: Option<RuntimeDirectoryLookup>,
}

impl std::fmt::Debug for RuntimeRegistryHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeRegistryHost")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl RuntimeRegistryHost {
    pub fn new(
        registry: Arc<AgentRegistry>,
        instance: AgentInstance,
        lookup: Option<RuntimeDirectoryLookup>,
    ) -> Option<Self> {
        let descriptor = registry.get_instance_descriptor(&instance)?;
        Some(Self {
            registry,
            instance,
            owner: descriptor.owner_id,
            zone: descriptor.zone_id,
            lookup,
        })
    }
}

struct ObservationBinding {
    registry: Arc<AgentRegistry>,
    instance: AgentInstance,
    source: RuntimeStatusSource,
}

impl Drop for ObservationBinding {
    fn drop(&mut self) {
        self.registry
            .unbind_runtime_status(&self.instance, &self.source);
    }
}

impl RuntimeObservationHost for RuntimeRegistryHost {
    fn bind(&self, source: RuntimeStatusSource) -> Option<Box<dyn Send>> {
        self.registry
            .bind_runtime_status(&self.instance, Arc::clone(&source))
            .then(|| {
                Box::new(ObservationBinding {
                    registry: Arc::clone(&self.registry),
                    instance: self.instance.clone(),
                    source,
                }) as Box<dyn Send>
            })
    }

    fn instance(&self) -> Option<RuntimeInstanceId> {
        self.registry.runtime_instance_id(&self.instance)
    }

    fn discover(&self) -> Result<RuntimeDirectory, String> {
        self.instance().ok_or("runtime host retired")?;
        match &self.lookup {
            Some(lookup) => lookup(&self.owner, &self.zone),
            None => Ok(RuntimeDirectory {
                version: 1,
                inventories: vec![self
                    .registry
                    .runtime_inventory(Some(&self.owner), &self.zone)],
                unavailable: Vec::new(),
            }),
        }
    }
}

#[derive(Clone)]
pub(super) enum RuntimeObservationSource {
    Live(RuntimeStatusSource),
    External {
        update: RuntimeStatusUpdate,
        received: Instant,
    },
}

// Unknown after a missed publisher interval. Expiry never proves remote exit.
const EXTERNAL_FRESHNESS: Duration = Duration::from_secs(3);

fn age_millis(age: Duration) -> u64 {
    u64::try_from(age.as_millis()).unwrap_or(u64::MAX)
}

impl AgentRegistry {
    /// Retry only this authenticated admission intent. A caller cannot adopt
    /// another registration merely because it now owns the same logical PID.
    pub fn register_runtime_instance(
        &self,
        request: &contracts::runtime_status::RegisterRuntimeRequest,
        owner: &str,
        zone: &str,
    ) -> Result<AgentInstance, AgentError> {
        match self.spawn_with_instance(
            request.name.clone(),
            owner.into(),
            zone.into(),
            AgentKind::Unmanaged,
            None,
            Some(request.connection_id.clone()),
            "/".into(),
            Some(super::ExternalProcessInfo {
                connection_id: request.connection_id.clone(),
                remote_addr: None,
                protocol: "runtime-status/1".into(),
                last_heartbeat_ms: Some(super::now_ms()),
            }),
            std::collections::HashMap::new(),
            true,
            Some(request.registration_id.clone()),
        ) {
            Ok((instance, _)) => Ok(instance),
            Err(AgentError::AlreadyExists(_)) => {
                let entry = self
                    .agents
                    .get(&request.connection_id)
                    .ok_or_else(|| AgentError::NotFound(request.connection_id.clone()))?;
                if entry.removing
                    || entry.state.is_terminal()
                    || entry.kind != AgentKind::Unmanaged
                    || entry.name != request.name
                    || entry.owner_id != owner
                    || entry.zone_id != zone
                    || entry.runtime_registration.as_deref()
                        != Some(request.registration_id.as_str())
                {
                    return Err(AgentError::Protocol(
                        "runtime admission intent does not match".into(),
                    ));
                }
                Ok(entry.instance())
            }
            Err(error) => Err(error),
        }
    }

    /// Bind a read-through source only to the captured live incarnation.
    pub fn bind_runtime_status(
        &self,
        instance: &AgentInstance,
        source: RuntimeStatusSource,
    ) -> bool {
        let Some(mut entry) = self.agents.get_mut(&instance.pid) else {
            return false;
        };
        if entry.removing
            || !entry.matches(instance)
            || entry.state.is_terminal()
            || entry.runtime.is_some()
        {
            return false;
        }
        entry.runtime = Some(RuntimeObservationSource::Live(source));
        true
    }

    /// Drop this source without touching a managed host's process lifecycle.
    pub fn unbind_runtime_status(
        &self,
        instance: &AgentInstance,
        source: &RuntimeStatusSource,
    ) -> bool {
        let Some(mut entry) = self.agents.get_mut(&instance.pid) else {
            return false;
        };
        if entry.removing
            || !entry.matches(instance)
            || !matches!(&entry.runtime, Some(RuntimeObservationSource::Live(current)) if Arc::ptr_eq(current, source))
        {
            return false;
        }
        entry.runtime = None;
        true
    }

    /// Publish one newer external observation without replacing a live source.
    /// An identical replay is acknowledged but cannot refresh its freshness.
    pub fn publish_runtime_status(
        &self,
        instance: &AgentInstance,
        update: RuntimeStatusUpdate,
    ) -> Result<bool, AgentError> {
        let Some(mut entry) = self.agents.get_mut(&instance.pid) else {
            return Ok(false);
        };
        if entry.removing || !entry.matches(instance) {
            return Ok(false);
        }
        if entry.kind != AgentKind::Unmanaged || update.revision == 0 {
            return Err(AgentError::Protocol(
                "runtime publication requires an external instance and a positive revision".into(),
            ));
        }
        match &entry.runtime {
            Some(RuntimeObservationSource::Live(_)) => {
                return Err(AgentError::Protocol(
                    "runtime has a live engine source".into(),
                ));
            }
            Some(RuntimeObservationSource::External {
                update: previous, ..
            }) => {
                if update.revision == previous.revision && update == *previous {
                    return Ok(true);
                }
                if update.revision <= previous.revision {
                    return Err(AgentError::Protocol(
                        "runtime revision did not advance".into(),
                    ));
                }
            }
            None => {}
        }
        // A snapshot can coalesce intermediate lifecycle events. Preserve the
        // same transition validation while reaching its observed final state.
        if entry.state == AgentState::Registered {
            entry.change_state(AgentState::WarmingUp, None)?;
        }
        if entry.state == AgentState::WarmingUp {
            entry.change_state(AgentState::Ready, None)?;
        }
        let (state, reason) = AgentState::project_foreground(update.status.foreground);
        if entry.state == AgentState::Ready && state == AgentState::AwaitingInput {
            entry.change_state(AgentState::Busy, None)?;
        }
        entry.change_state(state, reason)?;
        let now = super::now_ms();
        entry.last_heartbeat_ms = Some(now);
        if let Some(info) = entry.external_info.as_mut() {
            info.last_heartbeat_ms = Some(now);
        }
        let received = Instant::now();
        entry.runtime = Some(RuntimeObservationSource::External { update, received });
        entry.runtime_last_seen = Some(received);
        drop(entry);
        self.finish_state_change(instance, false);
        Ok(true)
    }

    /// Query outside registry locks, then recheck the exact incarnation.
    pub fn runtime_observation(&self, instance: &AgentInstance) -> Option<RuntimeObservation> {
        self.runtime_observation_with_clock(instance, Instant::now)
    }

    fn runtime_observation_with_clock(
        &self,
        instance: &AgentInstance,
        now: impl FnOnce() -> Instant,
    ) -> Option<RuntimeObservation> {
        let (name, source, last_seen) = {
            let entry = self.agents.get(&instance.pid)?;
            if entry.removing || !entry.matches(instance) || entry.state == AgentState::Terminated {
                return None;
            }
            (
                entry.name.clone(),
                entry.runtime.clone(),
                entry.runtime_last_seen,
            )
        };
        let live_facts = match &source {
            Some(RuntimeObservationSource::Live(read)) => read(),
            _ => None,
        };
        let observed_at = now();
        let (mut availability, mut age, mut update) = match &source {
            Some(RuntimeObservationSource::Live(_)) => match live_facts {
                Some(facts) => (
                    RuntimeAvailability::Fresh,
                    Some(Duration::ZERO),
                    Some(RuntimeStatusUpdate::from_facts(0, facts)),
                ),
                None => (RuntimeAvailability::Unavailable, None, None),
            },
            Some(RuntimeObservationSource::External { update, received }) => {
                let age = observed_at.saturating_duration_since(*received);
                if age <= EXTERNAL_FRESHNESS {
                    (RuntimeAvailability::Fresh, Some(age), Some(update.clone()))
                } else {
                    (RuntimeAvailability::Stale, Some(age), None)
                }
            }
            None => (RuntimeAvailability::Unsupported, None, None),
        };
        let id = {
            let mut entry = self.agents.get_mut(&instance.pid)?;
            if entry.removing || !entry.matches(instance) || entry.state.is_terminal() {
                return None;
            }
            let source_changed = match (&source, &entry.runtime) {
                (
                    Some(RuntimeObservationSource::Live(previous)),
                    Some(RuntimeObservationSource::Live(current)),
                ) => !Arc::ptr_eq(previous, current),
                (Some(RuntimeObservationSource::Live(_)), _) => true,
                _ => false,
            };
            if source_changed {
                // Rebinding can replace the SID reader while preserving the
                // host instance. Never pair retired identity with new facts.
                availability = RuntimeAvailability::Unavailable;
                age = None;
                update = None;
            } else if matches!(&source, Some(RuntimeObservationSource::Live(_))) {
                if let Some(frame) = update.as_mut() {
                    // Keep ordering on this registration: a model/SID reader
                    // rebind must not reset the instance's observation clock.
                    if let Some(revision) = entry.runtime_revision.checked_add(1) {
                        entry.runtime_revision = revision;
                        frame.revision = revision;
                    } else {
                        availability = RuntimeAvailability::Unavailable;
                        age = None;
                        update = None;
                    }
                }
            }
            self.runtime_instance_key(instance)
        };
        let heartbeat_age = last_seen.map(|seen| observed_at.saturating_duration_since(seen));
        let last_seen_age = match (
            heartbeat_age,
            age.filter(|_| availability == RuntimeAvailability::Fresh),
        ) {
            (Some(heartbeat), Some(observation)) => Some(heartbeat.min(observation)),
            (heartbeat, observation) => heartbeat.or(observation),
        };
        let presence = if last_seen_age.is_some_and(|age| age <= EXTERNAL_FRESHNESS) {
            RuntimePresence::Online
        } else {
            RuntimePresence::Unknown
        };
        Some(RuntimeObservation {
            instance: id,
            agent_id: name,
            presence,
            last_seen_age_ms: last_seen_age.map(age_millis),
            availability,
            age_ms: age.map(age_millis),
            update,
        })
    }

    /// Enumerate the authorized scope without collapsing instances by Agent or SID.
    /// All hosts share this read path; callbacks run outside registry guards.
    pub fn runtime_inventory(&self, owner: Option<&str>, zone: &str) -> RuntimeInventory {
        let instances: Vec<_> = self
            .agents
            .iter()
            .filter_map(|entry| {
                (!entry.removing
                    && entry.zone_id == zone
                    && owner.is_none_or(|owner| owner == entry.owner_id))
                .then(|| entry.instance())
            })
            .collect();
        let mut observations: Vec<_> = instances
            .iter()
            .filter_map(|instance| self.runtime_observation(instance))
            .collect();
        observations.sort_by(|left, right| {
            left.agent_id
                .cmp(&right.agent_id)
                .then_with(|| left.instance.pid.cmp(&right.instance.pid))
        });
        RuntimeInventory {
            version: 1,
            scope: RuntimeInventoryScope {
                registry_id: self.runtime_scope_id().into(),
                owner_id: owner.map(str::to_owned),
                zone_id: zone.into(),
                complete: true,
            },
            instances: observations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contracts::runtime_status::{
        BackgroundTaskSummary, ForegroundState, RegisterRuntimeRequest, RuntimeIdentity,
        RuntimeStatus,
    };

    fn external_runtime() -> (AgentRegistry, AgentInstance, RuntimeStatusUpdate) {
        let registry = AgentRegistry::new();
        let instance = registry
            .register_runtime_instance(
                &RegisterRuntimeRequest {
                    name: "agent-a".into(),
                    connection_id: "connection-a".into(),
                    registration_id: "registration-a".into(),
                    owner_id: None,
                    zone_id: None,
                },
                "alice",
                "alpha",
            )
            .unwrap();
        let update = RuntimeStatusUpdate {
            revision: 1,
            identity: RuntimeIdentity {
                session_id: Some("session-a".into()),
                os_pid: Some(std::process::id()),
            },
            status: RuntimeStatus {
                foreground: ForegroundState::Running,
                background: BackgroundTaskSummary {
                    terminals: 0,
                    agents: 0,
                    execution_unconfirmed: 0,
                    tool_operations: 0,
                },
            },
        };
        assert!(registry
            .publish_runtime_status(&instance, update.clone())
            .unwrap());
        (registry, instance, update)
    }

    #[test]
    fn external_observation_and_presence_share_the_exact_expiry_boundary() {
        let (registry, instance, update) = external_runtime();
        let received = {
            let entry = registry.agents.get(&instance.pid).unwrap();
            let Some(RuntimeObservationSource::External { received, .. }) = &entry.runtime else {
                panic!("external publication required");
            };
            assert_eq!(entry.runtime_last_seen, Some(*received));
            *received
        };
        for (age, availability, presence) in [
            (
                EXTERNAL_FRESHNESS - Duration::from_nanos(1),
                RuntimeAvailability::Fresh,
                RuntimePresence::Online,
            ),
            (
                EXTERNAL_FRESHNESS,
                RuntimeAvailability::Fresh,
                RuntimePresence::Online,
            ),
            (
                EXTERNAL_FRESHNESS + Duration::from_nanos(1),
                RuntimeAvailability::Stale,
                RuntimePresence::Unknown,
            ),
        ] {
            let observation = registry
                .runtime_observation_with_clock(&instance, || received + age)
                .unwrap();
            assert_eq!(observation.availability, availability);
            assert_eq!(observation.presence, presence);
            assert_eq!(observation.age_ms, Some(age_millis(age)));
            assert_eq!(observation.last_seen_age_ms, observation.age_ms);
            assert_eq!(
                observation.update.is_some(),
                availability == RuntimeAvailability::Fresh
            );
        }
        assert!(registry.publish_runtime_status(&instance, update).unwrap());
        let replay = registry
            .runtime_observation_with_clock(&instance, || {
                received + EXTERNAL_FRESHNESS + Duration::from_nanos(1)
            })
            .unwrap();
        assert_eq!(replay.availability, RuntimeAvailability::Stale);
        assert_eq!(replay.presence, RuntimePresence::Unknown);
        assert!(replay.update.is_none());
    }

    #[test]
    fn heartbeat_refreshes_presence_without_refreshing_external_work() {
        let (registry, instance, update) = external_runtime();
        let old = Instant::now() - EXTERNAL_FRESHNESS * 2;
        {
            let mut entry = registry.agents.get_mut(&instance.pid).unwrap();
            let Some(RuntimeObservationSource::External { received, .. }) = &mut entry.runtime
            else {
                panic!("external publication required");
            };
            *received = old;
            entry.runtime_last_seen = Some(old);
        }
        let stale = registry.runtime_observation(&instance).unwrap();
        assert_eq!(stale.availability, RuntimeAvailability::Stale);
        assert_eq!(stale.presence, RuntimePresence::Unknown);
        assert!(registry.heartbeat_instance(&instance).unwrap().is_some());
        let heartbeat = registry
            .agents
            .get(&instance.pid)
            .unwrap()
            .runtime_last_seen
            .unwrap();
        let online = registry
            .runtime_observation_with_clock(&instance, || heartbeat)
            .unwrap();
        assert_eq!(online.availability, RuntimeAvailability::Stale);
        assert_eq!(online.presence, RuntimePresence::Online);
        assert_eq!(online.last_seen_age_ms, Some(0));
        assert!(online.update.is_none());
        assert!(registry.publish_runtime_status(&instance, update).unwrap());
        let replay = registry
            .runtime_observation_with_clock(&instance, || heartbeat)
            .unwrap();
        assert_eq!(replay, online);
    }

    #[test]
    fn observation_time_follows_the_live_reader() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (registry, instance, _) = external_runtime();
        let last_seen = {
            let mut entry = registry.agents.get_mut(&instance.pid).unwrap();
            entry.runtime = None;
            entry.runtime_last_seen.unwrap()
        };
        let returned = Arc::new(AtomicBool::new(false));
        let reader_returned = Arc::clone(&returned);
        let reader: RuntimeStatusSource = Arc::new(move || {
            reader_returned.store(true, Ordering::SeqCst);
            None
        });
        assert!(registry.bind_runtime_status(&instance, reader));
        let observation = registry
            .runtime_observation_with_clock(&instance, || {
                assert!(returned.load(Ordering::SeqCst));
                last_seen + EXTERNAL_FRESHNESS + Duration::from_nanos(1)
            })
            .unwrap();
        assert_eq!(observation.availability, RuntimeAvailability::Unavailable);
        assert_eq!(observation.presence, RuntimePresence::Unknown);
        assert!(observation.update.is_none());
    }
}
