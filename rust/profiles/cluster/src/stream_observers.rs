//! Apply-side stream notifications shared by cluster and confined runtimes.

use std::sync::Arc;

use kernel::kernel::Kernel;
use nexus_raft::prelude::{FullStateMachine, ZoneConsensus};
use nexus_raft::ZoneManager;

type ZoneInstaller = Arc<dyn Fn(&str, &ZoneConsensus<FullStateMachine>) + Send + Sync>;

/// Arm stream notifications for resident and future zones. The observer uses
/// keyed registration and retains only a weak Kernel reference.
pub fn install_wakeup(kernel: &Arc<Kernel>, zones: &Arc<ZoneManager>) {
    let kernel = Arc::downgrade(kernel);
    for_each_zone(
        zones,
        Arc::new(move |zone_id, consensus| {
            nexus_raft::stream_wakeup::install_stream_wakeup_observer(
                consensus,
                kernel.clone(),
                zone_id,
            );
        }),
    );
}

/// Retention remains a separate cluster service. Its work runs outside apply.
pub(super) fn install_retention_gc(kernel: &Arc<Kernel>, zones: &Arc<ZoneManager>) {
    let kernel = Arc::downgrade(kernel);
    let runtime = zones.runtime_handle();
    for_each_zone(
        zones,
        Arc::new(move |zone_id, consensus| {
            nexus_raft::stream_retention_gc::install_stream_trim_gc_observer(
                consensus,
                kernel.clone(),
                zone_id,
                runtime.clone(),
            );
        }),
    );
}

fn for_each_zone(zones: &Arc<ZoneManager>, arm: ZoneInstaller) {
    let arm_for_hook = arm.clone();
    zones
        .registry()
        .add_on_materialized(Arc::new(move |zone_id, consensus| {
            arm_for_hook(zone_id, consensus)
        }));
    // Register first, then cover resident zones without opening the catalog.
    for zone_id in zones.registry().resident_zones() {
        if let Some(zone) = zones.get_zone(&zone_id) {
            arm(&zone_id, &zone.consensus_node());
        }
    }
}
