//! The member-address record: the one place that builds, decodes and
//! interprets the control-store entry mapping a zone member's Raft node id to
//! its dial address. See `docs/member-address.md`.
//!
//! Key = the member's node id in decimal. Value = its bare advertise
//! authority (`host:port`) in the operator-address parser's canonical form.
//! The `http`/`https` scheme is never stored: each reader derives its dial
//! endpoint from its own TLS posture.

use super::Command;

pub(crate) use contracts::constants::CONTROL_NS_MEMBER_ADDRESS as NAMESPACE;

/// The record key for `node_id`.
#[cfg(feature = "consensus")]
pub(crate) fn key(node_id: u64) -> String {
    node_id.to_string()
}

/// Decode one stored record. Only a canonical non-zero decimal key and a UTF-8
/// value form a record.
pub(crate) fn decode(key: &str, value: &[u8]) -> Option<(u64, String)> {
    let node_id: u64 = key.parse().ok()?;
    if node_id == 0 || node_id.to_string() != key {
        return None;
    }
    let address = std::str::from_utf8(value).ok()?;
    Some((node_id, address.to_string()))
}

/// The canonical bare `host:port` form of `address` (a scheme prefix is
/// accepted and dropped), or `None` when it is not a dial address. A build
/// without the network transport has no dial addresses.
#[cfg(feature = "consensus")]
pub(crate) fn canonical(address: &str) -> Option<String> {
    #[cfg(feature = "grpc")]
    {
        lib::transport_primitives::PeerAddress::parse_operator_addr(address, false)
            .ok()
            .map(|parsed| parsed.to_operator_str())
    }
    #[cfg(not(feature = "grpc"))]
    {
        let _ = address;
        None
    }
}

/// Record `address` for `node_id`, or `None` when `address` is not a dial
/// address.
#[cfg(feature = "consensus")]
pub(crate) fn put(node_id: u64, address: &str) -> Option<Command> {
    Some(Command::PutControlState {
        namespace: NAMESPACE.to_string(),
        key: key(node_id),
        value: canonical(address)?.into_bytes(),
        if_absent: false,
    })
}

/// Remove `node_id`'s record.
#[cfg(feature = "consensus")]
pub(crate) fn delete(node_id: u64) -> Command {
    Command::DeleteControlState {
        namespace: NAMESPACE.to_string(),
        key: key(node_id),
    }
}

/// Whether `command` writes a member-address record. Such a command changes
/// state only as a committed Raft entry: the consistency classifier refuses it
/// on the EC and local write paths, and an applied batch that contains one
/// refreshes the derived peer map.
pub(crate) fn is_record_command(command: &Command) -> bool {
    matches!(
        command,
        Command::PutControlState { namespace, .. } | Command::DeleteControlState { namespace, .. }
            if namespace == NAMESPACE
    )
}

/// The dial endpoint for a recorded `address`, schemed by the reading node's
/// TLS posture.
#[cfg(feature = "grpc")]
pub(crate) fn endpoint(
    node_id: u64,
    address: &str,
    use_tls: bool,
) -> Option<lib::transport_primitives::NodeAddress> {
    let mut parsed =
        lib::transport_primitives::PeerAddress::parse_operator_addr(address, use_tls).ok()?;
    parsed.id = node_id;
    Some(parsed)
}

#[cfg(all(test, feature = "grpc"))]
mod tests {
    use super::*;

    #[test]
    fn put_stores_the_canonical_bare_authority() {
        for given in [
            "10.0.0.2:2126",
            "http://10.0.0.2:2126",
            "https://10.0.0.2:2126",
        ] {
            let Some(Command::PutControlState {
                namespace,
                key,
                value,
                if_absent,
            }) = put(42, given)
            else {
                panic!("{given} is a dial address");
            };
            assert_eq!(namespace, NAMESPACE);
            assert_eq!(key, "42");
            assert_eq!(value, b"10.0.0.2:2126");
            assert!(
                !if_absent,
                "a member's address is replaced, never CAS-gated"
            );
        }
        assert_eq!(canonical("[::1]:2126").as_deref(), Some("[::1]:2126"));
    }

    #[test]
    fn put_refuses_what_is_not_a_dial_address() {
        for given in [
            "",
            "nexus-2",
            "nexus-2:0",
            "7@nexus-2:2126",
            "::1:2126",
            "\u{0}",
        ] {
            assert!(
                put(42, given).is_none(),
                "{given:?} must not become a record"
            );
        }
    }

    #[test]
    fn decode_accepts_only_canonical_keys() {
        assert_eq!(
            decode("42", b"nexus-2:2126"),
            Some((42, "nexus-2:2126".to_string()))
        );
        for key in ["0", "042", "+42", "-1", "x", "", "18446744073709551616"] {
            assert_eq!(decode(key, b"nexus-2:2126"), None, "{key:?}");
        }
        assert_eq!(decode("42", &[0xff, 0xfe]), None);
    }

    #[test]
    fn records_round_trip_through_the_command_pair() {
        let Some(Command::PutControlState { key, value, .. }) = put(7, "nexus-7:9000") else {
            unreachable!()
        };
        assert_eq!(decode(&key, &value), Some((7, "nexus-7:9000".to_string())));
        assert!(is_record_command(&put(7, "nexus-7:9000").unwrap()));
        assert!(is_record_command(&delete(7)));
        assert!(!is_record_command(&Command::PutControlState {
            namespace: contracts::CONTROL_NS_AUTH.into(),
            key: "7".into(),
            value: b"nexus-7:9000".to_vec(),
            if_absent: false,
        }));
        assert!(!is_record_command(&Command::Noop));
    }

    fn state_machine() -> crate::raft::FullStateMachine {
        let store = crate::storage::RedbStore::open_temporary().unwrap();
        crate::raft::FullStateMachine::new(&store).unwrap()
    }

    #[test]
    fn committed_puts_and_deletes_are_the_records_and_survive_a_snapshot() {
        use crate::raft::StateMachine;
        let mut sm = state_machine();
        sm.apply(1, &put(7, "nexus-7:9000").unwrap()).unwrap();
        sm.apply(2, &put(8, "nexus-8:9000").unwrap()).unwrap();
        sm.apply(3, &put(7, "nexus-7:9100").unwrap()).unwrap();
        sm.apply(4, &delete(8)).unwrap();
        // A record in another namespace is not a member address.
        sm.apply(
            5,
            &Command::PutControlState {
                namespace: contracts::CONTROL_NS_AUTH.into(),
                key: "9".into(),
                value: b"nexus-9:9000".to_vec(),
                if_absent: false,
            },
        )
        .unwrap();
        assert_eq!(
            sm.member_addresses().unwrap(),
            vec![(7, "nexus-7:9100".to_string())]
        );

        let snapshot = sm.snapshot().unwrap();
        let mut restored = state_machine();
        restored.apply(1, &put(99, "stale:1").unwrap()).unwrap();
        restored.restore_snapshot(&snapshot).unwrap();
        assert_eq!(
            restored.member_addresses().unwrap(),
            vec![(7, "nexus-7:9100".to_string())],
            "a snapshot install replaces the records with the snapshot's cut"
        );
        assert_eq!(restored.last_applied_index(), 5);
    }

    #[test]
    fn records_change_only_through_committed_entries() {
        use crate::raft::StateMachine;
        let mut sm = state_machine();
        for command in [put(7, "nexus-7:9000").unwrap(), delete(7)] {
            assert!(sm.requires_strong_consistency(&command).unwrap());
            assert!(sm.apply_local(&command).is_err(), "EC origin refuses it");
            assert!(matches!(
                sm.apply_ec_with_lww(&command, u64::MAX),
                Ok(crate::raft::CommandResult::Success)
            ));
        }
        assert!(
            sm.member_addresses().unwrap().is_empty(),
            "neither the local nor the peer EC path wrote a record"
        );
        let witness = crate::raft::WitnessStateMachineInMemory::new();
        assert!(witness
            .requires_strong_consistency(&put(7, "nexus-7:9000").unwrap())
            .unwrap());
        assert!(witness.member_addresses().unwrap().is_empty());
    }

    #[test]
    fn a_membership_entry_commits_its_records_with_its_index() {
        use crate::raft::StateMachine;
        let mut sm = state_machine();
        sm.apply_membership(
            3,
            &[
                put(7, "nexus-7:9000").unwrap(),
                put(8, "nexus-8:9000").unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(sm.last_applied_index(), 3);
        assert_eq!(sm.member_addresses().unwrap().len(), 2);
        // A replayed entry at or below the marker writes nothing.
        sm.apply_membership(3, &[delete(7)]).unwrap();
        assert_eq!(sm.member_addresses().unwrap().len(), 2);
        sm.apply_membership(4, &[delete(7)]).unwrap();
        assert_eq!(
            sm.member_addresses().unwrap(),
            vec![(8, "nexus-8:9000".to_string())]
        );
        // An entry with no address effect advances only the marker.
        sm.apply_membership(5, &[]).unwrap();
        assert_eq!(sm.last_applied_index(), 5);
        assert_eq!(sm.member_addresses().unwrap().len(), 1);
    }

    #[test]
    fn endpoint_follows_the_reading_nodes_tls_posture() {
        let plain = endpoint(7, "nexus-7:9000", false).unwrap();
        assert_eq!(
            (plain.id, plain.endpoint.as_str()),
            (7, "http://nexus-7:9000")
        );
        let tls = endpoint(7, "nexus-7:9000", true).unwrap();
        assert_eq!((tls.id, tls.endpoint.as_str()), (7, "https://nexus-7:9000"));
        assert_eq!(tls.to_operator_str(), "nexus-7:9000");
        assert!(endpoint(7, "nexus-7", true).is_none());
    }
}
