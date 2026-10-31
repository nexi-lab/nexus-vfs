//! Operator-only entry. It cannot start a Nexus daemon.
fn main() -> anyhow::Result<()> {
    nexus_cluster::operator_enrollment::main()
}
