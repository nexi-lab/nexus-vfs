//! Build script for nexus_raft.
//!
//! This script compiles protobuf files from the project-root proto/ directory.
//! All proto files are centralized there for SSOT (Single Source of Truth).
//!
//! Proto structure:
//!   proto/nexus/core/metadata.proto  - FileMetadata (shared with Python)
//!   proto/nexus/raft/transport.proto - Raft gRPC service
//!   proto/nexus/raft/commands.proto  - Raft state machine commands

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=CARGO_MANIFEST_DIR");
    // Only compile protos when grpc feature is enabled
    #[cfg(feature = "grpc")]
    {
        // Point tonic_prost_build (via prost-build) at the vendored protoc binary so
        // the crate builds without a system-wide protobuf-compiler. Respect
        // an externally-set PROTOC if the caller already chose one.
        if std::env::var_os("PROTOC").is_none() {
            std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        }

        // Proto files are in project root's proto/ directory (SSOT)
        // A shared target directory can outlive the worktree that generated
        // its previous output. Watch absolute inputs from this invocation's
        // manifest, not relative paths interpreted against an older root.
        let manifest = std::path::PathBuf::from(
            std::env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest directory")?,
        );
        let proto_root = manifest
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("raft manifest is not below the repository root")?
            .join("proto");
        let core_proto = proto_root.join("nexus/core/metadata.proto");

        // Skip proto compilation if proto files don't exist yet (Issue #1159)
        if !core_proto.exists() {
            println!(
                "cargo:warning=Proto files not found at {}, \
                 skipping gRPC codegen. See Issue #1159.",
                proto_root.display()
            );
            // Create empty stub files so include!() in transport/mod.rs won't fail
            let out_dir = std::env::var("OUT_DIR")?;
            let stub = "// Proto stub (Issue #1159)\n";
            std::fs::write(format!("{out_dir}/nexus.core.rs"), stub)?;
            std::fs::write(format!("{out_dir}/nexus.raft.rs"), stub)?;
            // Do NOT set has_protos cfg - transport client/server won't compile
            return Ok(());
        }

        // Signal that proto codegen succeeded - enables full transport module
        println!("cargo:rustc-cfg=has_protos");

        // First compile core/metadata.proto separately
        let core_protos = &[core_proto];
        let includes = std::slice::from_ref(&proto_root);

        tonic_prost_build::configure()
            .build_server(false)
            .build_client(false)
            .out_dir(std::env::var("OUT_DIR")?)
            .compile_protos(core_protos, includes)?;

        // Then compile raft protos, mapping nexus.core to the generated module
        let raft_protos = &[
            proto_root.join("nexus/raft/transport.proto"),
            proto_root.join("nexus/raft/commands.proto"),
        ];

        tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            // Map nexus.core.FileMetadata to our generated core module
            .extern_path(".nexus.core", "crate::transport::proto::nexus::core")
            .out_dir(std::env::var("OUT_DIR")?)
            .compile_protos(raft_protos, includes)?;

        let out_dir = std::path::PathBuf::from(
            std::env::var_os("OUT_DIR").ok_or("missing output directory")?,
        );
        for (source, snapshot) in [
            ("nexus/raft/transport.proto", "raft-transport.source.proto"),
            ("nexus/raft/commands.proto", "raft-commands.source.proto"),
            ("nexus/core/metadata.proto", "raft-metadata.source.proto"),
        ] {
            let source = proto_root.join(source).canonicalize()?;
            println!("cargo:rerun-if-changed={}", source.display());
            std::fs::copy(source, out_dir.join(snapshot))?;
        }
    }

    Ok(())
}
