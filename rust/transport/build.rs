// Only wire messages: the host enforces access without linking the search engine.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../proto/nexus/search/v1/search.proto";
    println!("cargo:rerun-if-changed={proto}");
    if std::env::var_os("PROTOC").is_none() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&[proto], &["../proto"])?;
    Ok(())
}
