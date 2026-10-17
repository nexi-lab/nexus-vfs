//! Vectored metadata must agree with point stat across sibling and nested mounts.

mod common;

use std::sync::Arc;

use kernel::abc::meta_store::MetaStore;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::{Kernel, StatResult};
use kernel::meta_store::LocalMetaStore;

fn projection(stat: Option<StatResult>) -> Option<(String, u64, bool, Option<String>)> {
    stat.map(|stat| (stat.path, stat.size, stat.is_directory, stat.content_id))
}

#[test]
fn mixed_mounts_preserve_positions_duplicates_missing_paths_and_metadata_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let kernel = Kernel::new();
    common::mount_mem_root(&kernel);
    let ctx = common::admin_ctx();
    let mut stores = Vec::new();
    for (index, mount) in ["/a", "/b", "/a/nested"].into_iter().enumerate() {
        let store =
            Arc::new(LocalMetaStore::open(&temp.path().join(format!("{index}.redb"))).unwrap());
        kernel
            .mount(
                mount,
                MountOptions::new("mem")
                    .with_backend(Arc::new(common::MemBackend::default()))
                    .with_metastore(store.clone()),
            )
            .unwrap();
        KernelConvenience::write(
            &kernel,
            &format!("{mount}/file & 测试.txt"),
            &ctx,
            &vec![index as u8; index + 1],
            0,
        )
        .unwrap();
        stores.push(store);
    }
    // A stale row in a sibling store must never supply another mount's facts.
    let foreign = "/b/file & 测试.txt";
    let mut decoy = stores[1].get(foreign).unwrap().unwrap();
    decoy.size = 999;
    stores[0].put(foreign, decoy).unwrap();
    for paths in [
        vec![
            "/a/file & 测试.txt",
            foreign,
            "/b/missing",
            "/a/nested/file & 测试.txt",
            foreign,
            "/a",
            "/b",
        ],
        vec![foreign, "/a/nested/file & 测试.txt", "/a/file & 测试.txt"],
        vec!["/a/file & 测试.txt", "/a/missing", "/a/file & 测试.txt"],
        Vec::new(),
    ] {
        let paths: Vec<String> = paths.into_iter().map(str::to_owned).collect();
        let expected: Vec<_> = paths
            .iter()
            .map(|path| projection(kernel.sys_stat(path, "root")))
            .collect();
        let actual: Vec<_> = kernel
            .stat_batch(&paths, "root")
            .into_iter()
            .map(projection)
            .collect();
        assert_eq!(actual, expected, "{paths:?}");
    }
}
