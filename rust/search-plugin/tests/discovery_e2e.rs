//! Discovery journeys through the service and the kernel C ABI.

use std::sync::Arc;

use nexus_search_plugin::index_manager::IndexManager;
use nexus_search_plugin::search_proto::search_service_server::SearchService;
use nexus_search_plugin::search_proto::{DiscoveryFiles, GlobRequest, GrepRequest};
use nexus_search_plugin::service::SearchServiceImpl;
use tempfile::TempDir;
use tonic::Request;

mod common;
use common::{handle_for, MockKernel};

struct Harness {
    kernel: Box<MockKernel>,
    service: SearchServiceImpl,
    _data: TempDir,
}

impl Harness {
    fn new(kernel: MockKernel) -> Self {
        let kernel = Box::new(kernel);
        let data = TempDir::new().unwrap();
        let service = SearchServiceImpl::builder(Arc::new(handle_for(kernel.as_ref())))
            .manager(Arc::new(IndexManager::with_root(data.path().into())))
            .build();
        Self {
            kernel,
            service,
            _data: data,
        }
    }
}

fn working_set(paths: Vec<String>) -> Option<DiscoveryFiles> {
    Some(DiscoveryFiles { paths })
}

#[tokio::test]
async fn glob_to_grep_refinement_preserves_working_set_context_and_empty_selection() {
    let mut kernel = MockKernel::new();
    kernel.add_dir("/");
    kernel.add_dir("/docs");
    kernel.add_file("/docs/a.md", b"before\nneedle one\nafter\n", 1);
    kernel.add_file("/docs/b.md", b"needle two\n", 2);
    kernel.add_file("/docs/private.md", b"needle private\n", 3);
    let harness = Harness::new(kernel);
    let before = harness.kernel.io_counts();
    let glob = harness
        .service
        .glob(Request::new(GlobRequest {
            root_path: "/docs".into(),
            pattern: "*.md".into(),
            files: working_set(vec!["/docs/a.md".into(), "/docs/b.md".into()]),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(glob.error.is_none(), "{glob:?}");
    assert_eq!(glob.paths, ["/docs/a.md", "/docs/b.md"]);
    assert_eq!(
        harness.kernel.io_counts().1,
        before.1,
        "working sets must not walk directories"
    );

    let grep = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/docs".into(),
            pattern: "needle".into(),
            files: working_set(glob.paths),
            file_pattern: "a.md".into(),
            before_context: 1,
            after_context: 1,
            max_results: 1,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(grep.error.is_none(), "{grep:?}");
    assert_eq!(grep.matches.len(), 1);
    assert_eq!(grep.matches[0].path, "/docs/a.md");
    assert_eq!(grep.matches[0].line_number, 2);
    assert_eq!(grep.matches[0].before, ["before"]);
    assert_eq!(grep.matches[0].after, ["after"]);
    assert!(
        !grep.truncated,
        "nonmatching trailing lines do not prove truncation"
    );
    assert_eq!(
        harness.kernel.io_counts().0 - before.0,
        1,
        "read only the intersected working set"
    );

    let before_empty = harness.kernel.io_counts();
    let empty = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/docs".into(),
            pattern: "needle".into(),
            files: working_set(vec![]),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(empty.matches.is_empty());
    assert!(!empty.truncated);
    assert_eq!(
        harness.kernel.io_counts(),
        before_empty,
        "empty selection must perform no VFS I/O"
    );

    let recursive = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/docs".into(),
            pattern: "needle".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        recursive.matches.len(),
        3,
        "omission still means a recursive walk"
    );
}

#[tokio::test]
async fn recency_selects_newest_files_before_capping_and_preserves_line_order() {
    let mut kernel = MockKernel::new();
    kernel.add_dir("/");
    kernel.add_file("/old.md", b"needle old\n", 1);
    kernel.add_file(
        "/latest.md",
        b"needle newest one\nneedle newest two\ntail\n",
        100,
    );
    kernel.add_file("/middle.md", b"needle middle\n", 50);
    let harness = Harness::new(kernel);
    let glob = harness
        .service
        .glob(Request::new(GlobRequest {
            root_path: "/".into(),
            pattern: "*.md".into(),
            sort_recency: true,
            max_results: 1,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(glob.paths, ["/latest.md"]);
    assert!(glob.truncated);
    let grep = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/".into(),
            pattern: "needle".into(),
            sort_recency: true,
            max_results: 2,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        grep.matches
            .iter()
            .map(|row| (row.path.as_str(), row.line_number))
            .collect::<Vec<_>>(),
        [("/latest.md", 1), ("/latest.md", 2)]
    );
    assert!(
        grep.truncated,
        "the older matching file proves another hit exists"
    );
    assert_eq!(
        harness.kernel.io_counts().0,
        2,
        "stop reading after finding the first extra hit"
    );

    let only_newest = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/".into(),
            pattern: "needle".into(),
            max_results: 2,
            files: working_set(glob.paths),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(only_newest.matches.len(), 2);
    assert!(!only_newest.truncated);
}

#[tokio::test]
async fn exact_glob_cap_ignores_unmatched_entries_and_directories() {
    let mut kernel = MockKernel::new();
    kernel.add_dir("/");
    kernel.add_file("/hit.md", b"needle\n", 1);
    kernel.add_file("/skip.txt", b"no hit\n", 2);
    kernel.add_dir("/empty");
    let harness = Harness::new(kernel);
    let result = harness
        .service
        .glob(Request::new(GlobRequest {
            root_path: "/".into(),
            pattern: "*.md".into(),
            max_results: 1,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.paths, ["/hit.md"]);
    assert!(!result.truncated);
    let result = harness
        .service
        .glob(Request::new(GlobRequest {
            root_path: "/".into(),
            pattern: "*.md".into(),
            max_results: 1,
            sort_recency: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.paths, ["/hit.md"]);
    assert!(!result.truncated);
}

#[tokio::test]
async fn equal_and_unknown_mtimes_preserve_encounter_order_in_both_searches() {
    let mut kernel = MockKernel::new();
    kernel.add_dir("/");
    for (path, mtime) in [("/unknown.md", 0), ("/first.md", 10), ("/second.md", 10)] {
        kernel.add_file(path, b"needle\n", mtime);
    }
    kernel.clear_mtime("/unknown.md");
    let harness = Harness::new(kernel);
    let glob = harness
        .service
        .glob(Request::new(GlobRequest {
            root_path: "/".into(),
            pattern: "*.md".into(),
            sort_recency: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(glob.paths, ["/first.md", "/second.md", "/unknown.md"]);
    let grep = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/".into(),
            pattern: "needle".into(),
            sort_recency: true,
            files: working_set(vec![
                "/unknown.md".into(),
                "/first.md".into(),
                "/second.md".into(),
            ]),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        grep.matches
            .iter()
            .map(|row| row.path.as_str())
            .collect::<Vec<_>>(),
        ["/first.md", "/second.md", "/unknown.md"]
    );
    assert_eq!(
        harness.kernel.io_counts().2,
        6,
        "one stat per candidate per search"
    );
}
