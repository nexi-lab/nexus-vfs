//! Discovery journeys through the service and the kernel C ABI.

use std::sync::Arc;

use nexus_search_plugin::index_manager::IndexManager;
use nexus_search_plugin::search_proto::search_service_server::SearchService;
use nexus_search_plugin::search_proto::{
    DiscoveryFiles, DiscoveryFilter, GlobRequest, GrepRequest,
};
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

#[tokio::test]
async fn markdown_refinement_filters_before_cap_and_tracks_current_source_without_metadata() {
    let source = "---\nneedle: metadata\n---\n\nneedle preamble\n\n# Root\n## Target\nneedle paragraph\n\n```txt\nneedle code\n## fake heading\n```\n\n### Nested\n> needle quote\n\n- needle list\n\n| a |\n| - |\n| needle table |\n\n## Other\nneedle outside\n";
    let mut kernel = MockKernel::new();
    kernel.add_dir("/");
    kernel.add_file("/spec.MD", source.as_bytes(), 1);
    kernel.add_file("/ordinary.txt", b"needle plain\n", 2);
    let mut harness = Harness::new(kernel);
    let selection = working_set(vec!["/spec.MD".into(), "/ordinary.txt".into()]);
    let filtered = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/".into(),
            pattern: "needle".into(),
            files: selection.clone(),
            section: Some("## target".into()),
            block_type: Some("code".into()),
            before_context: 1,
            after_context: 1,
            max_results: 1,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        filtered.applied_filters,
        DiscoveryFilter::Files as u32
            | DiscoveryFilter::BlockType as u32
            | DiscoveryFilter::Section as u32
    );
    assert_eq!(filtered.matches.len(), 1);
    assert_eq!(filtered.matches[0].line, "needle code");
    assert_eq!(filtered.matches[0].line_number, 12);
    assert_eq!(filtered.matches[0].before, ["```txt"]);
    assert_eq!(filtered.matches[0].after, ["## fake heading"]);
    let section = filtered.matches[0].section.as_ref().unwrap();
    assert_eq!(
        (
            &*section.heading,
            section.depth,
            section.line_start,
            section.line_end
        ),
        ("Target", 2, 8, 24)
    );
    assert!(
        !filtered.truncated,
        "outside matches cannot consume the cap"
    );
    assert_eq!(harness.kernel.io_counts().0, 2, "read each candidate once");

    // Search the parent to include descendants; a missing/depth-mismatched section stays empty.
    for (query, expected) in [("Root", 6), ("### Target", 0), ("missing", 0)] {
        let response = harness
            .service
            .grep(Request::new(GrepRequest {
                root_path: "/".into(),
                pattern: "needle".into(),
                files: selection.clone(),
                section: Some(query.into()),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.matches.len(), expected, "{query}: {response:?}");
    }

    // A source rewrite changes the next answer without an index write or parser xattr.
    harness
        .kernel
        .add_file("/spec.MD", b"## Target\nneedle revised\n", 3);
    let revised = harness
        .service
        .grep(Request::new(GrepRequest {
            root_path: "/".into(),
            pattern: "needle".into(),
            files: selection,
            section: Some("Target".into()),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(revised.matches.len(), 1);
    assert_eq!(revised.matches[0].line, "needle revised");
    assert_eq!(revised.matches[0].section.as_ref().unwrap().line_end, 2);
}

#[tokio::test]
async fn every_markdown_block_filters_nested_unicode_crlf_source_and_plain_files() {
    let source = "---\r\nneedle: yaml\r\n---\r\n\r\nneedle paragraph\r\n\r\n# needle 标题\r\n\r\n```\r\nneedle code\r\n```\r\n\r\n> needle quote\r\n\r\n- needle list\r\n\r\n| a |\r\n| - |\r\n| needle table |";
    let mut kernel = MockKernel::new();
    kernel.add_dir("/");
    kernel.add_file("/all.markdown", source.as_bytes(), 1);
    kernel.add_file("/plain.txt", b"needle plain\n", 2);
    let harness = Harness::new(kernel);
    for (block, lines) in [
        ("frontmatter", vec![2]),
        ("paragraph", vec![5, 13, 15]),
        ("heading", vec![7]),
        ("code", vec![10]),
        ("blockquote", vec![13]),
        ("list", vec![15]),
        ("table", vec![19]),
    ] {
        let response = harness
            .service
            .grep(Request::new(GrepRequest {
                root_path: "/".into(),
                pattern: "needle".into(),
                block_type: Some(block.into()),
                files: working_set(vec!["/all.markdown".into(), "/plain.txt".into()]),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        let actual: Vec<_> = response
            .matches
            .iter()
            .filter(|row| row.path == "/all.markdown")
            .map(|row| row.line_number)
            .collect();
        assert_eq!(actual, lines, "{block}: {response:?}");
        assert_eq!(response.matches.last().unwrap().line, "needle plain");
        assert!(!response.truncated);
    }
    let before = harness.kernel.io_counts();
    for (block, section) in [(Some("invalid"), None), (None, Some("  "))] {
        let error = harness
            .service
            .grep(Request::new(GrepRequest {
                pattern: "needle".into(),
                block_type: block.map(str::to_owned),
                section: section.map(str::to_owned),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
    assert_eq!(
        harness.kernel.io_counts(),
        before,
        "reject malformed filters before VFS I/O"
    );
}

#[tokio::test]
async fn tight_list_paragraphs_include_inline_text_and_exclude_nested_block_types() {
    let source = "- needle **outer**\n  needle continuation\n  - needle inner `inline`\n- ## needle heading\n- ```text\n  needle fenced\n  ```\n- > needle quote\n";
    let mut kernel = MockKernel::new();
    kernel.add_dir("/");
    kernel.add_file("/tight.md", source.as_bytes(), 1);
    let harness = Harness::new(kernel);
    let response = harness
        .service
        .grep(Request::new(GrepRequest {
            pattern: "needle".into(),
            files: working_set(vec!["/tight.md".into()]),
            block_type: Some("paragraph".into()),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let lines: Vec<_> = response.matches.iter().map(|row| row.line_number).collect();
    assert_eq!(lines, [1, 2, 3, 8], "{response:?}");
    assert!(!response.truncated);
}
