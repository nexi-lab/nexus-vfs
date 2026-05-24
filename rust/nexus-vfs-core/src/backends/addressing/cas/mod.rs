//! CAS addressing — content-hash-keyed blob storage.
//!
//! The CAS engine + chunking + remote fetcher + local transport live
//! **in the kernel crate** (`crate::kernel::cas_engine`, `crate::kernel::cas_chunking`,
//! `crate::kernel::cas_remote`, `crate::kernel::cas_transport`) because they're the
//! kernel's content-addressed storage primitive — the
//! Linux-VFS-equivalent pillar that backends consume rather than
//! implement.
//!
//! This module is a placeholder for future CAS-side helpers that
//! belong to backends (e.g. per-backend CAS sidecar metadata, gc
//! policy hooks).  The `addressing/cas/` directory exists so the
//! file layout reflects the architecture's
//! `crate::backends::backends::addressing::cas::*` shape even when the implementation
//! gravitates kernel-side for primitive sharing.
