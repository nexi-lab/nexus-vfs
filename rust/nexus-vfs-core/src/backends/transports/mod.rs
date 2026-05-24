//! Transports — `where` blobs travel to.
//!
//! Trim fork keeps only `blob` (Nexus-managed blob storage on local fs,
//! S3, GCS). External-API connectors (anthropic/openai/google/social/cli)
//! were agent integrations from upstream's Python deployment and were
//! removed in this fork.

pub mod blob;
