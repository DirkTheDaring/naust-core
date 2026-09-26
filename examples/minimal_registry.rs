//! A complete, working registry composed from `naust-core` alone — no HTTP,
//! no auth, no server configuration (the proof of ADR-010's purpose).
//!
//! Run with: `cargo run -p naust-core --example minimal_registry`
//!
//! The composition mirrors what any transport (HTTP server, gRPC front-end,
//! embedded library) must do:
//!   1. pick a backend and build the `StorageWiring` port views,
//!   2. acquire the exclusive `RuntimeMutationAuthority`,
//!   3. open/heal the `BlobRefIndex`,
//!   4. create ONE `ConsistencyCoordinator` for this composition root,
//!   5. assemble the application services,
//! then drive pushes/pulls exclusively through those services.

use naust_core::prelude::*;
use naust_core::storage::fs::FsStorage;
use naust_core::storage::upload_session::{UploadByteStream, UploadStreamError};
use std::sync::Arc;

fn byte_stream(data: &'static [u8]) -> UploadByteStream {
    let items: Vec<Result<bytes::Bytes, UploadStreamError>> =
        vec![Ok(bytes::Bytes::from_static(data))];
    Box::pin(futures_util::stream::iter(items))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("minimal-registry-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;

    // 1. Backend + port views. Any backend implementing the storage ports
    //    works; FsStorage and S3Storage are the bundled references.
    let backend = Arc::new(FsStorage::new(root.clone(), 64 * 1024 * 1024));
    let wiring = StorageWiring::from_backend(backend);

    // 2. Exclusive writer authority (fail-closed against concurrent mutators).
    let authority = RuntimeMutationAuthority::acquire(wiring.cluster_lock(), "example").await?;

    // 3. Reference index (sled), healed against the storage backend.
    let idx = Arc::new(BlobRefIndex::open(root.join("ref-index"))?);
    idx.ensure_healthy_or_rebuild(wiring.blob_ref_index().as_ref(), true, true)
        .await?;

    // 4. One coordinator per composition root.
    let consistency = ConsistencyCoordinator::new();

    // 5. Application services — the crate's public use-case surface.
    let blobs = BlobMutationService::new(
        wiring.blob_mutation(),
        Some(idx.clone()),
        consistency.clone(),
        BlobUploadCoordinatorConfig {
            signing_key: b"example-upload-state-key".to_vec(),
            max_upload_bytes: 64 * 1024 * 1024,
            abort_on_digest_mismatch: true,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 60,
            finalize_grace_secs: 0,
        },
    );
    let manifests = ManifestMutationService::new(
        wiring.manifest_lifecycle(),
        Some(idx.clone()),
        consistency.clone(),
    );
    let tags = TagQueryService::new(wiring.tag_reader());

    // --- Push: one layer blob + a manifest tagged "latest". -----------------
    let layer: &[u8] = b"minimal registry layer bytes";
    let layer_digest = Digest::parse(&format!(
        "sha256:{}",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(layer))
    ))?;
    blobs
        .monolithic_upload("examples/hello", &layer_digest, Some(byte_stream(layer)))
        .await?;

    let config_bytes: &[u8] = b"{}";
    let config_digest = Digest::parse(&format!(
        "sha256:{}",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(config_bytes))
    ))?;
    blobs
        .monolithic_upload(
            "examples/hello",
            &config_digest,
            Some(byte_stream(config_bytes)),
        )
        .await?;

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": config_bytes.len(),
            "digest": config_digest.as_str(),
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "size": layer.len(),
            "digest": layer_digest.as_str(),
        }],
    });
    let published = manifests
        .publish_manifest(PublishManifestRequest {
            repo: "examples/hello".to_string(),
            reference: "latest".to_string(),
            payload: bytes::Bytes::from(serde_json::to_vec(&manifest)?),
            declared_media_type: Some("application/vnd.oci.image.manifest.v1+json".to_string()),
            allow_tag_overwrite: false,
        })
        .await?;
    println!("published examples/hello:latest -> {}", published.digest);

    // --- Pull side: resolve the tag back. -----------------------------------
    let tag_list = tags.list_tags("examples/hello", None).await?;
    println!("tags: {tag_list:?}");
    assert_eq!(tag_list, vec!["latest".to_string()]);

    // Orderly shutdown: release the writer authority.
    drop(consistency);
    let mut authority = authority;
    authority.release().await?;
    let _ = std::fs::remove_dir_all(&root);
    println!("ok");
    Ok(())
}
