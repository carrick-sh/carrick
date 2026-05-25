use carrick_image::{ImageReference, ImageStore, LayerSummary, PullSummary};

#[test]
fn normalizes_short_docker_hub_references() {
    let image = ImageReference::parse("alpine").unwrap();

    assert_eq!(image.registry(), "docker.io");
    assert_eq!(image.repository(), "library/alpine");
    assert_eq!(image.tag(), Some("latest"));
    assert_eq!(image.digest(), None);
    assert_eq!(image.canonical(), "docker.io/library/alpine:latest");
}

#[test]
fn computes_content_addressed_storage_paths() {
    let dir = tempfile::tempdir().unwrap();
    let store = ImageStore::new(dir.path());
    let image = ImageReference::parse("registry.example.com/team/app:v1").unwrap();

    assert_eq!(
        store.image_dir(&image),
        dir.path().join("images/registry.example.com/team/app/v1")
    );
    assert_eq!(
        store.blob_path("sha256:abcdef").unwrap(),
        dir.path().join("blobs/sha256/abcdef")
    );
}

#[test]
fn rejects_unsafe_digests_for_blob_paths() {
    let dir = tempfile::tempdir().unwrap();
    let store = ImageStore::new(dir.path());

    assert!(store.blob_path("sha256:../escape").is_err());
    assert!(store.blob_path("md5:abcdef").is_err());
}

#[tokio::test]
async fn loads_pull_summary_from_image_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = ImageStore::new(dir.path());
    let image = ImageReference::parse("registry.example.com/team/app:v1").unwrap();
    let summary = PullSummary {
        image: image.canonical(),
        digest: Some("sha256:manifest".to_owned()),
        image_dir: store.image_dir(&image),
        config_size: 0,
        layers: vec![LayerSummary {
            digest: "sha256:abcdef".to_owned(),
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
            size: 12,
            path: store.blob_path("sha256:abcdef").unwrap(),
        }],
    };
    std::fs::create_dir_all(store.image_dir(&image)).unwrap();
    std::fs::write(
        store.image_summary_path(&image),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();

    let loaded = store.load_pull_summary(&image).await.unwrap();

    assert_eq!(loaded, summary);
}
