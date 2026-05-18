use carrick::oci::{ImageReference, ImageStore};

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
