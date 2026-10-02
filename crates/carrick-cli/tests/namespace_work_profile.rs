#[path = "../src/namespace_work_profile.rs"]
mod namespace_work_profile;

#[test]
fn namespace_artifact_identity_changes_with_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("probe");
    std::fs::write(&path, b"before").unwrap();
    let before = namespace_work_profile::artifact_sha256(&path).unwrap();
    std::fs::write(&path, b"after").unwrap();
    assert_ne!(
        before,
        namespace_work_profile::artifact_sha256(&path).unwrap()
    );
    assert!(namespace_work_profile::artifact_sha256(&directory.path().join("missing")).is_err());
}

#[test]
fn namespace_observations_bind_each_actor_and_operation() {
    let census = namespace_work_profile::validate(&complete(), 1).unwrap();
    let observations =
        namespace_work_profile::observations(&census, 1, &"a".repeat(64), "embed:namespace")
            .unwrap();
    assert_eq!(observations.len(), 8);
    assert!(observations.iter().all(|item| item.layer == carrick_conformance_contract::ExecutionLayer::EmbedStructural));
    assert!(namespace_work_profile::observations(&census, 1, "", "embed:namespace").is_err());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let registry = carrick_conformance_contract::ContractRegistry::load(&root).unwrap();
    let id =
        carrick_conformance_contract::ContractId::new("kernel.vfs.host-namespace-mutation-work")
            .unwrap();
    let contract = registry.get(&id).unwrap();
    carrick_conformance_contract::evaluate(contract, &observations).unwrap();
    let mut red = observations;
    red[0].work.as_mut().unwrap().values.insert(
        carrick_conformance_contract::WorkMetric::NamespacePathVisits,
        9,
    );
    assert!(carrick_conformance_contract::evaluate(contract, &red).is_err());
}

#[test]
fn namespace_census_accepts_in_process_embed_fixture() {
    let command = [
        "debug",
        "host-namespace-work",
        "ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/tmp/probes",
        "8",
        "128",
        "unrelated",
    ]
    .map(str::to_owned);
    assert_eq!(namespace_work_profile::fixture_scale(&command).unwrap(), 8);
    let mut bad = command.clone();
    bad[2] = "ubuntu:24.04".into();
    assert!(namespace_work_profile::fixture_scale(&bad).is_err());
}

fn complete() -> String {
    let mut raw = format!(
        "NSWORK1|header|program_sha256={}\nNSWORK1|summary|seen=1|errors=0|code=0|bounded=0\n",
        namespace_work_profile::program_sha256()
    );
    for actor in [3, 4] {
        for op in ["renameat", "unlinkat", "linkat", "openat"] {
            for phase in ["begin", "end", "armed"] {
                raw.push_str(&format!("NSWORK1|{phase}|actor={actor}|op={op}|count=1\n"));
            }
            for phase in ["host-begin", "host-end"] {
                raw.push_str(&format!(
                    "NSWORK1|{phase}|actor={actor}|op={op}|name=fstat64|count=1\n"
                ));
                if op == "openat" {
                    raw.push_str(&format!(
                        "NSWORK1|{phase}|actor={actor}|op={op}|name=openat|count=1\n"
                    ));
                }
            }
            for stage in ["dentry", "host-parent", "host-leaf"] {
                raw.push_str(&format!(
                    "NSWORK1|visit|actor={actor}|op={op}|stage={stage}|count=0\n"
                ));
            }
        }
    }
    raw
}

#[test]
fn namespace_census_requires_exact_completed_populations() {
    let raw = complete();
    let census = namespace_work_profile::validate(&raw, 1).unwrap();
    assert_eq!(
        census.calls[&(
            namespace_work_profile::NamespaceActorFd::from_positive(3).unwrap(),
            "renameat".into()
        )],
        1
    );
    assert_eq!(
        census.host_calls[&(
            namespace_work_profile::NamespaceActorFd::from_positive(3).unwrap(),
            "openat".into(),
            "fstat64".into()
        )],
        1
    );
    assert_eq!(
        census.visits[&(
            namespace_work_profile::NamespaceActorFd::from_positive(3).unwrap(),
            "openat".into(),
            "host-leaf".into()
        )],
        0
    );
    assert!(namespace_work_profile::validate(&raw, 8).is_err());
    assert!(
        namespace_work_profile::validate(
            &raw.replace(
                "|end|actor=3|op=renameat|count=1",
                "|end|actor=3|op=renameat|count=0"
            ),
            1
        )
        .is_err()
    );
    assert!(
        namespace_work_profile::validate(
            &raw.replace(
                "|host-end|actor=3|op=openat|name=fstat64|count=1",
                "|host-end|actor=3|op=openat|name=fstat64|count=0"
            ),
            1
        )
        .is_err()
    );
    assert!(namespace_work_profile::validate(&raw.replace("errors=0", "errors=1"), 1).is_err());
    assert!(namespace_work_profile::validate(&(raw.clone() + &raw), 1).is_err());
    assert!(namespace_work_profile::validate("", 1).is_err());
    assert!(
        namespace_work_profile::validate(
            &raw.replace(&namespace_work_profile::program_sha256(), &"0".repeat(64)),
            1
        )
        .is_err()
    );
}

#[test]
fn namespace_profile_binds_scale_and_program() {
    let command = vec![
        "run".into(),
        format!("ubuntu@sha256:{}", "a".repeat(64)),
        "/bin/sh".into(),
        "-c".into(),
        "/p/perf_namespace_scale 8 128 unrelated".into(),
    ];
    assert_eq!(namespace_work_profile::fixture_scale(&command).unwrap(), 8);
    let mut bad = command.clone();
    bad[4] = "/p/perf_namespace_scale 008 128 unrelated".into();
    assert!(namespace_work_profile::fixture_scale(&bad).is_err());
    bad[4] = "/p/perf_namespace_scale 8 64 unrelated".into();
    assert!(namespace_work_profile::fixture_scale(&bad).is_err());
    bad[4] = "/p/perf_namespace_scale 8 128 unrelated; true".into();
    assert!(namespace_work_profile::fixture_scale(&bad).is_err());
    let rendered = namespace_work_profile::render_profile_script().unwrap();
    assert!(rendered.contains(&namespace_work_profile::program_sha256()));
    assert!(!rendered.contains("/* CARRICK_NSWORK_PROGRAM_SHA256 */"));
}

#[test]
fn namespace_open_requires_one_real_backend_open_per_request() {
    let raw = complete();
    let without_open = raw
        .lines()
        .filter(|line| !line.contains("|name=openat|"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(namespace_work_profile::validate(&without_open, 1).is_err());
    let extra_open = raw.replace(
        "op=openat|name=openat|count=1",
        "op=openat|name=openat|count=2",
    );
    assert!(namespace_work_profile::validate(&extra_open, 1).is_err());
}

#[test]
fn namespace_profile_requires_a_digest_pinned_image() {
    let unpinned = vec![
        "run".into(),
        "ubuntu:24.04".into(),
        "/bin/sh".into(),
        "-c".into(),
        "/p/perf_namespace_scale 1 0 same".into(),
    ];
    assert!(namespace_work_profile::fixture_scale(&unpinned).is_err());
}

#[test]
fn namespace_census_closes_every_registered_scale_and_both_actors() {
    for scale in [1, 8, 32, 128] {
        let raw = complete().replace("|count=1", &format!("|count={scale}"));
        assert!(namespace_work_profile::validate(&raw, scale).is_ok());
        let missing_actor = raw
            .lines()
            .filter(|line| !line.contains("|actor=4|"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(namespace_work_profile::validate(&missing_actor, scale).is_err());
        let missing_arm = raw
            .lines()
            .filter(|line| !line.contains("|armed|"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(namespace_work_profile::validate(&missing_arm, scale).is_err());
    }
}
