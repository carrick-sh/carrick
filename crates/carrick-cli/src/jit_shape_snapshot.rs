use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotManifest {
    pub(crate) sha256: String,
    pub(crate) pairs: u64,
    pub(crate) pids: u64,
    pub(crate) blocks: u64,
    pub(crate) bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionOrigin {
    Own,
    Ancestor { pid: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedInstruction {
    pub(crate) word: u32,
    pub(crate) origin: ResolutionOrigin,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMetadata {
    schema: String,
    pid: u32,
    cache_base: u64,
    code_len: usize,
    code_sha256: String,
    blocks: Vec<(u64, u64)>,
}

#[derive(Clone, Debug)]
struct Snapshot {
    path: PathBuf,
    base: u64,
    end: u64,
    code: Vec<u8>,
}

impl Snapshot {
    fn contains(&self, pc: u64) -> bool {
        pc >= self.base && pc < self.end
    }

    fn word_at(&self, pc: u64) -> anyhow::Result<u32> {
        let offset = pc
            .checked_sub(self.base)
            .with_context(|| format!("PC {pc:#x} precedes snapshot base {:#x}", self.base))?;
        let offset = usize::try_from(offset).context("snapshot offset does not fit usize")?;
        let end = offset
            .checked_add(4)
            .context("snapshot word offset overflow")?;
        let bytes = self
            .code
            .get(offset..end)
            .with_context(|| format!("PC {pc:#x} is truncated in {}", self.path.display()))?;
        if offset % 4 != 0 {
            bail!(
                "PC {pc:#x} is not word-aligned in snapshot {}",
                self.path.display()
            );
        }
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[derive(Debug)]
pub(crate) struct SnapshotSet {
    manifest: SnapshotManifest,
    by_pid: BTreeMap<u32, Vec<Snapshot>>,
}

impl SnapshotSet {
    pub(crate) fn load(directory: &Path) -> anyhow::Result<Self> {
        let entries = fs::read_dir(directory)
            .with_context(|| format!("read snapshot directory {}", directory.display()))?;
        let mut json_paths = BTreeMap::new();
        let mut bin_paths = BTreeMap::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("read entry in {}", directory.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .with_context(|| format!("read file type for {}", path.display()))?;
            if file_type.is_symlink() {
                bail!("snapshot directory contains symlink {}", path.display());
            }
            if file_type.is_dir() {
                bail!("snapshot directory contains directory {}", path.display());
            }
            if !file_type.is_file() {
                bail!(
                    "snapshot directory contains unknown entry {}",
                    path.display()
                );
            }
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .with_context(|| format!("unknown snapshot entry {}", path.display()))?;
            if !matches!(extension, "json" | "bin") {
                bail!(
                    "snapshot directory contains unknown entry {}",
                    path.display()
                );
            }
            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .filter(|stem| !stem.is_empty())
                .with_context(|| format!("invalid snapshot name {}", path.display()))?
                .to_owned();
            let target = if extension == "json" {
                &mut json_paths
            } else {
                &mut bin_paths
            };
            if target.insert(stem.clone(), path).is_some() {
                bail!("duplicate snapshot stem `{stem}`");
            }
        }
        if json_paths.is_empty() && bin_paths.is_empty() {
            bail!(
                "snapshot directory {} contains no snapshots",
                directory.display()
            );
        }
        let json_stems = json_paths.keys().cloned().collect::<BTreeSet<_>>();
        let bin_stems = bin_paths.keys().cloned().collect::<BTreeSet<_>>();
        if json_stems != bin_stems {
            let missing_bins = json_stems.difference(&bin_stems).collect::<Vec<_>>();
            let missing_json = bin_stems.difference(&json_stems).collect::<Vec<_>>();
            bail!(
                "snapshot pairs are incomplete: missing .bin for {missing_bins:?}; missing .json for {missing_json:?}"
            );
        }

        let mut by_pid: BTreeMap<u32, Vec<Snapshot>> = BTreeMap::new();
        let mut manifest_bytes = Vec::new();
        let mut pairs = 0_u64;
        let mut pids = 0_u64;
        let mut blocks = 0_u64;
        let mut bytes = 0_u64;
        for (stem, json_path) in json_paths {
            let bin_path = bin_paths
                .get(&stem)
                .with_context(|| format!("snapshot {stem} lost its paired payload"))?;
            let json = fs::read(&json_path)
                .with_context(|| format!("read snapshot metadata {}", json_path.display()))?;
            let metadata: SnapshotMetadata = serde_json::from_slice(&json)
                .with_context(|| format!("parse snapshot metadata {}", json_path.display()))?;
            if metadata.schema != "carrick.code-snapshot.v4" {
                bail!(
                    "snapshot {} has unsupported schema `{}`",
                    json_path.display(),
                    metadata.schema
                );
            }
            let code = fs::read(bin_path)
                .with_context(|| format!("read snapshot payload {}", bin_path.display()))?;
            if code.len() != metadata.code_len {
                bail!(
                    "snapshot {} length {} does not match authenticated length {}",
                    bin_path.display(),
                    code.len(),
                    metadata.code_len
                );
            }
            if code.is_empty() {
                bail!("snapshot {} payload is empty", bin_path.display());
            }
            if code.len() % 4 != 0 {
                bail!("snapshot {} length is not word-aligned", bin_path.display());
            }
            if metadata.cache_base % 4 != 0 {
                bail!(
                    "snapshot {} cache base is not word-aligned",
                    bin_path.display()
                );
            }
            let code_len = u64::try_from(code.len()).context("snapshot length does not fit u64")?;
            let end = metadata.cache_base.checked_add(code_len).with_context(|| {
                format!("snapshot {} address range overflows", bin_path.display())
            })?;
            let code_sha256 = format!("{:x}", Sha256::digest(&code));
            if code_sha256 != metadata.code_sha256 {
                bail!(
                    "snapshot {} SHA-256 {} does not match authenticated digest {}",
                    bin_path.display(),
                    code_sha256,
                    metadata.code_sha256
                );
            }
            for &(guest_entry, cache_entry) in &metadata.blocks {
                if guest_entry % 4 != 0 || cache_entry % 4 != 0 {
                    bail!(
                        "snapshot {} block endpoint is not word-aligned",
                        bin_path.display()
                    );
                }
                let cache_word_end = cache_entry.checked_add(4).with_context(|| {
                    format!("snapshot {} block endpoint overflows", bin_path.display())
                })?;
                if cache_entry < metadata.cache_base || cache_word_end > end {
                    bail!(
                        "snapshot {} block endpoint is outside payload",
                        bin_path.display()
                    );
                }
            }

            let json_sha256 = format!("{:x}", Sha256::digest(&json));
            manifest_bytes.extend_from_slice(stem.as_bytes());
            manifest_bytes.push(0);
            manifest_bytes.extend_from_slice(json_sha256.as_bytes());
            manifest_bytes.push(0);
            manifest_bytes.extend_from_slice(code_sha256.as_bytes());
            manifest_bytes.push(b'\n');
            pairs = pairs
                .checked_add(1)
                .context("snapshot pair count overflow")?;
            blocks = blocks
                .checked_add(
                    u64::try_from(metadata.blocks.len()).context("block count does not fit u64")?,
                )
                .context("snapshot block count overflow")?;
            bytes = bytes
                .checked_add(code_len)
                .context("snapshot payload byte count overflow")?;
            if !by_pid.contains_key(&metadata.pid) {
                pids = pids.checked_add(1).context("snapshot pid count overflow")?;
            }
            by_pid.entry(metadata.pid).or_default().push(Snapshot {
                path: bin_path.clone(),
                base: metadata.cache_base,
                end,
                code,
            });
        }
        for snapshots in by_pid.values_mut() {
            snapshots.sort_by(|left, right| {
                left.base
                    .cmp(&right.base)
                    .then_with(|| left.path.cmp(&right.path))
            });
            for pair in snapshots.windows(2) {
                if pair[1].base < pair[0].end {
                    bail!(
                        "snapshot ranges overlap for pid in {} and {}",
                        pair[0].path.display(),
                        pair[1].path.display()
                    );
                }
            }
        }
        Ok(Self {
            manifest: SnapshotManifest {
                sha256: format!("{:x}", Sha256::digest(manifest_bytes)),
                pairs,
                pids,
                blocks,
                bytes,
            },
            by_pid,
        })
    }

    pub(crate) fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }

    pub(crate) fn resolve(
        &self,
        pid: u32,
        pc: u64,
        parents: &BTreeMap<u32, u32>,
    ) -> anyhow::Result<ResolvedInstruction> {
        let own = self.by_pid.get(&pid).with_context(|| {
            format!("pid {pid} has no own authenticated snapshot for ancestor fallback")
        })?;
        let own_matches = own
            .iter()
            .filter(|snapshot| snapshot.contains(pc))
            .collect::<Vec<_>>();
        match own_matches.as_slice() {
            [snapshot] => {
                return Ok(ResolvedInstruction {
                    word: snapshot.word_at(pc)?,
                    origin: ResolutionOrigin::Own,
                });
            }
            [] => {}
            matches => bail!(
                "pid {pid} PC {pc:#x} resolves in {} own snapshots",
                matches.len()
            ),
        }

        let mut candidates = Vec::new();
        let mut cursor = pid;
        let mut seen = BTreeSet::new();
        while let Some(&parent) = parents.get(&cursor) {
            if !seen.insert(cursor) {
                bail!("fork ancestry cycle while resolving pid {pid}");
            }
            if let Some(parent_snapshots) = self.by_pid.get(&parent) {
                candidates.extend(
                    parent_snapshots
                        .iter()
                        .filter(|snapshot| snapshot.contains(pc))
                        .map(|snapshot| (parent, snapshot)),
                );
            }
            cursor = parent;
        }
        match candidates.as_slice() {
            [(ancestor_pid, snapshot)] => Ok(ResolvedInstruction {
                word: snapshot.word_at(pc)?,
                origin: ResolutionOrigin::Ancestor { pid: *ancestor_pid },
            }),
            [] => bail!("pid {pid} PC {pc:#x} resolves in no own or ancestor snapshot"),
            matches => bail!(
                "pid {pid} PC {pc:#x} resolves ambiguously in {} ancestor snapshots",
                matches.len()
            ),
        }
    }
}

#[cfg(test)]
pub(crate) fn write_v4_test_snapshot(
    directory: &Path,
    stem: &str,
    pid: u32,
    base: u64,
    words: &[u32],
) {
    let code = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    fs::write(directory.join(format!("{stem}.bin")), &code).expect("write snapshot bytes");
    let metadata = serde_json::json!({
        "schema": "carrick.code-snapshot.v4",
        "pid": pid,
        "cache_base": base,
        "code_len": code.len(),
        "code_sha256": format!("{:x}", Sha256::digest(&code)),
        "blocks": [[0x4000, base]],
    });
    fs::write(
        directory.join(format!("{stem}.json")),
        serde_json::to_vec(&metadata).expect("serialize snapshot metadata"),
    )
    .expect("write snapshot metadata");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use super::{ResolutionOrigin, SnapshotSet};

    struct SnapshotFixture {
        directory: tempfile::TempDir,
    }

    impl SnapshotFixture {
        fn one_pair(pid: u32, base: u64, code: &[u8]) -> Self {
            let fixture = Self::empty();
            fixture.write_pair("41-1", pid, base, code, &[(0x4000, base)]);
            fixture
        }

        fn two_pairs_in_order(stems: [&str; 2]) -> Self {
            let fixture = Self::empty();
            for stem in stems {
                let base = match stem {
                    "41-1" => 0x1000,
                    "41-2" => 0x2000,
                    _ => panic!("unexpected fixture stem {stem}"),
                };
                fixture.write_pair(stem, 41, base, &[0x20, 0x00, 0x1f, 0xd6], &[(0x4000, base)]);
            }
            fixture
        }

        fn parent_and_child() -> Self {
            let fixture = Self::empty();
            fixture.write_pair(
                "41-1",
                41,
                0x1000,
                &[0x20, 0x00, 0x1f, 0xd6],
                &[(0x4000, 0x1000)],
            );
            fixture.write_pair(
                "42-1",
                42,
                0x3000,
                &[0x1f, 0x20, 0x03, 0xd5],
                &[(0x5000, 0x3000)],
            );
            fixture
        }

        fn parent_only() -> Self {
            let fixture = Self::empty();
            fixture.write_pair(
                "41-1",
                41,
                0x1000,
                &[0x20, 0x00, 0x1f, 0xd6],
                &[(0x4000, 0x1000)],
            );
            fixture
        }

        fn empty() -> Self {
            Self {
                directory: tempfile::tempdir().expect("snapshot tempdir"),
            }
        }

        fn path(&self) -> &Path {
            self.directory.path()
        }

        fn load(&self) -> SnapshotSet {
            SnapshotSet::load(self.path()).expect("load snapshot fixture")
        }

        fn write_pair(&self, stem: &str, pid: u32, base: u64, code: &[u8], blocks: &[(u64, u64)]) {
            fs::write(self.path().join(format!("{stem}.bin")), code).expect("write snapshot bytes");
            let metadata = serde_json::json!({
                "schema": "carrick.code-snapshot.v4",
                "pid": pid,
                "cache_base": base,
                "code_len": code.len(),
                "code_sha256": format!("{:x}", Sha256::digest(code)),
                "blocks": blocks,
            });
            fs::write(
                self.path().join(format!("{stem}.json")),
                serde_json::to_vec(&metadata).expect("serialize snapshot metadata"),
            )
            .expect("write snapshot metadata");
        }

        fn metadata_path(&self, stem: &str) -> PathBuf {
            self.path().join(format!("{stem}.json"))
        }

        fn payload_path(&self, stem: &str) -> PathBuf {
            self.path().join(format!("{stem}.bin"))
        }

        fn mutate_metadata(&self, stem: &str, change: impl FnOnce(&mut serde_json::Value)) {
            let path = self.metadata_path(stem);
            let mut metadata: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("read metadata"))
                    .expect("parse metadata");
            change(&mut metadata);
            fs::write(
                path,
                serde_json::to_vec(&metadata).expect("serialize metadata"),
            )
            .expect("write metadata");
        }

        fn write_unknown(&self, name: &str, contents: &[u8]) {
            fs::write(self.path().join(name), contents).expect("write unknown entry");
        }

        fn remove(&self, name: &str) {
            fs::remove_file(self.path().join(name)).expect("remove fixture entry");
        }

        fn symlink_pair(&self, name: &str) {
            #[cfg(unix)]
            std::os::unix::fs::symlink(self.metadata_path("41-1"), self.path().join(name))
                .expect("create snapshot symlink");
        }
    }

    #[test]
    fn snapshot_directory_rejects_unknown_entries_and_symlinks() {
        let fixture = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
        fixture.write_unknown("notes.txt", b"not evidence");
        assert!(
            SnapshotSet::load(fixture.path())
                .unwrap_err()
                .to_string()
                .contains("unknown")
        );
        fixture.remove("notes.txt");
        fixture.symlink_pair("linked.json");
        assert!(
            SnapshotSet::load(fixture.path())
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn manifest_is_sorted_and_domain_separated() {
        let a = SnapshotFixture::two_pairs_in_order(["41-2", "41-1"]);
        let b = SnapshotFixture::two_pairs_in_order(["41-1", "41-2"]);
        assert_eq!(
            SnapshotSet::load(a.path()).unwrap().manifest(),
            SnapshotSet::load(b.path()).unwrap().manifest()
        );
        let manifest = SnapshotSet::load(a.path()).unwrap().manifest().clone();
        assert_eq!(manifest.pairs, 2);
        assert_eq!(
            manifest.sha256,
            "211e5bde08de8cf9fa95a62385581d4cb4a3649e53419847c2b80ed9a724403c"
        );
    }

    #[test]
    fn snapshot_directory_rejects_directories_nested_directories_and_incomplete_pairs() {
        let fixture = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
        fs::create_dir(fixture.path().join("nested")).expect("create nested directory");
        fs::create_dir(fixture.path().join("nested/deeper"))
            .expect("create deeper nested directory");
        assert!(
            SnapshotSet::load(fixture.path())
                .unwrap_err()
                .to_string()
                .contains("directory")
        );
        fs::remove_dir_all(fixture.path().join("nested")).expect("remove nested directory");
        fixture.remove("41-1.bin");
        assert!(
            SnapshotSet::load(fixture.path())
                .unwrap_err()
                .to_string()
                .contains("incomplete")
        );
    }

    #[test]
    fn snapshot_loader_rejects_bad_v4_metadata_and_payloads() {
        let cases: [(&str, Box<dyn Fn(&SnapshotFixture)>); 6] = [
            (
                "wrong schema",
                Box::new(|fixture| {
                    fixture.mutate_metadata("41-1", |metadata| metadata["schema"] = "old".into())
                }),
            ),
            (
                "metadata digest",
                Box::new(|fixture| {
                    fixture
                        .mutate_metadata("41-1", |metadata| metadata["code_sha256"] = "00".into())
                }),
            ),
            (
                "payload digest",
                Box::new(|fixture| {
                    fs::write(fixture.payload_path("41-1"), [0x1f, 0x20, 0x03, 0xd5])
                        .expect("mutate payload")
                }),
            ),
            (
                "length",
                Box::new(|fixture| {
                    fixture.mutate_metadata("41-1", |metadata| metadata["code_len"] = 8.into())
                }),
            ),
            (
                "empty",
                Box::new(|fixture| {
                    fs::write(fixture.payload_path("41-1"), []).expect("empty payload");
                    fixture.mutate_metadata("41-1", |metadata| {
                        metadata["code_len"] = 0.into();
                        metadata["code_sha256"] = format!("{:x}", Sha256::digest([])).into();
                    });
                }),
            ),
            (
                "non word length",
                Box::new(|fixture| {
                    fs::write(fixture.payload_path("41-1"), [1, 2, 3]).expect("short payload");
                    fixture.mutate_metadata("41-1", |metadata| {
                        metadata["code_len"] = 3.into();
                        metadata["code_sha256"] = format!("{:x}", Sha256::digest([1, 2, 3])).into();
                    });
                }),
            ),
        ];
        for (name, mutate) in cases {
            let fixture = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
            mutate(&fixture);
            assert!(
                SnapshotSet::load(fixture.path()).is_err(),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn snapshot_loader_rejects_invalid_address_and_block_ranges() {
        let cases: [(&str, Box<dyn Fn(&SnapshotFixture)>); 5] = [
            (
                "unaligned cache base",
                Box::new(|fixture| {
                    fixture
                        .mutate_metadata("41-1", |metadata| metadata["cache_base"] = 0x1001.into())
                }),
            ),
            (
                "unaligned guest block",
                Box::new(|fixture| {
                    fixture.mutate_metadata("41-1", |metadata| {
                        metadata["blocks"] = serde_json::json!([[0x4001, 0x1000]])
                    })
                }),
            ),
            (
                "unaligned cache block",
                Box::new(|fixture| {
                    fixture.mutate_metadata("41-1", |metadata| {
                        metadata["blocks"] = serde_json::json!([[0x4000, 0x1001]])
                    })
                }),
            ),
            (
                "cache range overflow",
                Box::new(|fixture| {
                    fixture.mutate_metadata("41-1", |metadata| {
                        metadata["cache_base"] = (u64::MAX - 3).into()
                    })
                }),
            ),
            (
                "outside payload",
                Box::new(|fixture| {
                    fixture.mutate_metadata("41-1", |metadata| {
                        metadata["blocks"] = serde_json::json!([[0x4000, 0x1004]])
                    })
                }),
            ),
        ];
        for (name, mutate) in cases {
            let fixture = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
            mutate(&fixture);
            assert!(
                SnapshotSet::load(fixture.path()).is_err(),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn snapshot_loader_rejects_overflowing_block_endpoint_before_range_check() {
        let fixture = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
        fixture.mutate_metadata("41-1", |metadata| {
            metadata["blocks"] = serde_json::json!([[0x4000, u64::MAX - 3]])
        });
        let error = SnapshotSet::load(fixture.path()).unwrap_err();
        assert!(error.to_string().contains("block endpoint overflows"));
    }

    #[test]
    fn snapshot_loader_counts_pairs_pids_blocks_and_bytes() {
        let fixture = SnapshotFixture::empty();
        fixture.write_pair(
            "41-1",
            41,
            0x1000,
            &[0x20, 0x00, 0x1f, 0xd6],
            &[(0x4000, 0x1000)],
        );
        fixture.write_pair(
            "41-2",
            41,
            0x2000,
            &[0x1f, 0x20, 0x03, 0xd5],
            &[(0x5000, 0x2000)],
        );
        let manifest = fixture.load().manifest().clone();
        assert_eq!(manifest.pairs, 2);
        assert_eq!(manifest.pids, 1);
        assert_eq!(manifest.blocks, 2);
        assert_eq!(manifest.bytes, 8);
    }

    #[test]
    fn snapshot_loader_accepts_nonoverlapping_duplicate_pid_ranges_and_rejects_overlaps() {
        let accepted = SnapshotFixture::empty();
        accepted.write_pair(
            "41-1",
            41,
            0x1000,
            &[0x20, 0x00, 0x1f, 0xd6],
            &[(0x4000, 0x1000)],
        );
        accepted.write_pair(
            "41-2",
            41,
            0x2000,
            &[0x1f, 0x20, 0x03, 0xd5],
            &[(0x5000, 0x2000)],
        );
        assert_eq!(accepted.load().manifest().pairs, 2);

        let overlapping = SnapshotFixture::empty();
        overlapping.write_pair(
            "41-1",
            41,
            0x1000,
            &[0x20, 0x00, 0x1f, 0xd6, 0x1f, 0x20, 0x03, 0xd5],
            &[(0x4000, 0x1000)],
        );
        overlapping.write_pair(
            "41-2",
            41,
            0x1004,
            &[0x1f, 0x20, 0x03, 0xd5],
            &[(0x5000, 0x1004)],
        );
        assert!(
            SnapshotSet::load(overlapping.path())
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );
    }

    #[test]
    fn resolve_requires_own_snapshot_before_ancestor_fallback() {
        let set = SnapshotFixture::parent_and_child().load();
        let parents = BTreeMap::from([(42, 41)]);
        let resolved = set.resolve(42, 0x1000, &parents).unwrap();
        assert_eq!(resolved.origin, ResolutionOrigin::Ancestor { pid: 41 });

        let only_parent = SnapshotFixture::parent_only().load();
        let error = only_parent.resolve(42, 0x1000, &parents).unwrap_err();
        assert!(error.to_string().contains("own authenticated snapshot"));
    }

    #[test]
    fn resolve_returns_exact_own_word_and_unique_ancestor_word() {
        let fixture = SnapshotFixture::parent_and_child();
        let set = fixture.load();
        let own = set
            .resolve(42, 0x3000, &BTreeMap::from([(42, 41)]))
            .unwrap();
        assert_eq!(own.word, 0xd503_201f);
        assert_eq!(own.origin, ResolutionOrigin::Own);
        let ancestor = set
            .resolve(42, 0x1000, &BTreeMap::from([(42, 41)]))
            .unwrap();
        assert_eq!(ancestor.word, 0xd61f_0020);
        assert_eq!(ancestor.origin, ResolutionOrigin::Ancestor { pid: 41 });
    }

    #[test]
    fn resolve_rejects_missing_ranges_ambiguity_cycles_and_truncated_words() {
        let fixture = SnapshotFixture::parent_and_child();
        let set = fixture.load();
        assert!(
            set.resolve(42, 0x2000, &BTreeMap::from([(42, 41)]))
                .unwrap_err()
                .to_string()
                .contains("no own or ancestor")
        );
        assert!(
            set.resolve(99, 0x1000, &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("own authenticated snapshot")
        );
        assert!(
            set.resolve(42, 0x2000, &BTreeMap::from([(42, 41), (41, 42)]))
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );

        let truncated = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
        assert!(
            truncated
                .load()
                .resolve(41, 0x1002, &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
    }

    #[test]
    fn resolve_rejects_ambiguous_own_and_ancestor_ranges() {
        let own_fixture = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
        let mut own = own_fixture.load();
        let duplicate = own.by_pid.get(&41).expect("own snapshots")[0].clone();
        own.by_pid
            .get_mut(&41)
            .expect("own snapshots")
            .push(duplicate);
        assert!(
            own.resolve(41, 0x1000, &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("own snapshots")
        );

        let ancestors_fixture = SnapshotFixture::parent_and_child();
        let mut ancestors = ancestors_fixture.load();
        let duplicate = ancestors.by_pid.get(&41).expect("parent snapshots")[0].clone();
        ancestors.by_pid.insert(40, vec![duplicate]);
        assert!(
            ancestors
                .resolve(42, 0x1000, &BTreeMap::from([(42, 41), (41, 40)]))
                .unwrap_err()
                .to_string()
                .contains("ancestor snapshots")
        );
    }
}
