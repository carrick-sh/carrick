use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    Budget, Claim, ClaimId, ConformanceContract, ContractId, ExecutionLayer, ModelError,
    SurfaceAssignment, SurfaceRegistry,
};

#[derive(Clone, Debug)]
pub struct ContractRegistry {
    contracts: BTreeMap<ContractId, ConformanceContract>,
    claims: BTreeMap<ClaimId, Claim>,
    surfaces: Vec<SurfaceAssignment>,
    surface_entry_count: usize,
}

impl ContractRegistry {
    pub fn load(root: &Path) -> Result<Self, RegistryError> {
        let registry_root = root.join("conformance-contracts");
        let contracts_root = registry_root.join("contracts");
        let mut paths = read_toml_contract_paths(&contracts_root)?;
        paths.sort();

        let mut contracts = BTreeMap::new();
        for path in paths {
            let text = read_to_string(&path)?;
            let contract: ConformanceContract =
                toml::from_str(&text).map_err(|source| RegistryError::Toml {
                    path: path.clone(),
                    source,
                })?;
            validate_contract(&contract)?;
            let id = contract.id.clone();
            if contracts.insert(id.clone(), contract).is_some() {
                return Err(RegistryError::Duplicate(id));
            }
        }

        let claims_root = registry_root.join("claims");
        let mut claims = BTreeMap::new();
        if claims_root.exists() {
            let mut claim_paths = read_toml_contract_paths(&claims_root)?;
            claim_paths.sort();
            for path in claim_paths {
                let text = read_to_string(&path)?;
                let file: ClaimsFile =
                    toml::from_str(&text).map_err(|source| RegistryError::Toml {
                        path: path.clone(),
                        source,
                    })?;
                for claim in file.into_claims() {
                    validate_claim(&claim, &contracts)?;
                    let id = claim.id.clone();
                    if claims.insert(id.clone(), claim).is_some() {
                        return Err(RegistryError::DuplicateClaim(id));
                    }
                }
            }
        }

        let surfaces_path = registry_root.join("surfaces.toml");
        let surfaces_text = read_to_string(&surfaces_path)?;
        let surface_registry: SurfaceRegistry =
            toml::from_str(&surfaces_text).map_err(|source| RegistryError::Toml {
                path: surfaces_path,
                source,
            })?;
        let surface_entry_count = surface_registry.surfaces.len();
        let mut grouped_surfaces: BTreeMap<String, BTreeSet<ContractId>> = BTreeMap::new();
        let mut empty_surfaces: BTreeSet<String> = BTreeSet::new();
        let mut previous_surface: Option<(String, Option<ContractId>)> = None;
        for entry in surface_registry.surfaces {
            if entry.path.trim().is_empty() {
                return Err(RegistryError::EmptySurfacePath);
            }
            match &entry.contract {
                Some(contract) => {
                    if !contracts.contains_key(contract) {
                        return Err(RegistryError::UnknownSurfaceContract {
                            surface: entry.path,
                            contract: contract.clone(),
                        });
                    }
                    if empty_surfaces.contains(&entry.path) {
                        return Err(RegistryError::ConflictingEmptySurfaceEntry {
                            surface: entry.path,
                        });
                    }
                    if !grouped_surfaces
                        .entry(entry.path.clone())
                        .or_default()
                        .insert(contract.clone())
                    {
                        return Err(RegistryError::DuplicateSurfaceEntry {
                            surface: entry.path,
                            contract: contract.clone(),
                        });
                    }
                }
                None => {
                    if grouped_surfaces.contains_key(&entry.path) {
                        return Err(RegistryError::ConflictingEmptySurfaceEntry {
                            surface: entry.path,
                        });
                    }
                    empty_surfaces.insert(entry.path.clone());
                    grouped_surfaces.entry(entry.path.clone()).or_default();
                }
            }
            if let Some((previous_path, previous_contract)) = &previous_surface {
                let prev_key = (
                    previous_path.as_str(),
                    previous_contract.as_ref().map_or("", ContractId::as_str),
                );
                let curr_key = (
                    entry.path.as_str(),
                    entry.contract.as_ref().map_or("", ContractId::as_str),
                );
                if curr_key < prev_key {
                    return Err(RegistryError::UnsortedSurfaceEntries {
                        previous_path: previous_path.clone(),
                        current_path: entry.path,
                    });
                }
            }
            previous_surface = Some((entry.path, entry.contract));
        }
        let surfaces = grouped_surfaces
            .into_iter()
            .map(|(path, contract_set)| SurfaceAssignment {
                path,
                contracts: contract_set.into_iter().collect(),
            })
            .collect();

        Ok(Self {
            contracts,
            claims,
            surfaces,
            surface_entry_count,
        })
    }

    pub fn get(&self, id: &ContractId) -> Option<&ConformanceContract> {
        self.contracts.get(id)
    }

    pub fn require(&self, id: &str) -> Result<&ConformanceContract, RegistryError> {
        let id = ContractId::new(id)?;
        self.get(&id).ok_or(RegistryError::UnknownContract(id))
    }

    pub fn contracts(&self) -> impl ExactSizeIterator<Item = &ConformanceContract> {
        self.contracts.values()
    }

    pub fn get_claim(&self, id: &ClaimId) -> Option<&Claim> {
        self.claims.get(id)
    }

    pub fn require_claim(&self, id: &str) -> Result<&Claim, RegistryError> {
        let id = ClaimId::new(id)?;
        self.get_claim(&id).ok_or(RegistryError::UnknownClaim(id))
    }

    pub fn claims(&self) -> impl ExactSizeIterator<Item = &Claim> {
        self.claims.values()
    }

    pub fn surfaces(&self) -> &[SurfaceAssignment] {
        &self.surfaces
    }

    pub fn surface_entry_count(&self) -> usize {
        self.surface_entry_count
    }
}

#[derive(Debug)]
pub(crate) struct RegistryIoError {
    pub path: PathBuf,
    pub source: std::io::Error,
}

impl From<RegistryIoError> for RegistryError {
    fn from(err: RegistryIoError) -> Self {
        Self::Io {
            path: err.path,
            source: err.source,
        }
    }
}

/// Enumerates immediate entries under `root` through the crate's reviewed
/// `std::fs::read_dir` authority cohort (`registry::read_contract_paths`).
pub(crate) fn read_contract_paths(
    root: &Path,
) -> Result<Vec<(PathBuf, fs::FileType)>, RegistryIoError> {
    let entries = fs::read_dir(root).map_err(|source| RegistryIoError {
        path: root.to_path_buf(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| RegistryIoError {
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| RegistryIoError {
            path: path.clone(),
            source,
        })?;
        paths.push((path, file_type));
    }
    Ok(paths)
}

fn read_toml_contract_paths(root: &Path) -> Result<Vec<PathBuf>, RegistryError> {
    let mut paths = Vec::new();
    for (path, file_type) in read_contract_paths(root)? {
        if !file_type.is_file()
            || path.extension().and_then(|extension| extension.to_str()) != Some("toml")
        {
            return Err(RegistryError::UnexpectedContractFile(path));
        }
        paths.push(path);
    }
    Ok(paths)
}

/// Reads UTF-8 text from `path` through the crate's reviewed
/// `std::fs::read_to_string` authority cohort (`registry::read_to_string`).
pub(crate) fn read_to_string(path: &Path) -> Result<String, RegistryIoError> {
    fs::read_to_string(path).map_err(|source| RegistryIoError {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_contract(contract: &ConformanceContract) -> Result<(), RegistryError> {
    if contract.semantic_authority.is_empty() {
        return Err(RegistryError::MissingSemanticAuthority(contract.id.clone()));
    }
    if contract.rationale.trim().is_empty() {
        return Err(RegistryError::MissingContractRationale(contract.id.clone()));
    }
    for (layer, entries) in [
        (ExecutionLayer::VmFree, &contract.bindings.vm_free),
        (ExecutionLayer::EmbedStructural, &contract.bindings.embed),
        (ExecutionLayer::Docker, &contract.bindings.docker),
    ] {
        if entries.is_empty() {
            if contract
                .bindings
                .unresolved
                .get(&layer.to_string())
                .is_some_and(|reason| !reason.trim().is_empty())
            {
                continue;
            }
            return Err(RegistryError::MissingBinding {
                id: contract.id.clone(),
                layer,
            });
        }
    }
    for (layer, entries) in [
        (ExecutionLayer::VmFree, &contract.bindings.vm_free),
        (ExecutionLayer::EmbedStructural, &contract.bindings.embed),
        (ExecutionLayer::Docker, &contract.bindings.docker),
        (ExecutionLayer::Ecosystem, &contract.bindings.ecosystem),
    ] {
        let mut seen = BTreeSet::new();
        for entry in entries {
            if entry.trim().is_empty() {
                return Err(RegistryError::EmptyBindingEntry {
                    id: contract.id.clone(),
                    layer,
                });
            }
            if !seen.insert(entry.as_str()) {
                return Err(RegistryError::DuplicateBindingEntry {
                    id: contract.id.clone(),
                    layer,
                    entry: entry.clone(),
                });
            }
        }
    }
    for (index, budget) in contract.structural_budgets.iter().enumerate() {
        if budget.layers.is_empty()
            || budget.layers.iter().any(|layer| {
                !matches!(
                    layer,
                    ExecutionLayer::VmFree | ExecutionLayer::EmbedStructural
                )
            })
        {
            return Err(RegistryError::InvalidBudgetLayers {
                id: contract.id.clone(),
                index,
            });
        }
        if budget
            .rationale
            .as_deref()
            .is_none_or(|rationale| rationale.trim().is_empty())
        {
            return Err(RegistryError::MissingBudgetRationale {
                id: contract.id.clone(),
                index,
            });
        }
    }
    if contract
        .structural_budgets
        .iter()
        .any(|budget| matches!(budget.budget, Budget::Affine { .. }))
        && contract.scale_points.len() < 3
    {
        return Err(RegistryError::InsufficientScalePoints {
            id: contract.id.clone(),
        });
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ClaimsFile {
    Multiple { claims: Vec<Claim> },
    BareList(Vec<Claim>),
    Single(Box<Claim>),
}

impl ClaimsFile {
    fn into_claims(self) -> Vec<Claim> {
        match self {
            ClaimsFile::Multiple { claims } => claims,
            ClaimsFile::BareList(claims) => claims,
            ClaimsFile::Single(claim) => vec![*claim],
        }
    }
}

fn validate_claim(
    claim: &Claim,
    contracts: &BTreeMap<ContractId, ConformanceContract>,
) -> Result<(), RegistryError> {
    if claim.description.trim().is_empty() {
        return Err(RegistryError::MissingClaimDescription(claim.id.clone()));
    }
    if claim.linux_authority.is_empty() || claim.linux_authority.iter().any(|a| a.trim().is_empty())
    {
        return Err(RegistryError::MissingClaimAuthority(claim.id.clone()));
    }
    if !contracts.contains_key(&claim.contract) {
        return Err(RegistryError::UnknownClaimContract {
            claim: claim.id.clone(),
            contract: claim.contract.clone(),
        });
    }
    for related in &claim.related_contracts {
        if !contracts.contains_key(related) {
            return Err(RegistryError::UnknownClaimContract {
                claim: claim.id.clone(),
                contract: related.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("cannot read contract registry path {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid contract TOML {path}: {source}")]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("unexpected non-TOML contract registry entry {0}")]
    UnexpectedContractFile(PathBuf),
    #[error("duplicate contract id {0}")]
    Duplicate(ContractId),
    #[error("duplicate claim id {0}")]
    DuplicateClaim(ClaimId),
    #[error("contract {id} has no rationale for budget {index}")]
    MissingBudgetRationale { id: ContractId, index: usize },
    #[error("contract {id} budget {index} must name at least one structural evidence layer")]
    InvalidBudgetLayers { id: ContractId, index: usize },
    #[error("contract {id} scaling budget requires at least three scale points")]
    InsufficientScalePoints { id: ContractId },
    #[error("surface entry has an empty path")]
    EmptySurfacePath,
    #[error("duplicate surface entry for {surface} -> {contract}")]
    DuplicateSurfaceEntry {
        surface: String,
        contract: ContractId,
    },
    #[error(
        "surface {surface} cannot combine `contracts = []` with another surface entry for the same path"
    )]
    ConflictingEmptySurfaceEntry { surface: String },
    #[error(
        "surfaces.toml entries must be sorted by (path, contract): {current_path} appears after {previous_path}"
    )]
    UnsortedSurfaceEntries {
        previous_path: String,
        current_path: String,
    },
    #[error("surface {surface} references unknown contract family {contract}")]
    UnknownSurfaceContract {
        surface: String,
        contract: ContractId,
    },
    #[error("claim {claim} references unknown contract family {contract}")]
    UnknownClaimContract {
        claim: ClaimId,
        contract: ContractId,
    },
    #[error("claim {0} has no description")]
    MissingClaimDescription(ClaimId),
    #[error("claim {0} has empty semantic authority")]
    MissingClaimAuthority(ClaimId),
    #[error("invalid contract id: {0}")]
    InvalidContractId(#[from] ModelError),
    #[error("unknown contract id {0}")]
    UnknownContract(ContractId),
    #[error("unknown claim id {0}")]
    UnknownClaim(ClaimId),
    #[error("contract {0} has no semantic authority")]
    MissingSemanticAuthority(ContractId),
    #[error("contract {0} has no contract rationale")]
    MissingContractRationale(ContractId),
    #[error("{id}: missing {layer} binding")]
    MissingBinding {
        id: ContractId,
        layer: ExecutionLayer,
    },
    #[error("{id}: empty {layer} binding entry")]
    EmptyBindingEntry {
        id: ContractId,
        layer: ExecutionLayer,
    },
    #[error("{id}: duplicate {layer} binding entry {entry:?}")]
    DuplicateBindingEntry {
        id: ContractId,
        layer: ExecutionLayer,
        entry: String,
    },
}
