use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    Budget, ConformanceContract, ContractId, ExecutionLayer, ModelError, SurfaceAssignment,
    SurfaceRegistry,
};

#[derive(Clone, Debug)]
pub struct ContractRegistry {
    contracts: BTreeMap<ContractId, ConformanceContract>,
    surfaces: Vec<SurfaceAssignment>,
}

impl ContractRegistry {
    pub fn load(root: &Path) -> Result<Self, RegistryError> {
        let registry_root = root.join("conformance-contracts");
        let contracts_root = registry_root.join("contracts");
        let mut paths = read_contract_paths(&contracts_root)?;
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

        let surfaces_path = registry_root.join("surfaces.toml");
        let surfaces_text = read_to_string(&surfaces_path)?;
        let surface_registry: SurfaceRegistry =
            toml::from_str(&surfaces_text).map_err(|source| RegistryError::Toml {
                path: surfaces_path,
                source,
            })?;
        for surface in &surface_registry.surfaces {
            for contract in &surface.contracts {
                if !contracts.contains_key(contract) {
                    return Err(RegistryError::UnknownSurfaceContract {
                        surface: surface.path.clone(),
                        contract: contract.clone(),
                    });
                }
            }
        }

        Ok(Self {
            contracts,
            surfaces: surface_registry.surfaces,
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

    pub fn surfaces(&self) -> &[SurfaceAssignment] {
        &self.surfaces
    }
}

fn read_contract_paths(root: &Path) -> Result<Vec<PathBuf>, RegistryError> {
    let entries = fs::read_dir(root).map_err(|source| RegistryError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| RegistryError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if !entry
            .file_type()
            .map_err(|source| RegistryError::Io {
                path: path.clone(),
                source,
            })?
            .is_file()
            || path.extension().and_then(|extension| extension.to_str()) != Some("toml")
        {
            return Err(RegistryError::UnexpectedContractFile(path));
        }
        paths.push(path);
    }
    Ok(paths)
}

fn read_to_string(path: &Path) -> Result<String, RegistryError> {
    fs::read_to_string(path).map_err(|source| RegistryError::Io {
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
    for (layer, binding) in [
        (ExecutionLayer::VmFree, contract.bindings.vm_free.as_deref()),
        (
            ExecutionLayer::EmbedStructural,
            contract.bindings.embed.as_deref(),
        ),
        (ExecutionLayer::Docker, contract.bindings.docker.as_deref()),
    ] {
        if binding.is_none_or(str::is_empty) {
            return Err(RegistryError::MissingBinding {
                id: contract.id.clone(),
                layer,
            });
        }
    }
    for (index, budget) in contract.structural_budgets.iter().enumerate() {
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
    #[error("contract {id} has no rationale for budget {index}")]
    MissingBudgetRationale { id: ContractId, index: usize },
    #[error("contract {id} scaling budget requires at least three scale points")]
    InsufficientScalePoints { id: ContractId },
    #[error("surface {surface} references unknown contract family {contract}")]
    UnknownSurfaceContract {
        surface: String,
        contract: ContractId,
    },
    #[error("invalid contract id: {0}")]
    InvalidContractId(#[from] ModelError),
    #[error("unknown contract id {0}")]
    UnknownContract(ContractId),
    #[error("contract {0} has no semantic authority")]
    MissingSemanticAuthority(ContractId),
    #[error("contract {0} has no contract rationale")]
    MissingContractRationale(ContractId),
    #[error("{id}: missing {layer} binding")]
    MissingBinding {
        id: ContractId,
        layer: ExecutionLayer,
    },
}
