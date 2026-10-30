use std::{collections::BTreeSet, fs::File, io::Read, path::Path};

use authpath_analysis::{
    AccountSnapshots, DeclaredSigner, Operation, SetOptionsChanges, SignerChange,
    TransactionDescription,
    rotation::{
        ExpectedAccount, ExpectedSigner, PlannedTransaction, ReserveDeclaration, RotationPlan,
        SignerDeclaration,
    },
};
use authpath_model::{
    AccountId, AccountSnapshot, ConfiguredSigner, Ed25519PublicKey, MasterKeyWeight,
    NetworkIdentity, SignerAvailability, SignerType, SignerWeight, SnapshotProvenance, Thresholds,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::error::AppError;

pub(crate) const ACCOUNT_SCHEMA: &str = "authpath.account_snapshot.v1";
pub(crate) const PLAN_SCHEMA: &str = "authpath.rotation_plan.v1";
pub(crate) const OBSERVED_SCHEMA: &str = "authpath.observed_configuration.v1";
pub(crate) const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_PLAN_ACCOUNTS: usize = 256;
pub(crate) const MAX_DECLARED_SIGNERS: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountDocument {
    pub(crate) schema: String,
    pub(crate) account_id: String,
    pub(crate) master_key_weight: u32,
    pub(crate) thresholds: ThresholdInput,
    pub(crate) signers: Vec<SignerInput>,
    pub(crate) provenance: ProvenanceInput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThresholdInput {
    pub(crate) low: u32,
    pub(crate) medium: u32,
    pub(crate) high: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignerInput {
    pub(crate) key: String,
    pub(crate) weight: u32,
    pub(crate) availability: AvailabilityInput,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AvailabilityInput {
    Available,
    Unavailable,
}

impl AvailabilityInput {
    fn model(self) -> SignerAvailability {
        match self {
            Self::Available => SignerAvailability::Available,
            Self::Unavailable => SignerAvailability::Unavailable,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvenanceInput {
    pub(crate) kind: String,
    pub(crate) network: Option<String>,
    pub(crate) ledger_sequence: Option<u32>,
}

impl ProvenanceInput {
    fn model(self) -> Result<SnapshotProvenance, AppError> {
        match self.kind.as_str() {
            "caller_provided" => {
                if self.ledger_sequence.is_some() {
                    return Err(AppError::invalid(
                        "caller_provided provenance cannot contain ledger_sequence",
                    ));
                }
                let network = self
                    .network
                    .map(NetworkIdentity::new)
                    .transpose()
                    .map_err(|error| AppError::invalid(error.to_string()))?;
                Ok(SnapshotProvenance::caller_provided(network))
            }
            "ledger" => {
                let network = self.network.ok_or_else(|| {
                    AppError::invalid("ledger provenance requires a network passphrase")
                })?;
                let network = NetworkIdentity::new(network)
                    .map_err(|error| AppError::invalid(error.to_string()))?;
                let sequence = self.ledger_sequence.ok_or_else(|| {
                    AppError::invalid("ledger provenance requires ledger_sequence")
                })?;
                SnapshotProvenance::ledger(network, sequence)
                    .map_err(|error| AppError::invalid(error.to_string()))
            }
            kind => Err(AppError::invalid(format!(
                "unsupported provenance kind {kind:?}"
            ))),
        }
    }
}

impl AccountDocument {
    pub(crate) fn into_model(self) -> Result<AccountSnapshot, AppError> {
        if self.schema != ACCOUNT_SCHEMA {
            return Err(AppError::invalid(format!(
                "unsupported account schema {:?}; expected {ACCOUNT_SCHEMA:?}",
                self.schema
            )));
        }
        if self.signers.len() > authpath_model::MAX_SIGNERS {
            return Err(AppError::invalid(format!(
                "account snapshot contains too many signers: {} (maximum {})",
                self.signers.len(),
                authpath_model::MAX_SIGNERS
            )));
        }

        let account_id = parse_account(&self.account_id, "account_id")?;
        let master_key_weight = MasterKeyWeight::new(self.master_key_weight)
            .map_err(|error| AppError::invalid(error.to_string()))?;
        let thresholds = Thresholds::new(
            self.thresholds.low,
            self.thresholds.medium,
            self.thresholds.high,
        )
        .map_err(|error| AppError::invalid(error.to_string()))?;
        let mut signers = self
            .signers
            .into_iter()
            .map(|signer| {
                let key = parse_key(&signer.key, "signer key")?;
                let weight = SignerWeight::new(signer.weight)
                    .map_err(|error| AppError::invalid(error.to_string()))?;
                Ok(ConfiguredSigner::new(
                    key,
                    weight,
                    signer.availability.model(),
                ))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        signers.sort_by_key(|signer| *signer.key());

        AccountSnapshot::new(
            account_id,
            master_key_weight,
            thresholds,
            signers,
            self.provenance.model()?,
        )
        .map_err(|error| AppError::invalid(error.to_string()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotationPlanDocument {
    pub(crate) schema: String,
    pub(crate) initial_accounts: Vec<AccountDocument>,
    pub(crate) available_signers: Vec<AvailableSignerInput>,
    pub(crate) transactions: Vec<TransactionInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AvailableSignerInput {
    pub(crate) kind: String,
    pub(crate) key: Option<String>,
    pub(crate) code: Option<u32>,
}

impl AvailableSignerInput {
    fn into_declared(self) -> Result<DeclaredSigner, AppError> {
        match self.kind.as_str() {
            "ed25519" => {
                if self.code.is_some() {
                    return Err(AppError::invalid(
                        "ed25519 available signer cannot contain code",
                    ));
                }
                let key = self
                    .key
                    .ok_or_else(|| AppError::invalid("ed25519 signer requires key"))?;
                Ok(DeclaredSigner::Ed25519(parse_key(
                    &key,
                    "available signer key",
                )?))
            }
            "pre_auth_tx" => unsupported_signer(self.key, self.code, SignerType::PreAuthTx),
            "hash_x" => unsupported_signer(self.key, self.code, SignerType::HashX),
            "ed25519_signed_payload" => {
                unsupported_signer(self.key, self.code, SignerType::Ed25519SignedPayload)
            }
            "unknown" => {
                if self.key.is_some() {
                    return Err(AppError::invalid("unknown signer type cannot contain key"));
                }
                let code = self
                    .code
                    .ok_or_else(|| AppError::invalid("unknown signer type requires code"))?;
                Ok(DeclaredSigner::Unsupported(SignerType::Unknown(code)))
            }
            kind => Err(AppError::invalid(format!(
                "unsupported available signer kind {kind:?}"
            ))),
        }
    }
}

fn unsupported_signer(
    key: Option<String>,
    code: Option<u32>,
    signer_type: SignerType,
) -> Result<DeclaredSigner, AppError> {
    if key.is_some() || code.is_some() {
        return Err(AppError::invalid(format!(
            "{signer_type} signer declaration cannot contain key or code"
        )));
    }
    Ok(DeclaredSigner::Unsupported(signer_type))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransactionInput {
    pub(crate) source_account: String,
    pub(crate) operations: Vec<OperationInput>,
    pub(crate) signer_availability: Vec<SignerDeclarationInput>,
    pub(crate) reserve: ReserveInput,
    pub(crate) expected: Vec<ExpectedAccountInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationInput {
    pub(crate) kind: String,
    pub(crate) source_account: Option<String>,
    pub(crate) changes: Option<SetOptionsInput>,
}

impl OperationInput {
    fn into_model(self) -> Result<Operation, AppError> {
        let source = self
            .source_account
            .as_deref()
            .map(|value| parse_account(value, "operation source_account"))
            .transpose()?;
        match self.kind.as_str() {
            "payment" => {
                require_no_changes(self.changes, "payment").map(|()| Operation::payment(source))
            }
            "bump_sequence" => require_no_changes(self.changes, "bump_sequence")
                .map(|()| Operation::bump_sequence(source)),
            "account_merge" => require_no_changes(self.changes, "account_merge")
                .map(|()| Operation::account_merge(source)),
            "set_options" => {
                let changes = self
                    .changes
                    .ok_or_else(|| AppError::invalid("set_options requires changes"))?
                    .into_model()?;
                Ok(Operation::set_options(source, changes))
            }
            kind => {
                require_no_changes(self.changes, kind)?;
                Ok(Operation::unsupported(source, kind))
            }
        }
    }
}

fn require_no_changes(changes: Option<SetOptionsInput>, kind: &str) -> Result<(), AppError> {
    if changes.is_some() {
        return Err(AppError::invalid(format!("{kind} cannot contain changes")));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetOptionsInput {
    pub(crate) master_key_weight: Option<u32>,
    pub(crate) low_threshold: Option<u32>,
    pub(crate) medium_threshold: Option<u32>,
    pub(crate) high_threshold: Option<u32>,
    pub(crate) signer: Option<SignerChangeInput>,
    pub(crate) set_flags: Option<bool>,
    pub(crate) clear_flags: Option<bool>,
    pub(crate) inflation_destination: Option<serde_json::Value>,
    pub(crate) home_domain: Option<serde_json::Value>,
}

impl SetOptionsInput {
    fn into_model(self) -> Result<SetOptionsChanges, AppError> {
        let mut changes = SetOptionsChanges::new();
        changes.master_key_weight = self
            .master_key_weight
            .map(MasterKeyWeight::new)
            .transpose()
            .map_err(|error| AppError::invalid(error.to_string()))?;
        changes.low_threshold = self
            .low_threshold
            .map(|value| Thresholds::new(value, 0, 0).map(|thresholds| thresholds.low()))
            .transpose()
            .map_err(|error| AppError::invalid(error.to_string()))?;
        changes.medium_threshold = self
            .medium_threshold
            .map(|value| Thresholds::new(0, value, 0).map(|thresholds| thresholds.medium()))
            .transpose()
            .map_err(|error| AppError::invalid(error.to_string()))?;
        changes.high_threshold = self
            .high_threshold
            .map(|value| Thresholds::new(0, 0, value).map(|thresholds| thresholds.high()))
            .transpose()
            .map_err(|error| AppError::invalid(error.to_string()))?;
        changes.signer = self.signer.map(SignerChangeInput::into_model).transpose()?;
        changes.has_set_flags = self.set_flags.is_some();
        changes.has_clear_flags = self.clear_flags.is_some();
        let inflation_destination = self.inflation_destination;
        let home_domain = self.home_domain;
        changes.has_inflation_destination = inflation_destination.is_some();
        changes.has_home_domain = home_domain.is_some();
        validate_non_authorization_field(inflation_destination, "inflation_destination")?;
        validate_non_authorization_field(home_domain, "home_domain")?;
        Ok(changes)
    }
}

fn validate_non_authorization_field(
    value: Option<serde_json::Value>,
    name: &str,
) -> Result<(), AppError> {
    if let Some(value) = value {
        if !(value.is_null() || value.is_string()) {
            return Err(AppError::invalid(format!(
                "{name} must be a string or null"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignerChangeInput {
    pub(crate) key: String,
    pub(crate) weight: u32,
}

impl SignerChangeInput {
    fn into_model(self) -> Result<SignerChange, AppError> {
        let key = parse_key(&self.key, "signer change key")?;
        let weight =
            SignerWeight::new(self.weight).map_err(|error| AppError::invalid(error.to_string()))?;
        Ok(SignerChange::new(key, weight))
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReserveInput {
    Unverified,
    DeclaredInsufficient,
}

impl ReserveInput {
    fn model(self) -> ReserveDeclaration {
        match self {
            Self::Unverified => ReserveDeclaration::Unverified,
            Self::DeclaredInsufficient => ReserveDeclaration::DeclaredInsufficient,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignerDeclarationInput {
    pub(crate) operation_index: usize,
    pub(crate) key: String,
    pub(crate) availability: AvailabilityInput,
}

impl SignerDeclarationInput {
    fn into_model(self) -> Result<SignerDeclaration, AppError> {
        Ok(SignerDeclaration::new(
            self.operation_index,
            parse_key(&self.key, "signer availability key")?,
            self.availability.model(),
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedAccountInput {
    pub(crate) account_id: String,
    pub(crate) master_key_weight: u32,
    pub(crate) thresholds: ThresholdInput,
    pub(crate) signers: Vec<ExpectedSignerInput>,
}

impl ExpectedAccountInput {
    fn into_model(self) -> Result<ExpectedAccount, AppError> {
        if self.signers.len() > authpath_model::MAX_SIGNERS {
            return Err(AppError::invalid(format!(
                "expected account contains too many signers: {} (maximum {})",
                self.signers.len(),
                authpath_model::MAX_SIGNERS
            )));
        }
        let signers = self
            .signers
            .into_iter()
            .map(|signer| {
                Ok(ExpectedSigner::new(
                    parse_key(&signer.key, "expected signer key")?,
                    SignerWeight::new(signer.weight)
                        .map_err(|error| AppError::invalid(error.to_string()))?,
                ))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let master = MasterKeyWeight::new(self.master_key_weight)
            .map_err(|error| AppError::invalid(error.to_string()))?;
        let thresholds = Thresholds::new(
            self.thresholds.low,
            self.thresholds.medium,
            self.thresholds.high,
        )
        .map_err(|error| AppError::invalid(error.to_string()))?;
        ExpectedAccount::new(
            parse_account(&self.account_id, "expected account_id")?,
            master,
            thresholds,
            signers,
        )
        .map_err(|error| AppError::invalid(error.to_string()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedSignerInput {
    pub(crate) key: String,
    pub(crate) weight: u32,
}

impl RotationPlanDocument {
    pub(crate) fn into_model(self) -> Result<RotationPlan, AppError> {
        if self.schema != PLAN_SCHEMA {
            return Err(AppError::invalid(format!(
                "unsupported rotation-plan schema {:?}; expected {PLAN_SCHEMA:?}",
                self.schema
            )));
        }
        if self.initial_accounts.len() > MAX_PLAN_ACCOUNTS {
            return Err(AppError::invalid(format!(
                "rotation plan contains too many initial accounts: {} (maximum {MAX_PLAN_ACCOUNTS})",
                self.initial_accounts.len()
            )));
        }
        if self.available_signers.len() > MAX_DECLARED_SIGNERS {
            return Err(AppError::invalid(format!(
                "rotation plan contains too many available signer declarations: {} (maximum {MAX_DECLARED_SIGNERS})",
                self.available_signers.len()
            )));
        }

        let initial = self
            .initial_accounts
            .into_iter()
            .map(AccountDocument::into_model)
            .collect::<Result<Vec<_>, AppError>>()?;
        let initial =
            AccountSnapshots::new(initial).map_err(|error| AppError::invalid(error.to_string()))?;
        let available = parse_declared_signers(self.available_signers)?;
        let transactions = self
            .transactions
            .into_iter()
            .map(TransactionInput::into_model)
            .collect::<Result<Vec<_>, AppError>>()?;
        RotationPlan::new(initial, available, transactions)
            .map_err(|error| AppError::invalid(error.to_string()))
    }
}

impl TransactionInput {
    fn into_model(self) -> Result<PlannedTransaction, AppError> {
        let source = parse_account(&self.source_account, "transaction source_account")?;
        if self.operations.len() > authpath_analysis::rotation::MAX_OPERATIONS_PER_TRANSACTION {
            return Err(AppError::invalid(format!(
                "transaction contains too many operations: {} (maximum {})",
                self.operations.len(),
                authpath_analysis::rotation::MAX_OPERATIONS_PER_TRANSACTION
            )));
        }
        let operations = self
            .operations
            .into_iter()
            .map(|operation| operation.into_model())
            .collect::<Result<Vec<_>, AppError>>()?;
        let description = TransactionDescription::new(source, operations)
            .map_err(|error| AppError::invalid(error.to_string()))?;
        let declarations = self
            .signer_availability
            .into_iter()
            .map(SignerDeclarationInput::into_model)
            .collect::<Result<Vec<_>, AppError>>()?;
        let expected = self
            .expected
            .into_iter()
            .map(ExpectedAccountInput::into_model)
            .collect::<Result<Vec<_>, AppError>>()?;
        PlannedTransaction::new(description, declarations, self.reserve.model(), expected)
            .map_err(|error| AppError::invalid(error.to_string()))
    }
}

fn parse_declared_signers(
    inputs: Vec<AvailableSignerInput>,
) -> Result<Vec<DeclaredSigner>, AppError> {
    let mut seen_ed25519 = BTreeSet::new();
    let mut seen_unsupported = BTreeSet::new();
    let mut declarations = Vec::with_capacity(inputs.len());
    for input in inputs {
        let declaration = input.into_declared()?;
        match declaration {
            DeclaredSigner::Ed25519(key) => {
                if !seen_ed25519.insert(key) {
                    return Err(AppError::invalid(format!(
                        "duplicate available signer {key}"
                    )));
                }
            }
            DeclaredSigner::Unsupported(signer_type) => {
                if !seen_unsupported.insert(signer_type) {
                    return Err(AppError::invalid(format!(
                        "duplicate unsupported signer declaration {signer_type}"
                    )));
                }
            }
        }
        declarations.push(declaration);
    }
    Ok(declarations)
}

pub(crate) fn load_account(path: &Path) -> Result<AccountSnapshot, AppError> {
    read_json::<AccountDocument>(path)?.into_model()
}

pub(crate) fn load_plan(path: &Path) -> Result<RotationPlan, AppError> {
    read_json::<RotationPlanDocument>(path)?.into_model()
}

pub(crate) fn parse_account(value: &str, field: &str) -> Result<AccountId, AppError> {
    value
        .parse()
        .map_err(|error| AppError::invalid(format!("{field} is invalid: {error}")))
}

pub(crate) fn parse_key(value: &str, field: &str) -> Result<Ed25519PublicKey, AppError> {
    value
        .parse()
        .map_err(|error| AppError::invalid(format!("{field} is invalid: {error}")))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, AppError> {
    let mut file = File::open(path).map_err(|error| AppError::io(path, error))?;
    let metadata = file.metadata().map_err(|error| AppError::io(path, error))?;
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(AppError::invalid(format!(
            "{} exceeds the {}-byte input limit",
            path.display(),
            MAX_INPUT_BYTES
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
    file.by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| AppError::io(path, error))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(AppError::invalid(format!(
            "{} exceeds the {}-byte input limit",
            path.display(),
            MAX_INPUT_BYTES
        )));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        AppError::invalid(format!("{} is malformed JSON: {error}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_requires_ledger_fields() {
        let error = ProvenanceInput {
            kind: "ledger".to_owned(),
            network: None,
            ledger_sequence: None,
        }
        .model()
        .unwrap_err();
        assert!(error.to_string().contains("network"));
    }

    #[test]
    fn unknown_account_schema_is_rejected() {
        let document = AccountDocument {
            schema: "authpath.account_snapshot.v2".to_owned(),
            account_id: String::new(),
            master_key_weight: 0,
            thresholds: ThresholdInput {
                low: 0,
                medium: 0,
                high: 0,
            },
            signers: Vec::new(),
            provenance: ProvenanceInput {
                kind: "caller_provided".to_owned(),
                network: None,
                ledger_sequence: None,
            },
        };
        assert!(document.into_model().is_err());
    }
}
