//! Conservative authorization-threshold analysis for classic Stellar
//! transactions.
//!
//! The analysis answers only whether caller-declared Ed25519 identities have
//! enough configured weight for the modeled authorization checks. It does not
//! verify cryptographic signatures, prove private-key possession, validate
//! ledger evidence, or guarantee transaction execution.

#![forbid(unsafe_code)]

pub mod rotation;

use std::{collections::BTreeMap, fmt};

use authpath_model::{
    AccountId, AccountSnapshot, Ed25519PublicKey, MasterKeyWeight, SignerAvailability, SignerType,
};

/// The threshold category used by a Stellar authorization check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThresholdCategory {
    /// The account's low threshold.
    Low,
    /// The account's medium threshold.
    Medium,
    /// The account's high threshold.
    High,
}

impl fmt::Display for ThresholdCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => formatter.write_str("low"),
            Self::Medium => formatter.write_str("medium"),
            Self::High => formatter.write_str("high"),
        }
    }
}

/// The deliberately narrow set of classic operations modeled by C2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// A native or issued-asset payment.
    Payment,
    /// A sequence-number bump.
    BumpSequence,
    /// An account merge.
    AccountMerge,
    /// An account-options update.
    SetOptions,
}

impl fmt::Display for OperationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payment => formatter.write_str("payment"),
            Self::BumpSequence => formatter.write_str("bump-sequence"),
            Self::AccountMerge => formatter.write_str("account-merge"),
            Self::SetOptions => formatter.write_str("set-options"),
        }
    }
}

/// The part of a transaction represented by an authorization finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationSubject {
    /// The transaction's top-level source-account check.
    TransactionSource,
    /// An individual operation's source-account check.
    Operation {
        /// The zero-based operation index.
        index: usize,
        /// The supported operation kind.
        kind: OperationKind,
    },
}

impl fmt::Display for AuthorizationSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionSource => formatter.write_str("transaction source"),
            Self::Operation { index, kind } => {
                write!(formatter, "operation {index} ({kind})")
            }
        }
    }
}

/// A signer change included in a SetOptions authorization description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerChange {
    key: Ed25519PublicKey,
    weight: authpath_model::SignerWeight,
}

impl SignerChange {
    /// Constructs a signer change. A weight of zero is retained as a
    /// snapshot/operation value and still makes SetOptions high-threshold.
    #[must_use]
    pub const fn new(key: Ed25519PublicKey, weight: authpath_model::SignerWeight) -> Self {
        Self { key, weight }
    }

    /// Returns the signer key affected by the change.
    #[must_use]
    pub const fn key(self) -> Ed25519PublicKey {
        self.key
    }

    /// Returns the configured signer weight in the description.
    #[must_use]
    pub const fn weight(self) -> authpath_model::SignerWeight {
        self.weight
    }
}

/// The SetOptions fields relevant to authorization classification.
///
/// C2 models field presence rather than applying the operation. Any master
/// weight, threshold, or signer field makes SetOptions high-threshold;
/// otherwise a non-empty SetOptions operation is medium-threshold.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SetOptionsChanges {
    /// A present master-key weight update.
    pub master_key_weight: Option<MasterKeyWeight>,
    /// A present low-threshold update.
    pub low_threshold: Option<authpath_model::Threshold>,
    /// A present medium-threshold update.
    pub medium_threshold: Option<authpath_model::Threshold>,
    /// A present high-threshold update.
    pub high_threshold: Option<authpath_model::Threshold>,
    /// A present signer add, removal, or weight update.
    pub signer: Option<SignerChange>,
    /// Whether a set-flags field is present.
    pub has_set_flags: bool,
    /// Whether a clear-flags field is present.
    pub has_clear_flags: bool,
    /// Whether an inflation-destination field is present.
    pub has_inflation_destination: bool,
    /// Whether a home-domain field is present.
    pub has_home_domain: bool,
}

impl SetOptionsChanges {
    /// Creates an empty SetOptions description.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            master_key_weight: None,
            low_threshold: None,
            medium_threshold: None,
            high_threshold: None,
            signer: None,
            has_set_flags: false,
            has_clear_flags: false,
            has_inflation_destination: false,
            has_home_domain: false,
        }
    }

    /// Reports whether at least one SetOptions field is present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.master_key_weight.is_none()
            && self.low_threshold.is_none()
            && self.medium_threshold.is_none()
            && self.high_threshold.is_none()
            && self.signer.is_none()
            && !self.has_set_flags
            && !self.has_clear_flags
            && !self.has_inflation_destination
            && !self.has_home_domain
    }

    /// Reports whether this variation requires the high threshold.
    #[must_use]
    pub const fn requires_high_threshold(&self) -> bool {
        self.master_key_weight.is_some()
            || self.low_threshold.is_some()
            || self.medium_threshold.is_some()
            || self.high_threshold.is_some()
            || self.signer.is_some()
    }
}

/// A bounded operation description containing only authorization-relevant
/// fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    /// A payment operation.
    Payment {
        /// An explicit operation source, or the transaction source when absent.
        source: Option<AccountId>,
    },
    /// A BumpSequence operation.
    BumpSequence {
        /// An explicit operation source, or the transaction source when absent.
        source: Option<AccountId>,
    },
    /// An AccountMerge operation.
    AccountMerge {
        /// An explicit operation source, or the transaction source when absent.
        source: Option<AccountId>,
    },
    /// A SetOptions operation.
    SetOptions {
        /// An explicit operation source, or the transaction source when absent.
        source: Option<AccountId>,
        /// The fields present in the operation.
        changes: SetOptionsChanges,
    },
    /// An operation kind intentionally rejected by the analyzer.
    Unsupported {
        /// An explicit operation source, if one was supplied.
        source: Option<AccountId>,
        /// The caller-provided operation type name.
        operation_type: String,
    },
}

impl Operation {
    /// Constructs a payment with an optional explicit operation source.
    #[must_use]
    pub const fn payment(source: Option<AccountId>) -> Self {
        Self::Payment { source }
    }

    /// Constructs a BumpSequence operation with an optional explicit source.
    #[must_use]
    pub const fn bump_sequence(source: Option<AccountId>) -> Self {
        Self::BumpSequence { source }
    }

    /// Constructs an AccountMerge operation with an optional explicit source.
    #[must_use]
    pub const fn account_merge(source: Option<AccountId>) -> Self {
        Self::AccountMerge { source }
    }

    /// Constructs a SetOptions operation with an optional explicit source.
    #[must_use]
    pub const fn set_options(source: Option<AccountId>, changes: SetOptionsChanges) -> Self {
        Self::SetOptions { source, changes }
    }

    /// Constructs an unsupported operation that will fail closed during analysis.
    pub fn unsupported(source: Option<AccountId>, operation_type: impl Into<String>) -> Self {
        Self::Unsupported {
            source,
            operation_type: operation_type.into(),
        }
    }

    /// Returns the explicit operation source, if supplied.
    #[must_use]
    pub const fn source_account(&self) -> Option<AccountId> {
        match self {
            Self::Payment { source }
            | Self::BumpSequence { source }
            | Self::AccountMerge { source }
            | Self::SetOptions { source, .. }
            | Self::Unsupported { source, .. } => *source,
        }
    }
}

/// A transaction description containing only authorization-relevant fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionDescription {
    source_account: AccountId,
    operations: Vec<Operation>,
}

impl TransactionDescription {
    /// Constructs a transaction with a required source account.
    pub fn new(
        source_account: AccountId,
        operations: Vec<Operation>,
    ) -> Result<Self, AnalysisError> {
        Self::try_new(Some(source_account), operations)
    }

    /// Constructs a transaction from an input boundary where the source may
    /// be missing.
    pub fn try_new(
        source_account: Option<AccountId>,
        operations: Vec<Operation>,
    ) -> Result<Self, AnalysisError> {
        let source_account = source_account.ok_or(AnalysisError::InvalidTransaction {
            reason: InvalidTransactionReason::MissingSourceAccount,
        })?;
        if operations.is_empty() {
            return Err(AnalysisError::InvalidTransaction {
                reason: InvalidTransactionReason::EmptyOperations,
            });
        }
        Ok(Self {
            source_account,
            operations,
        })
    }

    /// Returns the transaction source account.
    #[must_use]
    pub const fn source_account(&self) -> AccountId {
        self.source_account
    }

    /// Returns the described operations in transaction order.
    #[must_use]
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
}

/// A validated collection of account snapshots keyed by account identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountSnapshots {
    by_account: BTreeMap<AccountId, AccountSnapshot>,
}

impl AccountSnapshots {
    /// Validates and indexes account snapshots.
    pub fn new<I>(snapshots: I) -> Result<Self, AnalysisError>
    where
        I: IntoIterator<Item = AccountSnapshot>,
    {
        let mut by_account = BTreeMap::new();
        for snapshot in snapshots {
            let account = *snapshot.account_id();
            if by_account.insert(account, snapshot).is_some() {
                return Err(AnalysisError::AmbiguousAccountSnapshots { account });
            }
        }
        Ok(Self { by_account })
    }

    /// Returns a snapshot by account identity.
    #[must_use]
    pub fn get(&self, account: &AccountId) -> Option<&AccountSnapshot> {
        self.by_account.get(account)
    }

    /// Returns the number of indexed snapshots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_account.len()
    }

    /// Reports whether no snapshots are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_account.is_empty()
    }
}

impl TryFrom<Vec<AccountSnapshot>> for AccountSnapshots {
    type Error = AnalysisError;

    fn try_from(value: Vec<AccountSnapshot>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A signer declaration at the analysis input boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclaredSigner {
    /// A supported Ed25519 signer identity.
    Ed25519(Ed25519PublicKey),
    /// A signer kind that must not be coerced into Ed25519.
    Unsupported(SignerType),
}

/// A deduplicated set of caller-declared available Ed25519 identities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AvailableSigners {
    keys: std::collections::BTreeSet<Ed25519PublicKey>,
}

impl AvailableSigners {
    /// Creates a deduplicated set of Ed25519 identities.
    #[must_use]
    pub fn new<I>(keys: I) -> Self
    where
        I: IntoIterator<Item = Ed25519PublicKey>,
    {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    /// Converts typed signer declarations, failing closed on unsupported kinds.
    pub fn from_declarations<I>(declarations: I) -> Result<Self, AnalysisError>
    where
        I: IntoIterator<Item = DeclaredSigner>,
    {
        let mut keys = std::collections::BTreeSet::new();
        for declaration in declarations {
            match declaration {
                DeclaredSigner::Ed25519(key) => {
                    keys.insert(key);
                }
                DeclaredSigner::Unsupported(signer_type) => {
                    return Err(AnalysisError::UnsupportedSignerType { signer_type });
                }
            }
        }
        Ok(Self { keys })
    }

    /// Reports whether an identity was explicitly declared available.
    #[must_use]
    pub fn contains(&self, key: &Ed25519PublicKey) -> bool {
        self.keys.contains(key)
    }

    /// Returns the number of distinct declared identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Reports whether no identities were declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Reasons a transaction description is not analyzable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidTransactionReason {
    /// No transaction source account was supplied.
    MissingSourceAccount,
    /// The transaction contained no operations.
    EmptyOperations,
}

impl fmt::Display for InvalidTransactionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSourceAccount => formatter.write_str("missing source account"),
            Self::EmptyOperations => formatter.write_str("transaction has no operations"),
        }
    }
}

/// Reasons an operation description is not analyzable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidOperationReason {
    /// SetOptions contained no present field.
    EmptySetOptionsChanges,
}

impl fmt::Display for InvalidOperationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySetOptionsChanges => {
                formatter.write_str("SetOptions contains no present field")
            }
        }
    }
}

/// Errors that prevent a conservative authorization analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnalysisError {
    /// The transaction description is malformed or incomplete.
    InvalidTransaction { reason: InvalidTransactionReason },
    /// An operation description is malformed or incomplete.
    InvalidOperation {
        /// The zero-based operation index.
        index: usize,
        /// The validation reason.
        reason: InvalidOperationReason,
    },
    /// The operation type is outside the deliberate C2 support boundary.
    UnsupportedOperation {
        /// The zero-based operation index.
        index: usize,
        /// The caller-provided operation name.
        operation_type: String,
    },
    /// No snapshot was supplied for an account that must authorize a check.
    MissingAccountSnapshot {
        /// The account whose snapshot is missing.
        account: AccountId,
        /// The check that needed the snapshot.
        subject: AuthorizationSubject,
    },
    /// More than one snapshot was supplied for the same account.
    AmbiguousAccountSnapshots { account: AccountId },
    /// The snapshot has no network identity for analysis.
    InsufficientProvenance {
        /// The account whose provenance is insufficient.
        account: AccountId,
        /// The check that needed the snapshot.
        subject: AuthorizationSubject,
    },
    /// Snapshots from different network identities were mixed.
    NetworkMismatch { account: AccountId },
    /// A declared signer kind is outside the Ed25519-only boundary.
    UnsupportedSignerType { signer_type: SignerType },
    /// A checked sum could not be represented by the analysis accumulator.
    WeightOverflow,
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransaction { reason } => {
                write!(formatter, "invalid transaction: {reason}")
            }
            Self::InvalidOperation { index, reason } => {
                write!(formatter, "invalid operation {index}: {reason}")
            }
            Self::UnsupportedOperation {
                index,
                operation_type,
            } => write!(formatter, "unsupported operation {index}: {operation_type}"),
            Self::MissingAccountSnapshot { account, subject } => {
                write!(
                    formatter,
                    "missing snapshot for {account} while evaluating {subject}"
                )
            }
            Self::AmbiguousAccountSnapshots { account } => {
                write!(formatter, "multiple snapshots supplied for {account}")
            }
            Self::InsufficientProvenance { account, subject } => {
                write!(
                    formatter,
                    "snapshot for {account} lacks network provenance while evaluating {subject}"
                )
            }
            Self::NetworkMismatch { account } => {
                write!(
                    formatter,
                    "snapshot for {account} is from a different network"
                )
            }
            Self::UnsupportedSignerType { signer_type } => {
                write!(formatter, "unsupported signer type {signer_type}")
            }
            Self::WeightOverflow => formatter.write_str("configured signer weight overflow"),
        }
    }
}

impl std::error::Error for AnalysisError {}

/// Limitations attached to every successful analysis finding and report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceLimitation {
    /// Signature bytes were not cryptographically checked.
    CryptographicSignaturesNotVerified,
    /// Private-key possession was not proven.
    SignerPossessionNotVerified,
    /// Ledger evidence was not fetched or verified.
    LedgerEvidenceNotVerified,
    /// Execution success was not simulated or guaranteed.
    ExecutionNotGuaranteed,
}

static LIMITATIONS: [EvidenceLimitation; 4] = [
    EvidenceLimitation::CryptographicSignaturesNotVerified,
    EvidenceLimitation::SignerPossessionNotVerified,
    EvidenceLimitation::LedgerEvidenceNotVerified,
    EvidenceLimitation::ExecutionNotGuaranteed,
];

/// The structured explanation for a threshold result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationExplanation {
    /// The available configured weight reaches the required threshold.
    RequirementMet,
    /// The available configured weight is short by this amount.
    MissingWeight { missing: u64 },
    /// The threshold is met numerically, but no declared identity matches a
    /// signer with positive weight. stellar-core only compares weight to the
    /// threshold after a signature matches a listed signer, so even a
    /// threshold of zero requires one matching signature.
    NoMatchingSigner,
}

/// One transaction-source or operation-source authorization requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationFinding {
    account: AccountId,
    subject: AuthorizationSubject,
    threshold: ThresholdCategory,
    required_weight: u64,
    available_weight: u64,
    meets_requirement: bool,
    explanation: AuthorizationExplanation,
}

impl AuthorizationFinding {
    /// Returns the account being evaluated.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the transaction or operation being evaluated.
    #[must_use]
    pub const fn subject(&self) -> AuthorizationSubject {
        self.subject
    }

    /// Returns the required threshold category.
    #[must_use]
    pub const fn threshold(&self) -> ThresholdCategory {
        self.threshold
    }

    /// Returns the required configured weight.
    #[must_use]
    pub const fn required_weight(&self) -> u64 {
        self.required_weight
    }

    /// Returns the available configured signing weight.
    #[must_use]
    pub const fn available_weight(&self) -> u64 {
        self.available_weight
    }

    /// Reports whether the declared identities meet this requirement.
    #[must_use]
    pub const fn meets_requirement(&self) -> bool {
        self.meets_requirement
    }

    /// Returns the structured result explanation.
    #[must_use]
    pub const fn explanation(&self) -> AuthorizationExplanation {
        self.explanation
    }

    /// Returns the fixed evidence and assumption limitations.
    #[must_use]
    pub fn limitations(&self) -> &'static [EvidenceLimitation] {
        &LIMITATIONS
    }
}

/// The conclusion of a successful threshold analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationConclusion {
    /// Every modeled authorization requirement is met by configured weight.
    MeetsConfiguredRequirements,
    /// At least one modeled authorization requirement is not met.
    DoesNotMeetConfiguredRequirements,
}

/// A complete conservative analysis report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationReport {
    transaction_source: AccountId,
    findings: Vec<AuthorizationFinding>,
}

impl AuthorizationReport {
    /// Returns the transaction source account.
    #[must_use]
    pub const fn transaction_source(&self) -> AccountId {
        self.transaction_source
    }

    /// Returns findings in transaction-source-then-operation order.
    #[must_use]
    pub fn findings(&self) -> &[AuthorizationFinding] {
        &self.findings
    }

    /// Returns the report conclusion.
    #[must_use]
    pub fn conclusion(&self) -> AuthorizationConclusion {
        if self
            .findings
            .iter()
            .all(AuthorizationFinding::meets_requirement)
        {
            AuthorizationConclusion::MeetsConfiguredRequirements
        } else {
            AuthorizationConclusion::DoesNotMeetConfiguredRequirements
        }
    }

    /// Reports whether all modeled requirements are met.
    #[must_use]
    pub fn meets_configured_requirements(&self) -> bool {
        matches!(
            self.conclusion(),
            AuthorizationConclusion::MeetsConfiguredRequirements
        )
    }

    /// Returns the fixed evidence and assumption limitations.
    #[must_use]
    pub fn limitations(&self) -> &'static [EvidenceLimitation] {
        &LIMITATIONS
    }
}

/// Analyzes transaction-source and supported operation-source authorization.
pub fn analyze(
    transaction: &TransactionDescription,
    accounts: &AccountSnapshots,
    available_signers: &AvailableSigners,
) -> Result<AuthorizationReport, AnalysisError> {
    let source_account = transaction.source_account();
    let mut findings = Vec::with_capacity(transaction.operations().len() + 1);
    let mut network = None;

    findings.push(evaluate_requirement(
        accounts,
        available_signers,
        source_account,
        AuthorizationSubject::TransactionSource,
        ThresholdCategory::Low,
        &mut network,
    )?);

    for (index, operation) in transaction.operations().iter().enumerate() {
        let (kind, threshold) = match operation {
            Operation::Payment { .. } => (OperationKind::Payment, ThresholdCategory::Medium),
            Operation::BumpSequence { .. } => (OperationKind::BumpSequence, ThresholdCategory::Low),
            Operation::AccountMerge { .. } => {
                (OperationKind::AccountMerge, ThresholdCategory::High)
            }
            Operation::SetOptions { changes, .. } => {
                if changes.is_empty() {
                    return Err(AnalysisError::InvalidOperation {
                        index,
                        reason: InvalidOperationReason::EmptySetOptionsChanges,
                    });
                }
                let threshold = if changes.requires_high_threshold() {
                    ThresholdCategory::High
                } else {
                    ThresholdCategory::Medium
                };
                (OperationKind::SetOptions, threshold)
            }
            Operation::Unsupported { operation_type, .. } => {
                return Err(AnalysisError::UnsupportedOperation {
                    index,
                    operation_type: operation_type.clone(),
                });
            }
        };

        let account = operation.source_account().unwrap_or(source_account);
        findings.push(evaluate_requirement(
            accounts,
            available_signers,
            account,
            AuthorizationSubject::Operation { index, kind },
            threshold,
            &mut network,
        )?);
    }

    Ok(AuthorizationReport {
        transaction_source: source_account,
        findings,
    })
}

fn evaluate_requirement(
    accounts: &AccountSnapshots,
    available_signers: &AvailableSigners,
    account: AccountId,
    subject: AuthorizationSubject,
    threshold: ThresholdCategory,
    network: &mut Option<authpath_model::NetworkIdentity>,
) -> Result<AuthorizationFinding, AnalysisError> {
    let snapshot = accounts
        .get(&account)
        .ok_or(AnalysisError::MissingAccountSnapshot { account, subject })?;

    let snapshot_network = snapshot
        .provenance()
        .network()
        .ok_or(AnalysisError::InsufficientProvenance { account, subject })?;
    if let Some(expected_network) = network {
        if expected_network != snapshot_network {
            return Err(AnalysisError::NetworkMismatch { account });
        }
    } else {
        *network = Some(snapshot_network.clone());
    }

    let required_weight = required_weight(snapshot, threshold);
    let available_weight = available_weight(snapshot, available_signers)?;
    // stellar-core evaluates `totalWeight >= neededWeight` only after a
    // signature matched a listed signer (SignatureChecker::checkSignature),
    // and the master key is listed only when its weight is non-zero. A
    // threshold of zero therefore still needs a matching positive-weight
    // signer, which is exactly `available_weight > 0` here.
    let meets_requirement = available_weight >= required_weight && available_weight > 0;
    let explanation = if meets_requirement {
        AuthorizationExplanation::RequirementMet
    } else if available_weight < required_weight {
        AuthorizationExplanation::MissingWeight {
            missing: required_weight - available_weight,
        }
    } else {
        AuthorizationExplanation::NoMatchingSigner
    };

    Ok(AuthorizationFinding {
        account,
        subject,
        threshold,
        required_weight,
        available_weight,
        meets_requirement,
        explanation,
    })
}

fn required_weight(snapshot: &AccountSnapshot, threshold: ThresholdCategory) -> u64 {
    let thresholds = snapshot.thresholds();
    match threshold {
        ThresholdCategory::Low => u64::from(thresholds.low().value()),
        ThresholdCategory::Medium => u64::from(thresholds.medium().value()),
        ThresholdCategory::High => u64::from(thresholds.high().value()),
    }
}

fn available_weight(
    snapshot: &AccountSnapshot,
    available_signers: &AvailableSigners,
) -> Result<u64, AnalysisError> {
    let mut total = 0_u64;
    let master_key = snapshot.account_id().as_ed25519_key();
    if available_signers.contains(&master_key) {
        total = total
            .checked_add(u64::from(snapshot.master_key_weight().value()))
            .ok_or(AnalysisError::WeightOverflow)?;
    }

    for signer in snapshot.signers() {
        if signer.availability() == SignerAvailability::Available
            && available_signers.contains(signer.key())
        {
            total = total
                .checked_add(u64::from(signer.weight().value()))
                .ok_or(AnalysisError::WeightOverflow)?;
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authpath_model::{
        AccountSnapshot, ConfiguredSigner, MasterKeyWeight, NetworkIdentity, SignerWeight,
        SnapshotProvenance, Threshold, Thresholds,
    };

    fn account(seed: u8) -> AccountId {
        AccountId::from_bytes([seed; 32])
    }

    fn signer(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes([seed; 32])
    }

    fn provenance() -> SnapshotProvenance {
        SnapshotProvenance::caller_provided(Some(NetworkIdentity::new("fixture-network").unwrap()))
    }

    fn snapshot(
        seed: u8,
        master_weight: u32,
        thresholds: (u32, u32, u32),
        signers: Vec<ConfiguredSigner>,
    ) -> AccountSnapshot {
        AccountSnapshot::new(
            account(seed),
            MasterKeyWeight::new(master_weight).unwrap(),
            Thresholds::new(thresholds.0, thresholds.1, thresholds.2).unwrap(),
            signers,
            provenance(),
        )
        .unwrap()
    }

    fn configured(seed: u8, weight: u32, availability: SignerAvailability) -> ConfiguredSigner {
        ConfiguredSigner::new(
            signer(seed),
            SignerWeight::new(weight).unwrap(),
            availability,
        )
    }

    fn accounts(snapshots: Vec<AccountSnapshot>) -> AccountSnapshots {
        AccountSnapshots::new(snapshots).unwrap()
    }

    fn payment_transaction(source: AccountId) -> TransactionDescription {
        TransactionDescription::new(source, vec![Operation::payment(None)]).unwrap()
    }

    #[test]
    fn a_single_master_key_meets_a_threshold() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(1, 3, (2, 2, 2), vec![])]);
        let available = AvailableSigners::new([signer(1)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert!(report.meets_configured_requirements());
        assert_eq!(report.findings()[0].available_weight(), 3);
        assert_eq!(report.findings()[0].required_weight(), 2);
    }

    #[test]
    fn multiple_signers_collectively_meet_a_threshold() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(
            1,
            0,
            (1, 5, 5),
            vec![
                configured(2, 2, SignerAvailability::Available),
                configured(3, 3, SignerAvailability::Available),
            ],
        )]);
        let available = AvailableSigners::new([signer(2), signer(3)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        let operation_finding = &report.findings()[1];
        assert_eq!(operation_finding.threshold(), ThresholdCategory::Medium);
        assert_eq!(operation_finding.available_weight(), 5);
        assert!(operation_finding.meets_requirement());
    }

    #[test]
    fn available_weight_below_threshold_is_reported_structurally() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(1, 1, (1, 4, 4), vec![])]);
        let available = AvailableSigners::new([signer(1)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert!(!report.meets_configured_requirements());
        assert_eq!(
            report.findings()[1].explanation(),
            AuthorizationExplanation::MissingWeight { missing: 3 }
        );
    }

    #[test]
    fn zero_weight_master_key_contributes_nothing() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(1, 0, (1, 1, 1), vec![])]);
        let available = AvailableSigners::new([signer(1)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert_eq!(report.findings()[0].available_weight(), 0);
        assert!(!report.findings()[0].meets_requirement());
    }

    #[test]
    fn zero_threshold_still_requires_a_matching_positive_weight_signer() {
        // stellar-core checks weight only after a signature matches a listed
        // signer, and omits a zero-weight master key from the signer list.
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(1, 0, (0, 0, 0), vec![])]);
        let available = AvailableSigners::new([signer(1)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert!(!report.meets_configured_requirements());
        for finding in report.findings() {
            assert_eq!(finding.required_weight(), 0);
            assert_eq!(
                finding.explanation(),
                AuthorizationExplanation::NoMatchingSigner
            );
        }
    }

    #[test]
    fn zero_threshold_is_met_by_any_positive_weight_signer() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(1, 1, (0, 0, 0), vec![])]);
        let available = AvailableSigners::new([signer(1)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert!(report.meets_configured_requirements());
    }

    #[test]
    fn unavailable_signer_contributes_nothing_even_when_declared_in_the_set() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(
            1,
            0,
            (1, 5, 5),
            vec![configured(2, 5, SignerAvailability::Unavailable)],
        )]);
        let available = AvailableSigners::new([signer(2)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert_eq!(report.findings()[1].available_weight(), 0);
        assert!(!report.findings()[1].meets_requirement());
    }

    #[test]
    fn duplicate_available_signer_declarations_do_not_inflate_weight() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(
            1,
            0,
            (1, 4, 4),
            vec![configured(2, 2, SignerAvailability::Available)],
        )]);
        let available = AvailableSigners::new([signer(2), signer(2), signer(2)]);

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert_eq!(available.len(), 1);
        assert_eq!(report.findings()[1].available_weight(), 2);
        assert!(!report.findings()[1].meets_requirement());
    }

    #[test]
    fn exact_threshold_equality_succeeds_and_one_unit_below_fails() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(1, 2, (1, 2, 2), vec![])]);

        let equal = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1)]),
        )
        .unwrap();
        assert!(equal.findings()[1].meets_requirement());

        let below_snapshots = accounts(vec![snapshot(1, 1, (1, 2, 2), vec![])]);
        let below = analyze(
            &transaction,
            &below_snapshots,
            &AvailableSigners::new([signer(1)]),
        )
        .unwrap();
        assert!(!below.findings()[1].meets_requirement());
    }

    #[test]
    fn mixed_operations_use_their_verified_threshold_categories() {
        let transaction = TransactionDescription::new(
            account(1),
            vec![
                Operation::payment(None),
                Operation::bump_sequence(None),
                Operation::account_merge(None),
            ],
        )
        .unwrap();
        let snapshots = accounts(vec![snapshot(1, 3, (1, 2, 3), vec![])]);
        let report = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1)]),
        )
        .unwrap();

        assert_eq!(report.findings()[0].threshold(), ThresholdCategory::Low);
        assert_eq!(report.findings()[1].threshold(), ThresholdCategory::Medium);
        assert_eq!(report.findings()[2].threshold(), ThresholdCategory::Low);
        assert_eq!(report.findings()[3].threshold(), ThresholdCategory::High);
    }

    #[test]
    fn explicit_operation_source_is_evaluated_against_its_own_account() {
        let transaction =
            TransactionDescription::new(account(1), vec![Operation::payment(Some(account(2)))])
                .unwrap();
        let snapshots = accounts(vec![
            snapshot(1, 1, (1, 1, 1), vec![]),
            snapshot(
                2,
                0,
                (1, 2, 2),
                vec![configured(3, 2, SignerAvailability::Available)],
            ),
        ]);
        let report = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1), signer(3)]),
        )
        .unwrap();

        assert_eq!(report.findings()[0].account(), account(1));
        assert_eq!(report.findings()[1].account(), account(2));
        assert_eq!(report.findings()[1].available_weight(), 2);
        assert!(report.meets_configured_requirements());
    }

    #[test]
    fn account_weights_are_not_combined_across_sources() {
        let transaction =
            TransactionDescription::new(account(1), vec![Operation::payment(Some(account(2)))])
                .unwrap();
        let snapshots = accounts(vec![
            snapshot(1, 1, (1, 2, 2), vec![]),
            snapshot(2, 1, (1, 2, 2), vec![]),
        ]);
        let report = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1), signer(2)]),
        )
        .unwrap();

        assert_eq!(report.findings()[0].available_weight(), 1);
        assert_eq!(report.findings()[1].available_weight(), 1);
        assert!(!report.meets_configured_requirements());
    }

    #[test]
    fn set_options_classifies_each_supported_variation() {
        let source = account(1);
        let cases = [
            (
                SetOptionsChanges {
                    has_home_domain: true,
                    ..SetOptionsChanges::new()
                },
                ThresholdCategory::Medium,
            ),
            (
                SetOptionsChanges {
                    has_set_flags: true,
                    ..SetOptionsChanges::new()
                },
                ThresholdCategory::Medium,
            ),
            (
                SetOptionsChanges {
                    master_key_weight: Some(MasterKeyWeight::from_u8(0)),
                    ..SetOptionsChanges::new()
                },
                ThresholdCategory::High,
            ),
            (
                SetOptionsChanges {
                    low_threshold: Some(Threshold::from_u8(0)),
                    ..SetOptionsChanges::new()
                },
                ThresholdCategory::High,
            ),
            (
                SetOptionsChanges {
                    signer: Some(SignerChange::new(signer(2), SignerWeight::from_u8(0))),
                    ..SetOptionsChanges::new()
                },
                ThresholdCategory::High,
            ),
        ];

        for (changes, expected) in cases {
            let transaction =
                TransactionDescription::new(source, vec![Operation::set_options(None, changes)])
                    .unwrap();
            let snapshots = accounts(vec![snapshot(1, 3, (1, 2, 3), vec![])]);
            let report = analyze(
                &transaction,
                &snapshots,
                &AvailableSigners::new([signer(1)]),
            )
            .unwrap();
            assert_eq!(report.findings()[1].threshold(), expected);
        }
    }

    #[test]
    fn signer_changes_do_not_modify_later_operation_authorization() {
        let transaction = TransactionDescription::new(
            account(1),
            vec![
                Operation::set_options(
                    None,
                    SetOptionsChanges {
                        signer: Some(SignerChange::new(signer(2), SignerWeight::from_u8(1))),
                        ..SetOptionsChanges::new()
                    },
                ),
                Operation::payment(None),
            ],
        )
        .unwrap();
        let snapshots = accounts(vec![snapshot(1, 1, (1, 1, 2), vec![])]);
        let report = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1)]),
        )
        .unwrap();

        assert!(!report.findings()[1].meets_requirement());
        assert!(report.findings()[2].meets_requirement());
        assert_eq!(report.findings()[2].available_weight(), 1);
    }

    #[test]
    fn unsupported_operation_fails_closed() {
        let transaction = TransactionDescription::new(
            account(1),
            vec![Operation::unsupported(None, "change-trust")],
        )
        .unwrap();
        let snapshots = accounts(vec![snapshot(1, 1, (1, 1, 1), vec![])]);

        let error = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1)]),
        )
        .unwrap_err();

        assert_eq!(
            error,
            AnalysisError::UnsupportedOperation {
                index: 0,
                operation_type: "change-trust".to_owned(),
            }
        );
    }

    #[test]
    fn missing_snapshots_do_not_produce_a_safe_result() {
        let transaction =
            TransactionDescription::new(account(1), vec![Operation::payment(Some(account(2)))])
                .unwrap();
        let snapshots = accounts(vec![snapshot(1, 1, (1, 1, 1), vec![])]);

        let error = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1)]),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            AnalysisError::MissingAccountSnapshot {
                account: found_account,
                subject: AuthorizationSubject::Operation { index: 0, .. }
            } if found_account == account(2)
        ));
    }

    #[test]
    fn duplicate_snapshots_are_ambiguous() {
        let first = snapshot(1, 1, (1, 1, 1), vec![]);
        let second = snapshot(1, 2, (1, 1, 1), vec![]);

        let error = AccountSnapshots::new(vec![first, second]).unwrap_err();

        assert!(matches!(
            error,
            AnalysisError::AmbiguousAccountSnapshots {
                account: found_account
            } if found_account == account(1)
        ));
    }

    #[test]
    fn missing_or_inconsistent_transaction_input_is_rejected() {
        assert!(matches!(
            TransactionDescription::try_new(None, vec![Operation::payment(None)]),
            Err(AnalysisError::InvalidTransaction {
                reason: InvalidTransactionReason::MissingSourceAccount
            })
        ));
        assert!(matches!(
            TransactionDescription::new(account(1), vec![]),
            Err(AnalysisError::InvalidTransaction {
                reason: InvalidTransactionReason::EmptyOperations
            })
        ));

        let transaction = TransactionDescription::new(
            account(1),
            vec![Operation::set_options(None, SetOptionsChanges::new())],
        )
        .unwrap();
        let snapshots = accounts(vec![snapshot(1, 1, (1, 1, 1), vec![])]);
        assert!(matches!(
            analyze(
                &transaction,
                &snapshots,
                &AvailableSigners::new([signer(1)])
            ),
            Err(AnalysisError::InvalidOperation {
                index: 0,
                reason: InvalidOperationReason::EmptySetOptionsChanges
            })
        ));
    }

    #[test]
    fn insufficient_provenance_is_inconclusive() {
        let snapshot = AccountSnapshot::new(
            account(1),
            MasterKeyWeight::new(1).unwrap(),
            Thresholds::new(1, 1, 1).unwrap(),
            vec![],
            SnapshotProvenance::caller_provided(None),
        )
        .unwrap();
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot]);

        assert!(matches!(
            analyze(
                &transaction,
                &snapshots,
                &AvailableSigners::new([signer(1)])
            ),
            Err(AnalysisError::InsufficientProvenance { .. })
        ));
    }

    #[test]
    fn unsupported_signer_declarations_fail_closed() {
        let error = AvailableSigners::from_declarations([
            DeclaredSigner::Ed25519(signer(1)),
            DeclaredSigner::Unsupported(SignerType::HashX),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            AnalysisError::UnsupportedSignerType {
                signer_type: SignerType::HashX
            }
        );
    }

    #[test]
    fn maximum_supported_signer_weights_sum_without_overflow() {
        let configured_signers = (2..=21)
            .map(|seed| configured(seed, 255, SignerAvailability::Available))
            .collect();
        let snapshots = accounts(vec![snapshot(1, 255, (255, 255, 255), configured_signers)]);
        let transaction = payment_transaction(account(1));
        let available =
            AvailableSigners::new(std::iter::once(signer(1)).chain((2..=21).map(signer)));

        let report = analyze(&transaction, &snapshots, &available).unwrap();

        assert_eq!(report.findings()[1].available_weight(), 5_355);
        assert!(report.findings()[1].meets_requirement());
    }

    #[test]
    fn equivalent_inputs_produce_identical_results() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(
            1,
            1,
            (1, 2, 3),
            vec![configured(2, 2, SignerAvailability::Available)],
        )]);
        let available = AvailableSigners::new([signer(2), signer(1), signer(2)]);

        let first = analyze(&transaction, &snapshots, &available).unwrap();
        let second = analyze(&transaction, &snapshots, &available).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn every_finding_exposes_the_non_execution_limitations() {
        let transaction = payment_transaction(account(1));
        let snapshots = accounts(vec![snapshot(1, 1, (1, 1, 1), vec![])]);
        let report = analyze(
            &transaction,
            &snapshots,
            &AvailableSigners::new([signer(1)]),
        )
        .unwrap();

        assert_eq!(report.limitations().len(), 4);
        assert_eq!(report.findings()[0].limitations(), report.limitations());
    }
}
