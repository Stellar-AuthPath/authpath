//! Typed, validated rotation plan inputs.

use std::{collections::BTreeSet, fmt};

use authpath_model::{
    AccountId, Ed25519PublicKey, MAX_SIGNERS, MasterKeyWeight, SignerAvailability, SignerType,
    SignerWeight, Thresholds,
};

use crate::{
    AccountSnapshots, AvailableSigners, DeclaredSigner, Operation, SetOptionsChanges,
    TransactionDescription,
};

/// The protocol limit on operations in one transaction (`MAX_OPS_PER_TX` in
/// `Stellar-transaction.x`).
pub const MAX_OPERATIONS_PER_TRANSACTION: usize = 100;

/// An AuthPath resource bound on plan length. This is not a protocol limit.
pub const MAX_PLAN_TRANSACTIONS: usize = 256;

/// An explicit post-operation availability declaration for a signer added or
/// re-weighted by a SetOptions operation.
///
/// The declaration must agree with the [`RotationPlan`] wide set of identities
/// explicitly declared available: `Available` requires membership and
/// `Unavailable` requires absence. Availability is never inferred from a
/// configured weight or public key. Every positive-weight signer change in a
/// plan needs exactly one declaration; removals (weight zero) take none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerDeclaration {
    operation_index: usize,
    key: Ed25519PublicKey,
    availability: SignerAvailability,
}

impl SignerDeclaration {
    /// Declares the availability of the signer set by an operation.
    #[must_use]
    pub const fn new(
        operation_index: usize,
        key: Ed25519PublicKey,
        availability: SignerAvailability,
    ) -> Self {
        Self {
            operation_index,
            key,
            availability,
        }
    }

    /// Returns the zero-based index of the SetOptions operation.
    #[must_use]
    pub const fn operation_index(&self) -> usize {
        self.operation_index
    }

    /// Returns the declared signer key.
    #[must_use]
    pub const fn key(&self) -> Ed25519PublicKey {
        self.key
    }

    /// Returns the declared availability.
    #[must_use]
    pub const fn availability(&self) -> SignerAvailability {
        self.availability
    }
}

/// A caller declaration about whether the source account can fund new
/// subentries. The engine never derives this from balances.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReserveDeclaration {
    /// Reserves are not modeled and were not checked (the default).
    #[default]
    Unverified,
    /// The caller states the account cannot fund a new signer; adding a
    /// signer would fail with `SET_OPTIONS_LOW_RESERVE`.
    DeclaredInsufficient,
}

/// A signer in an expected resulting configuration. Weights are positive:
/// a zero-weight signer is not a ledger state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedSigner {
    key: Ed25519PublicKey,
    weight: SignerWeight,
}

impl ExpectedSigner {
    /// Constructs an expected signer.
    #[must_use]
    pub const fn new(key: Ed25519PublicKey, weight: SignerWeight) -> Self {
        Self { key, weight }
    }

    /// Returns the signer key.
    #[must_use]
    pub const fn key(&self) -> Ed25519PublicKey {
        self.key
    }

    /// Returns the signer weight.
    #[must_use]
    pub const fn weight(&self) -> SignerWeight {
        self.weight
    }
}

/// The caller's expectation of one account's configuration after a
/// transaction. This is a caller-supplied assertion about the intended
/// result, not proof that a ledger executed the transaction. The engine
/// compares it with its modeled result and never trusts it as ledger
/// evidence; disagreement stops dependent analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedAccount {
    account: AccountId,
    master_key_weight: MasterKeyWeight,
    thresholds: Thresholds,
    signers: Vec<ExpectedSigner>,
}

impl ExpectedAccount {
    /// Validates and constructs an expected account configuration.
    pub fn new(
        account: AccountId,
        master_key_weight: MasterKeyWeight,
        thresholds: Thresholds,
        mut signers: Vec<ExpectedSigner>,
    ) -> Result<Self, TransactionPlanError> {
        if signers.len() > MAX_SIGNERS {
            return Err(TransactionPlanError::ExpectedTooManySigners {
                account,
                actual: signers.len(),
            });
        }
        let mut seen = BTreeSet::new();
        for signer in &signers {
            if signer.key == account.as_ed25519_key() {
                return Err(TransactionPlanError::ExpectedSignerIsMasterKey { account });
            }
            if signer.weight.value() == 0 {
                return Err(TransactionPlanError::ExpectedZeroWeightSigner {
                    account,
                    key: signer.key,
                });
            }
            if !seen.insert(signer.key) {
                return Err(TransactionPlanError::ExpectedDuplicateSigner {
                    account,
                    key: signer.key,
                });
            }
        }
        signers.sort_by_key(ExpectedSigner::key);
        Ok(Self {
            account,
            master_key_weight,
            thresholds,
            signers,
        })
    }

    /// Returns the account the expectation is about.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the expected master-key weight.
    #[must_use]
    pub const fn master_key_weight(&self) -> MasterKeyWeight {
        self.master_key_weight
    }

    /// Returns the expected thresholds.
    #[must_use]
    pub const fn thresholds(&self) -> Thresholds {
        self.thresholds
    }

    /// Returns the expected signers, sorted by key.
    #[must_use]
    pub fn signers(&self) -> &[ExpectedSigner] {
        &self.signers
    }
}

/// Reasons one planned transaction is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionPlanError {
    /// The transaction has more operations than the protocol permits.
    TooManyOperations {
        /// The number of operations supplied.
        actual: usize,
    },
    /// An operation kind outside the rotation model. AccountMerge destroys
    /// the account being analyzed and is deliberately not modeled.
    UnsupportedOperation {
        /// The zero-based operation index.
        index: usize,
        /// A name for the rejected operation.
        operation_type: String,
    },
    /// A SetOptions operation has no present field.
    EmptySetOptions {
        /// The zero-based operation index.
        index: usize,
    },
    /// A SetOptions operation names its own source account as a signer,
    /// which the protocol rejects with `SET_OPTIONS_BAD_SIGNER`.
    SignerIsOperationSource {
        /// The zero-based operation index.
        index: usize,
    },
    /// A positive-weight signer change has no availability declaration.
    MissingSignerDeclaration {
        /// The zero-based operation index.
        index: usize,
    },
    /// More than one declaration targets the same operation.
    DuplicateSignerDeclaration {
        /// The zero-based operation index.
        index: usize,
    },
    /// A declaration does not match a positive-weight signer change.
    DeclarationWithoutSignerChange {
        /// The zero-based operation index named by the declaration.
        index: usize,
    },
    /// Two expectations in one transaction name the same account.
    DuplicateExpectation {
        /// The account named twice.
        account: AccountId,
    },
    /// An expected configuration lists more than the protocol's signer limit.
    ExpectedTooManySigners {
        /// The expected account.
        account: AccountId,
        /// The number of expected signers.
        actual: usize,
    },
    /// An expected configuration lists the account's own master key as a signer.
    ExpectedSignerIsMasterKey {
        /// The expected account.
        account: AccountId,
    },
    /// An expected configuration lists a zero-weight signer.
    ExpectedZeroWeightSigner {
        /// The expected account.
        account: AccountId,
        /// The offending key.
        key: Ed25519PublicKey,
    },
    /// An expected configuration lists the same signer twice.
    ExpectedDuplicateSigner {
        /// The expected account.
        account: AccountId,
        /// The duplicated key.
        key: Ed25519PublicKey,
    },
}

impl fmt::Display for TransactionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyOperations { actual } => write!(
                formatter,
                "{actual} operations exceeds the protocol limit of {MAX_OPERATIONS_PER_TRANSACTION}"
            ),
            Self::UnsupportedOperation {
                index,
                operation_type,
            } => write!(
                formatter,
                "operation {index} ({operation_type}) is not supported by the rotation model"
            ),
            Self::EmptySetOptions { index } => {
                write!(
                    formatter,
                    "operation {index}: SetOptions has no present field"
                )
            }
            Self::SignerIsOperationSource { index } => write!(
                formatter,
                "operation {index}: a signer cannot be the operation's own source account"
            ),
            Self::MissingSignerDeclaration { index } => write!(
                formatter,
                "operation {index}: signer change has no availability declaration"
            ),
            Self::DuplicateSignerDeclaration { index } => write!(
                formatter,
                "operation {index}: multiple availability declarations"
            ),
            Self::DeclarationWithoutSignerChange { index } => write!(
                formatter,
                "availability declaration for operation {index} matches no positive-weight signer change"
            ),
            Self::DuplicateExpectation { account } => {
                write!(formatter, "multiple expectations for {account}")
            }
            Self::ExpectedTooManySigners { account, actual } => write!(
                formatter,
                "expected configuration for {account} lists {actual} signers (limit {MAX_SIGNERS})"
            ),
            Self::ExpectedSignerIsMasterKey { account } => write!(
                formatter,
                "expected configuration for {account} lists its master key as a signer"
            ),
            Self::ExpectedZeroWeightSigner { account, key } => write!(
                formatter,
                "expected configuration for {account} lists zero-weight signer {key}"
            ),
            Self::ExpectedDuplicateSigner { account, key } => write!(
                formatter,
                "expected configuration for {account} lists signer {key} twice"
            ),
        }
    }
}

impl std::error::Error for TransactionPlanError {}

/// One proposed transaction in a rotation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedTransaction {
    description: TransactionDescription,
    declarations: Vec<SignerDeclaration>,
    reserve: ReserveDeclaration,
    expected: Vec<ExpectedAccount>,
}

impl PlannedTransaction {
    /// Validates a proposed transaction.
    ///
    /// Only Payment, BumpSequence and SetOptions are accepted. Payment and
    /// BumpSequence never change authorization configuration.
    pub fn new(
        description: TransactionDescription,
        declarations: Vec<SignerDeclaration>,
        reserve: ReserveDeclaration,
        expected: Vec<ExpectedAccount>,
    ) -> Result<Self, TransactionPlanError> {
        let operations = description.operations();
        if operations.len() > MAX_OPERATIONS_PER_TRANSACTION {
            return Err(TransactionPlanError::TooManyOperations {
                actual: operations.len(),
            });
        }

        let mut needs_declaration = BTreeSet::new();
        for (index, operation) in operations.iter().enumerate() {
            match operation {
                Operation::Payment { .. } | Operation::BumpSequence { .. } => {}
                Operation::AccountMerge { .. } => {
                    return Err(TransactionPlanError::UnsupportedOperation {
                        index,
                        operation_type: "account-merge".to_owned(),
                    });
                }
                Operation::Unsupported { operation_type, .. } => {
                    return Err(TransactionPlanError::UnsupportedOperation {
                        index,
                        operation_type: operation_type.clone(),
                    });
                }
                Operation::SetOptions { source, changes } => {
                    validate_set_options(
                        index,
                        source.unwrap_or(description.source_account()),
                        changes,
                    )?;
                    if changes
                        .signer
                        .is_some_and(|signer| signer.weight().value() > 0)
                    {
                        needs_declaration.insert(index);
                    }
                }
            }
        }

        let mut declared = BTreeSet::new();
        for declaration in &declarations {
            let index = declaration.operation_index;
            let matches = matches!(
                operations.get(index),
                Some(Operation::SetOptions { changes, .. })
                    if changes.signer.is_some_and(|signer| {
                        signer.key() == declaration.key && signer.weight().value() > 0
                    })
            );
            if !matches {
                return Err(TransactionPlanError::DeclarationWithoutSignerChange { index });
            }
            if !declared.insert(index) {
                return Err(TransactionPlanError::DuplicateSignerDeclaration { index });
            }
        }
        if let Some(&index) = needs_declaration.difference(&declared).next() {
            return Err(TransactionPlanError::MissingSignerDeclaration { index });
        }

        let mut accounts = BTreeSet::new();
        for expectation in &expected {
            if !accounts.insert(expectation.account) {
                return Err(TransactionPlanError::DuplicateExpectation {
                    account: expectation.account,
                });
            }
        }

        Ok(Self {
            description,
            declarations,
            reserve,
            expected,
        })
    }

    /// Returns the authorization-relevant transaction description.
    #[must_use]
    pub const fn description(&self) -> &TransactionDescription {
        &self.description
    }

    /// Returns the signer availability declarations.
    #[must_use]
    pub fn declarations(&self) -> &[SignerDeclaration] {
        &self.declarations
    }

    /// Returns the declared availability for the signer set by an operation.
    #[must_use]
    pub fn declared_availability(&self, operation_index: usize) -> Option<SignerAvailability> {
        self.declarations
            .iter()
            .find(|declaration| declaration.operation_index == operation_index)
            .map(SignerDeclaration::availability)
    }

    /// Returns the caller's reserve declaration.
    #[must_use]
    pub const fn reserve(&self) -> ReserveDeclaration {
        self.reserve
    }

    /// Returns caller-supplied post-transaction assertions, if any. These are
    /// not proof of actual ledger execution.
    #[must_use]
    pub fn expected(&self) -> &[ExpectedAccount] {
        &self.expected
    }
}

fn validate_set_options(
    index: usize,
    source: AccountId,
    changes: &SetOptionsChanges,
) -> Result<(), TransactionPlanError> {
    if changes.is_empty() {
        return Err(TransactionPlanError::EmptySetOptions { index });
    }
    if changes
        .signer
        .is_some_and(|signer| signer.key() == source.as_ed25519_key())
    {
        return Err(TransactionPlanError::SignerIsOperationSource { index });
    }
    Ok(())
}

/// Reasons a whole plan is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The plan contains no transactions.
    Empty,
    /// The plan exceeds [`MAX_PLAN_TRANSACTIONS`].
    TooManyTransactions {
        /// The number of transactions supplied.
        actual: usize,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("rotation plan has no transactions"),
            Self::TooManyTransactions { actual } => write!(
                formatter,
                "{actual} transactions exceeds the plan limit of {MAX_PLAN_TRANSACTIONS}"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

/// An ordered sequence of proposed transactions over initial account
/// snapshots, with explicit signer availability.
///
/// The plan-wide Ed25519 set is the caller's explicit identity-availability
/// declaration for the whole sequence. A configured signer contributes to
/// reachability only when its account-state availability is also
/// `Available`; a positive-weight per-operation declaration must agree with
/// the plan-wide set. Unsupported signer kinds in the declarations are
/// retained rather than coerced or dropped, so the analysis can report that it
/// cannot evaluate them. None of these declarations proves private-key
/// possession.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationPlan {
    initial: AccountSnapshots,
    available: AvailableSigners,
    unsupported_signer_types: Vec<SignerType>,
    transactions: Vec<PlannedTransaction>,
}

impl RotationPlan {
    /// Validates and constructs a rotation plan.
    pub fn new<I>(
        initial: AccountSnapshots,
        declared_signers: I,
        transactions: Vec<PlannedTransaction>,
    ) -> Result<Self, PlanError>
    where
        I: IntoIterator<Item = DeclaredSigner>,
    {
        if transactions.is_empty() {
            return Err(PlanError::Empty);
        }
        if transactions.len() > MAX_PLAN_TRANSACTIONS {
            return Err(PlanError::TooManyTransactions {
                actual: transactions.len(),
            });
        }

        let mut keys = Vec::new();
        let mut unsupported_signer_types = Vec::new();
        for declaration in declared_signers {
            match declaration {
                DeclaredSigner::Ed25519(key) => keys.push(key),
                DeclaredSigner::Unsupported(signer_type) => {
                    if !unsupported_signer_types.contains(&signer_type) {
                        unsupported_signer_types.push(signer_type);
                    }
                }
            }
        }
        unsupported_signer_types.sort();

        Ok(Self {
            initial,
            available: AvailableSigners::new(keys),
            unsupported_signer_types,
            transactions,
        })
    }

    /// Returns the initial account snapshots.
    #[must_use]
    pub const fn initial(&self) -> &AccountSnapshots {
        &self.initial
    }

    /// Returns the declared-available Ed25519 identities.
    #[must_use]
    pub const fn available(&self) -> &AvailableSigners {
        &self.available
    }

    /// Returns declared signer kinds the model cannot evaluate, sorted.
    #[must_use]
    pub fn unsupported_signer_types(&self) -> &[SignerType] {
        &self.unsupported_signer_types
    }

    /// Returns the proposed transactions in order.
    #[must_use]
    pub fn transactions(&self) -> &[PlannedTransaction] {
        &self.transactions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignerChange;

    fn account(seed: u8) -> AccountId {
        AccountId::from_bytes([seed; 32])
    }

    fn key(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes([seed; 32])
    }

    fn add_signer(source: Option<AccountId>, seed: u8, weight: u8) -> Operation {
        let mut changes = SetOptionsChanges::new();
        changes.signer = Some(SignerChange::new(key(seed), SignerWeight::from_u8(weight)));
        Operation::set_options(source, changes)
    }

    fn transaction(operations: Vec<Operation>) -> TransactionDescription {
        TransactionDescription::new(account(1), operations).unwrap()
    }

    fn plain(operations: Vec<Operation>) -> Result<PlannedTransaction, TransactionPlanError> {
        PlannedTransaction::new(
            transaction(operations),
            Vec::new(),
            ReserveDeclaration::Unverified,
            Vec::new(),
        )
    }

    #[test]
    fn payment_and_bump_sequence_need_no_declarations() {
        let planned = plain(vec![
            Operation::payment(None),
            Operation::bump_sequence(None),
        ]);
        assert!(planned.is_ok());
    }

    #[test]
    fn account_merge_and_unknown_operations_are_rejected() {
        assert_eq!(
            plain(vec![
                Operation::payment(None),
                Operation::account_merge(None)
            ])
            .unwrap_err(),
            TransactionPlanError::UnsupportedOperation {
                index: 1,
                operation_type: "account-merge".to_owned()
            }
        );
        assert!(matches!(
            plain(vec![Operation::unsupported(None, "clawback")]),
            Err(TransactionPlanError::UnsupportedOperation { index: 0, .. })
        ));
    }

    #[test]
    fn operation_count_is_bounded_by_the_protocol_limit() {
        let at_limit = vec![Operation::payment(None); MAX_OPERATIONS_PER_TRANSACTION];
        assert!(plain(at_limit).is_ok());
        let over = vec![Operation::payment(None); MAX_OPERATIONS_PER_TRANSACTION + 1];
        assert_eq!(
            plain(over).unwrap_err(),
            TransactionPlanError::TooManyOperations { actual: 101 }
        );
    }

    #[test]
    fn empty_set_options_is_rejected() {
        assert_eq!(
            plain(vec![Operation::set_options(None, SetOptionsChanges::new())]).unwrap_err(),
            TransactionPlanError::EmptySetOptions { index: 0 }
        );
    }

    #[test]
    fn a_signer_cannot_be_its_own_operation_source() {
        // Transaction source is account(1); its key is key(1).
        assert_eq!(
            plain(vec![add_signer(None, 1, 1)]).unwrap_err(),
            TransactionPlanError::SignerIsOperationSource { index: 0 }
        );
        assert_eq!(
            plain(vec![add_signer(Some(account(2)), 2, 1)]).unwrap_err(),
            TransactionPlanError::SignerIsOperationSource { index: 0 }
        );
    }

    #[test]
    fn positive_weight_signer_changes_require_exactly_one_declaration() {
        let operations = vec![add_signer(None, 2, 1)];
        let missing = PlannedTransaction::new(
            transaction(operations.clone()),
            Vec::new(),
            ReserveDeclaration::Unverified,
            Vec::new(),
        );
        assert_eq!(
            missing.unwrap_err(),
            TransactionPlanError::MissingSignerDeclaration { index: 0 }
        );

        let declaration = SignerDeclaration::new(0, key(2), SignerAvailability::Available);
        let duplicated = PlannedTransaction::new(
            transaction(operations.clone()),
            vec![declaration, declaration],
            ReserveDeclaration::Unverified,
            Vec::new(),
        );
        assert_eq!(
            duplicated.unwrap_err(),
            TransactionPlanError::DuplicateSignerDeclaration { index: 0 }
        );

        let planned = PlannedTransaction::new(
            transaction(operations),
            vec![declaration],
            ReserveDeclaration::Unverified,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            planned.declared_availability(0),
            Some(SignerAvailability::Available)
        );
    }

    #[test]
    fn removals_and_mismatched_declarations_are_rejected() {
        let removal = vec![add_signer(None, 2, 0)];
        let declared = PlannedTransaction::new(
            transaction(removal.clone()),
            vec![SignerDeclaration::new(
                0,
                key(2),
                SignerAvailability::Available,
            )],
            ReserveDeclaration::Unverified,
            Vec::new(),
        );
        assert_eq!(
            declared.unwrap_err(),
            TransactionPlanError::DeclarationWithoutSignerChange { index: 0 }
        );
        assert!(plain(removal).is_ok());

        let wrong_key = PlannedTransaction::new(
            transaction(vec![add_signer(None, 2, 1)]),
            vec![SignerDeclaration::new(
                0,
                key(3),
                SignerAvailability::Available,
            )],
            ReserveDeclaration::Unverified,
            Vec::new(),
        );
        assert_eq!(
            wrong_key.unwrap_err(),
            TransactionPlanError::DeclarationWithoutSignerChange { index: 0 }
        );

        let out_of_range = PlannedTransaction::new(
            transaction(vec![Operation::payment(None)]),
            vec![SignerDeclaration::new(
                5,
                key(2),
                SignerAvailability::Available,
            )],
            ReserveDeclaration::Unverified,
            Vec::new(),
        );
        assert_eq!(
            out_of_range.unwrap_err(),
            TransactionPlanError::DeclarationWithoutSignerChange { index: 5 }
        );
    }

    fn expected(
        seed: u8,
        signers: Vec<ExpectedSigner>,
    ) -> Result<ExpectedAccount, TransactionPlanError> {
        ExpectedAccount::new(
            account(seed),
            MasterKeyWeight::from_u8(1),
            Thresholds::new(1, 1, 1).unwrap(),
            signers,
        )
    }

    #[test]
    fn expected_configurations_are_validated_and_sorted() {
        let sorted = expected(
            1,
            vec![
                ExpectedSigner::new(key(9), SignerWeight::from_u8(1)),
                ExpectedSigner::new(key(3), SignerWeight::from_u8(2)),
            ],
        )
        .unwrap();
        assert_eq!(sorted.signers()[0].key(), key(3));

        assert_eq!(
            expected(
                1,
                vec![ExpectedSigner::new(key(1), SignerWeight::from_u8(1))]
            )
            .unwrap_err(),
            TransactionPlanError::ExpectedSignerIsMasterKey {
                account: account(1)
            }
        );
        assert_eq!(
            expected(
                1,
                vec![ExpectedSigner::new(key(2), SignerWeight::from_u8(0))]
            )
            .unwrap_err(),
            TransactionPlanError::ExpectedZeroWeightSigner {
                account: account(1),
                key: key(2)
            }
        );
        let twice = ExpectedSigner::new(key(2), SignerWeight::from_u8(1));
        assert_eq!(
            expected(1, vec![twice, twice]).unwrap_err(),
            TransactionPlanError::ExpectedDuplicateSigner {
                account: account(1),
                key: key(2)
            }
        );
        let too_many = (0..=MAX_SIGNERS)
            .map(|seed| ExpectedSigner::new(key(seed as u8 + 10), SignerWeight::from_u8(1)))
            .collect();
        assert_eq!(
            expected(1, too_many).unwrap_err(),
            TransactionPlanError::ExpectedTooManySigners {
                account: account(1),
                actual: MAX_SIGNERS + 1
            }
        );
    }

    #[test]
    fn duplicate_expectations_for_one_account_are_rejected() {
        let one = expected(1, Vec::new()).unwrap();
        let result = PlannedTransaction::new(
            transaction(vec![Operation::payment(None)]),
            Vec::new(),
            ReserveDeclaration::Unverified,
            vec![one.clone(), one],
        );
        assert_eq!(
            result.unwrap_err(),
            TransactionPlanError::DuplicateExpectation {
                account: account(1)
            }
        );
    }

    #[test]
    fn plans_must_be_non_empty_and_bounded() {
        let initial = AccountSnapshots::default();
        assert_eq!(
            RotationPlan::new(initial.clone(), [], Vec::new()).unwrap_err(),
            PlanError::Empty
        );

        let one = plain(vec![Operation::payment(None)]).unwrap();
        let at_limit = vec![one.clone(); MAX_PLAN_TRANSACTIONS];
        assert!(RotationPlan::new(initial.clone(), [], at_limit).is_ok());
        let over = vec![one; MAX_PLAN_TRANSACTIONS + 1];
        assert_eq!(
            RotationPlan::new(initial, [], over).unwrap_err(),
            PlanError::TooManyTransactions { actual: 257 }
        );
    }

    #[test]
    fn unsupported_declared_signers_are_retained_not_coerced() {
        let one = plain(vec![Operation::payment(None)]).unwrap();
        let plan = RotationPlan::new(
            AccountSnapshots::default(),
            [
                DeclaredSigner::Ed25519(key(2)),
                DeclaredSigner::Ed25519(key(2)),
                DeclaredSigner::Unsupported(SignerType::HashX),
                DeclaredSigner::Unsupported(SignerType::HashX),
                DeclaredSigner::Unsupported(SignerType::PreAuthTx),
            ],
            vec![one],
        )
        .unwrap();

        assert_eq!(plan.available().len(), 1);
        assert_eq!(
            plan.unsupported_signer_types(),
            &[SignerType::PreAuthTx, SignerType::HashX]
        );
    }
}
