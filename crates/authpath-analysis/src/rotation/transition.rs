//! Conditional application of authorization-relevant SetOptions changes.
//!
//! [`apply_transaction`] answers: *if* every operation in a transaction
//! succeeds, what would each account's authorization configuration be? It
//! applies only master-key weight, threshold and signer changes, following
//! `SetOptionsOpFrame::doApply` in stellar-core. Flags, inflation destination
//! and home domain have no authorization effect and are ignored. The result
//! is a modeled state, not ledger evidence, and it does not authorize
//! anything: authorization is evaluated separately against the state that
//! exists *before* each transaction.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use authpath_model::{
    AccountId, AccountSnapshot, ConfiguredSigner, Ed25519PublicKey, MAX_SIGNERS, ModelError,
    SnapshotProvenance,
};

use super::plan::{ExpectedAccount, PlannedTransaction, ReserveDeclaration};
use crate::{AccountSnapshots, Operation};

/// Where an account's configuration in a [`ModeledState`] came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateOrigin {
    /// The supplied initial snapshot, unchanged by the plan so far.
    Initial,
    /// Derived by applying proposed changes; never observed on a ledger.
    Modeled,
}

/// Account configurations at one point in a plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeledState {
    accounts: BTreeMap<AccountId, AccountSnapshot>,
    modeled: BTreeSet<AccountId>,
}

impl ModeledState {
    /// Starts from the initial snapshots, all marked [`StateOrigin::Initial`].
    #[must_use]
    pub fn from_initial(initial: &AccountSnapshots) -> Self {
        Self {
            accounts: initial
                .accounts()
                .map(|snapshot| (*snapshot.account_id(), snapshot.clone()))
                .collect(),
            modeled: BTreeSet::new(),
        }
    }

    /// Returns an account's configuration, if known.
    #[must_use]
    pub fn get(&self, account: &AccountId) -> Option<&AccountSnapshot> {
        self.accounts.get(account)
    }

    /// Returns whether an account's configuration was observed or modeled.
    #[must_use]
    pub fn origin(&self, account: &AccountId) -> Option<StateOrigin> {
        self.accounts.contains_key(account).then(|| {
            if self.modeled.contains(account) {
                StateOrigin::Modeled
            } else {
                StateOrigin::Initial
            }
        })
    }

    /// Returns the configurations as an indexed collection usable by the C2
    /// authorization analysis.
    #[must_use]
    pub fn snapshots(&self) -> AccountSnapshots {
        AccountSnapshots::new(self.accounts.values().cloned())
            .expect("a map has at most one snapshot per account")
    }
}

/// Reasons a transaction cannot be applied as described.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionError {
    /// An operation's source account has no known configuration.
    MissingAccountSnapshot {
        /// The account with no snapshot.
        account: AccountId,
        /// The zero-based operation index.
        operation_index: usize,
    },
    /// Adding a signer would exceed [`MAX_SIGNERS`]
    /// (`SET_OPTIONS_TOO_MANY_SIGNERS`).
    SignerLimitExceeded {
        /// The account that is full.
        account: AccountId,
        /// The zero-based operation index.
        operation_index: usize,
    },
    /// The caller declared reserves insufficient for a new signer
    /// (`SET_OPTIONS_LOW_RESERVE`).
    InsufficientReserveDeclared {
        /// The account that cannot fund the signer.
        account: AccountId,
        /// The zero-based operation index.
        operation_index: usize,
    },
    /// A declaration contradicts the availability already recorded for an
    /// existing signer.
    ConflictingAvailability {
        /// The account holding the signer.
        account: AccountId,
        /// The zero-based operation index.
        operation_index: usize,
        /// The signer key.
        key: Ed25519PublicKey,
    },
    /// The resulting configuration failed model validation.
    InvalidResult(ModelError),
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAccountSnapshot {
                account,
                operation_index,
            } => write!(
                formatter,
                "operation {operation_index}: no snapshot for {account}"
            ),
            Self::SignerLimitExceeded {
                account,
                operation_index,
            } => write!(
                formatter,
                "operation {operation_index}: {account} already has {MAX_SIGNERS} signers"
            ),
            Self::InsufficientReserveDeclared {
                account,
                operation_index,
            } => write!(
                formatter,
                "operation {operation_index}: reserve declared insufficient for a new signer on {account}"
            ),
            Self::ConflictingAvailability {
                account,
                operation_index,
                key,
            } => write!(
                formatter,
                "operation {operation_index}: availability declared for {key} contradicts the existing signer on {account}"
            ),
            Self::InvalidResult(error) => write!(formatter, "invalid modeled result: {error}"),
        }
    }
}

impl std::error::Error for TransitionError {}

/// Applies a transaction's authorization-relevant changes, assuming every
/// operation succeeds, and returns the resulting modeled state.
///
/// Operations apply in order, so a later operation sees an earlier
/// operation's signer count. If any operation cannot apply, the whole
/// transaction is rejected and nothing changes, matching transaction
/// atomicity. Signature checks are not performed here.
pub fn apply_transaction(
    state: &ModeledState,
    transaction: &PlannedTransaction,
) -> Result<ModeledState, TransitionError> {
    let mut next = state.clone();
    let transaction_source = transaction.description().source_account();

    for (index, operation) in transaction.description().operations().iter().enumerate() {
        let Operation::SetOptions { source, changes } = operation else {
            continue;
        };
        let account = source.unwrap_or(transaction_source);
        let current =
            next.accounts
                .get(&account)
                .ok_or(TransitionError::MissingAccountSnapshot {
                    account,
                    operation_index: index,
                })?;

        let master = changes
            .master_key_weight
            .unwrap_or(current.master_key_weight());
        let existing = current.thresholds();
        let thresholds = authpath_model::Thresholds::new(
            u32::from(changes.low_threshold.unwrap_or(existing.low()).value()),
            u32::from(
                changes
                    .medium_threshold
                    .unwrap_or(existing.medium())
                    .value(),
            ),
            u32::from(changes.high_threshold.unwrap_or(existing.high()).value()),
        )
        .map_err(TransitionError::InvalidResult)?;

        let mut signers = current.signers().to_vec();
        if let Some(change) = changes.signer {
            let position = signers
                .iter()
                .position(|signer| signer.key() == &change.key());
            if change.weight().value() == 0 {
                // The protocol silently ignores removal of an absent signer.
                if let Some(position) = position {
                    signers.remove(position);
                }
            } else {
                let declared = transaction
                    .declared_availability(index)
                    .expect("plan validation requires a declaration for every signer addition");
                if let Some(position) = position {
                    if signers[position].availability() != declared {
                        return Err(TransitionError::ConflictingAvailability {
                            account,
                            operation_index: index,
                            key: change.key(),
                        });
                    }
                    signers[position] =
                        ConfiguredSigner::new(change.key(), change.weight(), declared);
                } else {
                    if signers.len() >= MAX_SIGNERS {
                        return Err(TransitionError::SignerLimitExceeded {
                            account,
                            operation_index: index,
                        });
                    }
                    if transaction.reserve() == ReserveDeclaration::DeclaredInsufficient {
                        return Err(TransitionError::InsufficientReserveDeclared {
                            account,
                            operation_index: index,
                        });
                    }
                    signers.push(ConfiguredSigner::new(
                        change.key(),
                        change.weight(),
                        declared,
                    ));
                }
            }
        }
        signers.sort_by_key(|signer| *signer.key());

        // The result is derived, so it is deliberately not ledger-backed.
        let provenance =
            SnapshotProvenance::caller_provided(current.provenance().network().cloned());
        let updated = AccountSnapshot::new(account, master, thresholds, signers, provenance)
            .map_err(TransitionError::InvalidResult)?;
        next.accounts.insert(account, updated);
        next.modeled.insert(account);
    }

    Ok(next)
}

/// A disagreement between a caller's expected configuration and the model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectationMismatch {
    /// The expected account has no modeled configuration.
    AccountMissing {
        /// The expected account.
        account: AccountId,
    },
    /// The master-key weight differs.
    MasterKeyWeight {
        /// The expected account.
        account: AccountId,
        /// The caller's expected weight.
        expected: u8,
        /// The modeled weight.
        modeled: u8,
    },
    /// At least one threshold differs.
    Thresholds {
        /// The expected account.
        account: AccountId,
    },
    /// The signer set or a signer weight differs.
    Signers {
        /// The expected account.
        account: AccountId,
    },
}

/// Compares caller-supplied expected configurations with a modeled state.
///
/// Signer availability is not compared: an expectation states what the ledger
/// would hold, and availability is caller metadata. An expectation is an
/// assertion about the intended result, not proof that the ledger executed
/// the transaction. Callers should not use a mismatch's modeled state as the
/// starting state for dependent analysis.
#[must_use]
pub fn compare_expected(
    state: &ModeledState,
    expected: &[ExpectedAccount],
) -> Vec<ExpectationMismatch> {
    let mut mismatches = Vec::new();
    for expectation in expected {
        let account = expectation.account();
        let Some(modeled) = state.get(&account) else {
            mismatches.push(ExpectationMismatch::AccountMissing { account });
            continue;
        };
        if modeled.master_key_weight() != expectation.master_key_weight() {
            mismatches.push(ExpectationMismatch::MasterKeyWeight {
                account,
                expected: expectation.master_key_weight().value(),
                modeled: modeled.master_key_weight().value(),
            });
        }
        if modeled.thresholds() != expectation.thresholds() {
            mismatches.push(ExpectationMismatch::Thresholds { account });
        }
        let modeled_signers: Vec<_> = modeled
            .signers()
            .iter()
            .map(|signer| (*signer.key(), signer.weight()))
            .collect();
        let expected_signers: Vec<_> = expectation
            .signers()
            .iter()
            .map(|signer| (signer.key(), signer.weight()))
            .collect();
        if modeled_signers != expected_signers {
            mismatches.push(ExpectationMismatch::Signers { account });
        }
    }
    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SetOptionsChanges, SignerChange, TransactionDescription};
    use authpath_model::{
        MasterKeyWeight, NetworkIdentity, SignerAvailability, SignerWeight, Threshold, Thresholds,
    };

    use super::super::plan::{ExpectedSigner, SignerDeclaration};

    fn account(seed: u8) -> AccountId {
        AccountId::from_bytes([seed; 32])
    }

    fn key(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes([seed; 32])
    }

    fn snapshot(
        seed: u8,
        master: u8,
        thresholds: (u32, u32, u32),
        signers: Vec<ConfiguredSigner>,
    ) -> AccountSnapshot {
        AccountSnapshot::new(
            account(seed),
            MasterKeyWeight::from_u8(master),
            Thresholds::new(thresholds.0, thresholds.1, thresholds.2).unwrap(),
            signers,
            SnapshotProvenance::caller_provided(Some(NetworkIdentity::new("fixture").unwrap())),
        )
        .unwrap()
    }

    fn signer(seed: u8, weight: u8, availability: SignerAvailability) -> ConfiguredSigner {
        ConfiguredSigner::new(key(seed), SignerWeight::from_u8(weight), availability)
    }

    fn state(snapshots: Vec<AccountSnapshot>) -> ModeledState {
        ModeledState::from_initial(&AccountSnapshots::new(snapshots).unwrap())
    }

    fn signer_op(source: Option<AccountId>, seed: u8, weight: u8) -> Operation {
        let mut changes = SetOptionsChanges::new();
        changes.signer = Some(SignerChange::new(key(seed), SignerWeight::from_u8(weight)));
        Operation::set_options(source, changes)
    }

    fn planned(
        operations: Vec<Operation>,
        declarations: Vec<SignerDeclaration>,
        reserve: ReserveDeclaration,
    ) -> PlannedTransaction {
        PlannedTransaction::new(
            TransactionDescription::new(account(1), operations).unwrap(),
            declarations,
            reserve,
            Vec::new(),
        )
        .unwrap()
    }

    fn available(op: usize, seed: u8) -> SignerDeclaration {
        SignerDeclaration::new(op, key(seed), SignerAvailability::Available)
    }

    #[test]
    fn adds_removes_and_reweights_signers() {
        let before = state(vec![snapshot(
            1,
            1,
            (1, 1, 1),
            vec![signer(2, 1, SignerAvailability::Available)],
        )]);

        let added = apply_transaction(
            &before,
            &planned(
                vec![signer_op(None, 3, 2)],
                vec![available(0, 3)],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        let keys: Vec<_> = added
            .get(&account(1))
            .unwrap()
            .signers()
            .iter()
            .map(|s| (*s.key(), s.weight().value()))
            .collect();
        assert_eq!(keys, vec![(key(2), 1), (key(3), 2)]);

        let reweighted = apply_transaction(
            &added,
            &planned(
                vec![signer_op(None, 2, 5)],
                vec![available(0, 2)],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        assert_eq!(
            reweighted
                .get(&account(1))
                .unwrap()
                .signer(&key(2))
                .unwrap()
                .weight()
                .value(),
            5
        );

        let removed = apply_transaction(
            &reweighted,
            &planned(
                vec![signer_op(None, 2, 0)],
                vec![],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        assert!(removed.get(&account(1)).unwrap().signer(&key(2)).is_none());
        assert_eq!(removed.get(&account(1)).unwrap().signers().len(), 1);
    }

    #[test]
    fn removing_an_absent_signer_is_a_no_op() {
        let before = state(vec![snapshot(1, 1, (1, 1, 1), vec![])]);
        let after = apply_transaction(
            &before,
            &planned(
                vec![signer_op(None, 9, 0)],
                vec![],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        assert_eq!(after.get(&account(1)), before.get(&account(1)));
    }

    #[test]
    fn master_weight_and_each_threshold_change_independently() {
        let before = state(vec![snapshot(1, 1, (1, 2, 3), vec![])]);
        let mut changes = SetOptionsChanges::new();
        changes.master_key_weight = Some(MasterKeyWeight::from_u8(0));
        changes.medium_threshold = Some(Threshold::from_u8(7));
        let after = apply_transaction(
            &before,
            &planned(
                vec![Operation::set_options(None, changes)],
                vec![],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        let account = after.get(&account(1)).unwrap();
        assert_eq!(account.master_key_weight().value(), 0);
        assert_eq!(account.thresholds(), Thresholds::new(1, 7, 3).unwrap());
    }

    #[test]
    fn flag_only_set_options_changes_no_authorization_state() {
        let before = state(vec![snapshot(1, 1, (1, 2, 3), vec![])]);
        let mut changes = SetOptionsChanges::new();
        changes.has_home_domain = true;
        changes.has_set_flags = true;
        let after = apply_transaction(
            &before,
            &planned(
                vec![Operation::set_options(None, changes)],
                vec![],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        assert_eq!(after.get(&account(1)), before.get(&account(1)));
    }

    #[test]
    fn operations_apply_in_order_within_a_transaction() {
        // At the 20-signer limit, removing one and then adding another in the
        // same transaction fits; the reverse order does not.
        let full: Vec<_> = (10..30)
            .map(|seed| signer(seed, 1, SignerAvailability::Available))
            .collect();
        assert_eq!(full.len(), MAX_SIGNERS);
        let before = state(vec![snapshot(1, 1, (1, 1, 1), full)]);

        let remove_then_add = planned(
            vec![signer_op(None, 10, 0), signer_op(None, 99, 1)],
            vec![available(1, 99)],
            ReserveDeclaration::Unverified,
        );
        let after = apply_transaction(&before, &remove_then_add).unwrap();
        assert_eq!(after.get(&account(1)).unwrap().signers().len(), MAX_SIGNERS);

        let add_then_remove = planned(
            vec![signer_op(None, 99, 1), signer_op(None, 10, 0)],
            vec![available(0, 99)],
            ReserveDeclaration::Unverified,
        );
        assert_eq!(
            apply_transaction(&before, &add_then_remove).unwrap_err(),
            TransitionError::SignerLimitExceeded {
                account: account(1),
                operation_index: 0
            }
        );
    }

    #[test]
    fn the_signer_limit_blocks_additions_but_not_reweights() {
        let full: Vec<_> = (10..30)
            .map(|seed| signer(seed, 1, SignerAvailability::Available))
            .collect();
        let before = state(vec![snapshot(1, 1, (1, 1, 1), full)]);

        let reweight = planned(
            vec![signer_op(None, 10, 9)],
            vec![available(0, 10)],
            ReserveDeclaration::Unverified,
        );
        assert!(apply_transaction(&before, &reweight).is_ok());

        let add = planned(
            vec![signer_op(None, 99, 1)],
            vec![available(0, 99)],
            ReserveDeclaration::Unverified,
        );
        assert!(matches!(
            apply_transaction(&before, &add),
            Err(TransitionError::SignerLimitExceeded { .. })
        ));
    }

    #[test]
    fn a_failing_operation_leaves_the_input_state_untouched() {
        let before = state(vec![snapshot(1, 1, (1, 1, 1), vec![])]);
        let mut changes = SetOptionsChanges::new();
        changes.master_key_weight = Some(MasterKeyWeight::from_u8(0));
        let transaction = planned(
            vec![
                Operation::set_options(None, changes),
                signer_op(Some(account(7)), 3, 1),
            ],
            vec![available(1, 3)],
            ReserveDeclaration::Unverified,
        );
        assert_eq!(
            apply_transaction(&before, &transaction).unwrap_err(),
            TransitionError::MissingAccountSnapshot {
                account: account(7),
                operation_index: 1
            }
        );
        assert_eq!(
            before.get(&account(1)).unwrap().master_key_weight().value(),
            1
        );
    }

    #[test]
    fn declared_insufficient_reserve_blocks_additions_only() {
        let before = state(vec![snapshot(
            1,
            1,
            (1, 1, 1),
            vec![signer(2, 1, SignerAvailability::Available)],
        )]);
        let add = planned(
            vec![signer_op(None, 3, 1)],
            vec![available(0, 3)],
            ReserveDeclaration::DeclaredInsufficient,
        );
        assert_eq!(
            apply_transaction(&before, &add).unwrap_err(),
            TransitionError::InsufficientReserveDeclared {
                account: account(1),
                operation_index: 0
            }
        );
        // Reweighting and removal create no subentry.
        let reweight = planned(
            vec![signer_op(None, 2, 4)],
            vec![available(0, 2)],
            ReserveDeclaration::DeclaredInsufficient,
        );
        assert!(apply_transaction(&before, &reweight).is_ok());
        let remove = planned(
            vec![signer_op(None, 2, 0)],
            vec![],
            ReserveDeclaration::DeclaredInsufficient,
        );
        assert!(apply_transaction(&before, &remove).is_ok());
    }

    #[test]
    fn availability_declarations_must_agree_with_existing_signers() {
        let before = state(vec![snapshot(
            1,
            1,
            (1, 1, 1),
            vec![signer(2, 1, SignerAvailability::Unavailable)],
        )]);
        let contradiction = planned(
            vec![signer_op(None, 2, 3)],
            vec![available(0, 2)],
            ReserveDeclaration::Unverified,
        );
        assert_eq!(
            apply_transaction(&before, &contradiction).unwrap_err(),
            TransitionError::ConflictingAvailability {
                account: account(1),
                operation_index: 0,
                key: key(2)
            }
        );
    }

    #[test]
    fn operation_source_selects_the_account_that_changes() {
        let before = state(vec![
            snapshot(1, 1, (1, 1, 1), vec![]),
            snapshot(2, 1, (1, 1, 1), vec![]),
        ]);
        let after = apply_transaction(
            &before,
            &planned(
                vec![signer_op(Some(account(2)), 5, 1)],
                vec![available(0, 5)],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        assert!(after.get(&account(1)).unwrap().signers().is_empty());
        assert_eq!(after.get(&account(2)).unwrap().signers().len(), 1);
        assert_eq!(after.origin(&account(1)), Some(StateOrigin::Initial));
        assert_eq!(after.origin(&account(2)), Some(StateOrigin::Modeled));
        assert_eq!(after.origin(&account(9)), None);
    }

    #[test]
    fn modeled_snapshots_are_not_ledger_backed() {
        let ledger =
            SnapshotProvenance::ledger(NetworkIdentity::new("fixture").unwrap(), 42).unwrap();
        let initial = AccountSnapshot::new(
            account(1),
            MasterKeyWeight::from_u8(1),
            Thresholds::new(1, 1, 1).unwrap(),
            vec![],
            ledger,
        )
        .unwrap();
        let before = state(vec![initial]);
        let after = apply_transaction(
            &before,
            &planned(
                vec![signer_op(None, 3, 1)],
                vec![available(0, 3)],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();
        let provenance = after.get(&account(1)).unwrap().provenance();
        assert_eq!(provenance.ledger_sequence(), None);
        assert_eq!(
            provenance.network(),
            before.get(&account(1)).unwrap().provenance().network()
        );
    }

    #[test]
    fn expectations_are_compared_with_the_modeled_result() {
        let before = state(vec![snapshot(1, 1, (1, 1, 1), vec![])]);
        let after = apply_transaction(
            &before,
            &planned(
                vec![signer_op(None, 3, 2)],
                vec![available(0, 3)],
                ReserveDeclaration::Unverified,
            ),
        )
        .unwrap();

        let expectation = |master: u8, high: u32, signers: Vec<ExpectedSigner>| {
            ExpectedAccount::new(
                account(1),
                MasterKeyWeight::from_u8(master),
                Thresholds::new(1, 1, high).unwrap(),
                signers,
            )
            .unwrap()
        };
        let right = ExpectedSigner::new(key(3), SignerWeight::from_u8(2));
        assert!(compare_expected(&after, &[expectation(1, 1, vec![right])]).is_empty());

        let wrong_weight = ExpectedSigner::new(key(3), SignerWeight::from_u8(3));
        assert_eq!(
            compare_expected(&after, &[expectation(0, 2, vec![wrong_weight])]),
            vec![
                ExpectationMismatch::MasterKeyWeight {
                    account: account(1),
                    expected: 0,
                    modeled: 1
                },
                ExpectationMismatch::Thresholds {
                    account: account(1)
                },
                ExpectationMismatch::Signers {
                    account: account(1)
                },
            ]
        );

        let other = ExpectedAccount::new(
            account(8),
            MasterKeyWeight::from_u8(1),
            Thresholds::new(1, 1, 1).unwrap(),
            vec![],
        )
        .unwrap();
        assert_eq!(
            compare_expected(&after, &[other]),
            vec![ExpectationMismatch::AccountMissing {
                account: account(8)
            }]
        );
    }
}
