//! Scenario tests for the rotation engine.
//!
//! Expected outcomes are derived by hand from stellar-core's rules, not from
//! the engine's output:
//!
//! * a signature set authorizes when the summed weight of the signers it
//!   matches reaches the threshold, and only after at least one signature
//!   matches (`SignatureChecker::checkSignature`); the master key is a
//!   signer only while its weight is non-zero;
//! * every operation's signatures are checked against the state *before* the
//!   transaction applies (`TransactionFrame::processSignatures`);
//! * the transaction source is checked at its low threshold and each
//!   operation source at the operation's threshold, independently;
//! * SetOptions changing master weight, a threshold or a signer needs the
//!   high threshold; a signer weight of zero removes the signer; an account
//!   holds at most `MAX_SIGNERS = 20` signers.
//!
//! Weights used below are small integers chosen so each outcome can be
//! checked with mental arithmetic; comments show the arithmetic.

use authpath_analysis::{
    AccountSnapshots, AnalysisError, AuthorizationExplanation, AuthorizationSubject,
    DeclaredSigner, Operation, SetOptionsChanges, SignerChange, ThresholdCategory,
    TransactionDescription,
    rotation::{
        ExpectationMismatch, ExpectedAccount, ExpectedSigner, LockoutKind, PlannedTransaction,
        ReachStatus, ReserveDeclaration, ResultBasis, RotationLimitation, RotationPlan,
        RotationReport, SafetyClassification, SignerDeclaration, StepReason, TransitionError,
        analyze_rotation,
    },
};
use authpath_model::{
    AccountId, AccountSnapshot, ConfiguredSigner, Ed25519PublicKey, MAX_SIGNERS, MasterKeyWeight,
    NetworkIdentity, SignerAvailability, SignerType, SignerWeight, SnapshotProvenance, Threshold,
    Thresholds,
};

use SafetyClassification::{
    Blocked, Inconclusive, InvalidTransition, LockoutRisk, SupportedReachable,
};

// Accounts are 1..=9 and their master keys are key(1)..=key(9).
// Non-master signers use seeds >= 100.
fn acct(seed: u8) -> AccountId {
    AccountId::from_bytes([seed; 32])
}

fn key(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes([seed; 32])
}

const HELD: SignerAvailability = SignerAvailability::Available;
const NOT_HELD: SignerAvailability = SignerAvailability::Unavailable;

fn network() -> NetworkIdentity {
    NetworkIdentity::new("scenario-network").unwrap()
}

fn snap(
    account: u8,
    master: u8,
    thresholds: (u32, u32, u32),
    signers: &[(u8, u8, SignerAvailability)],
) -> AccountSnapshot {
    AccountSnapshot::new(
        acct(account),
        MasterKeyWeight::from_u8(master),
        Thresholds::new(thresholds.0, thresholds.1, thresholds.2).unwrap(),
        signers
            .iter()
            .map(|&(seed, weight, availability)| {
                ConfiguredSigner::new(key(seed), SignerWeight::from_u8(weight), availability)
            })
            .collect(),
        SnapshotProvenance::caller_provided(Some(network())),
    )
    .unwrap()
}

fn signer_op(source: Option<u8>, signer: u8, weight: u8) -> Operation {
    let mut changes = SetOptionsChanges::new();
    changes.signer = Some(SignerChange::new(
        key(signer),
        SignerWeight::from_u8(weight),
    ));
    Operation::set_options(source.map(acct), changes)
}

fn thresholds_op(source: Option<u8>, low: u8, medium: u8, high: u8) -> Operation {
    let mut changes = SetOptionsChanges::new();
    changes.low_threshold = Some(Threshold::from_u8(low));
    changes.medium_threshold = Some(Threshold::from_u8(medium));
    changes.high_threshold = Some(Threshold::from_u8(high));
    Operation::set_options(source.map(acct), changes)
}

fn high_op(source: Option<u8>, high: u8) -> Operation {
    let mut changes = SetOptionsChanges::new();
    changes.high_threshold = Some(Threshold::from_u8(high));
    Operation::set_options(source.map(acct), changes)
}

fn master_op(source: Option<u8>, weight: u8) -> Operation {
    let mut changes = SetOptionsChanges::new();
    changes.master_key_weight = Some(MasterKeyWeight::from_u8(weight));
    Operation::set_options(source.map(acct), changes)
}

/// Declares availability for every positive-weight signer change in `ops`.
fn declarations(ops: &[Operation], availability: SignerAvailability) -> Vec<SignerDeclaration> {
    ops.iter()
        .enumerate()
        .filter_map(|(index, op)| match op {
            Operation::SetOptions { changes, .. } => changes
                .signer
                .filter(|signer| signer.weight().value() > 0)
                .map(|signer| SignerDeclaration::new(index, signer.key(), availability)),
            _ => None,
        })
        .collect()
}

fn tx(source: u8, ops: Vec<Operation>) -> PlannedTransaction {
    let declared = declarations(&ops, HELD);
    tx_with(
        source,
        ops,
        declared,
        ReserveDeclaration::Unverified,
        Vec::new(),
    )
}

fn tx_with(
    source: u8,
    ops: Vec<Operation>,
    declarations: Vec<SignerDeclaration>,
    reserve: ReserveDeclaration,
    expected: Vec<ExpectedAccount>,
) -> PlannedTransaction {
    PlannedTransaction::new(
        TransactionDescription::new(acct(source), ops).unwrap(),
        declarations,
        reserve,
        expected,
    )
    .unwrap()
}

fn held(seeds: &[u8]) -> Vec<DeclaredSigner> {
    seeds
        .iter()
        .map(|&seed| DeclaredSigner::Ed25519(key(seed)))
        .collect()
}

fn run(
    snapshots: Vec<AccountSnapshot>,
    declared: Vec<DeclaredSigner>,
    transactions: Vec<PlannedTransaction>,
) -> RotationReport {
    let initial = AccountSnapshots::new(snapshots).unwrap();
    analyze_rotation(&RotationPlan::new(initial, declared, transactions).unwrap())
}

fn classes(report: &RotationReport) -> Vec<SafetyClassification> {
    report
        .steps()
        .iter()
        .map(|step| step.classification())
        .collect()
}

fn expected_account(
    account: u8,
    master: u8,
    thresholds: (u32, u32, u32),
    signers: &[(u8, u8)],
) -> ExpectedAccount {
    ExpectedAccount::new(
        acct(account),
        MasterKeyWeight::from_u8(master),
        Thresholds::new(thresholds.0, thresholds.1, thresholds.2).unwrap(),
        signers
            .iter()
            .map(|&(seed, weight)| ExpectedSigner::new(key(seed), SignerWeight::from_u8(weight)))
            .collect(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Signer replacement order
// ---------------------------------------------------------------------------

/// Account 1: master 0, old signer 100 (weight 2), thresholds 2/2/2.
fn rotation_account() -> AccountSnapshot {
    snap(1, 0, (2, 2, 2), &[(100, 2, HELD)])
}

#[test]
fn adding_the_replacement_before_removing_the_old_signer_is_supported() {
    let report = run(
        vec![rotation_account()],
        held(&[100, 101]),
        vec![
            // Tx 0: 100 (2) >= high 2. After: 100 (2) + 101 (2).
            tx(1, vec![signer_op(None, 101, 2)]),
            // Tx 1: 101 alone (2) >= high 2. After: only 101 (2) >= 2.
            tx(1, vec![signer_op(None, 100, 0)]),
        ],
    );

    assert_eq!(classes(&report), [SupportedReachable, SupportedReachable]);
    assert_eq!(report.classification(), SupportedReachable);
    let account = report.final_state().get(&acct(1)).unwrap();
    assert_eq!(account.signers().len(), 1);
    assert_eq!(account.signers()[0].key(), &key(101));
}

#[test]
fn removing_the_old_signer_before_adding_the_replacement_locks_the_account() {
    let report = run(
        vec![rotation_account()],
        held(&[100, 101]),
        vec![
            // Tx 0 is authorized (2 >= 2) but leaves master 0 and no signers:
            // total configured weight 0 can never meet any threshold.
            tx(1, vec![signer_op(None, 100, 0)]),
            // Tx 1 would need high 2 and nobody can sign.
            tx(1, vec![signer_op(None, 101, 2)]),
        ],
    );

    assert_eq!(classes(&report), [LockoutRisk, Blocked]);
    assert_eq!(report.classification(), Blocked);
    assert_eq!(
        report.steps()[0].reasons(),
        &[StepReason::AdministrationLost {
            account: acct(1),
            kind: LockoutKind::HighThresholdUnreachable
        }]
    );
    // The model still applied tx 0 (it was authorized), so tx 1 saw the
    // emptied account and failed on weight, not on missing evidence.
    assert!(report.steps()[0].applied());
    let StepReason::AuthorizationNotMet { finding, status } = &report.steps()[1].reasons()[0]
    else {
        panic!("expected an unmet authorization requirement");
    };
    assert_eq!(*status, ReachStatus::Unreachable);
    assert_eq!(finding.available_weight(), 0);
}

// ---------------------------------------------------------------------------
// Master key
// ---------------------------------------------------------------------------

#[test]
fn disabling_the_master_key_while_replacements_are_unavailable_risks_lockout() {
    // Master 1, replacement 100 (weight 1) configured but not held.
    // Tx 0: master 1 >= high 1. After: available weight 0, configured 1.
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[(100, 1, NOT_HELD)])],
        held(&[1]),
        vec![tx(1, vec![master_op(None, 0)])],
    );

    assert_eq!(classes(&report), [LockoutRisk]);
    assert_eq!(
        report.steps()[0].reasons(),
        &[StepReason::AdministrationLost {
            account: acct(1),
            kind: LockoutKind::HighThresholdRequiresUnavailableSigners
        }]
    );
}

#[test]
fn disabling_the_master_key_with_a_held_replacement_is_supported() {
    // Same account, replacement held: after tx 0, signer 100 (1) >= 1.
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[(100, 1, HELD)])],
        held(&[1, 100]),
        vec![tx(1, vec![master_op(None, 0)])],
    );
    assert_eq!(classes(&report), [SupportedReachable]);
}

#[test]
fn disabling_the_master_key_with_no_signers_is_a_permanent_dead_end() {
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        held(&[1]),
        vec![tx(1, vec![master_op(None, 0)])],
    );
    assert_eq!(classes(&report), [LockoutRisk]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::AdministrationLost {
            kind: LockoutKind::HighThresholdUnreachable,
            ..
        }]
    ));
}

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/// Account 1: master 1, signer 100 weight 1, thresholds 1/1/1.
fn two_key_account(signer_availability: SignerAvailability) -> AccountSnapshot {
    snap(1, 1, (1, 1, 1), &[(100, 1, signer_availability)])
}

#[test]
fn raising_a_threshold_above_all_configured_weight_is_unreachable() {
    // Total configured weight 1 + 1 = 2, new high threshold 3.
    let report = run(
        vec![two_key_account(HELD)],
        held(&[1, 100]),
        vec![tx(1, vec![high_op(None, 3)])],
    );
    assert_eq!(classes(&report), [LockoutRisk]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::AdministrationLost {
            kind: LockoutKind::HighThresholdUnreachable,
            ..
        }]
    ));
}

#[test]
fn raising_a_threshold_above_available_but_within_configured_weight_depends_on_unavailable_signers()
{
    // Available weight 1 (master only), configured 2, new high threshold 2.
    let report = run(
        vec![two_key_account(NOT_HELD)],
        held(&[1]),
        vec![tx(1, vec![high_op(None, 2)])],
    );
    assert_eq!(classes(&report), [LockoutRisk]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::AdministrationLost {
            kind: LockoutKind::HighThresholdRequiresUnavailableSigners,
            ..
        }]
    ));
}

#[test]
fn raising_a_threshold_to_exactly_the_available_weight_is_supported() {
    // Available 1 + 1 = 2, new high threshold 2: 2 >= 2.
    let report = run(
        vec![two_key_account(HELD)],
        held(&[1, 100]),
        vec![tx(1, vec![high_op(None, 2)])],
    );
    assert_eq!(classes(&report), [SupportedReachable]);
}

#[test]
fn lowering_thresholds_before_removing_a_signer_keeps_administration() {
    // Signers 100 and 101, weight 1 each, master 0, thresholds 2/2/2.
    let accounts = || vec![snap(1, 0, (2, 2, 2), &[(100, 1, HELD), (101, 1, HELD)])];

    let good = run(
        accounts(),
        held(&[100, 101]),
        vec![
            // 100 + 101 = 2 >= 2; afterwards thresholds 1/1/1.
            tx(1, vec![thresholds_op(None, 1, 1, 1)]),
            // 100 alone = 1 >= 1; afterwards 101 (1) >= 1.
            tx(1, vec![signer_op(None, 100, 0)]),
        ],
    );
    assert_eq!(classes(&good), [SupportedReachable, SupportedReachable]);

    // Removing first leaves 101 (1) under the unchanged high threshold 2,
    // and the configured total (1) can never reach it.
    let bad = run(
        accounts(),
        held(&[100, 101]),
        vec![
            tx(1, vec![signer_op(None, 100, 0)]),
            tx(1, vec![thresholds_op(None, 1, 1, 1)]),
        ],
    );
    assert_eq!(classes(&bad), [LockoutRisk, Blocked]);
}

#[test]
fn a_single_sufficient_signer_is_not_a_lockout() {
    // One remaining key with weight 1 against thresholds 1/1/1 still
    // authorizes everything: signer count alone is not the criterion.
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[(100, 1, HELD)])],
        held(&[1, 100]),
        vec![tx(1, vec![signer_op(None, 100, 0)])],
    );
    assert_eq!(classes(&report), [SupportedReachable]);
}

#[test]
fn unreachable_low_threshold_is_reported_separately_from_high() {
    // Master 2 meets high 2, but the account would need low 3 to be its own
    // transaction source and has no other weight.
    let report = run(
        vec![snap(1, 2, (1, 1, 2), &[])],
        held(&[1]),
        vec![tx(1, vec![thresholds_op(None, 3, 1, 2)])],
    );
    assert_eq!(classes(&report), [LockoutRisk]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::AdministrationLost {
            kind: LockoutKind::LowThresholdNotReachable { permanent: true },
            ..
        }]
    ));
}

// ---------------------------------------------------------------------------
// Sequences and single-transaction operation changes
// ---------------------------------------------------------------------------

#[test]
fn multiple_sequential_changes_evolve_the_state_and_match_expectations() {
    let report = run(
        vec![snap(1, 2, (1, 1, 2), &[])],
        held(&[1, 100, 101]),
        vec![
            // Tx 0: master 2 >= 2. After: master 2, 100 (1).
            tx_with(
                1,
                vec![signer_op(None, 100, 1)],
                declarations(&[signer_op(None, 100, 1)], HELD),
                ReserveDeclaration::Unverified,
                vec![expected_account(1, 2, (1, 1, 2), &[(100, 1)])],
            ),
            // Tx 1: master 2 + 100 (1) = 3 >= 2. After: 100 (3).
            tx_with(
                1,
                vec![signer_op(None, 100, 3)],
                declarations(&[signer_op(None, 100, 3)], HELD),
                ReserveDeclaration::Unverified,
                vec![expected_account(1, 2, (1, 1, 2), &[(100, 3)])],
            ),
            // Tx 2: 2 + 3 = 5 >= 2. After: master 0, 100 (3) >= high 3.
            tx_with(
                1,
                vec![master_op(None, 0), high_op(None, 3)],
                Vec::new(),
                ReserveDeclaration::Unverified,
                vec![expected_account(1, 0, (1, 1, 3), &[(100, 3)])],
            ),
        ],
    );
    assert_eq!(
        classes(&report),
        [SupportedReachable, SupportedReachable, SupportedReachable]
    );
    assert!(report.steps().iter().all(|step| step.applied()));
}

#[test]
fn operations_in_one_transaction_are_all_authorized_against_the_pre_transaction_state() {
    // Old signer 100 (2) alone authorizes the transaction. Op 0 removes it;
    // op 1 would then lack authority if checked against the post-op state,
    // but stellar-core checks every operation before any applies.
    let report = run(
        vec![rotation_account()],
        held(&[100, 101]),
        vec![tx(
            1,
            vec![signer_op(None, 100, 0), signer_op(None, 101, 2)],
        )],
    );

    assert_eq!(classes(&report), [SupportedReachable]);
    let authorization = report.steps()[0].authorization().unwrap();
    // One transaction-source finding plus one per operation, all met.
    assert_eq!(authorization.findings().len(), 3);
    assert!(authorization.meets_configured_requirements());
    let account = report.final_state().get(&acct(1)).unwrap();
    assert_eq!(account.signers().len(), 1);
    assert_eq!(account.signers()[0].key(), &key(101));
}

#[test]
fn within_one_transaction_a_removal_without_replacement_is_still_a_lockout() {
    let report = run(
        vec![rotation_account()],
        held(&[100]),
        vec![tx(
            1,
            vec![signer_op(None, 100, 0), thresholds_op(None, 0, 0, 0)],
        )],
    );
    // Both operations were authorized up front, so this is not BLOCKED, but
    // the result has no signer: even thresholds of zero need a signature.
    assert_eq!(classes(&report), [LockoutRisk]);
}

#[test]
fn transaction_source_and_operation_source_are_authorized_separately() {
    // Account 2 pays and submits; account 1 is the operation source.
    // Account 2: master 1, thresholds 1/1/1. Account 1: signer 100 (2), 2/2/2.
    let accounts = || {
        vec![
            snap(2, 1, (1, 1, 1), &[]),
            snap(1, 0, (2, 2, 2), &[(100, 2, HELD)]),
        ]
    };
    let transactions = || vec![tx(2, vec![signer_op(Some(1), 101, 2)])];

    let both = run(accounts(), held(&[2, 100, 101]), transactions());
    assert_eq!(classes(&both), [SupportedReachable]);
    let findings = both.steps()[0].authorization().unwrap().findings();
    assert_eq!(findings[0].account(), acct(2));
    assert_eq!(
        findings[0].subject(),
        AuthorizationSubject::TransactionSource
    );
    assert_eq!(findings[0].threshold(), ThresholdCategory::Low);
    assert_eq!(findings[1].account(), acct(1));
    assert_eq!(findings[1].threshold(), ThresholdCategory::High);
    // Only the operation source's configuration changed.
    assert_eq!(both.steps()[0].changed_accounts().len(), 1);
    assert_eq!(both.steps()[0].changed_accounts()[0].account(), acct(1));
    assert!(
        both.final_state()
            .get(&acct(2))
            .unwrap()
            .signers()
            .is_empty()
    );

    // Holding only account 1's signer: the operation passes, the transaction
    // source fails. Weight from one account never counts for the other.
    let only_signer = run(accounts(), held(&[100]), transactions());
    assert_eq!(classes(&only_signer), [Blocked]);
    let StepReason::AuthorizationNotMet { finding, .. } = &only_signer.steps()[0].reasons()[0]
    else {
        panic!("expected an unmet requirement");
    };
    assert_eq!(finding.subject(), AuthorizationSubject::TransactionSource);
    assert_eq!(finding.account(), acct(2));

    // Holding only the source account's master key: the reverse.
    let only_source = run(accounts(), held(&[2]), transactions());
    assert_eq!(classes(&only_source), [Blocked]);
    let StepReason::AuthorizationNotMet { finding, .. } = &only_source.steps()[0].reasons()[0]
    else {
        panic!("expected an unmet requirement");
    };
    assert!(matches!(
        finding.subject(),
        AuthorizationSubject::Operation { index: 0, .. }
    ));
    assert_eq!(finding.account(), acct(1));
    // High threshold 2 against held weight 0: two short.
    assert_eq!(
        finding.explanation(),
        AuthorizationExplanation::MissingWeight { missing: 2 }
    );
}

// ---------------------------------------------------------------------------
// Signer limits, zero weights and removed signers
// ---------------------------------------------------------------------------

fn full_account() -> AccountSnapshot {
    let signers: Vec<_> = (0..MAX_SIGNERS as u8)
        .map(|offset| (100 + offset, 1, HELD))
        .collect();
    snap(1, 1, (1, 1, 1), &signers)
}

#[test]
fn a_twenty_first_signer_is_an_invalid_transition() {
    let report = run(
        vec![full_account()],
        held(&[1]),
        vec![tx(1, vec![signer_op(None, 200, 1)])],
    );
    assert_eq!(classes(&report), [InvalidTransition]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::InvalidTransition(
            TransitionError::SignerLimitExceeded { .. }
        )]
    ));
    // The invalid change was not applied.
    assert_eq!(
        report.final_state().get(&acct(1)).unwrap().signers().len(),
        MAX_SIGNERS
    );
}

#[test]
fn at_the_limit_replacement_works_when_the_removal_comes_first() {
    // In one transaction (remove, then add) and across two transactions.
    let one_tx = run(
        vec![full_account()],
        held(&[1]),
        vec![tx(
            1,
            vec![signer_op(None, 100, 0), signer_op(None, 200, 1)],
        )],
    );
    assert_eq!(classes(&one_tx), [SupportedReachable]);

    let two_tx = run(
        vec![full_account()],
        held(&[1]),
        vec![
            tx(1, vec![signer_op(None, 100, 0)]),
            tx(1, vec![signer_op(None, 200, 1)]),
        ],
    );
    assert_eq!(classes(&two_tx), [SupportedReachable, SupportedReachable]);

    // Reversed within one transaction, the add executes at 20 signers.
    let reversed = run(
        vec![full_account()],
        held(&[1]),
        vec![tx(
            1,
            vec![signer_op(None, 200, 1), signer_op(None, 100, 0)],
        )],
    );
    assert_eq!(classes(&reversed), [InvalidTransition]);
}

#[test]
fn a_zero_weight_snapshot_signer_contributes_nothing() {
    // Signer 100 has weight 0 and is held; signer 101 has weight 1. The held
    // weight is 1, so a high threshold of 2 is unmet.
    let report = run(
        vec![snap(1, 0, (1, 1, 2), &[(100, 0, HELD), (101, 1, HELD)])],
        held(&[100, 101]),
        vec![
            tx(1, vec![Operation::payment(None)]),
            tx(1, vec![high_op(None, 1)]),
        ],
    );
    // Payment (medium 1) is met by 101; the threshold change (high 2) is not.
    assert_eq!(classes(&report), [SupportedReachable, Blocked]);
}

#[test]
fn a_removed_signer_contributes_nothing_afterwards_even_if_still_declared() {
    // Master 1 (not held), signer 100 weight 1 (held), thresholds 1/1/1.
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[(100, 1, HELD)])],
        held(&[100]),
        vec![
            // 100 (1) >= 1; afterwards only the unheld master remains.
            tx(1, vec![signer_op(None, 100, 0)]),
            tx(1, vec![Operation::payment(None)]),
        ],
    );
    assert_eq!(classes(&report), [LockoutRisk, Blocked]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::AdministrationLost {
            kind: LockoutKind::HighThresholdRequiresUnavailableSigners,
            ..
        }]
    ));
    let StepReason::AuthorizationNotMet { finding, status } = &report.steps()[1].reasons()[0]
    else {
        panic!("expected an unmet requirement");
    };
    assert_eq!(finding.available_weight(), 0);
    assert_eq!(*status, ReachStatus::RequiresUnavailableSigners);
}

// ---------------------------------------------------------------------------
// Unmodeled constraints
// ---------------------------------------------------------------------------

#[test]
fn declared_insufficient_reserve_makes_a_signer_addition_invalid() {
    let ops = vec![signer_op(None, 100, 1)];
    let transaction = tx_with(
        1,
        ops.clone(),
        declarations(&ops, HELD),
        ReserveDeclaration::DeclaredInsufficient,
        Vec::new(),
    );
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        held(&[1, 100]),
        vec![transaction],
    );
    assert_eq!(classes(&report), [InvalidTransition]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::InvalidTransition(
            TransitionError::InsufficientReserveDeclared { .. }
        )]
    ));
}

#[test]
fn an_unverified_reserve_is_never_reported_as_safe() {
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        held(&[1, 100]),
        vec![tx(1, vec![signer_op(None, 100, 1)])],
    );
    // The addition is reachable under the declared assumptions...
    assert_eq!(classes(&report), [SupportedReachable]);
    // ...but the report says it is a model, that reserves were not checked,
    // and that nothing was verified on a ledger.
    assert_eq!(report.basis(), ResultBasis::ConditionalModel);
    assert!(!report.verified_on_chain());
    assert!(
        report
            .limitations()
            .contains(&RotationLimitation::ReservesNotModeled)
    );
    assert!(
        report
            .limitations()
            .contains(&RotationLimitation::LedgerEvidenceNotVerified)
    );
}

// ---------------------------------------------------------------------------
// Missing evidence and unsupported signer types
// ---------------------------------------------------------------------------

#[test]
fn a_missing_snapshot_is_inconclusive_and_halts_later_steps() {
    let report = run(
        Vec::new(),
        held(&[1]),
        vec![
            tx(1, vec![Operation::payment(None)]),
            tx(1, vec![Operation::payment(None)]),
        ],
    );
    assert_eq!(classes(&report), [Inconclusive, Inconclusive]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::EvidenceInsufficient(
            AnalysisError::MissingAccountSnapshot { .. }
        )]
    ));
    assert_eq!(
        report.steps()[1].reasons(),
        &[StepReason::PredecessorNotApplied { step: 0 }]
    );
}

#[test]
fn a_missing_operation_source_snapshot_is_inconclusive() {
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        held(&[1]),
        vec![tx(1, vec![signer_op(Some(2), 100, 1)])],
    );
    assert_eq!(classes(&report), [Inconclusive]);
    let StepReason::EvidenceInsufficient(AnalysisError::MissingAccountSnapshot { account, .. }) =
        &report.steps()[0].reasons()[0]
    else {
        panic!("expected a missing snapshot");
    };
    assert_eq!(*account, acct(2));
}

#[test]
fn a_snapshot_without_network_provenance_is_inconclusive() {
    let no_network = AccountSnapshot::new(
        acct(1),
        MasterKeyWeight::from_u8(1),
        Thresholds::new(1, 1, 1).unwrap(),
        Vec::new(),
        SnapshotProvenance::caller_provided(None),
    )
    .unwrap();
    let report = run(
        vec![no_network],
        held(&[1]),
        vec![tx(1, vec![Operation::payment(None)])],
    );
    assert_eq!(classes(&report), [Inconclusive]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::EvidenceInsufficient(
            AnalysisError::InsufficientProvenance { .. }
        )]
    ));
}

#[test]
fn unsupported_declared_signers_turn_an_unmet_requirement_inconclusive() {
    // Only a hash-X signer is declared. The model cannot count it, so it
    // cannot say the requirement is unmet either.
    let mut declared = held(&[]);
    declared.push(DeclaredSigner::Unsupported(SignerType::HashX));
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        declared,
        vec![tx(1, vec![Operation::payment(None)])],
    );
    assert_eq!(classes(&report), [Inconclusive]);
    // Both the transaction-source and the operation check are unmet.
    let reasons = report.steps()[0].reasons();
    assert_eq!(reasons.len(), 2);
    assert!(
        reasons
            .iter()
            .all(|reason| matches!(reason, StepReason::AuthorizationUndecidable { .. }))
    );
    assert_eq!(report.unsupported_signer_types(), &[SignerType::HashX]);
}

#[test]
fn unsupported_declared_signers_do_not_undermine_a_requirement_already_met() {
    let mut declared = held(&[1]);
    declared.push(DeclaredSigner::Unsupported(SignerType::PreAuthTx));
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        declared,
        vec![tx(1, vec![Operation::payment(None)])],
    );
    assert_eq!(classes(&report), [SupportedReachable]);
    assert_eq!(report.unsupported_signer_types(), &[SignerType::PreAuthTx]);
}

#[test]
fn contradictory_availability_for_an_existing_signer_is_inconclusive() {
    // The snapshot says signer 100 is not held; the plan says it is.
    let ops = vec![signer_op(None, 100, 2)];
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[(100, 1, NOT_HELD)])],
        held(&[1, 100]),
        vec![tx(1, ops)],
    );
    assert_eq!(classes(&report), [Inconclusive]);
    assert!(matches!(
        report.steps()[0].reasons(),
        [StepReason::TransitionUnresolved(
            TransitionError::ConflictingAvailability { .. }
        )]
    ));
}

#[test]
fn a_master_weight_expectation_mismatch_halts_dependent_transactions() {
    let ops = vec![master_op(None, 0)];
    let transaction = tx_with(
        1,
        ops,
        Vec::new(),
        ReserveDeclaration::Unverified,
        vec![expected_account(1, 2, (1, 1, 1), &[])],
    );
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        held(&[1]),
        vec![transaction, tx(1, vec![master_op(None, 1)])],
    );

    assert_eq!(classes(&report), [Inconclusive, Inconclusive]);
    assert_eq!(
        report.steps()[0].reasons(),
        &[StepReason::ExpectationMismatch(
            ExpectationMismatch::MasterKeyWeight {
                account: acct(1),
                expected: 2,
                modeled: 0,
            }
        )]
    );
    assert!(!report.steps()[0].applied());
    assert_eq!(
        report.steps()[1].reasons(),
        &[StepReason::PredecessorNotApplied { step: 0 }]
    );
    assert_eq!(
        report
            .final_state()
            .get(&acct(1))
            .unwrap()
            .master_key_weight()
            .value(),
        1
    );
}

#[test]
fn a_threshold_expectation_mismatch_halts_dependent_transactions() {
    let mut changes = SetOptionsChanges::new();
    changes.medium_threshold = Some(Threshold::from_u8(2));
    let transaction = tx_with(
        1,
        vec![Operation::set_options(None, changes)],
        Vec::new(),
        ReserveDeclaration::Unverified,
        vec![expected_account(1, 1, (1, 1, 1), &[])],
    );
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        held(&[1]),
        vec![transaction, tx(1, vec![Operation::payment(None)])],
    );

    assert_eq!(classes(&report), [Inconclusive, Inconclusive]);
    assert_eq!(
        report.steps()[0].reasons(),
        &[StepReason::ExpectationMismatch(
            ExpectationMismatch::Thresholds { account: acct(1) }
        )]
    );
    assert_eq!(
        report.steps()[1].reasons(),
        &[StepReason::PredecessorNotApplied { step: 0 }]
    );
    assert_eq!(
        report.final_state().get(&acct(1)).unwrap().thresholds(),
        Thresholds::new(1, 1, 1).unwrap()
    );
}

#[test]
fn a_signer_set_expectation_mismatch_halts_dependent_transactions() {
    let ops = vec![signer_op(None, 100, 2)];
    let transaction = tx_with(
        1,
        ops.clone(),
        declarations(&ops, HELD),
        ReserveDeclaration::Unverified,
        vec![expected_account(1, 1, (1, 1, 1), &[])],
    );
    let report = run(
        vec![snap(1, 1, (1, 1, 1), &[])],
        held(&[1, 100]),
        vec![transaction, tx(1, vec![signer_op(None, 100, 0)])],
    );

    assert_eq!(classes(&report), [Inconclusive, Inconclusive]);
    assert_eq!(
        report.steps()[0].reasons(),
        &[StepReason::ExpectationMismatch(
            ExpectationMismatch::Signers { account: acct(1) }
        )]
    );
    assert!(!report.steps()[0].applied());
    assert_eq!(
        report.steps()[1].reasons(),
        &[StepReason::PredecessorNotApplied { step: 0 }]
    );
    assert!(
        report
            .final_state()
            .get(&acct(1))
            .unwrap()
            .signers()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn results_do_not_depend_on_input_ordering() {
    let transactions = || {
        vec![
            tx(1, vec![signer_op(None, 101, 1), signer_op(None, 102, 1)]),
            tx(1, vec![signer_op(None, 100, 0)]),
        ]
    };
    let signers = [(100, 1, HELD), (103, 1, HELD)];
    let reversed = [(103, 1, HELD), (100, 1, HELD)];

    let first = run(
        vec![snap(2, 1, (1, 1, 1), &[]), snap(1, 0, (1, 1, 1), &signers)],
        held(&[100, 101, 102, 103]),
        transactions(),
    );
    let second = run(
        vec![snap(1, 0, (1, 1, 1), &reversed), snap(2, 1, (1, 1, 1), &[])],
        held(&[103, 102, 101, 100, 100]),
        transactions(),
    );
    assert_eq!(first, second);
    assert_eq!(first.classification(), SupportedReachable);
}

// ---------------------------------------------------------------------------
// C2 regression cases
// ---------------------------------------------------------------------------

#[test]
fn c2_regression_threshold_zero_still_needs_a_matching_signer() {
    // Master 0 is not a listed signer, so even all-zero thresholds cannot be
    // met by any signature.
    let report = run(
        vec![snap(1, 0, (0, 0, 0), &[])],
        held(&[1]),
        vec![tx(1, vec![Operation::payment(None)])],
    );
    assert_eq!(classes(&report), [Blocked]);
    let StepReason::AuthorizationNotMet { finding, status } = &report.steps()[0].reasons()[0]
    else {
        panic!("expected an unmet requirement");
    };
    assert_eq!(
        finding.explanation(),
        AuthorizationExplanation::NoMatchingSigner
    );
    assert_eq!(*status, ReachStatus::Unreachable);
}

#[test]
fn c2_regression_threshold_categories_are_applied_per_operation() {
    // Thresholds low 1 / medium 2 / high 3 with held weight 2:
    // bump sequence (low) and payment (medium) pass, set-options on a
    // threshold (high) does not.
    let accounts = || vec![snap(1, 2, (1, 2, 3), &[])];

    let low_and_medium = run(
        accounts(),
        held(&[1]),
        vec![tx(
            1,
            vec![Operation::bump_sequence(None), Operation::payment(None)],
        )],
    );
    assert_eq!(classes(&low_and_medium), [SupportedReachable]);

    let high = run(accounts(), held(&[1]), vec![tx(1, vec![high_op(None, 3)])]);
    assert_eq!(classes(&high), [Blocked]);

    // A flags-only SetOptions is medium, not high.
    let mut flags = SetOptionsChanges::new();
    flags.has_set_flags = true;
    let medium = run(
        accounts(),
        held(&[1]),
        vec![tx(1, vec![Operation::set_options(None, flags)])],
    );
    assert_eq!(classes(&medium), [SupportedReachable]);
}

#[test]
fn c2_regression_weights_sum_exactly_and_one_short_fails() {
    // Signers 100 (1) + 101 (1) + master 1 = 3 >= high 3; without 101 it is 2.
    let accounts = || vec![snap(1, 1, (1, 1, 3), &[(100, 1, HELD), (101, 1, HELD)])];
    let all = run(
        accounts(),
        held(&[1, 100, 101]),
        vec![tx(1, vec![high_op(None, 3)])],
    );
    assert_eq!(classes(&all), [SupportedReachable]);
    let short = run(
        accounts(),
        held(&[1, 100]),
        vec![tx(1, vec![high_op(None, 3)])],
    );
    assert_eq!(classes(&short), [Blocked]);
    let StepReason::AuthorizationNotMet { finding, .. } = &short.steps()[0].reasons()[0] else {
        panic!("expected an unmet requirement");
    };
    assert_eq!(
        finding.explanation(),
        AuthorizationExplanation::MissingWeight { missing: 1 }
    );
}

#[test]
fn c2_regression_unavailable_flag_overrides_a_declared_key() {
    let report = run(
        vec![snap(1, 0, (1, 1, 1), &[(100, 5, NOT_HELD)])],
        held(&[100]),
        vec![tx(1, vec![Operation::payment(None)])],
    );
    assert_eq!(classes(&report), [Blocked]);
}
