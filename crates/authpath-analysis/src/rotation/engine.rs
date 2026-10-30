//! Sequential rotation analysis.
//!
//! Each planned transaction is authorized against the configuration that
//! exists *before* it, using the C2 engine unchanged. Only if authorization
//! succeeds are its changes applied conditionally, and an internally
//! consistent result becomes the starting state of the next transaction. The
//! first step that cannot be authorized, cannot apply, lacks evidence, or
//! disagrees with an expected configuration halts the chain, because later
//! starting states would be unknown; later steps are reported as inconclusive
//! rather than evaluated against a state that was never reached.

use authpath_model::{AccountId, SignerType};

use super::{
    classification::{ResultBasis, RotationLimitation, SafetyClassification, StepReason, classify},
    plan::{PlannedTransaction, RotationPlan},
    reachability::{AccountReach, account_reach},
    transition::{
        ModeledState, TransitionError, apply_transaction, compare_expected,
        validate_transaction_availability,
    },
};
use crate::{AuthorizationReport, analyze};

/// The analysis of one planned transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepResult {
    index: usize,
    classification: SafetyClassification,
    reasons: Vec<StepReason>,
    authorization: Option<AuthorizationReport>,
    changed_accounts: Vec<AccountReach>,
    applied: bool,
}

impl StepResult {
    /// Returns the zero-based transaction index.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Returns the step's classification.
    #[must_use]
    pub const fn classification(&self) -> SafetyClassification {
        self.classification
    }

    /// Returns the evidence behind the classification; empty only for
    /// `SUPPORTED_REACHABLE`.
    #[must_use]
    pub fn reasons(&self) -> &[StepReason] {
        &self.reasons
    }

    /// Returns the C2 authorization report against the pre-transaction
    /// state, with transaction-source and operation-source findings kept
    /// separate. `None` when the step was not evaluated or lacked evidence.
    #[must_use]
    pub const fn authorization(&self) -> Option<&AuthorizationReport> {
        self.authorization.as_ref()
    }

    /// Returns post-transaction reachability for each account whose
    /// authorization configuration the step changed.
    #[must_use]
    pub fn changed_accounts(&self) -> &[AccountReach] {
        &self.changed_accounts
    }

    /// Reports whether this step was accepted into the sequential model.
    /// Application is conditional on the transaction actually succeeding on a
    /// ledger, and an expectation mismatch is not accepted as an applied step.
    #[must_use]
    pub const fn applied(&self) -> bool {
        self.applied
    }
}

/// The result of analyzing a rotation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationReport {
    steps: Vec<StepResult>,
    classification: SafetyClassification,
    unsupported_signer_types: Vec<SignerType>,
    final_state: ModeledState,
}

impl RotationReport {
    /// Returns one result per planned transaction, in order.
    #[must_use]
    pub fn steps(&self) -> &[StepResult] {
        &self.steps
    }

    /// Returns the most severe step classification.
    #[must_use]
    pub const fn classification(&self) -> SafetyClassification {
        self.classification
    }

    /// Returns the declared signer kinds the model could not evaluate.
    #[must_use]
    pub fn unsupported_signer_types(&self) -> &[SignerType] {
        &self.unsupported_signer_types
    }

    /// Returns the modeled state after the last step that was applied.
    #[must_use]
    pub const fn final_state(&self) -> &ModeledState {
        &self.final_state
    }

    /// Always [`ResultBasis::ConditionalModel`].
    #[must_use]
    pub const fn basis(&self) -> ResultBasis {
        ResultBasis::ConditionalModel
    }

    /// Always `false`: no result of this engine is a verified on-chain fact.
    #[must_use]
    pub const fn verified_on_chain(&self) -> bool {
        false
    }

    /// Returns the fixed limitations that qualify this report.
    #[must_use]
    pub fn limitations(&self) -> &'static [RotationLimitation] {
        super::classification::limitations()
    }
}

/// Analyzes a rotation plan step by step.
///
/// Evidence gaps never produce an error; they produce `INCONCLUSIVE` steps.
#[must_use]
pub fn analyze_rotation(plan: &RotationPlan) -> RotationReport {
    let mut state = ModeledState::from_initial(plan.initial());
    let mut steps = Vec::with_capacity(plan.transactions().len());
    let mut halted_at = None;

    for (index, transaction) in plan.transactions().iter().enumerate() {
        if let Some(step) = halted_at {
            steps.push(not_evaluated(index, step));
            continue;
        }
        let (result, next) = evaluate_step(plan, &state, index, transaction);
        match next {
            Some(next) => state = next,
            None => halted_at = Some(index),
        }
        steps.push(result);
    }

    let classification = steps.iter().map(StepResult::classification).fold(
        SafetyClassification::SupportedReachable,
        SafetyClassification::worst,
    );

    RotationReport {
        steps,
        classification,
        unsupported_signer_types: plan.unsupported_signer_types().to_vec(),
        final_state: state,
    }
}

fn not_evaluated(index: usize, step: usize) -> StepResult {
    let reasons = vec![StepReason::PredecessorNotApplied { step }];
    StepResult {
        index,
        classification: classify(&reasons),
        reasons,
        authorization: None,
        changed_accounts: Vec::new(),
        applied: false,
    }
}

fn halted(
    index: usize,
    reasons: Vec<StepReason>,
    authorization: Option<AuthorizationReport>,
) -> (StepResult, Option<ModeledState>) {
    let result = StepResult {
        index,
        classification: classify(&reasons),
        reasons,
        authorization,
        changed_accounts: Vec::new(),
        applied: false,
    };
    (result, None)
}

fn evaluate_step(
    plan: &RotationPlan,
    state: &ModeledState,
    index: usize,
    transaction: &PlannedTransaction,
) -> (StepResult, Option<ModeledState>) {
    let report = match analyze(
        transaction.description(),
        &state.snapshots(),
        plan.available(),
    ) {
        Ok(report) => report,
        Err(error) => return halted(index, vec![StepReason::EvidenceInsufficient(error)], None),
    };

    if !report.meets_configured_requirements() {
        let mut reasons = Vec::new();
        for finding in report.findings().iter().filter(|f| !f.meets_requirement()) {
            let reach = state
                .get(&finding.account())
                .map(|snapshot| account_reach(snapshot, plan.available()))
                .transpose();
            let reason = match reach {
                Err(error) => StepReason::EvidenceInsufficient(error),
                Ok(_) if !plan.unsupported_signer_types().is_empty() => {
                    StepReason::AuthorizationUndecidable {
                        finding: finding.clone(),
                        unsupported: plan.unsupported_signer_types().to_vec(),
                    }
                }
                Ok(reach) => StepReason::AuthorizationNotMet {
                    finding: finding.clone(),
                    // C2 succeeded, so every finding's snapshot exists.
                    status: reach.map_or(super::reachability::ReachStatus::Unreachable, |reach| {
                        reach.level(finding.threshold()).status()
                    }),
                },
            };
            reasons.push(reason);
        }
        return halted(index, reasons, Some(report));
    }

    if let Err(error) = validate_transaction_availability(transaction, plan.available()) {
        return halted(
            index,
            vec![StepReason::TransitionUnresolved(error)],
            Some(report),
        );
    }

    let next = match apply_transaction(state, transaction) {
        Ok(next) => next,
        Err(error) => {
            let reason = match error {
                TransitionError::SignerLimitExceeded { .. }
                | TransitionError::InsufficientReserveDeclared { .. } => {
                    StepReason::InvalidTransition(error)
                }
                TransitionError::MissingAccountSnapshot { .. }
                | TransitionError::ConflictingAvailability { .. }
                | TransitionError::GlobalAvailabilityMismatch { .. }
                | TransitionError::InvalidResult(_) => StepReason::TransitionUnresolved(error),
            };
            return halted(index, vec![reason], Some(report));
        }
    };

    // Expectations are caller-supplied assertions about the intended result,
    // not proof that a ledger executed the transaction. A disagreement means
    // that this candidate state is not authoritative enough to authorize any
    // dependent transaction, so do not commit it to the sequential model.
    let mismatches = compare_expected(&next, transaction.expected());
    if !mismatches.is_empty() {
        let reasons = mismatches
            .into_iter()
            .map(StepReason::ExpectationMismatch)
            .collect();
        return halted(index, reasons, Some(report));
    }

    let mut reasons = Vec::new();
    let mut changed_accounts = Vec::new();
    for changed in changed_accounts_between(state, &next) {
        let (Some(before), Some(after)) = (state.get(&changed), next.get(&changed)) else {
            continue;
        };
        match (
            account_reach(before, plan.available()),
            account_reach(after, plan.available()),
        ) {
            (Ok(before), Ok(after)) => {
                if let Some(kind) = after
                    .lockout()
                    .filter(|kind| before.lockout() != Some(*kind))
                {
                    reasons.push(StepReason::AdministrationLost {
                        account: changed,
                        kind,
                    });
                }
                changed_accounts.push(after);
            }
            (Err(error), _) | (_, Err(error)) => {
                reasons.push(StepReason::EvidenceInsufficient(error));
            }
        }
    }
    let result = StepResult {
        index,
        classification: classify(&reasons),
        reasons,
        authorization: Some(report),
        changed_accounts,
        applied: true,
    };
    (result, Some(next))
}

fn changed_accounts_between(before: &ModeledState, after: &ModeledState) -> Vec<AccountId> {
    after
        .snapshots()
        .accounts()
        .filter(|snapshot| before.get(snapshot.account_id()) != Some(snapshot))
        .map(|snapshot| *snapshot.account_id())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountSnapshots, DeclaredSigner, Operation, SetOptionsChanges, SignerChange,
        TransactionDescription,
        rotation::{ReserveDeclaration, SignerDeclaration},
    };
    use authpath_model::{
        AccountSnapshot, ConfiguredSigner, Ed25519PublicKey, MasterKeyWeight, NetworkIdentity,
        SignerAvailability, SignerWeight, SnapshotProvenance, Thresholds,
    };

    fn account() -> AccountId {
        AccountId::from_bytes([1; 32])
    }

    fn key(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes([seed; 32])
    }

    fn initial(master: u8, thresholds: (u32, u32, u32)) -> AccountSnapshots {
        AccountSnapshots::new([AccountSnapshot::new(
            account(),
            MasterKeyWeight::from_u8(master),
            Thresholds::new(thresholds.0, thresholds.1, thresholds.2).unwrap(),
            vec![ConfiguredSigner::new(
                key(2),
                SignerWeight::from_u8(1),
                SignerAvailability::Available,
            )],
            SnapshotProvenance::caller_provided(Some(NetworkIdentity::new("fixture").unwrap())),
        )
        .unwrap()])
        .unwrap()
    }

    fn set_master_weight(weight: u8) -> PlannedTransaction {
        let mut changes = SetOptionsChanges::new();
        changes.master_key_weight = Some(MasterKeyWeight::from_u8(weight));
        PlannedTransaction::new(
            TransactionDescription::new(account(), vec![Operation::set_options(None, changes)])
                .unwrap(),
            Vec::new(),
            ReserveDeclaration::Unverified,
            Vec::new(),
        )
        .unwrap()
    }

    fn add_signer(seed: u8, weight: u8) -> PlannedTransaction {
        let mut changes = SetOptionsChanges::new();
        changes.signer = Some(SignerChange::new(key(seed), SignerWeight::from_u8(weight)));
        PlannedTransaction::new(
            TransactionDescription::new(account(), vec![Operation::set_options(None, changes)])
                .unwrap(),
            vec![SignerDeclaration::new(
                0,
                key(seed),
                SignerAvailability::Available,
            )],
            ReserveDeclaration::Unverified,
            Vec::new(),
        )
        .unwrap()
    }

    fn plan(
        initial: AccountSnapshots,
        declared: Vec<DeclaredSigner>,
        transactions: Vec<PlannedTransaction>,
    ) -> RotationPlan {
        RotationPlan::new(initial, declared, transactions).unwrap()
    }

    #[test]
    fn an_authorized_change_that_keeps_administration_is_supported() {
        let report = analyze_rotation(&plan(
            initial(1, (1, 1, 1)),
            vec![
                DeclaredSigner::Ed25519(key(1)),
                DeclaredSigner::Ed25519(key(3)),
            ],
            vec![add_signer(3, 1)],
        ));

        assert_eq!(
            report.classification(),
            SafetyClassification::SupportedReachable
        );
        assert!(report.steps()[0].applied());
        assert!(report.steps()[0].reasons().is_empty());
        assert_eq!(report.basis(), ResultBasis::ConditionalModel);
        assert!(!report.verified_on_chain());
        assert_eq!(
            report
                .final_state()
                .get(&account())
                .unwrap()
                .signers()
                .len(),
            2
        );
    }

    #[test]
    fn a_blocked_step_halts_later_steps_without_evaluating_them() {
        // Master weight 1 cannot meet the high threshold of 2 without signer
        // 2, which is not declared available.
        let report = analyze_rotation(&plan(
            initial(1, (1, 1, 2)),
            vec![DeclaredSigner::Ed25519(key(1))],
            vec![set_master_weight(2), set_master_weight(0)],
        ));

        assert_eq!(report.classification(), SafetyClassification::Blocked);
        assert_eq!(
            report.steps()[0].classification(),
            SafetyClassification::Blocked
        );
        assert!(!report.steps()[0].applied());
        assert!(matches!(
            report.steps()[0].reasons(),
            [StepReason::AuthorizationNotMet {
                status: super::super::reachability::ReachStatus::RequiresUnavailableSigners,
                ..
            }]
        ));
        assert_eq!(
            report.steps()[1].reasons(),
            &[StepReason::PredecessorNotApplied { step: 0 }]
        );
        assert!(report.steps()[1].authorization().is_none());
        // The model never advanced past the initial state.
        assert_eq!(
            report
                .final_state()
                .get(&account())
                .unwrap()
                .master_key_weight()
                .value(),
            1
        );
    }

    #[test]
    fn identical_plans_produce_identical_reports() {
        let build = || {
            plan(
                initial(1, (1, 1, 1)),
                vec![
                    DeclaredSigner::Ed25519(key(1)),
                    DeclaredSigner::Ed25519(key(3)),
                ],
                vec![add_signer(3, 1), set_master_weight(0)],
            )
        };
        assert_eq!(analyze_rotation(&build()), analyze_rotation(&build()));
    }
}
