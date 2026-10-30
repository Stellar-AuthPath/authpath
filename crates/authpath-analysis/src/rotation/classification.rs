//! Safety classifications and the evidence behind them.
//!
//! Every classification is a statement about a *conditional model*: the
//! proposed transactions succeed, the declared signers are held, and the
//! supplied snapshots are accurate. None of them is a verified on-chain
//! result, and none of them says an account is absolutely safe.

use std::fmt;

use authpath_model::{AccountId, SignerType};

use super::{
    reachability::{LockoutKind, ReachStatus},
    transition::{ExpectationMismatch, TransitionError},
};
use crate::{AnalysisError, AuthorizationFinding};

/// The documented result categories, from least to most severe.
///
/// | Category | Meaning |
/// | --- | --- |
/// | `SUPPORTED_REACHABLE` | Under the declared assumptions the modeled configuration meets the step's authorization and every changed account stays administrable. |
/// | `INCONCLUSIVE` | Evidence or supported semantics are insufficient for a reliable finding. |
/// | `LOCKOUT_RISK` | The step is authorized but leaves a changed account unable to authorize future administrative changes with the declared signers. |
/// | `INVALID_TRANSITION` | The described change cannot apply under a supported protocol rule or a caller-declared constraint. |
/// | `BLOCKED` | A supported authorization requirement is not met by the declared signers. |
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SafetyClassification {
    /// The modeled configuration retains the specified capability under the
    /// declared assumptions. Not a guarantee of on-chain success.
    SupportedReachable,
    /// Evidence, unsupported signer types or unsupported semantics prevent a
    /// reliable finding.
    Inconclusive,
    /// A change may prevent required future administrative authorization.
    LockoutRisk,
    /// The change violates a supported protocol rule or declared constraint.
    InvalidTransition,
    /// A supported authorization requirement cannot be met.
    Blocked,
}

impl SafetyClassification {
    /// Returns the documented constant name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SupportedReachable => "SUPPORTED_REACHABLE",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::LockoutRisk => "LOCKOUT_RISK",
            Self::InvalidTransition => "INVALID_TRANSITION",
            Self::Blocked => "BLOCKED",
        }
    }

    /// Returns the more severe of two classifications.
    #[must_use]
    pub fn worst(self, other: Self) -> Self {
        self.max(other)
    }
}

impl fmt::Display for SafetyClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The nature of a rotation result. There is deliberately no verified
/// variant: this crate reads no ledger and executes nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultBasis {
    /// Derived from supplied snapshots and assumed-successful transitions.
    ConditionalModel,
}

/// Facts the rotation model does not establish, attached to every report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationLimitation {
    /// Signature bytes were not cryptographically checked.
    CryptographicSignaturesNotVerified,
    /// Private-key possession was not proven.
    SignerPossessionNotVerified,
    /// Snapshots were not fetched or verified against a ledger.
    LedgerEvidenceNotVerified,
    /// Base reserves and balances were not modeled (`LOW_RESERVE`,
    /// subentry and sponsorship limits).
    ReservesNotModeled,
    /// Sequence numbers, fees and preconditions (time bounds, ledger bounds,
    /// extra signers) were not modeled.
    SequenceFeesAndPreconditionsNotModeled,
    /// Ledger acceptance and transaction ordering were not modeled, nor were
    /// concurrent changes by other parties between planned transactions.
    LedgerAcceptanceNotModeled,
    /// Pre-authorized transaction, hash-X and signed-payload signers cannot
    /// be represented in snapshots, so their presence on a real account
    /// would make weight totals incomplete.
    UnsupportedSignerKindsNotRepresentable,
    /// Operation effects other than authorization configuration (balances,
    /// trustlines, flags) were not modeled.
    NonAuthorizationEffectsNotModeled,
}

static LIMITATIONS: [RotationLimitation; 8] = [
    RotationLimitation::CryptographicSignaturesNotVerified,
    RotationLimitation::SignerPossessionNotVerified,
    RotationLimitation::LedgerEvidenceNotVerified,
    RotationLimitation::ReservesNotModeled,
    RotationLimitation::SequenceFeesAndPreconditionsNotModeled,
    RotationLimitation::LedgerAcceptanceNotModeled,
    RotationLimitation::UnsupportedSignerKindsNotRepresentable,
    RotationLimitation::NonAuthorizationEffectsNotModeled,
];

/// Returns the fixed limitations that qualify every rotation result.
#[must_use]
pub fn limitations() -> &'static [RotationLimitation] {
    &LIMITATIONS
}

/// Evidence for a step's classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepReason {
    /// A supported authorization requirement is not met by declared signers.
    AuthorizationNotMet {
        /// The unmet check.
        finding: AuthorizationFinding,
        /// Whether unavailable signers would suffice or no signer set could.
        status: ReachStatus,
    },
    /// A requirement is unmet by the modeled signers, but declared signer
    /// kinds the model cannot evaluate might satisfy it.
    AuthorizationUndecidable {
        /// The unmet check.
        finding: AuthorizationFinding,
        /// The declared signer kinds that were not evaluated.
        unsupported: Vec<SignerType>,
    },
    /// The transition cannot apply under a protocol rule or declared constraint.
    InvalidTransition(TransitionError),
    /// The state could not be resolved because the plan is contradictory or
    /// incomplete.
    TransitionUnresolved(TransitionError),
    /// A changed account lost administrative reach.
    AdministrationLost {
        /// The changed account.
        account: AccountId,
        /// How reach was lost.
        kind: LockoutKind,
    },
    /// Authorization could not be evaluated for lack of evidence.
    EvidenceInsufficient(AnalysisError),
    /// The caller's expected configuration disagrees with the model.
    ExpectationMismatch(ExpectationMismatch),
    /// An earlier step did not apply, so this step's starting state is unknown.
    PredecessorNotApplied {
        /// The zero-based index of the earlier step.
        step: usize,
    },
}

impl StepReason {
    /// Returns the classification this reason supports.
    #[must_use]
    pub const fn classification(&self) -> SafetyClassification {
        match self {
            Self::AuthorizationNotMet { .. } => SafetyClassification::Blocked,
            Self::InvalidTransition(_) => SafetyClassification::InvalidTransition,
            Self::AdministrationLost { .. } => SafetyClassification::LockoutRisk,
            Self::AuthorizationUndecidable { .. }
            | Self::TransitionUnresolved(_)
            | Self::EvidenceInsufficient(_)
            | Self::ExpectationMismatch(_)
            | Self::PredecessorNotApplied { .. } => SafetyClassification::Inconclusive,
        }
    }
}

/// Derives a classification from reasons: the most severe one, or
/// `SUPPORTED_REACHABLE` when there are none.
#[must_use]
pub fn classify(reasons: &[StepReason]) -> SafetyClassification {
    reasons.iter().map(StepReason::classification).fold(
        SafetyClassification::SupportedReachable,
        SafetyClassification::worst,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> AccountId {
        AccountId::from_bytes([1; 32])
    }

    #[test]
    fn names_match_the_documented_constants() {
        let names: Vec<_> = [
            SafetyClassification::SupportedReachable,
            SafetyClassification::Inconclusive,
            SafetyClassification::LockoutRisk,
            SafetyClassification::InvalidTransition,
            SafetyClassification::Blocked,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            names,
            [
                "SUPPORTED_REACHABLE",
                "INCONCLUSIVE",
                "LOCKOUT_RISK",
                "INVALID_TRANSITION",
                "BLOCKED"
            ]
        );
    }

    #[test]
    fn severity_increases_from_supported_to_blocked() {
        use SafetyClassification::*;
        assert!(SupportedReachable < Inconclusive);
        assert!(Inconclusive < LockoutRisk);
        assert!(LockoutRisk < InvalidTransition);
        assert!(InvalidTransition < Blocked);
        assert_eq!(Inconclusive.worst(LockoutRisk), LockoutRisk);
        assert_eq!(Blocked.worst(SupportedReachable), Blocked);
    }

    #[test]
    fn no_reasons_means_supported_and_the_worst_reason_wins() {
        assert_eq!(classify(&[]), SafetyClassification::SupportedReachable);

        let lost = StepReason::AdministrationLost {
            account: account(),
            kind: LockoutKind::HighThresholdUnreachable,
        };
        let predecessor = StepReason::PredecessorNotApplied { step: 0 };
        assert_eq!(
            classify(std::slice::from_ref(&predecessor)),
            SafetyClassification::Inconclusive
        );
        assert_eq!(
            classify(&[predecessor, lost]),
            SafetyClassification::LockoutRisk
        );
    }

    #[test]
    fn evidence_gaps_are_inconclusive_never_supported() {
        let missing = StepReason::EvidenceInsufficient(AnalysisError::MissingAccountSnapshot {
            account: account(),
            subject: crate::AuthorizationSubject::TransactionSource,
        });
        assert_eq!(missing.classification(), SafetyClassification::Inconclusive);
        let unresolved =
            StepReason::TransitionUnresolved(TransitionError::MissingAccountSnapshot {
                account: account(),
                operation_index: 0,
            });
        assert_eq!(
            unresolved.classification(),
            SafetyClassification::Inconclusive
        );
        let invalid = StepReason::InvalidTransition(TransitionError::SignerLimitExceeded {
            account: account(),
            operation_index: 0,
        });
        assert_eq!(
            invalid.classification(),
            SafetyClassification::InvalidTransition
        );
    }

    #[test]
    fn limitations_always_disclose_what_is_not_modeled() {
        assert!(limitations().contains(&RotationLimitation::ReservesNotModeled));
        assert!(limitations().contains(&RotationLimitation::LedgerEvidenceNotVerified));
        assert!(limitations().contains(&RotationLimitation::SignerPossessionNotVerified));
    }
}
