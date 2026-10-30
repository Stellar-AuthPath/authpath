//! Multi-transaction rotation planning for classic Stellar accounts.
//!
//! A rotation plan describes an ordered sequence of proposed transactions
//! together with explicit signer-availability declarations. The types in this
//! module validate plan structure only; they do not apply or authorize
//! anything. Results derived from a plan are conditional model outputs, never
//! verified on-chain facts.

pub mod classification;
pub mod engine;
pub mod plan;
pub mod reachability;
pub mod transition;

pub use classification::{
    ResultBasis, RotationLimitation, SafetyClassification, StepReason, classify, limitations,
};
pub use engine::{RotationReport, StepResult, analyze_rotation};
pub use plan::{
    ExpectedAccount, ExpectedSigner, MAX_OPERATIONS_PER_TRANSACTION, MAX_PLAN_TRANSACTIONS,
    PlanError, PlannedTransaction, ReserveDeclaration, RotationPlan, SignerDeclaration,
    TransactionPlanError,
};
pub use reachability::{AccountReach, LevelReach, LockoutKind, ReachStatus, account_reach};
pub use transition::{
    ExpectationMismatch, ModeledState, StateOrigin, TransitionError, apply_transaction,
    compare_expected,
};
