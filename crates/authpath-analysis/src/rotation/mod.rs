//! Multi-transaction rotation planning for classic Stellar accounts.
//!
//! A rotation plan describes an ordered sequence of proposed transactions
//! together with explicit signer-availability declarations. The types in this
//! module validate plan structure only; they do not apply or authorize
//! anything. Results derived from a plan are conditional model outputs, never
//! verified on-chain facts.

pub mod plan;

pub use plan::{
    ExpectedAccount, ExpectedSigner, MAX_OPERATIONS_PER_TRANSACTION, MAX_PLAN_TRANSACTIONS,
    PlanError, PlannedTransaction, ReserveDeclaration, RotationPlan, SignerDeclaration,
    TransactionPlanError,
};
