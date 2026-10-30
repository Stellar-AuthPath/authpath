use std::{collections::BTreeSet, fmt::Write as _, path::Path};

use authpath_analysis::{
    AuthorizationExplanation, AuthorizationFinding, AuthorizationReport,
    rotation::{
        AccountReach, ExpectationMismatch, LevelReach, LockoutKind, ReachStatus,
        RotationLimitation, RotationReport, SafetyClassification, StateOrigin, StepReason,
    },
};
use authpath_model::{
    AccountId, AccountSnapshot, SignerAvailability, SignerType, SnapshotProvenance,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    input::{
        self, ACCOUNT_SCHEMA, AccountDocument, AvailabilityInput, ProvenanceInput, SignerInput,
        ThresholdInput,
    },
};

pub(crate) const ANALYSIS_SCHEMA: &str = "authpath.analysis_report.v1";
pub(crate) const EXPLANATION_SCHEMA: &str = "authpath.explanation.v1";

const MAX_REPORT_STEPS: usize = 256;
const MAX_REPORT_ACCOUNTS: usize = 256;
const MAX_REPORT_REASONS: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AccountFileJson {
    pub(crate) schema: &'static str,
    pub(crate) account_id: String,
    pub(crate) master_key_weight: u32,
    pub(crate) thresholds: ThresholdJson,
    pub(crate) signers: Vec<SignerJson>,
    pub(crate) provenance: ProvenanceJson,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ThresholdJson {
    pub(crate) low: u32,
    pub(crate) medium: u32,
    pub(crate) high: u32,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SignerJson {
    pub(crate) key: String,
    pub(crate) weight: u32,
    pub(crate) availability: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvenanceJson {
    pub(crate) kind: String,
    pub(crate) network: Option<String>,
    pub(crate) ledger_sequence: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountConfigJson {
    pub(crate) account_id: String,
    pub(crate) master_key_weight: u32,
    pub(crate) thresholds: ThresholdInput,
    pub(crate) signers: Vec<SignerInput>,
    pub(crate) provenance: ProvenanceInput,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnalysisReportJson {
    pub(crate) schema: String,
    pub(crate) basis: String,
    pub(crate) verified_on_chain: bool,
    pub(crate) classification: String,
    pub(crate) steps: Vec<StepJson>,
    pub(crate) unsupported_signer_types: Vec<String>,
    pub(crate) final_state: Vec<StateAccountJson>,
    pub(crate) limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateAccountJson {
    pub(crate) origin: String,
    pub(crate) snapshot: AccountConfigJson,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StepJson {
    pub(crate) index: usize,
    pub(crate) classification: String,
    pub(crate) applied: bool,
    pub(crate) authorization: Option<AuthorizationJson>,
    pub(crate) changed_accounts: Vec<ChangedAccountJson>,
    pub(crate) reasons: Vec<ReasonJson>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizationJson {
    pub(crate) transaction_source: String,
    pub(crate) conclusion: String,
    pub(crate) findings: Vec<FindingJson>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingJson {
    pub(crate) account: String,
    pub(crate) subject: String,
    pub(crate) threshold: String,
    pub(crate) required_weight: u64,
    pub(crate) available_weight: u64,
    pub(crate) meets_requirement: bool,
    pub(crate) explanation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChangedAccountJson {
    pub(crate) account: String,
    pub(crate) low: ReachJson,
    pub(crate) medium: ReachJson,
    pub(crate) high: ReachJson,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReachJson {
    pub(crate) threshold: String,
    pub(crate) required_weight: u64,
    pub(crate) available_weight: u64,
    pub(crate) configured_weight: u64,
    pub(crate) status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReasonJson {
    pub(crate) kind: String,
    pub(crate) message: String,
    pub(crate) finding: Option<FindingJson>,
    pub(crate) status: Option<String>,
    pub(crate) unsupported_signer_types: Vec<String>,
    pub(crate) account: Option<String>,
    pub(crate) lockout_kind: Option<String>,
    pub(crate) mismatch: Option<MismatchJson>,
    pub(crate) predecessor_step: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MismatchJson {
    pub(crate) kind: String,
    pub(crate) account: String,
    pub(crate) expected_master_key_weight: Option<u8>,
    pub(crate) modeled_master_key_weight: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExplanationJson {
    pub(crate) schema: &'static str,
    pub(crate) basis: &'static str,
    pub(crate) verified_on_chain: bool,
    pub(crate) classification: String,
    pub(crate) summary: String,
    pub(crate) steps: Vec<ExplanationStepJson>,
    pub(crate) limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExplanationStepJson {
    pub(crate) index: usize,
    pub(crate) classification: String,
    pub(crate) explanation: String,
    pub(crate) findings: Vec<String>,
}

impl AccountFileJson {
    pub(crate) fn from_model(snapshot: &AccountSnapshot) -> Self {
        let config = AccountConfigJson::from_model(snapshot);
        Self {
            schema: ACCOUNT_SCHEMA,
            account_id: config.account_id,
            master_key_weight: config.master_key_weight,
            thresholds: ThresholdJson {
                low: config.thresholds.low,
                medium: config.thresholds.medium,
                high: config.thresholds.high,
            },
            signers: config
                .signers
                .into_iter()
                .map(|signer| SignerJson {
                    key: signer.key,
                    weight: signer.weight,
                    availability: match signer.availability {
                        AvailabilityInput::Available => "available",
                        AvailabilityInput::Unavailable => "unavailable",
                    },
                })
                .collect(),
            provenance: config.provenance.into(),
        }
    }
}

impl AccountConfigJson {
    fn from_model(snapshot: &AccountSnapshot) -> Self {
        Self {
            account_id: snapshot.account_id().to_string(),
            master_key_weight: u32::from(snapshot.master_key_weight().value()),
            thresholds: ThresholdInput {
                low: u32::from(snapshot.thresholds().low().value()),
                medium: u32::from(snapshot.thresholds().medium().value()),
                high: u32::from(snapshot.thresholds().high().value()),
            },
            signers: snapshot
                .signers()
                .iter()
                .map(|signer| SignerInput {
                    key: signer.key().to_string(),
                    weight: u32::from(signer.weight().value()),
                    availability: match signer.availability() {
                        SignerAvailability::Available => AvailabilityInput::Available,
                        SignerAvailability::Unavailable => AvailabilityInput::Unavailable,
                    },
                })
                .collect(),
            provenance: ProvenanceInput::from_model(snapshot.provenance()),
        }
    }

    pub(crate) fn into_model(self) -> Result<AccountSnapshot, AppError> {
        AccountDocument {
            schema: ACCOUNT_SCHEMA.to_owned(),
            account_id: self.account_id,
            master_key_weight: self.master_key_weight,
            thresholds: self.thresholds,
            signers: self.signers,
            provenance: self.provenance,
        }
        .into_model()
    }
}

impl From<ProvenanceInput> for ProvenanceJson {
    fn from(value: ProvenanceInput) -> Self {
        Self {
            kind: value.kind,
            network: value.network,
            ledger_sequence: value.ledger_sequence,
        }
    }
}

impl ProvenanceInput {
    fn from_model(provenance: &SnapshotProvenance) -> Self {
        match provenance {
            SnapshotProvenance::CallerProvided { network } => Self {
                kind: "caller_provided".to_owned(),
                network: network.as_ref().map(|value| value.passphrase().to_owned()),
                ledger_sequence: None,
            },
            SnapshotProvenance::Ledger {
                network,
                ledger_sequence,
            } => Self {
                kind: "ledger".to_owned(),
                network: Some(network.passphrase().to_owned()),
                ledger_sequence: Some(*ledger_sequence),
            },
        }
    }
}

impl AnalysisReportJson {
    pub(crate) fn from_model(report: &RotationReport) -> Self {
        let final_state = report
            .final_state()
            .snapshots()
            .accounts()
            .map(|snapshot| StateAccountJson {
                origin: match report.final_state().origin(snapshot.account_id()) {
                    Some(StateOrigin::Initial) => "initial".to_owned(),
                    Some(StateOrigin::Modeled) => "modeled".to_owned(),
                    None => "unknown".to_owned(),
                },
                snapshot: AccountConfigJson::from_model(snapshot),
            })
            .collect();

        Self {
            schema: ANALYSIS_SCHEMA.to_owned(),
            basis: "conditional_model".to_owned(),
            verified_on_chain: report.verified_on_chain(),
            classification: report.classification().as_str().to_owned(),
            steps: report.steps().iter().map(StepJson::from_model).collect(),
            unsupported_signer_types: report
                .unsupported_signer_types()
                .iter()
                .map(signer_type_name)
                .collect(),
            final_state,
            limitations: report
                .limitations()
                .iter()
                .map(rotation_limitation_name)
                .collect(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), AppError> {
        if self.schema != ANALYSIS_SCHEMA {
            return Err(AppError::invalid(format!(
                "unsupported analysis report schema {:?}; expected {ANALYSIS_SCHEMA:?}",
                self.schema
            )));
        }
        if self.basis != "conditional_model" {
            return Err(AppError::invalid(
                "analysis report basis must be conditional_model",
            ));
        }
        if self.verified_on_chain {
            return Err(AppError::invalid(
                "analysis reports cannot claim verified_on_chain",
            ));
        }
        parse_classification(&self.classification)?;
        if self.steps.len() > MAX_REPORT_STEPS {
            return Err(AppError::invalid("analysis report contains too many steps"));
        }
        if self.final_state.len() > MAX_REPORT_ACCOUNTS {
            return Err(AppError::invalid(
                "analysis report contains too many final-state accounts",
            ));
        }
        if self.limitations.is_empty() || self.limitations.iter().any(String::is_empty) {
            return Err(AppError::invalid(
                "analysis report must contain non-empty limitations",
            ));
        }

        let mut accounts = BTreeSet::new();
        for state_account in &self.final_state {
            if !matches!(state_account.origin.as_str(), "initial" | "modeled") {
                return Err(AppError::invalid(format!(
                    "unsupported final-state origin {:?}",
                    state_account.origin
                )));
            }
            let snapshot = state_account.snapshot.clone().into_model()?;
            if !accounts.insert(*snapshot.account_id()) {
                return Err(AppError::invalid(format!(
                    "duplicate final-state account {}",
                    snapshot.account_id()
                )));
            }
        }

        for (expected_index, step) in self.steps.iter().enumerate() {
            if step.index != expected_index {
                return Err(AppError::invalid(format!(
                    "analysis steps must be zero-based and ordered; expected index {expected_index}, found {}",
                    step.index
                )));
            }
            step.validate()?;
        }
        Ok(())
    }
}

impl StepJson {
    fn from_model(step: &authpath_analysis::rotation::StepResult) -> Self {
        Self {
            index: step.index(),
            classification: step.classification().as_str().to_owned(),
            applied: step.applied(),
            authorization: step.authorization().map(AuthorizationJson::from_model),
            changed_accounts: step
                .changed_accounts()
                .iter()
                .map(ChangedAccountJson::from_model)
                .collect(),
            reasons: step.reasons().iter().map(ReasonJson::from_model).collect(),
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        parse_classification(&self.classification)?;
        if self.reasons.len() > MAX_REPORT_REASONS {
            return Err(AppError::invalid(format!(
                "step {} contains too many reasons",
                self.index
            )));
        }
        if let Some(authorization) = &self.authorization {
            authorization.validate()?;
        }
        for changed in &self.changed_accounts {
            changed.validate()?;
        }
        for reason in &self.reasons {
            reason.validate()?;
        }
        Ok(())
    }
}

impl AuthorizationJson {
    fn from_model(report: &AuthorizationReport) -> Self {
        Self {
            transaction_source: report.transaction_source().to_string(),
            conclusion: if report.meets_configured_requirements() {
                "meets_configured_requirements".to_owned()
            } else {
                "does_not_meet_configured_requirements".to_owned()
            },
            findings: report
                .findings()
                .iter()
                .map(FindingJson::from_model)
                .collect(),
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        parse_key_or_account(&self.transaction_source, "transaction source")?;
        if !matches!(
            self.conclusion.as_str(),
            "meets_configured_requirements" | "does_not_meet_configured_requirements"
        ) {
            return Err(AppError::invalid(format!(
                "unsupported authorization conclusion {:?}",
                self.conclusion
            )));
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        Ok(())
    }
}

impl FindingJson {
    fn from_model(finding: &AuthorizationFinding) -> Self {
        Self {
            account: finding.account().to_string(),
            subject: finding.subject().to_string(),
            threshold: finding.threshold().to_string(),
            required_weight: finding.required_weight(),
            available_weight: finding.available_weight(),
            meets_requirement: finding.meets_requirement(),
            explanation: authorization_explanation_name(finding.explanation()).to_owned(),
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        parse_key_or_account(&self.account, "finding account")?;
        if !matches!(self.threshold.as_str(), "low" | "medium" | "high") {
            return Err(AppError::invalid(format!(
                "unsupported finding threshold {:?}",
                self.threshold
            )));
        }
        if !matches!(
            self.explanation.as_str(),
            "requirement_met" | "missing_weight" | "no_matching_signer"
        ) {
            return Err(AppError::invalid(format!(
                "unsupported finding explanation {:?}",
                self.explanation
            )));
        }
        Ok(())
    }
}

impl ChangedAccountJson {
    fn from_model(reach: &AccountReach) -> Self {
        Self {
            account: reach.account().to_string(),
            low: ReachJson::from_model(reach.low()),
            medium: ReachJson::from_model(reach.medium()),
            high: ReachJson::from_model(reach.high()),
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        parse_key_or_account(&self.account, "changed account")?;
        self.low.validate("low")?;
        self.medium.validate("medium")?;
        self.high.validate("high")?;
        Ok(())
    }
}

impl ReachJson {
    fn from_model(reach: LevelReach) -> Self {
        Self {
            threshold: reach.threshold().to_string(),
            required_weight: reach.required_weight(),
            available_weight: reach.available_weight(),
            configured_weight: reach.configured_weight(),
            status: reach_status_name(reach.status()).to_owned(),
        }
    }

    fn validate(&self, expected_threshold: &str) -> Result<(), AppError> {
        if self.threshold != expected_threshold {
            return Err(AppError::invalid(format!(
                "reachability threshold is {:?}; expected {:?}",
                self.threshold, expected_threshold
            )));
        }
        if !matches!(
            self.status.as_str(),
            "reachable" | "requires_unavailable_signers" | "unreachable"
        ) {
            return Err(AppError::invalid(format!(
                "unsupported reachability status {:?}",
                self.status
            )));
        }
        Ok(())
    }
}

impl ReasonJson {
    fn from_model(reason: &StepReason) -> Self {
        let mut value = Self {
            kind: String::new(),
            message: String::new(),
            finding: None,
            status: None,
            unsupported_signer_types: Vec::new(),
            account: None,
            lockout_kind: None,
            mismatch: None,
            predecessor_step: None,
        };
        match reason {
            StepReason::AuthorizationNotMet { finding, status } => {
                value.kind = "authorization_not_met".to_owned();
                value.message = format!(
                    "{} does not meet the {} threshold: available weight {} of required {}",
                    finding.subject(),
                    finding.threshold(),
                    finding.available_weight(),
                    finding.required_weight()
                );
                value.finding = Some(FindingJson::from_model(finding));
                value.status = Some(reach_status_name(*status).to_owned());
            }
            StepReason::AuthorizationUndecidable {
                finding,
                unsupported,
            } => {
                value.kind = "authorization_undecidable".to_owned();
                value.message = format!(
                    "{} is not met by modeled signers; unsupported signer types may change the result",
                    finding.subject()
                );
                value.finding = Some(FindingJson::from_model(finding));
                value.unsupported_signer_types = unsupported.iter().map(signer_type_name).collect();
            }
            StepReason::InvalidTransition(error) => {
                value.kind = "invalid_transition".to_owned();
                value.message = error.to_string();
            }
            StepReason::TransitionUnresolved(error) => {
                value.kind = "transition_unresolved".to_owned();
                value.message = error.to_string();
            }
            StepReason::AdministrationLost { account, kind } => {
                value.kind = "administration_lost".to_owned();
                value.message = format!(
                    "account {account} lost administrative reach: {}",
                    lockout_kind_name(*kind)
                );
                value.account = Some(account.to_string());
                value.lockout_kind = Some(lockout_kind_name(*kind).to_owned());
            }
            StepReason::EvidenceInsufficient(error) => {
                value.kind = "evidence_insufficient".to_owned();
                value.message = error.to_string();
            }
            StepReason::ExpectationMismatch(mismatch) => {
                value.kind = "expectation_mismatch".to_owned();
                value.message = expectation_mismatch_message(*mismatch);
                value.mismatch = Some(MismatchJson::from_model(*mismatch));
            }
            StepReason::PredecessorNotApplied { step } => {
                value.kind = "predecessor_not_applied".to_owned();
                value.message =
                    format!("step {step} was not applied; this step's starting state is unknown");
                value.predecessor_step = Some(*step);
            }
        }
        value
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.message.is_empty() {
            return Err(AppError::invalid("analysis reason message cannot be empty"));
        }
        match self.kind.as_str() {
            "authorization_not_met" => {
                let finding = self
                    .finding
                    .as_ref()
                    .ok_or_else(|| AppError::invalid("authorization_not_met needs a finding"))?;
                finding.validate()?;
                if self.status.is_none() {
                    return Err(AppError::invalid(
                        "authorization_not_met needs a reachability status",
                    ));
                }
                validate_status(self.status.as_deref().unwrap_or_default())?;
            }
            "authorization_undecidable" => {
                self.finding
                    .as_ref()
                    .ok_or_else(|| AppError::invalid("authorization_undecidable needs a finding"))?
                    .validate()?;
                if self.unsupported_signer_types.is_empty() {
                    return Err(AppError::invalid(
                        "authorization_undecidable needs unsupported signer types",
                    ));
                }
            }
            "invalid_transition" | "transition_unresolved" | "evidence_insufficient" => {}
            "administration_lost" => {
                parse_key_or_account(
                    self.account
                        .as_deref()
                        .ok_or_else(|| AppError::invalid("administration_lost needs an account"))?,
                    "administration-lost account",
                )?;
                let lockout = self
                    .lockout_kind
                    .as_deref()
                    .ok_or_else(|| AppError::invalid("administration_lost needs a lockout kind"))?;
                validate_lockout_kind(lockout)?;
            }
            "expectation_mismatch" => {
                self.mismatch
                    .as_ref()
                    .ok_or_else(|| AppError::invalid("expectation_mismatch needs mismatch data"))?
                    .validate()?;
            }
            "predecessor_not_applied" => {
                if self.predecessor_step.is_none() {
                    return Err(AppError::invalid(
                        "predecessor_not_applied needs predecessor_step",
                    ));
                }
            }
            kind => {
                return Err(AppError::invalid(format!(
                    "unsupported analysis reason kind {kind:?}"
                )));
            }
        }
        Ok(())
    }
}

impl MismatchJson {
    fn from_model(mismatch: ExpectationMismatch) -> Self {
        match mismatch {
            ExpectationMismatch::AccountMissing { account } => Self {
                kind: "account_missing".to_owned(),
                account: account.to_string(),
                expected_master_key_weight: None,
                modeled_master_key_weight: None,
            },
            ExpectationMismatch::MasterKeyWeight {
                account,
                expected,
                modeled,
            } => Self {
                kind: "master_key_weight".to_owned(),
                account: account.to_string(),
                expected_master_key_weight: Some(expected),
                modeled_master_key_weight: Some(modeled),
            },
            ExpectationMismatch::Thresholds { account } => Self {
                kind: "thresholds".to_owned(),
                account: account.to_string(),
                expected_master_key_weight: None,
                modeled_master_key_weight: None,
            },
            ExpectationMismatch::Signers { account } => Self {
                kind: "signers".to_owned(),
                account: account.to_string(),
                expected_master_key_weight: None,
                modeled_master_key_weight: None,
            },
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        parse_key_or_account(&self.account, "expectation mismatch account")?;
        if !matches!(
            self.kind.as_str(),
            "account_missing" | "master_key_weight" | "thresholds" | "signers"
        ) {
            return Err(AppError::invalid(format!(
                "unsupported expectation mismatch kind {:?}",
                self.kind
            )));
        }
        if self.kind == "master_key_weight"
            && (self.expected_master_key_weight.is_none()
                || self.modeled_master_key_weight.is_none())
        {
            return Err(AppError::invalid(
                "master_key_weight mismatch needs expected and modeled weights",
            ));
        }
        Ok(())
    }
}

pub(crate) fn load_report(path: &Path) -> Result<AnalysisReportJson, AppError> {
    let report: AnalysisReportJson = input::read_json(path)?;
    report.validate()?;
    Ok(report)
}

pub(crate) fn render_inspect(snapshot: &AccountSnapshot) -> String {
    let document = AccountFileJson::from_model(snapshot);
    let mut text = String::new();
    writeln!(text, "account: {}", document.account_id).expect("writing to a String cannot fail");
    writeln!(text, "master-key weight: {}", document.master_key_weight)
        .expect("writing to a String cannot fail");
    writeln!(
        text,
        "thresholds: low={}, medium={}, high={}",
        document.thresholds.low, document.thresholds.medium, document.thresholds.high
    )
    .expect("writing to a String cannot fail");
    writeln!(
        text,
        "provenance: {}",
        provenance_description(&document.provenance)
    )
    .expect("writing to a String cannot fail");
    writeln!(text, "signers:").expect("writing to a String cannot fail");
    if document.signers.is_empty() {
        writeln!(text, "  (none)").expect("writing to a String cannot fail");
    } else {
        for signer in &document.signers {
            writeln!(
                text,
                "  {} weight={} availability={}",
                signer.key, signer.weight, signer.availability
            )
            .expect("writing to a String cannot fail");
        }
    }
    writeln!(text).expect("writing to a String cannot fail");
    writeln!(
        text,
        "A configured signer is an account setting; declared availability is caller metadata, not proof that a private key is possessed or usable."
    )
    .expect("writing to a String cannot fail");
    writeln!(
        text,
        "This snapshot is not independently verified ledger evidence."
    )
    .expect("writing to a String cannot fail");
    text
}

pub(crate) fn render_analysis(report: &AnalysisReportJson) -> String {
    let mut text = String::new();
    writeln!(text, "basis: conditional model (not ledger evidence)")
        .expect("writing to a String cannot fail");
    writeln!(text, "overall: {}", report.classification).expect("writing to a String cannot fail");
    for step in &report.steps {
        writeln!(
            text,
            "step {}: {} (applied={})",
            step.index, step.classification, step.applied
        )
        .expect("writing to a String cannot fail");
        if let Some(authorization) = &step.authorization {
            writeln!(
                text,
                "  authorization: {}",
                authorization.conclusion.replace('_', " ")
            )
            .expect("writing to a String cannot fail");
            for finding in &authorization.findings {
                writeln!(
                    text,
                    "  finding: {} on {} (available={}, required={}, meets={})",
                    finding.subject,
                    finding.threshold,
                    finding.available_weight,
                    finding.required_weight,
                    finding.meets_requirement
                )
                .expect("writing to a String cannot fail");
            }
        }
        for changed in &step.changed_accounts {
            writeln!(text, "  changed account: {}", changed.account)
                .expect("writing to a String cannot fail");
            for reach in [&changed.low, &changed.medium, &changed.high] {
                writeln!(
                    text,
                    "    {}: {} (available={}, configured={}, required={})",
                    reach.threshold,
                    reach.status,
                    reach.available_weight,
                    reach.configured_weight,
                    reach.required_weight
                )
                .expect("writing to a String cannot fail");
            }
        }
        for reason in &step.reasons {
            writeln!(text, "  reason [{}]: {}", reason.kind, reason.message)
                .expect("writing to a String cannot fail");
        }
    }
    if !report.unsupported_signer_types.is_empty() {
        writeln!(
            text,
            "unsupported signer types: {}",
            report.unsupported_signer_types.join(", ")
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(text).expect("writing to a String cannot fail");
    writeln!(
        text,
        "The result is conditional on caller-supplied snapshots, declarations and successful execution; it is not VERIFIED_ON_CHAIN."
    )
    .expect("writing to a String cannot fail");
    text
}

pub(crate) fn render_explanation(report: &AnalysisReportJson) -> ExplanationJson {
    let steps = report
        .steps
        .iter()
        .map(|step| ExplanationStepJson {
            index: step.index,
            classification: step.classification.clone(),
            explanation: step_explanation(step),
            findings: step
                .authorization
                .as_ref()
                .map(|authorization| {
                    authorization
                        .findings
                        .iter()
                        .map(finding_explanation)
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();
    ExplanationJson {
        schema: EXPLANATION_SCHEMA,
        basis: "conditional_model",
        verified_on_chain: false,
        classification: report.classification.clone(),
        summary: summary_for_classification(&report.classification),
        steps,
        limitations: report.limitations.clone(),
    }
}

pub(crate) fn render_human_explanation(explanation: &ExplanationJson) -> String {
    let mut text = String::new();
    writeln!(text, "basis: conditional model (not ledger evidence)")
        .expect("writing to a String cannot fail");
    writeln!(text, "overall: {}", explanation.classification)
        .expect("writing to a String cannot fail");
    writeln!(text, "{}", explanation.summary).expect("writing to a String cannot fail");
    for step in &explanation.steps {
        writeln!(
            text,
            "step {}: {}\n  {}",
            step.index, step.classification, step.explanation
        )
        .expect("writing to a String cannot fail");
        for finding in &step.findings {
            writeln!(text, "  finding: {finding}").expect("writing to a String cannot fail");
        }
    }
    writeln!(text).expect("writing to a String cannot fail");
    writeln!(text, "limitations:").expect("writing to a String cannot fail");
    for limitation in &explanation.limitations {
        writeln!(text, "  - {limitation}").expect("writing to a String cannot fail");
    }
    writeln!(
        text,
        "No field in this explanation is independently verified ledger evidence."
    )
    .expect("writing to a String cannot fail");
    text
}

fn step_explanation(step: &StepJson) -> String {
    if step.reasons.is_empty() {
        return "The modeled authorization requirements were met and the modeled changes preserved reachability under the declared assumptions.".to_owned();
    }
    step.reasons
        .iter()
        .map(|reason| reason.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

fn finding_explanation(finding: &FindingJson) -> String {
    if finding.meets_requirement {
        format!(
            "{} meets the {} threshold with available weight {} of required {}.",
            finding.subject, finding.threshold, finding.available_weight, finding.required_weight
        )
    } else {
        format!(
            "{} does not meet the {} threshold: available weight {} of required {}.",
            finding.subject, finding.threshold, finding.available_weight, finding.required_weight
        )
    }
}

fn summary_for_classification(classification: &str) -> String {
    match classification {
        "SUPPORTED_REACHABLE" => {
            "The conditional model found the planned steps reachable under the supplied assumptions; this is not proof of transaction success or ledger state.".to_owned()
        }
        "BLOCKED" => {
            "At least one modeled authorization requirement is not met by the explicitly declared signer identities.".to_owned()
        }
        "LOCKOUT_RISK" => {
            "A modeled change may leave an affected account unable to administer itself with the declared available identities.".to_owned()
        }
        "INVALID_TRANSITION" => {
            "A described change violates a supported protocol rule or an explicitly declared constraint.".to_owned()
        }
        _ => {
            "The supplied evidence or supported semantics are insufficient for a reliable conclusion; dependent steps must not be treated as evaluated.".to_owned()
        }
    }
}

fn parse_classification(value: &str) -> Result<SafetyClassification, AppError> {
    match value {
        "SUPPORTED_REACHABLE" => Ok(SafetyClassification::SupportedReachable),
        "INCONCLUSIVE" => Ok(SafetyClassification::Inconclusive),
        "LOCKOUT_RISK" => Ok(SafetyClassification::LockoutRisk),
        "INVALID_TRANSITION" => Ok(SafetyClassification::InvalidTransition),
        "BLOCKED" => Ok(SafetyClassification::Blocked),
        _ => Err(AppError::invalid(format!(
            "unsupported safety classification {value:?}"
        ))),
    }
}

pub(crate) fn parse_report_classification(value: &str) -> Result<SafetyClassification, AppError> {
    parse_classification(value)
}

fn parse_key_or_account(value: &str, field: &str) -> Result<(), AppError> {
    value
        .parse::<AccountId>()
        .map(|_| ())
        .map_err(|error| AppError::invalid(format!("{field}: {error}")))
}

fn validate_status(value: &str) -> Result<(), AppError> {
    if matches!(
        value,
        "reachable" | "requires_unavailable_signers" | "unreachable"
    ) {
        Ok(())
    } else {
        Err(AppError::invalid(format!(
            "unsupported reachability status {value:?}"
        )))
    }
}

fn validate_lockout_kind(value: &str) -> Result<(), AppError> {
    if matches!(
        value,
        "high_threshold_requires_unavailable_signers"
            | "high_threshold_unreachable"
            | "low_threshold_not_reachable"
            | "low_threshold_permanently_unreachable"
    ) {
        Ok(())
    } else {
        Err(AppError::invalid(format!(
            "unsupported lockout kind {value:?}"
        )))
    }
}

fn provenance_description(provenance: &ProvenanceJson) -> String {
    match (
        provenance.kind.as_str(),
        provenance.network.as_deref(),
        provenance.ledger_sequence,
    ) {
        ("caller_provided", Some(network), _) => {
            format!("caller-provided, network={network:?}")
        }
        ("caller_provided", None, _) => "caller-provided, network unspecified".to_owned(),
        ("ledger", Some(network), Some(sequence)) => {
            format!("declared ledger provenance, network={network:?}, sequence={sequence}")
        }
        (kind, network, sequence) => {
            format!("{kind}, network={network:?}, sequence={sequence:?}")
        }
    }
}

fn signer_type_name(signer_type: &SignerType) -> String {
    match signer_type {
        SignerType::Ed25519 => "ed25519".to_owned(),
        SignerType::PreAuthTx => "pre_auth_tx".to_owned(),
        SignerType::HashX => "hash_x".to_owned(),
        SignerType::Ed25519SignedPayload => "ed25519_signed_payload".to_owned(),
        SignerType::Unknown(code) => format!("unknown:{code}"),
    }
}

fn rotation_limitation_name(limitation: &RotationLimitation) -> String {
    match limitation {
        RotationLimitation::CryptographicSignaturesNotVerified => {
            "cryptographic_signatures_not_verified"
        }
        RotationLimitation::SignerPossessionNotVerified => "signer_possession_not_verified",
        RotationLimitation::LedgerEvidenceNotVerified => "ledger_evidence_not_verified",
        RotationLimitation::ReservesNotModeled => "reserves_not_modeled",
        RotationLimitation::SequenceFeesAndPreconditionsNotModeled => {
            "sequence_fees_and_preconditions_not_modeled"
        }
        RotationLimitation::LedgerAcceptanceNotModeled => "ledger_acceptance_not_modeled",
        RotationLimitation::UnsupportedSignerKindsNotRepresentable => {
            "unsupported_signer_kinds_not_representable"
        }
        RotationLimitation::NonAuthorizationEffectsNotModeled => {
            "non_authorization_effects_not_modeled"
        }
    }
    .to_owned()
}

fn reach_status_name(status: ReachStatus) -> &'static str {
    match status {
        ReachStatus::Reachable => "reachable",
        ReachStatus::RequiresUnavailableSigners => "requires_unavailable_signers",
        ReachStatus::Unreachable => "unreachable",
    }
}

fn authorization_explanation_name(explanation: AuthorizationExplanation) -> &'static str {
    match explanation {
        AuthorizationExplanation::RequirementMet => "requirement_met",
        AuthorizationExplanation::MissingWeight { .. } => "missing_weight",
        AuthorizationExplanation::NoMatchingSigner => "no_matching_signer",
    }
}

fn lockout_kind_name(kind: LockoutKind) -> &'static str {
    match kind {
        LockoutKind::HighThresholdRequiresUnavailableSigners => {
            "high_threshold_requires_unavailable_signers"
        }
        LockoutKind::HighThresholdUnreachable => "high_threshold_unreachable",
        LockoutKind::LowThresholdNotReachable { permanent: false } => "low_threshold_not_reachable",
        LockoutKind::LowThresholdNotReachable { permanent: true } => {
            "low_threshold_permanently_unreachable"
        }
    }
}

fn expectation_mismatch_message(mismatch: ExpectationMismatch) -> String {
    match mismatch {
        ExpectationMismatch::AccountMissing { account } => {
            format!("expected account {account} is missing from the modeled state")
        }
        ExpectationMismatch::MasterKeyWeight {
            account,
            expected,
            modeled,
        } => format!("expected master-key weight {expected} for {account}, modeled {modeled}"),
        ExpectationMismatch::Thresholds { account } => {
            format!("expected thresholds for {account} disagree with the modeled thresholds")
        }
        ExpectationMismatch::Signers { account } => {
            format!("expected signer set for {account} disagrees with the modeled signer set")
        }
    }
}
