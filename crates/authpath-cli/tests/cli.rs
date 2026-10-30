use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use authpath_model::AccountId;

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "authpath-cli-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.file(name);
        fs::write(&path, contents).expect("write test input");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn account(seed: u8) -> String {
    AccountId::from_bytes([seed; 32]).to_string()
}

fn snapshot(account_id: &str, master: u32, network: Option<&str>) -> String {
    snapshot_custom(account_id, master, (1, 1, 1), &[], network)
}

fn snapshot_custom(
    account_id: &str,
    master: u32,
    thresholds: (u32, u32, u32),
    signers: &[(&str, u32, &str)],
    network: Option<&str>,
) -> String {
    let network = network.map_or_else(|| "null".to_owned(), |value| format!("{value:?}"));
    let signers = signers
        .iter()
        .map(|(key, weight, availability)| {
            format!(r#"{{"key": "{key}", "weight": {weight}, "availability": "{availability}"}}"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{
  "schema": "authpath.account_snapshot.v1",
  "account_id": "{account_id}",
  "master_key_weight": {master},
  "thresholds": {{"low": {low}, "medium": {medium}, "high": {high}}},
  "signers": [{signers}],
  "provenance": {{"kind": "caller_provided", "network": {network}, "ledger_sequence": null}}
}}"#,
        low = thresholds.0,
        medium = thresholds.1,
        high = thresholds.2,
    )
}

fn observed(account_id: &str, master: u32, network: Option<&str>) -> String {
    let network = network.map_or_else(|| "null".to_owned(), |value| format!("{value:?}"));
    format!(
        r#"{{
  "schema": "authpath.observed_configuration.v1",
  "account_id": "{account_id}",
  "master_key_weight": {master},
  "thresholds": {{"low": 1, "medium": 1, "high": 1}},
  "signers": [],
  "provenance": {{"kind": "caller_provided", "network": {network}, "ledger_sequence": null}}
}}"#
    )
}

fn no_change_plan(account_id: &str) -> String {
    format!(
        r#"{{
  "schema": "authpath.rotation_plan.v1",
  "initial_accounts": [{initial}],
  "available_signers": [{{"kind": "ed25519", "key": "{account_id}", "code": null}}],
  "transactions": [{transaction}]
}}"#,
        initial = snapshot(account_id, 1, Some("Test Network")),
        transaction = format_args!(
            r#"{{
      "source_account": "{account_id}",
      "operations": [{{"kind": "payment", "source_account": null, "changes": null}}],
      "signer_availability": [],
      "reserve": "unverified",
      "expected": []
    }}"#
        )
    )
}

fn available_ed25519(keys: &[&str]) -> String {
    keys.iter()
        .map(|key| format!(r#"{{"kind": "ed25519", "key": "{key}", "code": null}}"#))
        .collect::<Vec<_>>()
        .join(",")
}

fn expected_account(
    account_id: &str,
    master: u32,
    thresholds: (u32, u32, u32),
    signers: &[(&str, u32)],
) -> String {
    let signers = signers
        .iter()
        .map(|(key, weight)| format!(r#"{{"key": "{key}", "weight": {weight}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{
  "account_id": "{account_id}",
  "master_key_weight": {master},
  "thresholds": {{"low": {low}, "medium": {medium}, "high": {high}}},
  "signers": [{signers}]
}}"#,
        low = thresholds.0,
        medium = thresholds.1,
        high = thresholds.2,
    )
}

fn payment_operation() -> &'static str {
    r#"{"kind": "payment", "source_account": null, "changes": null}"#
}

fn set_signer_operation(key: &str, weight: u32) -> String {
    format!(
        r#"{{"kind": "set_options", "source_account": null, "changes": {{"signer": {{"key": "{key}", "weight": {weight}}}}}}}"#
    )
}

fn set_master_operation(weight: u32) -> String {
    format!(
        r#"{{"kind": "set_options", "source_account": null, "changes": {{"master_key_weight": {weight}}}}}"#
    )
}

fn transaction(account_id: &str, operations: &str, declarations: &str, expected: &str) -> String {
    format!(
        r#"{{
  "source_account": "{account_id}",
  "operations": [{operations}],
  "signer_availability": [{declarations}],
  "reserve": "unverified",
  "expected": [{expected}]
}}"#
    )
}

fn signer_declaration(operation_index: usize, key: &str, availability: &str) -> String {
    format!(
        r#"{{"operation_index": {operation_index}, "key": "{key}", "availability": "{availability}"}}"#
    )
}

fn plan(initial: &str, available_signers: &str, transactions: &[String]) -> String {
    format!(
        r#"{{
  "schema": "authpath.rotation_plan.v1",
  "initial_accounts": [{initial}],
  "available_signers": [{available_signers}],
  "transactions": [{transactions}]
}}"#,
        transactions = transactions.join(",")
    )
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_authpath"))
        .args(args)
        .output()
        .expect("run authpath")
}

fn output_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 CLI output")
}

fn error_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("UTF-8 CLI error")
}

fn write_report(directory: &TestDirectory, account_id: &str) -> PathBuf {
    let plan = directory.write("plan.json", &no_change_plan(account_id));
    let report = directory.file("report.json");
    let plan = plan.to_string_lossy().into_owned();
    let report_string = report.to_string_lossy().into_owned();
    let output = run(&[
        "--format",
        "json",
        "--output",
        &report_string,
        "analyze",
        &plan,
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", error_text(&output));
    assert!(report.is_file());
    report
}

#[test]
fn verify_matches_exact_configuration_without_upgrading_provenance() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let report = write_report(&directory, &account_id);
    let observed = directory.write(
        "observed.json",
        &observed(&account_id, 1, Some("Test Network")),
    );
    let report = report.to_string_lossy().into_owned();
    let observed = observed.to_string_lossy().into_owned();
    let output = run(&[
        "--format",
        "json",
        "verify",
        "--report",
        &report,
        "--observed",
        &observed,
    ]);

    assert_eq!(output.status.code(), Some(0), "{}", error_text(&output));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["result"], "OFFLINE_CONFIGURATION_MATCH");
    assert_eq!(json["verified_on_chain"], false);
    assert_eq!(json["observed_provenance"]["kind"], "caller_provided");
    assert!(!output_text(&output).contains("VERIFIED_ON_CHAIN"));
}

#[test]
fn verify_reports_configuration_and_network_mismatches() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let report = write_report(&directory, &account_id);

    let wrong_weight = directory.write(
        "wrong-weight.json",
        &observed(&account_id, 2, Some("Test Network")),
    );
    let wrong_network = directory.write(
        "wrong-network.json",
        &observed(&account_id, 1, Some("Other Network")),
    );
    let report_string = report.to_string_lossy().into_owned();
    for (path, expected) in [
        (wrong_weight, "master-key weight differs"),
        (wrong_network, "network identity differs"),
    ] {
        let path_string = path.to_string_lossy().into_owned();
        let output = run(&[
            "verify",
            "--report",
            &report_string,
            "--observed",
            &path_string,
        ]);
        assert_eq!(output.status.code(), Some(10));
        assert!(error_text(&output).is_empty());
        assert!(output_text(&output).contains("OFFLINE_CONFIGURATION_MISMATCH"));
        assert!(output_text(&output).contains(expected));
    }
}

#[test]
fn verify_is_inconclusive_when_network_identity_is_unavailable() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let report = write_report(&directory, &account_id);
    let report_output_string = report.to_string_lossy().into_owned();

    let observed = directory.write("observed-no-network.json", &observed(&account_id, 1, None));
    let observed_string = observed.to_string_lossy().into_owned();
    let output = run(&[
        "verify",
        "--report",
        &report_output_string,
        "--observed",
        &observed_string,
    ]);
    assert_eq!(output.status.code(), Some(20));
    assert!(output_text(&output).contains("INCONCLUSIVE"));
}

#[test]
fn verify_rejects_unsupported_observed_schema() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let report = write_report(&directory, &account_id);
    let observed = directory.write(
        "bad-observed.json",
        &observed(&account_id, 1, Some("Test Network")).replace(
            "authpath.observed_configuration.v1",
            "authpath.observed_configuration.v2",
        ),
    );
    let report_string = report.to_string_lossy().into_owned();
    let observed_string = observed.to_string_lossy().into_owned();
    let output = run(&[
        "verify",
        "--report",
        &report_string,
        "--observed",
        &observed_string,
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(error_text(&output).contains("unsupported observed configuration schema"));
}

#[test]
fn inspect_displays_valid_snapshot_and_availability_boundary() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let signer_id = account(2);
    let input = directory.write(
        "account.json",
        &snapshot_custom(
            &account_id,
            1,
            (1, 2, 3),
            &[(&signer_id, 2, "available")],
            Some("Test Network"),
        ),
    );
    let input = input.to_string_lossy().into_owned();
    let output = run(&["inspect", &input]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output_text(&output).contains(&format!("account: {account_id}")));
    assert!(output_text(&output).contains("availability=available"));
    assert!(output_text(&output).contains("not proof that a private key is possessed"));
}

#[test]
fn inspect_rejects_invalid_account_identity() {
    let directory = TestDirectory::new();
    let input = directory.write("invalid.json", &snapshot("not-an-account", 1, None));
    let input = input.to_string_lossy().into_owned();
    let output = run(&["inspect", &input]);
    assert_eq!(output.status.code(), Some(2));
    assert!(error_text(&output).contains("malformed Stellar account id"));
}

#[test]
fn malformed_json_is_invalid_input() {
    let directory = TestDirectory::new();
    let input = directory.write("malformed.json", "{not-json");
    let input = input.to_string_lossy().into_owned();
    let output = run(&["inspect", &input]);
    assert_eq!(output.status.code(), Some(2));
    assert!(error_text(&output).contains("malformed JSON"));
}

#[test]
fn inspect_rejects_unsupported_schema_version() {
    let directory = TestDirectory::new();
    let input = directory.write(
        "unsupported.json",
        &snapshot(&account(1), 1, None).replace(
            "authpath.account_snapshot.v1",
            "authpath.account_snapshot.v2",
        ),
    );
    let input = input.to_string_lossy().into_owned();
    let output = run(&["inspect", &input]);
    assert_eq!(output.status.code(), Some(2));
    assert!(error_text(&output).contains("unsupported account schema"));
}

#[test]
fn duplicate_signers_are_rejected_by_the_existing_model_constructor() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let signer_id = account(2);
    let input = directory.write(
        "duplicate.json",
        &snapshot_custom(
            &account_id,
            1,
            (1, 1, 1),
            &[(&signer_id, 1, "available"), (&signer_id, 2, "unavailable")],
            None,
        ),
    );
    let input = input.to_string_lossy().into_owned();
    let output = run(&["inspect", &input]);
    assert_eq!(output.status.code(), Some(2));
    assert!(error_text(&output).contains("duplicate signer"));
}

#[test]
fn valid_multi_transaction_analysis_is_conditional_and_ordered() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let existing = account(2);
    let added = account(3);
    let initial = snapshot_custom(
        &account_id,
        1,
        (1, 2, 1),
        &[(&existing, 1, "available")],
        Some("Test Network"),
    );
    let first = transaction(
        &account_id,
        &set_signer_operation(&added, 1),
        &signer_declaration(0, &added, "available"),
        &expected_account(&account_id, 1, (1, 2, 1), &[(&existing, 1), (&added, 1)]),
    );
    let second = transaction(
        &account_id,
        &set_signer_operation(&added, 2),
        &signer_declaration(0, &added, "available"),
        &expected_account(&account_id, 1, (1, 2, 1), &[(&existing, 1), (&added, 2)]),
    );
    let plan = directory.write(
        "multi.json",
        &plan(
            &initial,
            &available_ed25519(&[&account_id, &existing, &added]),
            &[first, second],
        ),
    );
    let plan = plan.to_string_lossy().into_owned();
    let output = run(&["--format", "json", "analyze", &plan]);
    assert_eq!(output.status.code(), Some(0), "{}", error_text(&output));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["classification"], "SUPPORTED_REACHABLE");
    assert_eq!(json["steps"].as_array().unwrap().len(), 2);
    assert!(json["steps"].as_array().unwrap().iter().all(|step| {
        step["classification"] == "SUPPORTED_REACHABLE" && step["applied"] == true
    }));
}

#[test]
fn blocked_authorization_has_finding_exit_code() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let initial = snapshot(&account_id, 1, Some("Test Network"));
    let transaction = transaction(&account_id, payment_operation(), "", "");
    let plan = directory.write("blocked.json", &plan(&initial, "", &[transaction]));
    let plan = plan.to_string_lossy().into_owned();
    let output = run(&["--format", "json", "analyze", &plan]);
    assert_eq!(output.status.code(), Some(10));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["classification"], "BLOCKED");
    assert_eq!(
        json["steps"][0]["reasons"][0]["kind"],
        "authorization_not_met"
    );
}

#[test]
fn lockout_risk_has_finding_exit_code() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let initial = snapshot(&account_id, 1, Some("Test Network"));
    let transaction = transaction(
        &account_id,
        &set_master_operation(0),
        "",
        &expected_account(&account_id, 0, (1, 1, 1), &[]),
    );
    let plan = directory.write(
        "lockout.json",
        &plan(&initial, &available_ed25519(&[&account_id]), &[transaction]),
    );
    let plan = plan.to_string_lossy().into_owned();
    let output = run(&["--format", "json", "analyze", &plan]);
    assert_eq!(output.status.code(), Some(10));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["classification"], "LOCKOUT_RISK");
    assert_eq!(
        json["steps"][0]["reasons"][0]["kind"],
        "administration_lost"
    );
}

#[test]
fn expected_mismatch_halts_dependent_transactions_as_inconclusive() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let initial = snapshot(&account_id, 1, Some("Test Network"));
    let mismatch = transaction(
        &account_id,
        &set_master_operation(0),
        "",
        &expected_account(&account_id, 1, (1, 1, 1), &[]),
    );
    let dependent = transaction(&account_id, payment_operation(), "", "");
    let plan = directory.write(
        "mismatch.json",
        &plan(
            &initial,
            &available_ed25519(&[&account_id]),
            &[mismatch, dependent],
        ),
    );
    let plan = plan.to_string_lossy().into_owned();
    let output = run(&["--format", "json", "analyze", &plan]);
    assert_eq!(output.status.code(), Some(20));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["classification"], "INCONCLUSIVE");
    assert_eq!(json["steps"][0]["classification"], "INCONCLUSIVE");
    assert_eq!(json["steps"][1]["classification"], "INCONCLUSIVE");
    assert_eq!(
        json["steps"][1]["reasons"][0]["kind"],
        "predecessor_not_applied"
    );
    assert!(!output_text(&output).contains("SUPPORTED_REACHABLE"));
}

#[test]
fn contradictory_global_and_operation_availability_is_inconclusive() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let added = account(3);
    let initial = snapshot(&account_id, 1, Some("Test Network"));
    let transaction = transaction(
        &account_id,
        &set_signer_operation(&added, 1),
        &signer_declaration(0, &added, "unavailable"),
        &expected_account(&account_id, 1, (1, 1, 1), &[(&added, 1)]),
    );
    let plan = directory.write(
        "availability-contradiction.json",
        &plan(
            &initial,
            &available_ed25519(&[&account_id, &added]),
            &[transaction],
        ),
    );
    let plan = plan.to_string_lossy().into_owned();
    let output = run(&["--format", "json", "analyze", &plan]);
    assert_eq!(output.status.code(), Some(20));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["classification"], "INCONCLUSIVE");
    assert_eq!(
        json["steps"][0]["reasons"][0]["kind"],
        "transition_unresolved"
    );
    assert!(output_text(&output).contains("plan-wide"));
}

#[test]
fn newly_added_available_signer_can_authorize_a_later_transaction() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let added = account(3);
    let initial = snapshot_custom(&account_id, 1, (1, 2, 1), &[], Some("Test Network"));
    let add = transaction(
        &account_id,
        &set_signer_operation(&added, 1),
        &signer_declaration(0, &added, "available"),
        &expected_account(&account_id, 1, (1, 2, 1), &[(&added, 1)]),
    );
    let later = transaction(&account_id, payment_operation(), "", "");
    let plan = directory.write(
        "added-available.json",
        &plan(
            &initial,
            &available_ed25519(&[&account_id, &added]),
            &[add, later],
        ),
    );
    let plan = plan.to_string_lossy().into_owned();
    let output = run(&["--format", "json", "analyze", &plan]);
    assert_eq!(output.status.code(), Some(0), "{}", error_text(&output));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["classification"], "SUPPORTED_REACHABLE");
    assert!(
        json["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| { step["classification"] == "SUPPORTED_REACHABLE" })
    );
}

#[test]
fn newly_added_unavailable_signer_cannot_authorize_a_later_transaction() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let added = account(3);
    let initial = snapshot_custom(&account_id, 1, (1, 2, 1), &[], Some("Test Network"));
    let add = transaction(
        &account_id,
        &set_signer_operation(&added, 1),
        &signer_declaration(0, &added, "unavailable"),
        &expected_account(&account_id, 1, (1, 2, 1), &[(&added, 1)]),
    );
    let later = transaction(&account_id, payment_operation(), "", "");
    let plan = directory.write(
        "added-unavailable.json",
        &plan(&initial, &available_ed25519(&[&account_id]), &[add, later]),
    );
    let plan = plan.to_string_lossy().into_owned();
    let output = run(&["--format", "json", "analyze", &plan]);
    assert_eq!(output.status.code(), Some(10));
    let json: serde_json::Value = serde_json::from_str(&output_text(&output)).unwrap();
    assert_eq!(json["steps"][0]["classification"], "SUPPORTED_REACHABLE");
    assert_eq!(json["steps"][1]["classification"], "BLOCKED");
}

#[test]
fn equivalent_analysis_inputs_produce_byte_identical_json() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let plan_path = directory.write("deterministic.json", &no_change_plan(&account_id));
    let plan_path = plan_path.to_string_lossy().into_owned();
    let first = run(&["--format", "json", "analyze", &plan_path]);
    let second = run(&["--format", "json", "analyze", &plan_path]);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn explain_produces_human_findings_without_ledger_claims() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let report = write_report(&directory, &account_id);
    let report = report.to_string_lossy().into_owned();
    let output = run(&["explain", &report]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output_text(&output).contains("basis: conditional model"));
    assert!(output_text(&output).contains("independently verified ledger evidence"));
    assert!(!output_text(&output).contains("VERIFIED_ON_CHAIN"));
}

#[test]
fn explain_rejects_malformed_and_unsupported_reports() {
    let directory = TestDirectory::new();
    let malformed = directory.write("bad-report.json", "[]");
    let malformed = malformed.to_string_lossy().into_owned();
    let malformed_output = run(&["explain", &malformed]);
    assert_eq!(malformed_output.status.code(), Some(2));

    let account_id = account(1);
    let report = write_report(&directory, &account_id);
    let unsupported = directory.write(
        "unsupported-report.json",
        &fs::read_to_string(&report)
            .unwrap()
            .replace("authpath.analysis_report.v1", "authpath.analysis_report.v2"),
    );
    let unsupported = unsupported.to_string_lossy().into_owned();
    let unsupported_output = run(&["explain", &unsupported]);
    assert_eq!(unsupported_output.status.code(), Some(2));
    assert!(error_text(&unsupported_output).contains("unsupported analysis report schema"));
}

#[test]
fn missing_input_files_are_operational_failures() {
    let directory = TestDirectory::new();
    let missing = directory.file("does-not-exist.json");
    let missing = missing.to_string_lossy().into_owned();
    let output = run(&["inspect", &missing]);
    assert_eq!(output.status.code(), Some(3));
    assert!(error_text(&output).contains("does-not-exist.json"));
}

#[test]
fn oversized_input_is_rejected_before_json_parsing() {
    let directory = TestDirectory::new();
    let input = directory.file("oversized.json");
    fs::write(&input, vec![b' '; 4 * 1024 * 1024 + 1]).expect("write oversized input");
    let input = input.to_string_lossy().into_owned();
    let output = run(&["inspect", &input]);
    assert_eq!(output.status.code(), Some(2));
    assert!(error_text(&output).contains("input limit"));
}

#[test]
fn exit_codes_distinguish_supported_finding_inconclusive_and_invalid() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let supported = directory.write("supported.json", &no_change_plan(&account_id));
    let supported = supported.to_string_lossy().into_owned();
    assert_eq!(run(&["analyze", &supported]).status.code(), Some(0));

    let blocked = directory.write(
        "blocked-exit.json",
        &plan(
            &snapshot(&account_id, 1, Some("Test Network")),
            "",
            &[transaction(&account_id, payment_operation(), "", "")],
        ),
    );
    let blocked = blocked.to_string_lossy().into_owned();
    assert_eq!(run(&["analyze", &blocked]).status.code(), Some(10));

    let inconclusive = directory.write(
        "inconclusive-exit.json",
        &plan(
            &snapshot(&account_id, 1, Some("Test Network")),
            &available_ed25519(&[&account_id]),
            &[transaction(
                &account_id,
                &set_master_operation(0),
                "",
                &expected_account(&account_id, 1, (1, 1, 1), &[]),
            )],
        ),
    );
    let inconclusive = inconclusive.to_string_lossy().into_owned();
    assert_eq!(run(&["analyze", &inconclusive]).status.code(), Some(20));

    let invalid = directory.write("invalid-exit.json", "not-json");
    let invalid = invalid.to_string_lossy().into_owned();
    assert_eq!(run(&["analyze", &invalid]).status.code(), Some(2));
}

#[test]
fn report_output_requires_explicit_replacement_and_keeps_original_on_failure() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let plan = directory.write("output-plan.json", &no_change_plan(&account_id));
    let plan = plan.to_string_lossy().into_owned();
    let report = directory.file("result.json");
    let report_string = report.to_string_lossy().into_owned();
    let first = run(&[
        "--format",
        "json",
        "--output",
        &report_string,
        "analyze",
        &plan,
    ]);
    assert_eq!(first.status.code(), Some(0));
    let original = fs::read(&report).unwrap();

    let second = run(&[
        "--format",
        "json",
        "--output",
        &report_string,
        "analyze",
        &plan,
    ]);
    assert_eq!(second.status.code(), Some(3));
    assert_eq!(fs::read(&report).unwrap(), original);

    let forced = run(&[
        "--format",
        "json",
        "--force",
        "--output",
        &report_string,
        "analyze",
        &plan,
    ]);
    assert_eq!(forced.status.code(), Some(0));
    assert_eq!(fs::read(&report).unwrap(), original);
}

#[test]
fn report_output_failure_does_not_install_partial_file() {
    let directory = TestDirectory::new();
    let account_id = account(1);
    let plan = directory.write("atomic-plan.json", &no_change_plan(&account_id));
    let plan = plan.to_string_lossy().into_owned();
    let missing_parent = directory.path.join("missing").join("report.json");
    let missing_parent_string = missing_parent.to_string_lossy().into_owned();
    let output = run(&[
        "--format",
        "json",
        "--output",
        &missing_parent_string,
        "analyze",
        &plan,
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(!missing_parent.exists());
    assert!(!directory.path.join("missing").exists());
}
