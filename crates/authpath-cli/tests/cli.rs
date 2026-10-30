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
    let network = network.map_or_else(|| "null".to_owned(), |value| format!("{value:?}"));
    format!(
        r#"{{
  "schema": "authpath.account_snapshot.v1",
  "account_id": "{account_id}",
  "master_key_weight": {master},
  "thresholds": {{"low": 1, "medium": 1, "high": 1}},
  "signers": [],
  "provenance": {{"kind": "caller_provided", "network": {network}, "ledger_sequence": null}}
}}"#
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
