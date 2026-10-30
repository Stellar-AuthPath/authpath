# Phase C5 independent security and correctness audit

Audit date: 2026-10-30

This record describes the audit work performed on the AuthPath MVP. It is
not a claim that the project is a complete Stellar implementation or that a
ledger outcome was independently verified.

## Scope and baseline

The audit started from the merge of PR #4 on `main`:

```text
65284063e52567e8cebef079e1f8b28c172a2eb3
Merge pull request #4 from Stellar-AuthPath/phase-c4-cli
```

PR #4 was confirmed merged before the C5 branch was created. The C5 work is
on `phase-c5-security-correctness`, based on that commit. The pre-C5
workspace test baseline was 147 passing tests across five test targets.

The audit covered:

- `authpath-model` identity, weight, threshold and provenance validation;
- `authpath-analysis` C2 authorization and C3 sequential rotation behavior;
- `authpath-cli` JSON input adapters, report validation, commands, exit codes
  and output installation;
- the existing CI workflow, dependency lockfile and documentation; and
- the existing C1-C3 regression and C4 CLI fixtures.

The Universal Project Development Playbook v1.3 was not available in the
repository or in the local instruction resources. It was not reviewed and
is not treated as an audit authority here.

No approved AuthPath-specific protocol or architecture specification was
available. Protocol conclusions below use the primary Stellar references
listed in the next section and are limited to the implemented support
boundary.

## Reproducibility and environment

The checkout pins the development toolchain in `rust-toolchain.toml` to
Rust 1.99.1. The workspace declares `rust-version = "1.87"`, but this audit
tested only the pinned 1.99.1 toolchain; it does not independently establish
that Rust 1.87 builds the workspace.

Tool versions used locally:

```text
rustc 1.99.1 (58cf8f9c3 2026-10-13)
cargo 1.99.1 (5f94df478 2026-08-27)
cargo-audit-audit 0.22.2
```

The direct dependency versions in the locked workspace are:

| Crate | Version | Use |
| --- | ---: | --- |
| `stellar-strkey` | 1.0.0 | canonical Stellar identity parsing in `authpath-model` |
| `clap` | 4.6.7 | CLI argument parsing |
| `serde` | 1.0.229 | JSON serialization and deserialization |
| `serde_json` | 1.0.154 | bounded JSON input and deterministic output |

`cargo audit --deny warnings` completed successfully against the local RustSec
database. The command's deny set includes vulnerabilities, unmaintained,
unsound and yanked crates. No unavailable advisory or yanked-crate check was
encountered. CI currently runs the build, lint, test and documentation checks;
the audit command was run locally and is reported separately.

## Protocol references and independently derived rules

The comparison used primary Stellar protocol and stellar-core sources:

- [CAP-2: Transaction level signature verification](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0002.md)
- [stellar-core `TransactionFrame.cpp`](https://github.com/stellar/stellar-core/blob/master/src/transactions/TransactionFrame.cpp)
- [stellar-core `OperationFrame.cpp`](https://github.com/stellar/stellar-core/blob/master/src/transactions/OperationFrame.cpp)
- [stellar-core `SignatureChecker.cpp`](https://github.com/stellar/stellar-core/blob/master/src/transactions/SignatureChecker.cpp)
- [stellar-core `SetOptionsOpFrame.cpp`](https://github.com/stellar/stellar-core/blob/master/src/transactions/SetOptionsOpFrame.cpp)
- [stellar XDR transaction definitions](https://github.com/stellar/stellar-xdr/blob/main/Stellar-transaction.x)
- [SEP-23 strkeys](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md)

Expected outcomes were derived from those rules and then compared with the
implementation; they were not generated from the implementation's result.

| Rule checked | Affected implementation | Evidence | Result |
| --- | --- | --- | --- |
| CAP-2 checks transaction and operation signatures before operation effects | `crates/authpath-analysis/src/lib.rs`, `rotation/engine.rs` | `operations_in_one_transaction_are_all_authorized_against_the_pre_transaction_state`; `signer_changes_do_not_modify_later_operation_authorization` | Consistent within the supported model |
| Transaction source uses low threshold; explicit operation source uses its own account and category | `authpath_analysis::analyze` | `transaction_source_and_operation_source_are_authorized_separately`; `explicit_operation_source_is_evaluated_against_its_own_account`; `account_weights_are_not_combined_across_sources` | Consistent |
| Payment, bump-sequence, account-merge and SetOptions categories | `SetOptionsChanges::requires_high_threshold`, `analyze` | `c2_regression_threshold_categories_are_applied_per_operation`; `mixed_operations_use_their_verified_threshold_categories`; `set_options_classifies_each_supported_variation` | Consistent for supported descriptions |
| Threshold zero still needs a matching listed positive-weight signer; zero master weight contributes nothing | `available_weight`, `analyze`, `account_reach` | `c2_regression_threshold_zero_still_needs_a_matching_signer`; `zero_threshold_still_requires_a_matching_positive_weight_signer`; `zero_weight_master_key_contributes_nothing` | Consistent |
| Signer weight is accumulated once per matching configured identity | `available_weight` and `AvailableSigners` | `multiple_signers_collectively_meet_a_threshold`; `duplicate_available_signer_declarations_do_not_inflate_weight`; exact-equality tests | Consistent |
| SetOptions signer limit is 20 and operation order is atomic | `rotation::transition` | `a_twenty_first_signer_is_an_invalid_transition`; at-limit replacement tests; `operations_apply_in_order_within_a_transaction` | Consistent |
| Signer availability is the intersection of account-state and plan-wide declarations | `validate_transaction_availability`, `account_reach` | contradictory availability, newly-added available and newly-added unavailable signer scenarios | Conservative and consistent |
| Unsupported signer kinds and execution success are not inferred | C1 conversion, C2/C3 classifications and limitations | unsupported-signer, reserve, provenance and conditional-model tests | Correctly inconclusive or explicitly limited |

No protocol discrepancy was demonstrated within the supported operation and
signer boundary. AccountMerge, fee-bump transactions, extra signers,
sponsorship, muxed accounts, non-authorization effects, sequence/fee/
precondition checks and unsupported signer execution remain outside that
boundary; they are not silently modeled as supported.

## Confirmed findings and corrections

### Medium — standalone reports could previously contradict their own evidence

Affected behavior: `crates/authpath-cli/src/report.rs` accepted some
hand-edited reports whose arithmetic, reason metadata or step sequence did
not agree. Examples included changing a finding's available weight without
changing `meets_requirement`, omitting a report-level unsupported-signer
disclosure, and marking a later step applied after a halted predecessor.

Impact: `explain` or `verify` could consume an internally inconsistent
untrusted report and present a misleading classification or comparison.

Root cause: the original validator checked JSON shape and selected enum
values, but did not validate the relationships among findings, reachability,
reasons, applied flags and ordered steps.

Correction: report validation now checks finding and reachability arithmetic,
authorization finding order and threshold categories, reason-specific fields,
classification and applied-flag relationships, fixed limitation disclosures,
unsupported-signer disclosure consistency, expectation mismatch fields,
provenance/origin relationships, and dependent-step halting. A report still
cannot prove that its author ran the engine: the v1 standalone report does
not contain the original plan, authenticated inputs or a signature. That
remaining limitation is explicit and is not treated as solved by schema
validation.

Regression tests include:

- `explain_rejects_tampered_finding_arithmetic`;
- `explain_rejects_tampered_reachability_arithmetic`;
- `explain_rejects_applied_success_after_a_halted_predecessor`;
- `explain_rejects_hidden_unsupported_signer_disclosure`;
- `explain_rejects_equal_weights_disguised_as_a_mismatch`;
- `explain_rejects_removed_fixed_limitations`; and
- existing blocked, lockout, invalid-transition, inconclusive and partial
  completion comparison tests.

### Low — architecture text did not describe no-replace installation precisely

The C4 architecture text described every output installation as a rename,
although no-force installation uses an atomic same-directory hard link to
avoid replacing a destination created concurrently. The documentation is
corrected to describe the no-replace and explicit-force paths separately.
The implementation does not fall back to an existence check plus rename.

### Informational — report authenticity and ledger evidence remain unavailable

Reports, snapshots, expected configurations and availability declarations are
caller-supplied data. They do not prove private-key possession, signature
validity, transaction execution, ledger state or on-chain success. `explain`
and `verify` validate internal consistency and preserve provenance, but they
cannot establish the history of a standalone JSON file. `verified_on_chain`
remains false and there is no such success classification.

No Critical or High finding was confirmed. No unsupported protocol behavior was
"fixed" by guessing; unresolved behavior is kept outside the support
boundary.

## Input and filesystem adversarial coverage

The CLI continues to enforce a 4 MiB per-file input limit before and during
reading, strict versioned schemas, denied unknown fields, model-constructor
validation, bounded plans and bounded report collections. The C5 tests cover
malformed UTF-8, 2,000-level nested JSON, malformed JSON, invalid identities,
duplicate signers, unsupported versions, contradictory provenance and
availability, missing files, and deterministic output.

For output files, no-force installation writes and syncs a temporary file in
the destination directory, then creates the destination directory entry with
an atomic hard link. An existing or concurrently created destination is
rejected; there is no unsafe fallback. Temporary-name exhaustion, failed
installation, concurrent installers, existing output paths, symlinked output
paths and broken stdout are tested. `--force` is the explicit replacement
mode. If the platform or filesystem cannot provide the no-replace hard-link
operation, the CLI returns an operational error and cleans its temporary file.

The input path is read using normal operating-system path semantics, so a
caller-supplied input symlink is followed for reading. Parent-directory
replacement or other attacks by a party that can mutate the output directory
are outside this local CLI's filesystem capability boundary and are not
claimed to be prevented.

## Verification actually run

On the pinned local toolchain, the following commands passed:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo audit --deny warnings
```

The final local test command passed 161 tests:

```text
authpath-analysis unit tests:       62 passed
authpath-analysis scenarios:        38 passed
authpath-cli unit tests:             9 passed
authpath-cli integration tests:     42 passed
authpath-model unit tests:          10 passed
```

The local results above are not GitHub CI results. The CI workflow checks
formatting, locked workspace compilation, Clippy with warnings denied, all
workspace tests and rustdoc with warnings denied on pull requests. GitHub
Actions status for the final C5 pull-request head is reported separately in
the delivery record.

## Reproduction

From a clean checkout, verify the pinned toolchain and run:

```text
rustc --version
cargo --version
cargo tree --workspace --locked --depth 1
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo audit --deny warnings
```

The offline examples and CLI exit codes are documented in
[`docs/cli.md`](cli.md). They do not make network calls or submit
transactions. A passing command establishes only the documented conditional
or offline comparison result, never independently verified ledger evidence.
