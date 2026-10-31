# Final independent audit and submission readiness

Audit date: 2026-10-31

This is a dated evidence record, not an approval, grant recommendation,
adoption claim, or assertion of on-chain verification. It distinguishes checks
performed during this audit from earlier phase evidence and from items that
remain unverified.

## Executive summary

AuthPath is a keyless, offline Rust CLI for analyzing classic Stellar account
authorization and conditionally modeling ordered signer and threshold
rotations. The current repository builds and passes its workspace checks on
the pinned Rust 1.99.1 toolchain and on the declared Rust 1.87.0 minimum.
Current `main` CI and documentation workflows pass, and the public mdBook site
and its navigation pages were fetched successfully.

This audit found no demonstrated submission-blocking correctness or security
defect in the reviewed MVP boundary. That is not a full formal or independent
protocol audit. Submission readiness remains conditional: main permits merges
with zero approving reviews, repository secret scanning and private
vulnerability reporting are disabled, GitHub Actions accepts all actions
without SHA pinning, and AuthPath's analyzer overlaps materially with an
existing Stellar signer-inspection tool. These are review and governance
decisions, not reasons to add product features.

## Authoritative repository state

- Repository: <https://github.com/Stellar-AuthPath/authpath>
- `main` SHA during this audit: `6c4b42a298cd0c6d1278e669b7ac0800d918a155`
- Working branch for this evidence correction: `audit-final-2026-10-31`
- Pull requests #1 through #9 are merged. PR #9 merged at
  <https://github.com/Stellar-AuthPath/authpath/pull/9>.
- Current `main` CI: [run 41238694004, success](https://github.com/Stellar-AuthPath/authpath/actions/runs/41238694004)
- Current `main` documentation build/deployment: [run 41238694008, success](https://github.com/Stellar-AuthPath/authpath/actions/runs/41238694008)
- These workflow results are GitHub-hosted checks on the stated `main` SHA;
  local commands below are separate evidence.
- Public documentation: <https://stellar-authpath.github.io/authpath/>

The GitHub PR list confirmed that PRs #1–#9 are merged. Historical PR checks
are not substituted for the current-main runs above.

## Scope and method

The audit reviewed the C1 account model, C2 authorization analysis, C3
rotation engine, C4 CLI and report parser, C5 security/audit record, C6 docs,
tests, fixtures, workflows, README, architecture, CLI reference, `SECURITY.md`,
`CONTRIBUTING.md`, and license. Protocol comparisons used the linked Stellar
specifications and stellar-core implementation sources. Dependency audit data
was refreshed during the local check. Ecosystem research was targeted and
public; it is not exhaustive.

The available workspace contains no authoritative Universal Project
Development Playbook v1.3 text. No older version or reconstructed checklist
was substituted. Full playbook compliance is therefore **NOT VERIFIED**; the
playbook matrix requested for an available authoritative source cannot
honestly be completed. This limitation does not prevent the independent code,
protocol, docs, CI, and governance checks recorded here.

## Technical and security findings

| Severity | Finding | Evidence and disposition |
| --- | --- | --- |
| CRITICAL | None demonstrated | No reviewed path demonstrated an exploitable critical defect. |
| HIGH | None demonstrated | No reviewed path demonstrated a high-severity defect within the stated scope. |
| MEDIUM | Approval review is not required for protected `main` | GitHub protection reports `required_approving_review_count: 0`. Recommend at least one independent approval for contributor PRs. No setting was changed. |
| MEDIUM | GitHub Actions trust configuration is broad | All actions are allowed and SHA pinning is not required. CI uses major-version action tags; workflow token defaults to read-only. Pin third-party actions and consider an allowlist. No setting was changed. |
| MEDIUM | Material adjacent signer-analysis tool exists | StellarExpert's `stellar-tx-signers-inspector` analyzes signer requirements, weights, account signers, and feasibility. AuthPath must describe its incremental sequential-rotation scope precisely; see comparison below. |
| LOW | Secret scanning and private vulnerability reporting are disabled | Authenticated repository metadata reports both off. This reduces automatic detection and private disclosure support. Recommend maintainer review of enabling them; no setting was changed. |
| INFORMATIONAL | Audit boundary is not a formal verification | Reviewed source and tests provide evidence for the stated boundary, but do not prove correctness for all protocol versions, inputs, or ledger outcomes. |

No code correction was justified by a reproduced defect. Existing negative
tests cover malformed and oversized JSON, contradictory declarations,
expected-state mismatches, blocked and inconclusive dependency chains,
applied lockout-risk steps, report tampering, output races and filesystem
failure cases. Their existence is useful regression evidence, not proof that
all adversarial cases are covered.

### Protocol behavior checked

The implementation's reviewed classic Stellar model checks transaction
source and operation source authorization against the pre-operation account
configuration, accumulates matching signer weights, applies threshold
categories to SetOptions operations, and models represented signer and
threshold changes in order. The zero-threshold path still requires a positive
matching weight; a configured master weight of zero is not treated as usable
authorization. The C3 engine distinguishes an applied `LOCKOUT_RISK` step from
unapplied `BLOCKED`, `INVALID_TRANSITION`, and halted `INCONCLUSIVE` steps.
Expected states and available signer declarations are caller-supplied
assertions/metadata, not proof of ledger execution or private-key possession.

Primary protocol references checked:

- [CAP-2: transaction-level signature verification](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0002.md)
- [Stellar multisignature documentation](https://developers.stellar.org/docs/learn/fundamentals/transactions/signatures-multisig)
- [stellar-core `TransactionFrame`](https://github.com/stellar/stellar-core/blob/master/src/transactions/TransactionFrame.cpp)
- [stellar-core `OperationFrame`](https://github.com/stellar/stellar-core/blob/master/src/transactions/OperationFrame.cpp)
- [stellar-core `SignatureChecker`](https://github.com/stellar/stellar-core/blob/master/src/transactions/SignatureChecker.cpp)
- [stellar-core `SetOptionsOpFrame`](https://github.com/stellar/stellar-core/blob/master/src/transactions/SetOptionsOpFrame.cpp)
- [CAP-21 transaction preconditions and extra signers](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0021.md)
- [SEP-23 StrKeys](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md)
- [SEP-30 account recovery](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0030.md)

The implementation does not encode a ledger protocol version. Its classic
authorization model follows CAP-2 behavior; it does not establish compatibility
with every historical or future protocol version. Fee-bump semantics, extra
signers/preconditions, Soroban authorization, and other unsupported operation
behavior are outside the modeled boundary and should not be inferred from a
successful result.

## Local verification performed

The following completed on the locked workspace. Rust 1.99.1 is the repository
toolchain pin; Rust 1.87.0 was separately installed and tested as the declared
MSRV.

| Command | Rust 1.99.1 | Rust 1.87.0 |
| --- | --- | --- |
| `cargo fmt --all -- --check` | PASS | PASS |
| `cargo check --workspace --all-targets --locked` | PASS | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS | PASS |
| `cargo test --workspace --all-targets --locked` | PASS, 166 tests | PASS, 166 tests |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | PASS | PASS |
| `cargo audit --deny warnings` | PASS | PASS |

The refreshed cargo-audit database contained 1,395 advisories; 30 locked
dependencies were scanned. The command exited successfully without a reported
vulnerability or warning. This records the database snapshot at audit time,
not a guarantee about future advisories. `Cargo.lock` is present and all
workspace checks used `--locked`.

The current `main` workflows independently passed as linked above. The
documentation workflow uses mdBook 0.4.52. A local mdBook build succeeded.
The deployed root, architecture, CLI, C5 audit, submission-readiness, and
examples pages returned HTTP 200, and the site's internal navigation links
resolved during this audit.

## Reproducible CLI demonstration

From a clean checkout at the audited `main` SHA:

```sh
cargo build --workspace --locked
cargo run --locked -p authpath-cli -- inspect examples/account-snapshot.json
cargo run --locked -p authpath-cli -- --format json analyze \
  examples/rotation-plan.json --output /tmp/authpath-report.json
cargo run --locked -p authpath-cli -- explain /tmp/authpath-report.json
cargo run --locked -p authpath-cli -- verify \
  --report /tmp/authpath-report.json \
  --observed examples/observed-configuration.json
cargo run --locked -p authpath-cli -- analyze examples/blocked-rotation-plan.json
cargo run --locked -p authpath-cli -- analyze examples/lockout-risk-rotation-plan.json
```

Observed outcomes: inspect, supported analysis, explain, and exact offline
comparison exit `0`; blocked and applied lockout-risk analyses exit `10` and
preserve their findings. Examples are synthetic fixtures, not observed ledger
data. The CLI's result is not proof that a transaction will execute.

## Trust boundary and product limitations

The product distinguishes configured authorization sufficiency, conditional
rotation modeling, offline configuration comparison, and independently
verified ledger evidence. Only the first three are implemented, and all
inputs are untrusted local JSON. Provenance labels remain caller declarations.

AuthPath does not fetch network state, hold keys, sign, submit transactions,
prove private-key possession, or verify ledger execution. It cannot guarantee
that modeled transactions will be accepted or succeed. Unsupported classic
operations/features and Soroban authorization are outside scope. It is not a
production financial decision system or substitute for protocol review.

## Originality and ecosystem comparison

Research date: 2026-10-31. This was a targeted review of public sources, not
an exhaustive census. Capabilities below are limited to what the cited
documentation/repository describes.

| Comparator | Verified capabilities | Overlap with AuthPath | Distinction and reviewer-confidence risk |
| --- | --- | --- | --- |
| [Stellar CLI](https://github.com/stellar/stellar-cli) | Broad Stellar command-line workflows for building, signing, and interacting with network transactions and contracts | Account and transaction operations in CLI form | Operational/network-oriented and broader; AuthPath's offline sequential reachability analysis is narrower. |
| [Stellar Lab](https://lab.stellar.org/) | Interactive account/transaction construction, Set Options, simulation and network submission workflows | Directly handles signer/threshold configuration and transaction simulation | Different interactive workflow; overlap means AuthPath should not imply it is the only way to reason about multisig configuration. |
| [StellarExpert signer inspector](https://github.com/stellar-expert/stellar-tx-signers-inspector) | Inspects account/transaction signer requirements, signer weights, and signature feasibility | Material overlap in answering which signers/weights can authorize a transaction | Closest identified comparator. AuthPath's implemented distinction is ordered, multi-transaction conditional state/reachability analysis plus report validation; this is incremental, not category-first novelty. |
| [Stellar Guard `multisig-utils`](https://github.com/stellarguard/multisig-utils) | Multisig signature-feasibility utilities and coordinator/submission workflow | Signer feasibility and weighted authorization | AuthPath is an offline Rust plan analyzer without signing/coordinator/submission surfaces. |
| [SEP-30](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0030.md) | Standardized account-recovery server interactions and signer-based recovery | Recovery can involve signer/threshold changes | Recovery/signing service protocol, not an offline rotation safety analyzer. |
| [Wraith multisig runbook](https://github.com/wraith-protocol/contracts/blob/develop/stellar/MULTISIG.md) | Procedural multisig account/signer rotation guidance in a project runbook | Signer rotation and threshold safety | Procedure for that project's workflow rather than a general validated local analysis engine. |
| [OpenZeppelin Stellar account policies](https://docs.openzeppelin.com/stellar-contracts/accounts/policies) | Soroban contract-account policy mechanisms including weighted authorization | General weighted threshold concepts | Different Soroban contract-account model; not classic Stellar account signer analysis. |
| [GrantFox](https://communityfund.stellar.org/project/grantfox-4zq) | Public project describes a collaboration hub connecting contributors with Stellar projects/issues and syncing GitHub | Potentially relevant as a contribution/funding channel | No demonstrated analyzer overlap. Public GrantFox material did not establish an equivalent AuthPath project; absence from this search is not proof none exists. |

The [Stellar Drips Wave](https://www.drips.network/wave/stellar) page was
reviewed, but page search is not a complete approved-project registry query.
This audit does not establish AuthPath's admission or approval status.
The defensible differentiation is a specific mechanism—offline conditional
analysis across ordered signer/threshold rotations—not a claim of uniqueness.
The signer-inspector overlap creates a real originality and reviewer
confidence risk that should be addressed with precise positioning and user
validation before making funding claims. Neither Drips nor GrantFox approval
can be predicted from this evidence.

## Governance verification

Authenticated GitHub API access was available for this audit; the table
records actual reported repository settings. No settings were changed.

| Control | Verified state | Assessment |
| --- | --- | --- |
| `main` requires successful CI | Yes: strict required status context `checks` | PASS for this specific required check |
| Pull request approval required | No: required approving review count is 0 | NEEDS WORK; recommend at least one independent approval |
| Administrators covered | Yes: `enforce_admins.enabled=true` | PASS |
| Force pushes restricted | Yes: disabled | PASS |
| Branch deletion restricted | Yes: disabled | PASS |
| Secret scanning | Disabled | NEEDS WORK; maintainer may enable after assessing repository plan/settings |
| Secret-scanning non-provider patterns | Disabled | NEEDS WORK |
| Push protection | Disabled | NEEDS WORK |
| Private vulnerability reporting | Disabled | NEEDS WORK; provide a clear private disclosure path |
| Workflow token default | Read-only; workflows cannot approve PRs | PASS, least privilege at repository default |
| Actions allowlist / SHA pinning | All actions allowed; SHA pinning not required | NEEDS WORK; consider allowlisting and pinning third-party actions |
| CI PR trigger | `pull_request`; read-only `contents` permission | PASS against the specific `pull_request_target`/write-token risk reviewed |
| SECURITY.md | Present and linked | PASS for presence; private reporting path should be clarified because GitHub private reporting is off |

The repository uses `actions/checkout@v4` and
`dtolnay/rust-toolchain@1.99.1`, which are mutable tags rather than immutable
commit pins. Read-only workflow permissions reduce impact but do not eliminate
the supply-chain risk of unpinned actions. Recommendations are maintainer
decisions; none was changed as part of this audit.

## Playbook traceability

The authoritative Universal Project Development Playbook v1.3 was not present
in the authorized workspace or repository. Accordingly, no requirement list
or traceability matrix has been reconstructed from memory or an older version.
Overall playbook compliance is **NOT VERIFIED**. Product-scope rationale is
clear for several absences: the defined artifact is an offline CLI, so a web
app, Soroban contract, database, hosted service, and live Testnet transaction
flow are not required to demonstrate its current function. This rationale is
not a substitute for unknown playbook requirements.

## Readiness matrix

| Area | Status | Evidence / condition |
| --- | --- | --- |
| Technical correctness | PASS within reviewed scope | Protocol-source comparison, implementation review, 166 tests on Rust 1.87.0 and 1.99.1; not formal verification or exhaustive protocol-version coverage |
| Security | PASS within documented local-input boundary; residual governance risk | Adversarial JSON/report/filesystem tests and local source review; no keys/network/submission; repository security features are disabled |
| Reproducibility | PASS | Locked workspace checks and fixture-based CLI demonstrations |
| Documentation accuracy | PASS for reviewed current pages | README, architecture, CLI, C5 audit, examples, submission evidence; published pages fetched and navigation checked |
| Architecture | PASS for the current MVP | Trust boundaries, modeled behavior and exclusions documented |
| Stellar-specific value | PASS, narrow | Uses classic threshold, signer, source-account, CAP-2 and ordered rotation semantics |
| Originality evidence | PARTIAL | Closest signer-inspector overlap found; targeted research, not exhaustive; differentiation is incremental and bounded |
| Governance | NEEDS WORK | CI required and admin coverage present; approvals, scanning, private reporting, action restrictions/pinning need maintainer review |
| Playbook compliance | NOT VERIFIED | Authoritative v1.3 source unavailable |
| Independent external review | NOT VERIFIED | This audit does not substitute for an independent approving protocol/security reviewer |
| Public documentation site | PASS | Pages API and live HTTP checks; current deployment workflow succeeded |

## Smallest justified next actions

1. A maintainer should decide whether to require one independent PR approval
   and enable secret scanning, push protection, and private vulnerability
   reporting; review GitHub Actions allowlisting and immutable pins.
2. Obtain the actual authoritative playbook v1.3 text and run its traceability
   review if playbook compliance is a submission requirement.
3. Ask an independent Stellar protocol reviewer to assess the supported classic
   authorization boundary and review the documented overlap with
   `stellar-tx-signers-inspector` before making originality claims.
4. Validate the target program's current eligibility and submission criteria
   directly before applying. No submission was made in this audit.

No code-level blocker was reproduced, so no Rust change or code PR was created.
This dated evidence correction is documentation only.

## Provisional verdict

**CONDITIONALLY READY**

The MVP is reviewable and reproducible within its stated offline, classic
authorization scope. A stronger READY verdict is not supported because
independent external review has not occurred, main requires no approving
review, repository security settings and action restrictions need maintainer
decisions, the authoritative playbook is unavailable, and originality
positioning faces material overlap with an existing signer-analysis tool.
These limitations are disclosed rather than inferred away from green CI.
