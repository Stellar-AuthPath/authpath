# Final independent audit and submission readiness

Verification date: 2026-10-31

This is a dated evidence record, not an approval, grant recommendation,
adoption claim, or assertion of on-chain verification. It distinguishes checks
performed during this review from earlier phase evidence and from items that
remain unverified.

## Executive summary

AuthPath is a keyless, offline Rust CLI for analyzing classic Stellar account
authorization and conditionally modeling ordered signer and threshold
rotations. The current repository builds and passes its workspace checks on
the pinned Rust 1.99.1 toolchain and on the declared Rust 1.87.0 minimum.
Current `main` CI and documentation workflows pass, and the public mdBook site
and its navigation pages were fetched successfully. The authoritative
Universal Project Development Playbook v1.3 was supplied locally and is
traceable below; this review marks some requirements partial or unverified
instead of treating checklist completion as approval.

This review found no demonstrated submission-blocking correctness defect in
the reviewed MVP boundary. It is not a full formal or independent protocol
audit. Main requires the strict `checks` status, enforces admins, requires
review-conversation resolution, prevents force pushes and branch deletion,
and enables secret scanning and private vulnerability reporting. The
maintainer explicitly defers required independent approvals until the
project accepts external contributions; this is not a current submission
blocker and no independent review is claimed. The current branch-protection
API nevertheless reports one required approval, so the saved setting does not
match the maintainer's stated intention. No setting was changed. Repository
Actions policy allows all actions and does not require SHA pinning; the
effective organization policy could not be read with the available token.
Existing workflow actions are pinned to verified SHAs in the correction
branch, and dependency auditing is added to its CI. AuthPath overlaps with an
existing Stellar signer inspector; no uniqueness claim is made.

## Authoritative repository state

- Repository: <https://github.com/Stellar-AuthPath/authpath>
- Audited `main` baseline SHA: `2a09eaabf3e5c82ecf9febca1cdcaee759869c2e`.
  This is the evidence baseline and will not be rewritten when this report
  later merges.
- PRs #1 through #11 are merged. PR #11 merged at
  <https://github.com/Stellar-AuthPath/authpath/pull/11>.
- Baseline `main` CI: [run 41243948392, success](https://github.com/Stellar-AuthPath/authpath/actions/runs/41243948392)
- Baseline `main` documentation build and Pages deployment: [run 41243948441, success](https://github.com/Stellar-AuthPath/authpath/actions/runs/41243948441)
- Workflow-security and evidence corrections are on a separate review branch;
  their results are not attributed to baseline `main`.
- Candidate branch `submission-readiness-correction-2026-10-31` contains
  [commit `f138014`](https://github.com/Stellar-AuthPath/authpath/commit/f13801424172bc264c74f18fedc640ba634b1afe),
  which pins workflow actions to verified immutable revisions, and
  [commit `1c059a1`](https://github.com/Stellar-AuthPath/authpath/commit/1c059a103d880d63b0fb016afbb5fc781dc61635),
  which adds `cargo audit --deny warnings` to PR CI. These commits are not in
  the audited baseline SHA.
- These workflow results are GitHub-hosted checks on the stated `main` SHA;
  local commands below are separate evidence.
- Public documentation: <https://stellar-authpath.github.io/authpath/>

The GitHub PR list confirmed that PRs #1–#11 are merged. Historical PR checks
are not substituted for the current-main runs above.

## Scope and method

The audit reviewed the C1 account model, C2 authorization analysis, C3
rotation engine, C4 CLI and report parser, C5 security/audit record, C6 docs,
tests, fixtures, workflows, README, architecture, CLI reference, `SECURITY.md`,
`CONTRIBUTING.md`, and license. Protocol comparisons used the linked Stellar
specifications and stellar-core implementation sources. Dependency audit data
was refreshed during the local check. Ecosystem research was targeted and
public; it is not exhaustive.

The maintainer-provided local file `Universal_Project_Development_Playbook_v1.3.md`
was read in full for applicable requirements; it is not part of the repository.
Its header identifies v1.3, created 29 October 2026. It explicitly says to
apply only relevant phases and not to add infrastructure for checklist
appearance. The traceability matrix below covers applicable requirements for
this offline CLI; it does not claim that conditional or external requirements
have been satisfied.

## Technical and security findings

| Severity | Finding | Evidence and disposition |
| --- | --- | --- |
| CRITICAL | None demonstrated | No reviewed path demonstrated an exploitable critical defect. |
| HIGH | None demonstrated | No reviewed path demonstrated a high-severity defect within the stated scope. |
| LOW | Repository Actions policy is permissive; organization policy is not verified | Repository API reports `allowed_actions: all`, `sha_pinning_required: false`, and read-only default workflow permissions. Organization policy returned HTTP 403 without `admin:org`. Existing workflow actions are SHA-pinned in the correction branch; no settings changed. |
| INFORMATIONAL | Push protection and non-provider-pattern scanning are disabled | Secret scanning and private vulnerability reporting are enabled. No settings were changed. |
| INFORMATIONAL | Approval setting differs from maintainer-stated intention | Maintainer defers required approvals until external contribution intake. Current API reports one required approval. Recorded accurately; not treated as a submission blocker and not changed. |
| INFORMATIONAL | Material adjacent signer-analysis tool exists | StellarExpert's `stellar-tx-signers-inspector` analyzes transaction/account signers and feasibility; AuthPath's distinction is sequential conditional state analysis, not uniqueness. |
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

`cargo audit --deny warnings` passed locally with cargo-audit 0.22.2. Its
refreshed database contained 1,395 advisories and it scanned 30 locked
dependencies without a reported vulnerability or warning. The correction
branch adds the same command to PR CI; that result is separate from baseline
`main`. This records the audit database snapshot at that time, not a guarantee
about future advisories. `Cargo.lock` is present and workspace checks used
`--locked`.

The baseline `main` workflows independently passed as linked above. The
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
preserve their findings. The successful plan contains two ordered
SetOptions transactions. Step 0 adds a new signer at weight 1 and is applied
with `SUPPORTED_REACHABLE`; its changed account reports available weight 4
against configured high threshold 3. Step 1 reweights that signer to 2, is
also applied, and reports available weight 5 against high threshold 3. The
saved report contains both step findings and final modeled state. The existing
engine scenario test
`adding_the_replacement_before_removing_the_old_signer_is_supported` also
passes and covers the add-then-remove replacement ordering. The scenario test
`lowering_thresholds_before_removing_a_signer_keeps_administration` passes
both orderings: lowering thresholds before removing a signer leaves two
supported steps, while removing first yields lockout risk followed by blocked
authorization. `multiple_sequential_changes_evolve_the_state_and_match_expectations`
also passes three ordered state changes. These tests use synthetic model
inputs, not observed ledger data. CLI/model results are not proof that a
transaction will execute.

### Practical comparison with StellarExpert signer inspector

StellarExpert's published
[README](https://github.com/stellar-expert/stellar-tx-signers-inspector#readme)
documents `inspectTransactionSigners`, optimal signer discovery,
`checkFeasibility(availableSigners)`, account signer inspection, and handling
multiple operation sources within a transaction. That is direct overlap in
transaction-level authorization feasibility. AuthPath's runnable
`examples/rotation-plan.json` instead contains two transactions and declares
the expected signer configuration after each. Its CLI applies the first
modeled change before checking the second transaction, retains a per-step
reachability result, and writes a report that `explain` revalidates. This
demonstrates a different, sequential analysis workflow; it does not prove the
comparator cannot be extended to do the same, and it does not support a
first/only/unique claim.

The comparator README also documents Hash-X, signed-payload and
pre-authorized signers, Soroban authorization entries, Horizon account loading,
and excess-signature checks. AuthPath currently represents Ed25519 signers in
its rotation plans and does not model Soroban authorization. The comparator
therefore covers important adjacent signer types and transaction cases that
AuthPath deliberately excludes; the differentiation is in modeled sequence
state, not breadth of Stellar signer support.

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

## Governance and GitHub Actions verification

Authenticated GitHub API checks were performed on 2026-10-31. Repository
settings were not changed. The organization-level Actions endpoint returned
HTTP 403 because the available token lacks `admin:org`; effective organization
restrictions are therefore **NOT VERIFIED**.

| Control | Observed state | Assessment |
| --- | --- | --- |
| Required CI on `main` | Strict status context `checks` | PASS |
| PR approval requirement | API reports `required_approving_review_count: 1`; maintainer says approval is deliberately deferred until external contribution intake | Actual value recorded; no setting changed and this is not a submission blocker |
| Administrator enforcement | Enabled | PASS |
| Review conversation resolution | Enabled | PASS |
| Force pushes / branch deletion | Both disabled | PASS |
| Secret scanning | Enabled | PASS |
| Push protection | Disabled | Optional hardening recommendation |
| Non-provider pattern scanning | Disabled | Optional hardening recommendation |
| Private vulnerability reporting | Enabled | PASS |
| Dependabot security updates | Disabled | Unchanged by this work |
| Default `GITHUB_TOKEN` permissions | `contents: read`; workflows cannot approve PRs | PASS |
| Repository Actions policy | All actions allowed; immutable SHA pinning is not enforced | Limitation; the workflows themselves are pinned in the correction branch |
| Organization Actions policy | API returned 403 (missing `admin:org`) | NOT VERIFIED; do not infer enabled or disabled |
| PR workflow trigger / secrets | `pull_request`; no `pull_request_target` or workflow secret references | PASS for untrusted PR boundary reviewed |
| Pages deployment permissions | `pages: write` and `id-token: write` only on the deploy job, which does not run for pull requests | PASS for the workflow inspected |

The maintainer's approval decision is documented separately from GitHub's
observed `1` approval setting. This review neither changes the setting nor
asks for reviewers. No independent human or external protocol review is
claimed. Playbook §12A review requirements are deferred until the project
begins accepting external contributions; they are not used as a current
submission blocker.

The workflows at the audited baseline used mutable tags. The correction
branch pins all seven `uses:` references to verified 40-character commits:
`actions/checkout` v4.2.2, `dtolnay/rust-toolchain` 1.99.1,
`actions/configure-pages` v5.0.0, `actions/upload-pages-artifact` v4.0.0,
and `actions/deploy-pages` v4.0.5. Their resolved SHAs are recorded in the
workflow files. The repository-level allowed-Actions setting remains `all`;
no repository or organization setting was changed. The organization-level
policy remains unverified.

## Playbook v1.3 traceability

Source read: maintainer-provided `Universal_Project_Development_Playbook_v1.3.md`
(not checked into this repository), header version 1.3, created 2026-10-29.
Status applies to the current offline CLI; a PASS does not imply external
program approval.

| Exact requirement / section | Applicability | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- |
| §0: “A reviewer can understand the output without being shown a speculative feature list.” | Applies | README, `docs/architecture.md`, `docs/cli.md`, runnable examples | PASS | None for current scope |
| §1: “Build one end-to-end useful path”; “Test boundaries and failures.” | Applies | CLI integration tests, 166 tests in current-main CI, synthetic fixture commands | PASS | Continue to describe fixture results as conditional |
| §1: “Require protected default branches and verified CI gates”; “report platform enforcement limits honestly.” | Applies | Live API: strict required `checks`, admin enforcement, conversation resolution on, force pushes/deletion off. The API reports one required approval although maintainer says reviews are deferred. | PASS for observed protection; approval-policy mismatch disclosed | No setting changed. Maintainer can reconcile the approval value; it is not a current submission blocker. |
| §1 / §3: “Name the user, task, existing workaround, and failure/cost”; “review current ... approved/public projects.” | Applies | README and this dated StellarExpert/Drips/GrantFox comparison | PARTIAL | No empirical user/problem validation is documented; broader landscape search and current application eligibility remain unverified |
| §2 Phase A: define “core workflow and out-of-scope boundaries.” | Applies | README, architecture and CLI limitations | PASS | None for current MVP |
| §2 Phase B: “current external assumptions verified or marked unknown.” | Applies | Stellar protocol references, dependency/MSRV results and dated ecosystem links | PARTIAL | Supported OS matrix and effective org Actions policy are not verified |
| §2 Phase C / §5: risky assumptions get an experiment or explicit conditional result | Applies to protocol rules | Hand-derived authorization tests and current stellar-core source comparison; no live ledger or stellar-core differential harness | PARTIAL | Independent protocol review / differential testing remains useful; no live behavior is claimed |
| §2 Phase D: “components, interfaces, authority and data flow.” | Applies | `docs/architecture.md`, JSON schema docs, report validation and trust boundary | PASS | None for current scope |
| §2 Phase E: “minimal complete working feature set.” | Applies | `inspect`, `analyze`, `explain`, `verify`; actual commands recorded above | PASS | None |
| §2 Phase F: real cross-component boundary verified when 2+ components connect | Applies (workspace model, analysis and CLI crates) | Workspace tests and CLI integration suite exercise real constructors, engine and report handling | PASS | No external service boundary exists |
| §2 Phase G / §9: reproducible success, negative and security/failure tests; suitable dependency scan | Applies | Baseline CI passes fmt/check/Clippy/166 tests/Rustdoc; `cargo audit` 0.22.2 passed locally; correction branch adds locked `cargo audit --deny warnings` to CI | PARTIAL on baseline; candidate check must pass | Portability beyond tested Linux runner is not established; candidate PR CI result is reported separately |
| §2 Phase H / §10: live proof only when claims depend on live systems | N/A for analyzer; applies to docs site | No ledger/network claims; public Pages pages and current deployment workflow checked | PASS / N/A | No live Stellar transaction is required or claimed |
| §2 Phase I / §11: “A fresh user can obtain and execute the project in its intended environment.” | Applies | Source build/run commands, lockfile, CI clean runner, local fixture executions; no binary release | PASS for source installation | No release/tag required by current project or verified program rule |
| §2 Phase J / §12: truthful docs, runnable sample, verified entry point and reproduce workflow | Applies | README links published docs; CLI reference and `examples/`; live links and examples checked | PASS | Presentation below is a concise reviewer handoff |
| §12A: protect default branch, require exact CI checks, forbid force push/deletion, resolve review threads, review untrusted workflows | Applies to repository configuration | Current API reports strict `checks`, admin enforcement, conversation resolution, force/deletion disabled; PR workflow is read-only `pull_request` with no secrets or `pull_request_target`; correction branch SHA-pins actions | PASS for observed configuration; effective org Actions restrictions NOT VERIFIED | Organization endpoint requires `admin:org`; repository API allows all actions. No settings changed. |
| §12A: independent approval and human review for contributor PRs | Applies when accepting external contributions; maintainer defers until then | Maintainer instruction; branch API currently reports one required approval, contrary to stated intended value | DEFERRED, not a current submission blocker | Do not claim full §12A contribution-review compliance or independent review; reconcile setting before external PR intake. |
| §12A: “Confirm a deliberately failing PR cannot merge” | Applies before accepting external PRs | Required context `checks` is strict and configured; no failing PR was created during this read-only verification | NOT VERIFIED; deferred with external-contribution intake | Run a safe gate test before opening contribution intake; not a current submission blocker. |
| §13 Phase K: “Review without changing files first”; classify blockers and freeze unrelated work | Applies | Audit record and current verification; no code changes made | PASS for this audit | Continue freeze; this evidence update only refreshes facts and traceability |
| §13: only claim READY when release claims are evidence-backed | Applies | Provisional verdict and limitations in this report | PASS | Final program eligibility/approval is separate |
| §14 L1: pre-approval issue set should be “small, selective and genuine”; zero is allowed | Applies | Repository has zero open issues; no backlog was created | PASS | Keep at zero unless a concrete contributor task is justified |
| §14 L2/L3: verify approval before expanding the contributor roadmap | Conditional; no approval verified | No Drips/GrantFox submission or approval claimed | N/A now | Re-audit and publish only genuine acceptance-criteria issues if approval occurs |

No web application, database, Soroban contract, or Testnet transaction is
required by AuthPath's current core workflow. The Playbook says not to add
hosting or infrastructure by default and makes live verification conditional
on live-system claims. A docs site exists and is independently checked, but it
does not change the product into a hosted service.

## Reviewer-facing presentation

**Problem.** In classic Stellar, transactions are authorized from weighted
signers and low/medium/high thresholds. A rotation can be authorized now yet
leave later maintenance unreachable after signer or threshold changes.

**Implemented solution.** AuthPath is a local Rust CLI that inspects an
untrusted account snapshot, analyzes a bounded rotation plan through the
existing authorization and rotation engines, explains validated reports, and
compares modeled fields with a separate caller-supplied observed snapshot.

**Why Stellar matters.** The analysis depends on account and operation
sources, signer-weight accumulation, threshold categories, CAP-2 authorization
timing, SetOptions effects, and signer reachability. Generic weighted-vote
logic would miss those protocol-specific semantics.

**Demonstration.** Run `cargo run --locked -p authpath-cli -- --format json
analyze examples/rotation-plan.json --output /tmp/authpath-report.json`, then
`cargo run --locked -p authpath-cli -- explain /tmp/authpath-report.json`.
The two ordered steps are applied conditionally and remain
`SUPPORTED_REACHABLE`; `examples/blocked-rotation-plan.json` and
`examples/lockout-risk-rotation-plan.json` show exit code 10 with the respective
findings. See `examples/README.md` for commands.

**Differentiation.** StellarExpert's signer inspector already discovers
feasible signers/weights for transactions and multiple operation sources.
AuthPath's demonstrated distinction is carrying modeled account state from
one transaction into the next and reporting stepwise reachability. This is a
narrow implementation difference, not a uniqueness claim.

**Limitations.** Inputs and provenance are caller-supplied; signer availability
does not prove key possession. No private keys, signing, network access,
transaction submission, or authoritative ledger verification. A modeled
transaction is not evidence it will execute. Some classic behavior and
Soroban authorization are unsupported.

## Readiness matrix

| Area | Status | Evidence / remaining condition |
| --- | --- | --- |
| Technical correctness | PASS within reviewed scope | Current-main CI runs 166 tests; protocol/source and implementation review; not formal verification or all-version coverage |
| Security | PARTIAL on audited `main` | No application defect was demonstrated; secret scanning is enabled and PR workflows are read-only `pull_request` jobs. Main still uses mutable action tags and has no dependency-audit CI step; the candidate branch pins actions and adds `cargo audit`. Effective organization Actions policy is NOT VERIFIED. Push protection and non-provider-pattern scanning are optional hardening gaps. |
| Reproducibility | PASS for source build and fixtures | Locked CI, Rust 1.87/1.99 local evidence, executable examples |
| Documentation accuracy | PASS for reviewed current source | Published pages and internal navigation fetched; this report refreshes current SHA/governance/Playbook evidence |
| Architecture | PASS for MVP | Trust boundaries, conditional results and unsupported behavior documented |
| Stellar-specific value | PASS, narrow | Classic account signer/threshold and ordered authorization semantics used directly |
| Originality | PARTIAL | Practical sequential case runs; direct overlap with StellarExpert; broader research and user validation incomplete |
| Governance | PASS for verified branch rules; Actions policy PARTIAL | Strict required `checks`, administrator enforcement, conversation resolution, no force-push/deletion, secret scanning, private reporting, read-only default token. Live API reports one required approval despite the maintainer's stated deferral; this mismatch is not treated as a submission blocker. Repository allows all Actions and does not enforce SHA pins; candidate workflows pin their current action references. Organization policy is NOT VERIFIED. |
| Playbook compliance | PARTIAL | Applicable v1.3 requirements traceable; multiple rows partial and external claims/controls unverified |
| Independent protocol review | NOT VERIFIED | This review is not an independent external reviewer sign-off |
| Public documentation | PASS | Live site and links checked; current deployment workflow succeeded |

## Remaining justified follow-up

No submission-blocking Rust or CLI defect was reproduced. The first item is
the remaining project-owned correction before this evidence can be promoted
from conditional readiness. The other items are disclosed limitations or
maintainer-controlled follow-up:

1. This review branch's action-SHA pins and dependency-audit CI step require
   PR checks and maintainer review before they become part of `main`. Until
   merged, the audited `main` continues to use mutable action tags and does
   not run `cargo audit` in CI. Baseline `main` CI and Pages evidence above is
   distinct from candidate-branch evidence.
2. Effective organization-level Actions restrictions remain NOT VERIFIED
   because the authenticated API request returned 403 without `admin:org`.
   Repository-level permissions are recorded above; no settings were changed.
3. The live branch-protection API reports one required approval, while the
   maintainer has said mandatory independent review is deliberately deferred
   until external contributions begin. This discrepancy should be reconciled
   before external contribution intake. It is not a current submission
   blocker, and no reviewer was requested or independent review claimed.
4. Broader user/problem validation and independent protocol differential
   review would strengthen future evidence, but neither is represented as
   completed. The existing tests and protocol-source review do not constitute
   formal verification.

Application eligibility and submission are outside this repository review;
the maintainer will handle any application activity.

## Provisional verdict

**CONDITIONALLY READY**

The audited `main` is demonstrable and reproducible within AuthPath's stated
offline classic-account scope, and no submission-blocking Rust or CLI defect
was reproduced. The candidate workflow-security corrections are not in
`main` yet, so the baseline still lacks immutable action references and CI
dependency auditing. Effective organization-level Actions restrictions also
remain unverified. The maintainer's deliberate deferral of independent PR
approvals is not a reason for this verdict. Reassess after the correction PR
passes CI and the maintainer decides whether to merge it; no external review
or application approval is claimed.
