# Final review and submission readiness

Audit date: 2026-11-01

This is an evidence record for independent review, not an approval, grant
recommendation, adoption claim, or declaration that AuthPath is ready to
submit. It separates implemented facts from unverified claims and remaining
work.

## Canonical repository state

- Repository: <https://github.com/Stellar-AuthPath/authpath>
- Current main SHA before this correction: `4763682cee7fabe418930096057bfa962198c1d3`
- C6 review: <https://github.com/Stellar-AuthPath/authpath/pull/6> (merged)
- Documentation link correction: <https://github.com/Stellar-AuthPath/authpath/pull/7> (merged)
- Published examples page correction: <https://github.com/Stellar-AuthPath/authpath/pull/8> (merged)
- Base branch: `main`
- Base SHA before C6: `aa43350d7286624fe45bad374566bbbb3db10d1d`
- C5 review: <https://github.com/Stellar-AuthPath/authpath/pull/5> (merged)

The C1–C5 history was not rewritten. This phase changes documentation,
examples, evidence, and documentation build configuration only.

## Problem and target users

Classic Stellar accounts combine a master-key weight, additional signer
weights, and low/medium/high thresholds. A signer or threshold rotation can
be authorized under the current configuration yet leave a later transaction
or the account's administrative threshold unreachable. The danger is greater
when a plan spans multiple transactions or relies on signers whose usable
credentials have not been confirmed.

AuthPath is aimed at account operators, multisignature and treasury teams,
protocol engineers, and reviewers who want a deterministic, offline
pre-submission analysis of those assumptions. It is not aimed at custody,
wallet signing, transaction submission, or live ledger monitoring.

## Implemented solution

The current binary, `authpath`, provides:

- `inspect` for validated account snapshots;
- `analyze` for versioned rotation plans through the C2/C3 APIs;
- `explain` for revalidating and explaining untrusted reports; and
- `verify` for offline modeled-versus-observed configuration comparison.

The implementation is deliberately local and keyless. It accepts only
bounded, versioned JSON, preserves provenance, uses caller-supplied signer
availability as metadata, and never reports on-chain verification.

## Why Stellar protocol behavior matters

AuthPath's conclusions depend on Stellar-specific rules rather than generic
weighted voting. The analyzer accounts for the transaction source and each
operation source, threshold categories, signer weight accumulation, the
pre-operation authorization timing required by CAP-2, SetOptions changes, and
the 20-signer boundary. The C3 engine then applies only the represented
authorization-state changes conditionally and evaluates administrative reach
after each modeled transaction.

The checked primary references are:

- [CAP-2 transaction-level signature verification](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0002.md);
- [Stellar transaction XDR](https://github.com/stellar/stellar-xdr/blob/main/Stellar-transaction.x);
- [SEP-23 strkeys](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md);
- [stellar-core TransactionFrame](https://github.com/stellar/stellar-core/blob/master/src/transactions/TransactionFrame.cpp);
- [stellar-core OperationFrame](https://github.com/stellar/stellar-core/blob/master/src/transactions/OperationFrame.cpp); and
- [stellar-core SetOptionsOpFrame](https://github.com/stellar/stellar-core/blob/master/src/transactions/SetOptionsOpFrame.cpp).

No AuthPath-specific protocol or architecture specification was available,
and the Universal Project Development Playbook v1.3 was not available as an
authoritative text. Full compliance with either unavailable source cannot be
claimed.

## Reproducible CLI demonstrations

From a clean checkout, the following commands use only repository fixtures:

```sh
cargo build --workspace --locked
cargo run -p authpath-cli -- inspect examples/account-snapshot.json
cargo run -p authpath-cli -- --format json analyze \
  examples/rotation-plan.json --output /tmp/authpath-report.json
cargo run -p authpath-cli -- explain /tmp/authpath-report.json
cargo run -p authpath-cli -- verify \
  --report /tmp/authpath-report.json \
  --observed examples/observed-configuration.json
cargo run -p authpath-cli -- analyze examples/blocked-rotation-plan.json
cargo run -p authpath-cli -- analyze examples/lockout-risk-rotation-plan.json
```

Observed behavior for the classification examples is exit code `10` for both
`BLOCKED` and applied `LOCKOUT_RISK`. The supported example exits `0` for
analysis, explanation, and exact offline comparison. The final two commands
are findings requiring attention; they are not failed process executions.

## Safety model

The result types are intentionally separate:

1. configured authorization sufficiency in supplied snapshots;
2. conditional ordered rotation modeling;
3. offline comparison of modeled fields with an observed file; and
4. independently verified ledger evidence, which is not implemented.

`LOCKOUT_RISK` can be an applied step with a valid next modeled state, while
`BLOCKED`, `INVALID_TRANSITION`, and halted `INCONCLUSIVE` steps stop dependent
analysis. Expected configurations are caller assertions, not proof of ledger
execution. A report's `verified_on_chain` field remains false, and matching
JSON never upgrades caller-provided provenance.

## Verification evidence

The merged C1–C5 baseline recorded the following local results on the pinned
Rust 1.99.1 toolchain:

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets --locked` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --all-targets --locked` | 166 passed across five targets |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | Passed |
| `cargo audit --deny warnings` | Passed; no vulnerability or warning reported |

The complete locked workspace checks also passed under Rust 1.87.0, including
formatting, check, Clippy, all 166 tests, and Rustdoc. The repository pins
Rust 1.99.1 for development and CI. The dependency audit used cargo-audit
0.22.2 and the local RustSec database; it was not a required CI job.

The latest main commit is `4763682cee7fabe418930096057bfa962198c1d3`, the
merge commit for PR #8. Its PR checks passed: [CI](https://github.com/Stellar-AuthPath/authpath/actions/runs/41163390775)
and [Documentation](https://github.com/Stellar-AuthPath/authpath/actions/runs/41163390874).
PR #7 also passed its CI run
(https://github.com/Stellar-AuthPath/authpath/actions/runs/41162755782).
These are GitHub results for those PR heads; they are distinct from local
verification and do not imply a new CI run on every later main commit.

## C5 evidence

The [C5 audit record](c5-audit.md) documents the supported protocol boundary,
adversarial tests, report-tampering defenses, atomic no-replace output
installation, confirmed findings, dependency results, and known limitations.
It also records the applied-`LOCKOUT_RISK` validation correction and the
engine-generated producer/consumer regression tests.

## Originality and ecosystem positioning

This review checked public, materially adjacent tools and references on
2026-10-31. It was a targeted search, not an exhaustive ecosystem census.

| Existing offering | Overlap | Boundary and AuthPath distinction |
| --- | --- | --- |
| [Stellar Lab](https://lab.stellar.org/) | Reads/builds account and transaction operations, including Set Options weights, thresholds, and signers | Interactive transaction construction and network-facing workflows; it is not the same as AuthPath's offline multi-transaction conditional reachability report |
| [Stellar CLI](https://github.com/stellar/stellar-cli) | Developer CLI for Stellar transactions, identities, signing, and network workflows | Broader operational tooling with signing/network surfaces; AuthPath intentionally has none of those surfaces |
| [SEP-30 account recovery](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0030.md) | Key rotation and recovery workflows using signer changes | A signing-server protocol; AuthPath does not custody keys or sign and instead reviews caller-supplied plans |
| [LumenWipe](https://github.com/LumenWipe/lumenwipe) | Account-state inspection and recovery/closure transaction planning | Live-network and transaction-building recovery product; AuthPath is a narrower offline authorization/rotation analysis tool |

The supported differentiation is mechanism-based and modest: AuthPath combines
offline C2 authorization checks with C3 ordered signer/threshold modeling,
explicit signer-availability intersections, conditional lockout findings, and
strict validation of independently loaded reports. These capabilities are
implemented and tested in this repository. They do not justify a claim that
AuthPath is unique or that any external project is inferior. A maintainer or
independent reviewer should perform a broader landscape review before making
an originality or funding claim.

## Governance and repository readiness

Repository facts verified locally or through accessible GitHub metadata:

- `LICENSE` is Apache-2.0.
- `SECURITY.md` and `CONTRIBUTING.md` are present and linked from the README.
- The repository is public and `main` is the default branch.
- GitHub Pages is configured to publish from the main branch using GitHub
  Actions. The Pages API confirms the public URL
  <https://stellar-authpath.github.io/authpath/>. The root and examples page
  returned HTTP 200 after PR #8 merged.
- Main branch protection, required CI contexts, approving-review requirements,
  and administrator enforcement could not be verified: the branch-protection
  API returned 404 to the available credentials.
- Secret-scanning and private-vulnerability-reporting settings could not be
  verified: repository security endpoints returned 404 or omitted those
  fields for the available credentials. Dependabot settings were not changed.
- No releases or tags were present at review time.
- A targeted tracked-file scan found no private-key PEM blocks, obvious secret
  assignments, or AI co-author trailers. This is not a substitute for a
  dedicated secret-scanning service.

The repository has a lean issue surface and no generated backlog, release
claim, partner claim, usage metric, or reviewer approval claim.

## Readiness matrix

| Area | Status | Evidence or remaining condition |
| --- | --- | --- |
| Technical correctness | PASS within the documented operation boundary | C1–C5 tests, protocol comparison, and C3 producer/consumer tests |
| Local input/report security | PASS within the offline boundary | C5 adversarial and filesystem tests; no keys or network surface |
| Reproducibility | PASS locally | Rust 1.87.0 and 1.99.1 locked-workspace verification |
| Documentation accuracy | PASS after C8 | README, architecture, CLI, audit, examples, and evidence record updated |
| Architecture completeness | PASS for the current MVP | Trust boundaries and unsupported behavior are explicit |
| Stellar-specific value | PASS within a narrow scope | Uses threshold, signer, source-account, CAP-2, and rotation semantics |
| Originality evidence | NEEDS WORK | Targeted research only; no exhaustive landscape or uniqueness claim |
| Governance | NOT VERIFIED | Branch protection, secret scanning, and private vulnerability reporting are inaccessible through the available GitHub API permissions |
| Public documentation site | PASS | Pages API confirms workflow deployment; root and examples page returned HTTP 200 |
| Independent review | NOT VERIFIED | This phase prepares evidence but does not substitute for external review |

## Remaining submission blockers

The project should not be described as ready for submission solely because the
code checks are green. Before a final submission claim, maintainers should:

1. obtain independent technical and protocol review;
2. have a repository administrator verify main branch protection, required
   approvals, administrator enforcement, secret scanning, and private
   vulnerability reporting; consider requiring an approval and enabling
   secret scanning if currently off;
3. perform a broader, dated ecosystem/originality review; and
4. decide whether audit and MSRV checks belong in required CI rather than only
   local evidence.

## Provisional verdict

**NEEDS WORK — evidence prepared for independent review, but final submission
readiness is not established.** The current implementation is reviewable and
reproducible within its narrow offline boundary. No approval, adoption,
on-chain verification, public documentation deployment, or originality
guarantee is claimed.
