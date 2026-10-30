# `authpath` CLI reference

`authpath` is an offline Rust binary. It reads bounded JSON files from the
local filesystem and calls the existing AuthPath model and analysis crates.
It does not make network calls, read private keys, infer private-key
possession, sign, submit, or verify Stellar transactions.

## Installation

Run it from a checkout:

```text
cargo run -p authpath-cli -- --help
```

Install the binary locally with Cargo if desired:

```text
cargo install --path crates/authpath-cli --locked
authpath --help
```

The deterministic examples in [`examples/`](../examples/) use synthetic
valid strkeys and caller-provided provenance.

## Commands

### `inspect`

```text
authpath inspect ACCOUNT.json
authpath --format json inspect ACCOUNT.json --output account-report.json
```

Reads an `authpath.account_snapshot.v1` document and displays the account ID,
master-key weight, thresholds, configured signers, provenance, and each
signer's declared availability. A configured signer is an account setting.
Availability is caller metadata and is not proof that a usable signing
credential or private key exists.

### `analyze`

```text
authpath analyze ROTATION_PLAN.json
authpath --format json analyze ROTATION_PLAN.json --output analysis.json
```

Reads an `authpath.rotation_plan.v1` document and calls the C3 sequential
rotation engine. It reports every transaction's authorization findings,
conditional changes, reachability, reasons, and classification. The CLI does
not duplicate threshold or transition calculations.

The plan-wide Ed25519 identity set and each positive-weight signer
addition/reweight declaration must agree. A declared `available` signer must
be in the global set; a declared `unavailable` signer must not be in it. A
contradiction is inconclusive. Account-state availability is intersected with
the global identities for reachability. None of these declarations proves
private-key possession.

Expected configurations are caller-supplied assertions about the intended
result. If one disagrees with the modeled result, that step and every
dependent later step are `INCONCLUSIVE`; the modeled candidate is not used as
the next authoritative state.

### `explain`

```text
authpath explain analysis.json
authpath --format json explain analysis.json --output explanation.json
```

Reads an `authpath.analysis_report.v1` report previously produced by AuthPath
and explains its overall classification, individual findings, reasons, and
limitations. Unsupported versions, unknown fields, invalid identities, and
false on-chain claims are rejected as invalid input.

### `verify`

```text
authpath verify \
  --report analysis.json \
  --observed OBSERVED.json
```

This is an offline configuration comparison. It checks account identity,
network identity when both sides provide one, master-key weight, thresholds,
and configured Ed25519 signer keys and weights. Signer availability is
metadata and is not treated as an on-chain configuration field.

The observed document's provenance is retained in the result. A
`caller_provided` file is not upgraded to ledger evidence, even when every
compared field matches. A matching JSON file never becomes cryptographic or
on-chain verification. The JSON result separates `configuration_result` from
`plan_classification` and includes `completion_status`. An exact
`OFFLINE_CONFIGURATION_MATCH` is returned only when the report is
`SUPPORTED_REACHABLE`, every step is applied and supported, all compared
configuration fields match, and network identity is available and equal.
Matching fields do not turn a blocked, lockout-risk, invalid, incomplete, or
inconclusive plan into a successful rotation: those classifications remain in
`result` and keep their documented non-zero exit code.

## Global output options

- `--format human` (default) writes readable terminal explanations.
- `--format json` writes deterministic pretty-printed JSON with a final
  newline.
- `--output PATH` installs output atomically beside the requested path using a
  no-replace installation when `--force` is absent.
- Existing output files are rejected. `--force` is required to replace one.
  A failed output operation does not install a partial report. No-replace
  installation relies on the platform's atomic hard-link operation; if that
  operation is unavailable, the CLI reports an operational error instead of
  weakening the guarantee.

Without `--output`, output is written to stdout. Errors are written to stderr.

## Versioned JSON contracts

The CLI rejects unknown top-level and nested fields, unsupported schema
versions, malformed Stellar identities, duplicate signers, contradictory
availability declarations, and missing required fields. Optional fields in a
`set_options` change represent field absence; the transaction-level
`reserve`, `signer_availability`, and `expected` fields are required so a
safety-relevant omission is not silently defaulted.

### Account snapshots: `authpath.account_snapshot.v1`

```json
{
  "schema": "authpath.account_snapshot.v1",
  "account_id": "G...",
  "master_key_weight": 1,
  "thresholds": {"low": 1, "medium": 2, "high": 3},
  "signers": [
    {"key": "G...", "weight": 2, "availability": "available"}
  ],
  "provenance": {
    "kind": "caller_provided",
    "network": "Test Network",
    "ledger_sequence": null
  }
}
```

`provenance.kind` is `caller_provided` or `ledger`. Ledger provenance
requires a non-empty network and positive `ledger_sequence`. Caller-provided
provenance may omit the network and cannot include a ledger sequence. The
model validates the 0–255 weight domain, the 20-signer limit, duplicate keys,
and the account-master-key exclusion.

### Rotation plans: `authpath.rotation_plan.v1`

A plan contains `initial_accounts`, `available_signers`, and a non-empty
`transactions` array. Each transaction contains `source_account`,
`operations`, `signer_availability`, `reserve`, and `expected`.

Supported operation kinds are `payment`, `bump_sequence`, and `set_options`.
`set_options.changes` can name `master_key_weight`, thresholds, a signer
`{ "key": "G...", "weight": N }`, flags, inflation destination, and home
domain. Only authorization-relevant fields change modeled account state.
Account merge and unknown operation kinds are rejected by the rotation-plan
validator.

An Ed25519 global declaration is `{ "kind": "ed25519", "key": "G...",
"code": null }`. Unsupported signer kinds can be declared without key
material (`pre_auth_tx`, `hash_x`, `ed25519_signed_payload`, or
`{ "kind": "unknown", "code": N }`); the engine retains them and reports
unmet requirements conservatively.

`expected` entries contain account ID, master-key weight, thresholds, and
positive-weight signer keys. They do not prove ledger execution.

### Analysis reports: `authpath.analysis_report.v1`

Analysis JSON contains `basis: "conditional_model"`,
`verified_on_chain: false`, the overall classification, ordered step records,
unsupported signer types, the final modeled state with `initial` or `modeled`
origin, and fixed limitations. A report is still untrusted input when passed
to `explain` or `verify`; those commands validate it again.

### Observed configurations: `authpath.observed_configuration.v1`

Observed configurations use the same account fields as an account snapshot
with the observed schema string. Their provenance is copied into comparison
output exactly as supplied. The CLI never changes `caller_provided` into
`ledger` provenance.

### Explanations and comparisons

`explain --format json` produces `authpath.explanation.v1`. `verify --format
json` produces `authpath.offline_comparison.v1` with explicit field statuses,
observed provenance, `basis: "offline_configuration_comparison"`, and
`verified_on_chain: false`.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Successful inspection, supported analysis, explanation, or exact offline configuration match for a complete supported plan. |
| `2` | Invalid input: malformed JSON, unsupported schema, invalid identity, duplicate/contradictory declarations, or an untrusted report that fails validation. |
| `3` | Operational failure: missing/unreadable input, stdout failure, or output installation failure. |
| `10` | A finding requiring attention: `BLOCKED`, `LOCKOUT_RISK`, `INVALID_TRANSITION`, or offline configuration mismatch. |
| `20` | `INCONCLUSIVE`, including unsupported semantics, unavailable network identity, expectation mismatch, or a dependent step after a halted predecessor. |

An `INCONCLUSIVE` engine result always maps to exit code `20`; it is never
printed as `SUPPORTED_REACHABLE`. A comparison can report
`configuration_result: "MATCHED"` while returning `BLOCKED`, `LOCKOUT_RISK`,
`INVALID_TRANSITION`, or `INCONCLUSIVE` in `result`; this means only that the
observed fields match the modeled candidate, not that the intended rotation
completed.

## Resource bounds and limitations

Each JSON input is limited to 4 MiB. Plans are bounded to 256 accounts, 256
transactions, 100 operations per transaction, 1,024 declared signer
identities, and 20 configured signers per account. Reports also bound steps,
final-state accounts, and reasons per step. These are defensive input bounds,
not claims about all Stellar protocol behavior.

The CLI does not model or establish cryptographic signatures, private-key
possession, balances and reserves, fees, sequence numbers, preconditions,
ledger acceptance, concurrent changes, unsupported signer kinds, non-
authorization operation effects, or live network state. Configured
authorization sufficiency, conditional rotation modeling, and offline
configuration comparison are separate claims. Genuine independently
verified ledger evidence is not available in the current CLI.
