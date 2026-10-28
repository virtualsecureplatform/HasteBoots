# Fresh complete joint-backend binding audit

The complete-proof adversarial driver now accepts a statically selected masked
backend factory. Its original independent cases retain their parameter shapes,
key fixtures and requested statements; new cases use canonical joint-source
parameters. Both complete version 10 and shared-comparison version 11 construct
fresh certificates under the requested statement and actual source roots.
These attacks do not mutate an honest proof after its challenges are known.

Each field/version pair has one accepted control and fourteen rejected cases:

| Cases | Intended false reported obligation |
| --- | --- |
| Initial/final endpoints, addition, continuity, digit A/B views | Accumulator linkage |
| Rotation | Caller-derived public monomial factor |
| KeyProduct | Bootstrapping-key product |
| SwitchKeyProduct | Final switching-key product |
| Extraction A/B | Requested output extraction |
| Canonical A/B and SwitchCanonical | Final zero borrow for digits representing p |

The reference replay keeps every NTT and actual-root opening strict. It checks
each rational-lookup sum/reciprocal equation and original/helper authentication,
and separately reports both key products, three canonical-decomposition checks
for each blind-rotation half and the final key stage, linkage, rotation and
extraction. Every other reported obligation must hold in each attack. Linkage
is a reported group of coupled equalities, not a claim that exactly one internal
scalar equation differs. Production must accept controls and reject attacks at
the intended stage. Native key owners still spend one allowance per certificate.

Joint source sharing stays active through `CanonicalPcs`: every batch source
certificate and all its query-specific masked ladders are checked against the
independently expected root. No audit flag, relaxed verifier mode or backend
selector is deserialized from a proof. All fixture construction, reference hooks
and backend factories live under the existing `cfg(test)` audit module.
Production Rust routines, parameters, proof framing and source-sharing behavior
are unchanged by this audit extension.

## Stronger evidence records

The existing single-field end-of-proof transcript comparison remains. It is now
followed by a separate 32-byte challenge comparison between the constructor and
reference replay, covering the complete transcript rather than relying only on
one field challenge. This diagnostic runs after certificate construction, so it
does not change any proof messages or production verification.

Each emitted record includes the complete serialized proof byte count and
SHA-256, the 32-byte transcript fingerprint, the exact production rejection
message, all reported obligations, backend, prime and version. Certificates are
serialized and decoded before replay and production verification.

`tools/check_complete_binding_audit.py` checks complete field/version/attack
coverage, duplicates, boolean report shapes, the sole intended failed report,
production acceptance and rejection stages, fingerprint shape, fixture scope
and successful Rust test completion. It validates emitted reports, not proof
bytes independently. Negative checker exercises use actual Rust records with
missing/duplicate cases, altered acceptance/obligations/stages, malformed hashes,
nonboolean flags and zero byte counts; all must reject.

## Scope and running

These exact algebraic fixtures use zero native evaluation-key samples. The two
foreign-key cases add radix-weighted nonzero limbs and nonzero rotations to
isolate their intended products. Public deterministic mask seeds are test
controls. This is not an encrypted/native-security or original-size audit, nor
an adaptive hiding, robust proximity or knowledge/Fiat-Shamir theorem.
Fresh full false-lookup composition cases, secure encrypted original-size
adversarial fixtures, independent review, complete query/FRI aggregation and all
original security/performance promotion gates remain open.

The 60 new cases are opt-in because of CPU and memory cost:

```sh
RAYON_NUM_THREADS=8 cargo test --release --locked -p snarks --lib \
  packed_pbs::canonical::audit::v10_joint_ -- --ignored --nocapture --test-threads=8
RAYON_NUM_THREADS=8 cargo test --release --locked -p snarks --lib \
  packed_pbs::canonical::audit::v11_joint_ -- --ignored --nocapture --test-threads=8
```

A combined run may filter `joint_` to cover both versions and both fields. The
validator accepts a raw combined log, backend `masked-joint`, and versions 10/11.
Existing independent masked cases remain runnable without changing their
names. There are now 120 opt-in masked cases across the two backend types and
both versions. Executed/final source snapshots, frozen executable, checked
records and raw logs are retained under
`target/performance/joint-fresh-binding-audit/`.

## Verified results

The frozen test executable passes 80 default SNARK unit tests with 120 opt-in
cases ignored, plus all 60 selected joint-backend manual cases. The default run
also checks 60 fresh Brakedown certificates. Across the checked records there
are 120 complete certificates: eight controls accepted and 112 attacks rejected.
The joint subset has four accepted controls and 56 rejected attacks:

| Version | Field | Certificates | Accepted | Rejected | Complete proof byte range |
| --- | --- | --- | --- | --- | --- |
| 10 | BabyBear6 | 15 | 1 | 14 | 15,446,985–15,459,153 |
| 10 | Goldilocks3 | 15 | 1 | 14 | 11,223,550–11,242,110 |
| 11 | BabyBear6 | 15 | 1 | 14 | 14,743,710–14,755,746 |
| 11 | Goldilocks3 | 15 | 1 | 14 | 10,268,335–10,286,511 |

Every certificate is decoded, strictly replayed and checked by production, with
all unrelated reported obligations true and both end-of-proof transcript checks
matching. The coverage validator checks all 60 keys in each backend's record set,
including exact failure stages. Nine altered-record exercises reject, as does
a log containing all otherwise valid records but a failed Rust test completion.
The locked workspace check passes.

The manual run used eight Rayon threads and 24 test workers on the available
24-CPU host, finishing in 571.47 seconds. This is audit throughput, not a PBS
latency comparison. Existing independent masked manual cases were not rerun;
their names, fixture order and parameter factories remain unchanged through the
common helper. All production Rust files remain byte-identical to the baseline;
the only changed Rust file is the existing test-only audit module. Executed and
final code/lock snapshots agree exactly, with documentation-only final changes.
Per-certificate proof hashes, transcript fingerprints and production errors are
in `checked-joint-records.json` and `checked-brakedown-records.json` beside the
immutable raw logs and frozen executable.
