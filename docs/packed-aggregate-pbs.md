# Complete PBS with aggregated Hadamard authentication

Complete experimental protocol version 4 replaces only the blind-rotation
Hadamard relation's individual terminal PCS openings with the aggregate relation
frontend. Extension-field canonical comparisons and every other complete PBS
stage, including key-switch product authentication, keep their existing backend.
This aggregates factor authentication within one PBS, not multiple PBS statements.
Versions 2 and 3 and their defaults remain available and unchanged.
Version 5 additionally shares lookup source authentication across canonical
limbs; see `packed-deferred-pbs.md` for its separate API and measurements.

## API and binding

`snarks::packed_pbs::{prove_aggregated,prove_aggregated_with_statistics,
verify_aggregated}` use `AggregatedProof<F,EF,O>`. The full proof has a fourth
generic type for its Hadamard certificate, defaulting to the old relation type.
The explicit aggregate alias selects the new type and extension-comparison
backend. No new canonical source roots are introduced; the root inventory
remains 75 for the selected BabyBear profile and 131 for Goldilocks.

The full public context uses a distinct version-4 domain and includes the trusted
setup, four parameter contexts, original ciphertext statement, canonical roots
and shared final accumulator. Verification rejects the wrong version first.
For Hadamard authentication it calls the same trusted bootstrapping-key root
reconstruction as the old verifier: private evaluation roots are interleaved
with the expected public key roots, followed by the canonical sum root. The
relation shape comes from that trusted key's root count. No combined root or
unlinked witness view is accepted. The remainder of the complete verifier still
checks NTT links, canonical integer decomposition, accumulator continuity,
monomial initialization, modulus/key switching and extraction into the original
LWE key. The verifier takes no native trace or private PCS state.

The example flag is explicit and requires extension comparisons:

```sh
cargo run -p vfhe --release --example packed_extension_pbs_babybear6 -- --full --helper-left-extra 1 --aggregate-hadamard
cargo run -p vfhe --release --example packed_extension_pbs_goldilocks3 -- --full --width 4 --aggregate-hadamard
```

Omitting the flag selects the original version-3 path for those examples.
Metadata identifies version 4, `hadamard_backend=multi-root` and transcript
`merlin-direct-extension-comparisons-aggregated-hadamard-v1`. It continues to
label security experimental/unbudgeted for the whole cryptographic protocol.

## Conditional budget and tests

The Hadamard claim vectors precede the full-coordinate extension aggregation
weights. The proposed interactive argument in `packed-multi-root.md` applies
to their common query. The budget tool conservatively retains the old
per-factor Hadamard PCS terms and adds `1/p^degree` for aggregation cancellation.
It requires equal packing/block widths of at least three and unpadded source
symbols: under those hypotheses the old random-test/tail terms dominate the
proposed concatenated fixed-word RS terms. This does not validate other layouts,
Merkle/Fiat-Shamir extraction, hiding or complete knowledge soundness.

`full_pbs_budget.py` and `validate_full_batches.py` recognize version 4 explicitly;
the latter requires `--aggregate-hadamard` to audit that mode. New tests check the
extra exact rational term, mode binding, geometry restrictions and rejection of
mislabelled validation logs. All 81 Python tests pass. The existing conditional
per-proof / 21-proof profiles still meet their previous numerical thresholds;
those thresholds are not a full security certificate.

All sixteen complete-proof Rust tests pass, including old versions and new
BabyBear degree-six / Goldilocks cubic cases. The new tests cover decoded fresh
1/4/16 groups at test FHE dimensions, all NAND truth cases, state reuse, root
inventory, wrong versions, keys, statements, endpoints and splices. Fresh valid
traces under changed requested input masks or keys reject production equations.
The separate relation frontend's genuine fake-factor/valid-path tests remain
component evidence. A follow-up extends the full malicious-child reconstruction
fixture to version 4, independently rebuilding its aggregate Hadamard transcript
while keeping key-switch products on their original backend. All nine binding
audit tests pass across versions 2/3/4: ninety fresh reconstructed certificates,
nine valid controls and 81 intended rejections. Version 4 contributes twenty
cases (two controls/eighteen rejections) over BabyBear degree six and Goldilocks
cubic fields. Attacks cover requested input masks, output body/mask, wrong blind
and switching keys, initial/final endpoints, chain splices and duplicate witness
views. These are test-dimension composition controls, not a universal soundness
or knowledge proof. Evidence: `target/performance/aggregate-v4-binding-audit/`.

## Native measurements and limits

Two 16-thread native sessions reverse both field and backend order, with two
complete certificates per process and reused public setup. Both modes use the
original ring size 1024, LWE dimensions 728, original output key, unchanged four
PCS layouts, Q544, and the same statements and actual key/parameter digests.
All sixteen native certificates decode and verify. Default version-3 native and
toy proof hashes and sizes match archived fixtures exactly after the generic
backend refactor. Version-4 wire bytes are stable across reuse and sessions;
they are intentionally different from version 3.

| Field/session | Version 3 reused complete time | Version 4 reused complete time | Version 3 bytes | Version 4 bytes |
|---|---:|---:|---:|---:|
| BabyBear 0 | 18.446 s | 18.250 s | 405,612,783 | 378,478,271 |
| BabyBear 1 | 18.444 s | 18.249 s | 405,612,783 | 378,478,271 |
| Goldilocks 0 | 32.049 s | 32.113 s | 614,289,399 | 559,825,723 |
| Goldilocks 1 | 31.947 s | 32.135 s | 614,289,399 | 559,825,723 |

Proof sizes fall 6.69% / 8.87%. BabyBear's measured reused complete time falls
about 1.06% in both sessions; Goldilocks is 0.20% / 0.59% slower. Hadamard proving
itself drops 571.9/564.4→498.3/473.2 ms and 864.7/908.3→728.2/753.1 ms, but
that does not imply a large complete-prover gain. Complete verification is
2,080/2,054→2,147/2,217 ms for BabyBear and
2,955/2,676→2,659/1,891 ms for Goldilocks. These are two-session observations,
not confidence intervals; the flag stays opt-in and there is no promotion.

The runner also verifies eight repeated toy controls and 42 fresh version-4 toy
certificates. All 66 measured certificates verify. The fresh groups are still
independent single-PBS proofs, not an aggregated batch. A subsequent original-size
validation now verifies 42 fresh version-4 proofs, 21 per field in groups 1/4/16.
Every proof uses ring size 1024, LWE dimensions 728, the same original output key
and matched archived parameter/key/statement/layout fixtures. All NAND truth
pairs occur and decrypt correctly; each field reuses one setup. Every root
inventory matches its decoded proof digest and expected count. The combined
42-proof conditional interactive inventory is 129.3243 bits, still not a whole
security certificate. These concurrent correctness runs supply no new timing
claim. Evidence: `target/performance/aggregate-pbs-native-fresh/`.
Both selected release binaries and all workspace examples build/check; no
compilation or tests overlap the earlier serialized native timing.

`target/performance/aggregate-pbs/` preserves exact binaries, build/final source
snapshots and pinned Cargo.lock, commands, raw logs/resources, comparisons,
legacy-wire checks and fresh-toy results. Remaining requirements include full
independent version-4 adversarial composition/security review,
cross-statement aggregation, hiding/direct packed FRI work, concrete
hash/Fiat-Shamir resource analysis and security-matched promotion. A smaller
proof or successful decoded verification does not close those requirements.
