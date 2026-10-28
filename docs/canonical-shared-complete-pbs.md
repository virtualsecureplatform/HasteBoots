# Complete canonical PBS with shared comparisons (version 11)

`packed_pbs::canonical::shared` composes every binary NAND PBS stage with shared
canonical radix comparisons in both blind-rotation halves and final key
switching. It is a separate proof type, version and parent transcript domain.
The existing `canonical::Proof`, `prove`, `verify` and version-10 framing remain
available with per-limb comparisons.

One internal implementation dispatches through private static stage types. The
caller chooses the version-10 or version-11 entry point; serialized proof flags
cannot select a comparison implementation. Each verifier checks its expected
version before child verification. The new parent binds version 11, extension
degree, trusted native key descriptors, all seventeen parameter contexts,
complete input/output ciphertexts, original blind-rotation source roots and the
shared final accumulator before its child challenges.

Witness preparation, original-source NTTs, authenticated native-key products,
accumulator initial/final endpoints, additions, continuity, duplicated digit
views and public monomial rotations use the existing equations. Each shared
radix proof retains separate reconstruction and zero-borrow identities, every
limb's transition table and independent compression repetitions. Final key
switching retains the caller-derived known-input check, original key products,
canonical negative-mask digits and original output-key extraction. Verification
needs only trusted setup/PCS parameters and public ciphertexts.

No replacement source view, compressed digit root or untrusted trace key column
is introduced. Private states retain their original mask sessions across all
children. Shared comparisons use one query per used digit/borrow root and one
opening per reciprocal helper. A later failure does not refund earlier openings.
Helper memory grows with the grouped limbs/repetitions; native-size resource
behavior still requires measurement and potentially bounded helper groups.

`canonical_shared_inventory` counts declared version-11 root slots after full
verification. Reciprocal helper root counts remain unchanged even though their
query counts fall. As with the version-10 inventory, these slots exclude key
roots and internal PCS trees and are not a proof-security bound.

## Validation and remaining gates

Ordinary Brakedown controls serialize, decode and verify all four NAND inputs
over BabyBear/sextic and Goldilocks/cubic. Decryption checks the NAND truth table
under the same original output key. Frozen complete version-10 proof hashes over
both fields must remain byte-identical after static stage dispatch refactoring.

The masked comparison uses encrypted input 1/1, the original five-bit switching
radix, one comparison repetition and the same trusted role parameters, native
key roots, statement and native trace for both versions. Private coefficient,
evaluation and helper sessions are committed separately by each prover. Each
retained native key owner spends one opening for version 11 and a second for
version 10. Both complete certificates verify publicly after decoding.

Tests reject version relabeling, missing source/stage roots, changed endpoints,
missing NTT/decomposition children, changed products or shared helper terminals,
changed known-input roots, changed monomial children, changed extraction and
wrong public input/output ciphertext components. These are compatibility and
tamper controls. Fresh complete version-11 binding certificates now provide
separate evidence; see `canonical-v11-fresh-binding-audit.md`. Other adversarial
classes, secure encrypted/original-size cases and independent review remain open.

The fixtures use ring dimension 32, LWE dimension 21 and one proximity query for
completeness. They are not original-size or 128-bit profiles. Public linear,
NTT, multiplicity and sumcheck algebra remains non-hiding. Genuine 1/4/16 joint
aggregation, robust vector proximity, adaptive hiding, knowledge/Fiat-Shamir
composition, original-size matched-security bytes/latency, independent review
and promotion remain open. Sharing within a single PBS is not cross-statement
aggregation, and a smaller small-fixture proof does not establish the original
complete latency gate.

The evidence directory is `target/performance/complete-canonical-shared-pbs-v11/`,
including pre-refactor sources, frozen wire records, checked decoded certificate
records, release/locked logs and the validated final source snapshot.

The matched-parameter small complete-proof comparisons produce:

| Field | Version-10 children | Version-11 children | Version-10 bytes | Version-11 bytes |
| --- | ---: | ---: | ---: | ---: |
| BabyBear/sextic | 468 | 441 | 17,552,895 | 16,771,685 |
| Goldilocks/cubic | 554 | 499 | 12,523,853 | 11,444,568 |

The four decoded masked certificates authenticate 1,962 child PCS openings.
Both versions retain 76/132 declared root slots in these fixtures. Ordinary
truth tables contribute eight decoded complete certificates per version, and
two additional version-10 certificates enforce the frozen complete wire hashes:
22 complete encrypted-fixture certificates overall, including ten version-11
certificates. These are completeness/compatibility results, not a matched-security
latency claim.

Validation passes 78 default release/locked SNARK unit tests, nine sumcheck
tests, two version-10 truth-table tests, two frozen complete wire tests, two
version-11 truth-table tests and two masked complete comparison tests: 95 unique
tests. The existing version-10 masked integration target also builds, and the
locked workspace check passes. The 30 expensive version-10 algebraic audits
remain opt-in. A later fresh version-11 binding audit is documented separately.
