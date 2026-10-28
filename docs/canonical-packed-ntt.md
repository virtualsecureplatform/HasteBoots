# Canonical packed NTT authentication

`packed_ntt::prove_canonical` and `verify_canonical` authenticate the existing
packed tensor-row NTT relation through `CanonicalPcs`. Coefficient and evaluation
roles use their original expected commitments and retained tables. Logical shape,
transform size, base-field root, complete contexts and both ordered commitments
are fixed before the row challenges. Physical masked padding does not change the
NTT polynomial size or logical table dimensions.

`Shape::new_canonical` uses the same shape calculation as the legacy constructor.
It rejects a polynomial larger than the logical table even if the masked physical
capacity is larger. The row-fold, compression and source-query matrix algorithms
are shared. The backend opens all expected compression queries on both sources.
Each masked root spends one allowance per row repetition; no masks are refreshed.

The existing Brakedown `prove`/`verify` entry points and `Proof<F,O>` packet layout
remain available through wrappers over the shared implementation. A frozen direct
reference from `624adca` checks complete bytes and final prover/verifier challenges
for both fields across four shapes, including empty compression queries and
multiple polynomial blocks. Brakedown retains its v2 transcript domain.

The masked backend uses its own v2 NTT domain, canonicalizes both disclosed folded
polynomial lists before binding, and rejects noncanonical encoded fold entries.
Its trusted physical capacities may differ on the coefficient and evaluation
sides while their logical shapes agree. It uses direct extension challenges only
inside source authentication; the tensor-row and compression protocol remains the
original base-field relation.

## Validation

Eight legacy wire/transcript controls pass. The masked tests serialize, decode
and verify forward and inverse-derived NTT cases over BabyBear/sextic and
Goldilocks/cubic challenges. They check source counters, root-role swaps, changed
shapes, mutated folds, omitted child openings and equal-value noncanonical
Goldilocks fold encodings.

Two fresh false-transform certificates commit a correct coefficient word and an
incorrect evaluation word. With one polynomial, the declared row folds are the
actual committed words. All four source openings per certificate are generated
fresh and pass independent strict replay against the actual roots and claims.
The production verifier rejects the local NTT identity, rather than relying on
corrupted paths or a replayed honest transcript.

The folded-polynomial vectors remain public as in the existing NTT relation.
Selecting a masked PCS changes their authentication and does not hide the NTT
algebra itself. These small component cases are not native complete-PBS or
security-matched performance measurements. Polynomial-relation authentication,
key/setup ownership and multi-root Hadamard operations still need their remaining
backend generalization. General hiding, composed soundness and adaptive
Fiat–Shamir security remain open.

All 90 selected release/locked regressions pass: 78 SNARK component tests and
twelve complete v7/v8/v9 PBS integration tests. All sixty fresh full binding
certificates retain their expected outcomes (six controls accepted, fifty-four
attacks rejected). The locked workspace check also passes. These checks preserve
the existing complete formats; they do not add a masked complete-PBS format.

Logs, eight exact-wire records, four decoded masked transform records, two fresh
false-transform records and validated sources are under
`target/performance/canonical-packed-ntt-boundary/`, source SHA-256
`bcda934db53c7c38220781ff8c645840d4851d30f6361adcbdd22d92c8766ad7`.
