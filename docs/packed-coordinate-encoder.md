# Packed extension-coordinate encoding

Packed authenticated and masked PolyFRIM parameters can select the existing
coordinate-wise base-field FFT encoder with `with_base_field_encoder::<Base>()`.
The matrix-weighted Base-to-extension masked adapter selects it by default.
Generic packed parameters keep their generic extension-field encoder by default.

For a domain root in Base, both the coset twist and every FFT twiddle are in
Base. Extension coordinates therefore transform independently. Selection checks
that the root belongs to Base. The selected function is omitted from serialized
parameters; the domain, degree, queries, masking budget and transcript context
are unchanged. The choice propagates to paired data/mask source lanes and every
folded ladder. Encoded field values are canonicalized before Merkle hashing.
This reuses the existing scalar coordinate encoder without adding concurrent
lane scratch allocations.

The deterministic `masked_packed_profile` example records fixture, parameters,
root fingerprint, query, proof and final transcript hashes, randomness consumption,
opening counters, proof size and separate commit/prove/serialize/verify times.
Its public seed and masks are benchmark controls only. It decodes each proof and
runs the public verifier. The JSON `root` field is SHA-256 of the root bytes.

Frozen before/after executables and source snapshots live under
`target/performance/packed-coordinate-encoder/`. Small controls for BabyBear6
(width 8) and Goldilocks3 (width 4), logical dimension 4, physical dimension 12,
one query and a two-opening budget have identical non-timing records across
both openings. Regression tests additionally compare complete masked proofs
with every extension coordinate populated and cross-verify each arithmetic
choice under the other parameters.

## Validation and component timing

`cargo test --release --locked -p pcs --lib`: 53 passed. Serial frozen-executable
runs use `RAYON_NUM_THREADS=8`, logical dimension 12, physical dimension 16,
one query and budget two. Each row reports the median of two sequential reused
openings; order 0 is baseline then optimized, order 1 reverses that order.

| Field | Order | Baseline prove (s) | Optimized prove (s) | Reduction | Baseline commit (s) | Optimized commit (s) |
| --- | --- | --- | --- | --- | --- | --- |
| babybear | 0 | 3.4698 | 2.9094 | 16.2% | 2.3032 | 0.8885 |
| babybear | 1 | 3.4246 | 2.7535 | 19.6% | 2.2892 | 0.8910 |
| goldilocks | 0 | 0.8853 | 0.9054 | -2.3% | 0.6673 | 0.3170 |
| goldilocks | 1 | 1.1354 | 0.8704 | 23.3% | 0.6677 | 0.3112 |

All non-timing records match across all four runs per field. Proof sizes remain
46,352 bytes for BabyBear and 34,934 bytes for Goldilocks. Goldilocks proving
results are mixed, so these runs establish no repeatable Goldilocks proving
speedup. Commitment improves in both orders in both fields. These small synthetic
one-query profiles do not establish security-matched complete PBS performance.
Raw logs and `timing-summary.json` retain each opening and separate phase times.

This is an arithmetic optimization. It does not provide joint aggregation,
robust vector proximity, a whole-proof knowledge or zero-knowledge theorem, or
original-size security-matched complete PBS timing. All original promotion
gates in `implementation-status.md` remain open.
