# Packed NTT component

`snarks::packed_ntt` authenticates coefficient/NTT consistency against two
canonical matrix-weighted commitments. It handles the native bit-reversed NTT
order and uses the same relation for inverse transforms by reversing the source
roles. It is a component, not a complete PBS verifier.

The scalar table layout is consecutive polynomial blocks, each with N
coefficients. The packing width k and N must be powers of two, k <= N. Polynomial
rows include any zero-padding blocks. The native NTT root, field, dimensions,
row-code parameter digests and both roots are bound before challenges.

For each of k independent random points in log2(m) row variables, the prover
folds m source polynomials using scalar Boolean-MLE weights. All k folded
coefficient and NTT vectors are bound before coefficient-compression challenges.
The verifier checks their local NTTs. Ordered matrix queries compress the low
coefficient variables; scalar identity matrices fold the high row variables.
The resulting evaluations are authenticated against the canonical roots.

This is a tensor-row variant of Appendix H.1 of the small-prime-fields paper,
not its dense random-row construction. For a fixed nonzero row residual, the
row-test error is at most (log2(m)/p)^k (zero when m=1), rather than p^-k.
A conservative additional compression error is at most
2k * log2(N/k) * ((2k-1)/p)^k, before adding commitment errors. A complete
Fiat-Shamir and composed PBS budget remains outstanding.

The v2 transcript uses `Parameters::open_many` separately for each canonical
root. One random linear test and one set of whole-symbol authenticated columns
serve all points. Identical left matrix prefixes share their structured
response; all suffix evaluations are checked. When the PCS split lies within
the coefficient variables, all k row challenges share that prefix. Soundness
accounting must count the number of distinct structured responses plus the
random response per root, and all required lane/check events. Shared columns
are not independent repetitions.

`packed_relation::coefficients_from_sum_hadamard` preserves the exact factor
order used by the native Hadamard extractor: duplicated bit factors, concatenated
RLWE halves, then concatenated sum-product halves. These coefficient factors
are NTT sources; coefficient multiplication is convolution, so they are not
asserted to satisfy the pointwise Hadamard identity.

Run the native component integration with:

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --with-ntt
# Original FHE parameter sizes:
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --with-ntt
```

The public ciphertext tuple in that example is transcript context. Public
endpoint, key, digit-range and accumulator relations still need implementation.

## Validation recorded in this implementation

The original-parameter example with seed 42 passes with 16 Rayon threads.
Its 17 NTT link proofs and coefficient commitments add 126,369,724 bytes to
62,535,404 bytes for the existing Hadamard proof/roots: 188,905,128 bytes total.
Coefficient commits plus NTT proving and verification take 2.451 s in one smoke
run; full process wall time is 4.45 s and peak RSS is 1,405,340 KiB. These are
component smoke measurements, not repeated full-PBS promotion results.
Logs are under `target/performance/packed-ntt/`.

The validation run passes 69 Rust tests across algebra, PCS and SNARK libraries
and integration tests, plus four Python tool tests. NTT cases cover BabyBear and
Goldilocks, single/multiple polynomial rows, k=N, malformed shapes, invalid
transforms, and forged folded vectors recomputed to remain locally consistent.
Batch openings cover duplicate points, shared/distinct prefixes, every claimed
value, malformed response counts, column authentication and serialization.
The public prefix indicator is compared to exhaustive materialized masks for
small noncommuting matrix queries and checked on a virtual 2^40-cell domain.
