# Packed coefficient fold products

`Polynomial::fold` computes the same ordered matrix fold using
`M0 * even + M1 * (even + odd)`. Previously it computed the two contributions
of M1 separately. Each coefficient pair now takes two width-by-width
matrix-vector products instead of three, plus one width-sized vector sum.
One width-sized scratch buffer is reused across all pairs. Matrix validation,
constant-polynomial rejection, coefficient order and output shape are unchanged.
The public symbol verifier retains the original independent three-product formula.

This applies to masked preflight responses and authenticated folded ladders.
No protocol parameter, transcript binding, mask allowance, degree or security
assumption changes. Canonicalization at commitment and proof boundaries retains
the existing byte contract.

Tests compare against the original three-product equation for fully populated
BabyBear6 and Goldilocks3 extension coefficients and matrices, widths 1/2/4/8,
and coefficient counts 2/4/32. Existing ordered Boolean-weight and antipodal
symbol audits remain independent checks of the complete fold chain.

Frozen executables, source archives, raw phase timings and exact-record
comparisons are retained under `target/performance/packed-fold-products/`.
The deterministic profile uses public test masks and is not a secure proof
parameter selection. Component timings cannot establish original-size,
security-matched complete PBS latency. The full-plan security, aggregation,
hiding and promotion requirements remain open.

## Validation and timing

`cargo test --release --locked -p pcs --lib`: 55 passed. Timings below use serial
frozen-executable runs, eight Rayon threads, logical dimension 12, physical
dimension 16, one query and a two-opening budget. The baseline already includes
the coordinate-FFT optimization. Each proving time is the median of two reused
openings. Order 0 runs baseline then optimized; order 1 reverses that sequence.

| Field | Order | Baseline prove (s) | Optimized prove (s) | Reduction |
| --- | --- | --- | --- | --- |
| babybear | 0 | 2.8954 | 2.2543 | 22.1% |
| babybear | 1 | 2.7975 | 2.3076 | 17.5% |
| goldilocks | 0 | 0.7291 | 0.6437 | 11.7% |
| goldilocks | 1 | 0.7247 | 0.9165 | -26.5% |

Every non-timing record matches across all runs, including complete proof hashes,
roots, contexts, randomness consumption and final transcripts. Proof sizes stay
46,352 bytes (BabyBear) and 34,934 bytes (Goldilocks). Goldilocks timings are mixed;
no repeatable Goldilocks proving improvement is established. Commitment performs
no folds and stays outside the changed arithmetic. These measurements cover the
PCS component, not complete PBS or security-matched parameter sets.
