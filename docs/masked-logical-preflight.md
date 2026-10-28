# Logical-half masked preflight

The bounded-mask source pairs data and mask lanes and appends one high
coefficient variable. Its fixed final query is `(I, 0)`. Preflight now reads
only the low coefficient half and evaluates it under the original unpadded
query, instead of folding both halves and discarding the high contribution last.

For each lane polynomial write `P(X) = L(X) + X^m H(X)`, with m a power of two.
Every low-bit matrix fold operates independently within the two coefficient
blocks, preserving their order. After the original log2(m) folds the remaining
polynomial has two vector coefficients, the responses from L and H. The final
`(I, 0)` fold selects the former. This identity holds for arbitrary extension
coefficients and noncommuting matrices; it does not commute or merge queries.

The source, high padding, masks, randomness consumption, combined polynomial,
encoded values, authentication, proximity proofs and verifier remain unchanged.
Only private preflight response evaluation omits work known to have zero weight.
False data claims still reject before mask response, transcript mutation or
lifetime expenditure. The public statement and padded proof query are unchanged.

Each borrowed first-fold buffer now has S/8 field elements instead of S/4 for a
paired source of S elements. Data and mask preflight read half as many source
coefficients and perform one fewer fold. Later proof construction still handles
the complete padded source; this does not remove the original memory and
security requirements.

Regression tests compare each optimized response against the old full-source,
full-padded-query evaluation for full BabyBear6 and Goldilocks3 coefficients.
They also independently replace every high-padding coordinate and confirm both
responses remain unchanged, while checking retained-source immutability and
zero allowance expenditure. The ordinary masked rejection tests remain active.

Frozen executables, source snapshots, phase timings, exact proof/transcript hash
comparisons and GNU time peak RSS reports live under
`target/performance/masked-logical-preflight/`. Deterministic public mask seeds
are test controls. These component profiles do not establish original-size,
security-matched complete PBS performance or close any whole-proof security,
hiding, joint aggregation or promotion gate.

## Validation and component timing

`cargo test --release --locked -p pcs --lib`: 55 passed. Serial frozen-executable
runs use eight Rayon threads, logical dimension 12, physical dimension 16,
one query and budget two. Each proving time is the median of two reused
openings. Order 0 runs baseline then changed; order 1 reverses that order.
The baseline includes the previous borrowed-source preflight. GNU time records
whole-process peak RSS across commitment and both openings.

| Field | Order | Baseline prove (s) | Changed prove (s) | Reduction | Baseline peak (KiB) | Changed peak (KiB) |
| --- | --- | --- | --- | --- | --- | --- |
| babybear | 0 | 2.3144 | 1.8757 | 19.0% | 343020 | 342732 |
| babybear | 1 | 2.2241 | 2.0095 | 9.6% | 342504 | 342716 |
| goldilocks | 0 | 0.6526 | 0.7603 | -16.5% | 194880 | 195204 |
| goldilocks | 1 | 0.8933 | 0.6944 | 22.3% | 194668 | 195024 |

BabyBear component proving improves in both orders. Goldilocks results are mixed,
so no repeatable Goldilocks proving speedup is established. Process peak RSS is
essentially unchanged: reducing preflight scratch does not reduce the later
full-source proof construction peak. The prior memory reduction is retained.

Every non-timing record matches exactly across all runs, including parameter,
root, randomness-consumption, query, complete proof and final transcript hashes.
Proof sizes remain 46,352 bytes (BabyBear) and 34,934 bytes (Goldilocks). These
one-query component measurements do not meet the scope of complete PBS or
security-matched original-size promotion requirements.
