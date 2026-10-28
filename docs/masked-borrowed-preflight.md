# Borrowed masked opening preflight

Masked PolyFRIM preflight now evaluates each data/mask lane group directly from
the retained paired source. The first fold reads the two selected lane vectors
from each adjacent cell pair and allocates only the folded polynomial. Later
folds use the existing polynomial routine. The original source stays immutable.
The combined polynomial is also built directly from retained paired cells.

Previously each opening materialized both full lane polynomials, cloned each
for preflight evaluation, and retained the split copies while constructing the
combined source. If the paired source contains S field elements, this removes
S elements of persistent split buffers and S elements of full-input clone traffic
per opening. A selected first-fold result has S/4 elements; its further folds
are unchanged. These counts describe source-level allocations, not a measured
whole-process peak-memory bound. Encoded source values and Merkle trees remain.

Data claims still reject before mask-response computation, transcript mutation
or lifetime expenditure. The source context, canonical public inputs, first-fold
matrix order, canonical mask response, lifetime increment and transcript binding
retain their existing order. No verifier, parameter or proof format changes.

Regression tests compare both borrowed lane responses with the independently
split-polynomial route over full extension coefficients, check retained source
immutability and verify that preflight spends no allowance. Existing masked
round trips, exhaustion, failed-preflight and fresh false-transition tests remain.
Frozen executable comparisons, source archives, raw phase timings and GNU time
peak RSS reports are retained under
`target/performance/masked-borrowed-preflight/`.

This changes prover memory traffic only. Synthetic component profiles with public
test seeds are not original-size security-matched complete PBS measurements.
The complete security, hiding, joint aggregation and promotion gates remain open.

## Validation and measured tradeoff

`cargo test --release --locked -p pcs --lib`: all 55 tests pass. Frozen baseline
and changed executables run serially in both orders with eight Rayon threads,
logical dimension 12, physical dimension 16, one query and budget two. Each
proving time is the median of two reused openings. GNU time measures whole-process
peak RSS, including source commitment and both openings. Order 0 runs baseline
first; order 1 reverses it. The baseline includes the prior two-product fold.

| Field | Order | Baseline prove (s) | Borrowed prove (s) | Baseline peak (KiB) | Borrowed peak (KiB) |
| --- | --- | --- | --- | --- | --- |
| babybear | 0 | 2.1757 | 2.2461 | 392384 | 342656 |
| babybear | 1 | 2.2158 | 2.3140 | 392068 | 342600 |
| goldilocks | 0 | 0.6509 | 0.6331 | 219816 | 194952 |
| goldilocks | 1 | 0.6937 | 0.6455 | 219596 | 194924 |

Peak RSS falls 12.6–12.7% for BabyBear and 11.2–11.3% for Goldilocks. BabyBear
proving is 3.2–4.4% slower in these runs; Goldilocks is 2.7–6.9% faster. This is a
measured memory/latency tradeoff, not a general proving-speed improvement. Native
resource validation must retain both metrics. Commitment and verifier algorithms
are unchanged.

Every non-timing record matches exactly across all runs: parameters, roots,
randomness consumption, complete proof hashes, transcript hashes, and proof sizes
(46,352 bytes BabyBear; 34,934 bytes Goldilocks). `resource-summary.json` includes
both timing and peak RSS, and the raw GNU time logs retain the measurements.
