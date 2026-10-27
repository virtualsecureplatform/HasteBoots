# Lane lookup batching experiment

The reference scalar/tuple lookup components instantiate one packed algebraic
proof per rational challenge. Original-size measurements show this is too
expensive. `snarks::packed_lane_lookup` now packs independent challenge pairs
into helper lanes while keeping original source commitments. The implementation
is experimental: tests and a separate helper/source interactive budget exist;
complete-PBS performance and security promotion remain outstanding.

Let the original width k be a power of two and a canonical source table have
mu Boolean variables: its flattened scalar index is k*b+l. For each group of k
independent tuple-hash/reciprocal pairs (Y_r,r_r), form a helper table with
mu+log2(k) variables. A helper cell indexes one original scalar entry; its k
lanes index the independent challenge pairs. Prove the k reciprocal sums at
once with packed sumcheck and prove the pointwise reciprocal identities with
one packed ZeroCheck. Two groups supply the native 16 pairs at k=8. Do not
replace the 16 rational repetitions by only 8 without recomputing their error.

Original source a becomes the virtual broadcast table
`A[k*b+l][r] = a[b][l]`. No broadcast-view root is needed. To authenticate A at
an ordered matrix query Q, let t=log2(k) and construct a k-by-k matrix C whose
column l is `Q[t-1][l[t-1]] ... Q[0][l[0]] * ones_k`.
Then `eval(A,Q) = sum_b W_Qhigh(b) * C * a[b]`.
For mu>0 this is one ordinary canonical MW query: take the high pairs Q[t..]
and right-multiply BOTH matrices in its first pair by C. Subsequent matrices
are unchanged. Matrix order matters; C must be on the right. For mu=0, open
the constant canonical lane vector and apply C locally. Brute-force tests
against explicit broadcasts, with dense noncommuting matrices, must establish
this mapping before protocol integration.

The helper identity for tuple columns is
`f * (R + sum_j Y^j * A_j) = ones`, with public lane-constant R and Y^j factors.
For the full padded native domain no active mask is necessary: zeros are part
of the intended digit domain, and (0,0,0) is a valid comparison tuple. This
identity is cubic for j>0. Public lane-constant factors have MW evaluations
obtained by applying successive (Q0+Q1) matrices, with no full table at the
verifier. For a partial active scalar domain add the public cell-prefix mask;
its extra factor raises the degree, which must be included in the budget.
Mask zero forces helper zero because all R lane entries are nonzero; verify
that the packed polynomial itself enforces this before relying on it.

Tuple multiplicities and original roots remain bound before every independent
(Y,r) pair. Helper roots precede algebraic challenges. The s lane claims must
each agree with the table rational sum for their own challenges. For nonmultiple
repetition counts, the implementation samples a full final group and exposes
the actual amplification through `effective_repetitions`; there are no
duplicated filler challenges.

Expected advantage: fewer helper roots and PCS query batches, and far fewer
original-source openings. Helper scalar data still totals s*N, so reduction
in arithmetic is not automatic. Measure commit, polynomial, folding and
opening costs and proof bytes independently. The Brakedown layout optimizer
must account for the actual number of structured responses rather than use
its current single-opening estimate. Preserve the unbatched implementation
as a direct reference until transcript, mapping, tampering and native proof
comparisons establish the new construction.

## API and current verification

`packed_lane_lookup::prove/verify` take the trusted tuple configuration, explicit
helper parameters and the original canonical source oracles. The source width k
must be a power of two; helper parameters use mu+log2(k) variables and width k, with at least one
Boolean variable for ZeroCheck.
The source and helper row codes can have different layouts and domain lengths.
`packed_decomposition::prove_lanes/verify_lanes` reuse the same borrow/reconstruction
logic as the original backend and bind the helper parameter digest before checks.
The original `prove/verify` API and unbatched comparison backend remain available.

Full active domains use the at-most-cubic identity above, without multiplying source
terms by a mask. Partial active domains use the at-most-quartic mask identity, including
its higher interpolation degree. Lane-constant public factors are evaluated by
successive `(M0+M1)` matrices. Their evaluations and prefix masks are derived by
the verifier, rather than supplied in the proof.

Tests compare broadcast pullbacks to explicit tables over BabyBear and
Goldilocks, including zero-variable sources, k=1, dense noncommuting matrices and
an explicit wrong-order counterexample. Lookup tests independently reconstruct
helper roots by per-entry division, exercise both full and partial domains and
nonmultiple repetition counts, and reject altered original-column values,
helper data, counts, parameter digests and lane sums that preserve their scalar
total. The native canonical example selects this backend with `--lane-lookups`.

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --lane-lookups
python3 tools/packed_budget.py --lane-decomposition-component target/performance/lane-batching/full.log
```

The lane budget counts grouped sumchecks/ZeroChecks, the effective rational
repetitions, distinct helper/source proximity response events and random tests
at their own block-RS lengths, plus reconstruction and endpoint checks. It is
an experimental interactive component estimate, not a whole-PBS security claim.

## Original-size result

The seed-42, 16-thread release smoke passes at original BabyBear FHE sizes.
Canonical decomposition now adds 376,277,702 bytes, versus 1,162,351,774 for
independent repetitions: a 67.6% reduction. Its preparation, proving,
verification and serialization take 53.253 s, versus the earlier 66.693 s smoke
(20.1% lower). Combined Hadamard/NTT/decomposition bytes are 561,090,872. Process
wall time is 59.45 s, peak RSS 4,780,400 KiB. These are single component smoke
comparisons; full-PBS semantics and repeated promotion measurements are pending.

The source layout uses 4096 message blocks and 8192 encoded blocks; helpers use
8192 message blocks and 16384 encoded blocks. Both use 544 column draws. The
helper random linear-test contribution dominates the conservative interactive
component budget, whose total is 3.2428e-40. It remains below 2^-128, but the
higher helper-domain error demonstrates why reusing the smaller source-domain
budget would have been wrong. Whole-PBS and Fiat-Shamir analysis remain open.

The broader five-crate run passes 116 Rust tests. An additional focused inactive
pole/mask regression passes, as do seven Python tool tests. Logs, budget JSON,
source/binary hashes and the saved release binary are under
`target/performance/lane-batching/`. The independent backend remains available
for correctness and performance comparisons.

Latency is still far from promotion. The next measured kernel study should
separate reciprocal/helper commitment, ZeroCheck rounds/folding, original-source
openings and serialization costs. Public lane-constant R/Y/mask factors are
currently materialized and recomputed across cells; hoisting them may help, but
must preserve the exact factor polynomial and matrix order. Compare optimized
rounds to an independent direct reference, including Goldilocks lazy field
representations, before relying on a transcript or serialization equivalence.

The subsequent measured constant-factor kernels reduce this component further
to 46.069 s and 45.226 s in paired profile sessions, with unchanged bytes and
parameters. See `lookup-profiling.md` for phase costs, independent references and
scope limits. Complete PBS relations and promotion remain unfinished.
