# Common-query multi-root PCS aggregation

`pcs::matrix_weighted::aggregate` is an experimental, non-hiding aggregation
component for several committed tables with the same trusted PCS geometry and
one common ordered matrix query. It combines responses, rather than wrapping
independent proofs. Every source root and individual claimed vector remains
public and bound. It does not yet aggregate complete PBS proofs: their algebraic
checks must first produce common queries under a joint transcript.

## Protocol and implementation

For r roots and extension field E of degree d over F:

1. Bind the parameter digest, E's degree and basis multiplication products, all
   ordered roots, the common query and all individual Base-field claimed vectors.
2. Sample r independent E weights alpha by drawing all r*d Base coefficients.
   The measured caller uses the direct canonical Base transcript. The protocol
   does not expand a single short seed into these weights.
3. Draw the ordinary k-row Base random linear test on the concatenation of all
   source row matrices. Supply one joint Base test response. Separately compute
   each source's structured response S*T_i and supply only their scalar E sum
   `sum_i alpha_i*(S*T_i)`.
4. Bind both responses, then sample Q columns with replacement using the existing
   unbiased sampler. Deduplicate only after all accepted draws. Supply genuine
   column values and paths for **every** root at those common indices.
5. Verify authentication for every source. Check the joint random-response
   equations and the weighted structured-response equations on each block
   coordinate. Encode E responses coordinatewise through the trusted Base code.
   Finish each E coordinate with the original ordered Base query and compare
   with `sum_i alpha_i*claim_i`.

The implementation applies scalar extension weights after Base matrix response
calculation. It does not replace lane matrices with extension multiplication
matrices or reorder noncommuting operators. Both encoding and the suffix finish
are extended coefficientwise: Base linear maps commute with scalar E weights.
There is no assumption that E embeds into the block-RS symbol field; BabyBear's
outer degree six and symbol width eight are intentionally distinct.

Verification parallelizes the independent sampled-column checks. No transcript
messages are produced inside the parallel section. The original single-root
and single-root/many-query APIs, full-PBS protocols and their wire types remain
unchanged. The new proof has one Base response, one E response and a root-major
array of authenticated columns. There is no unauthenticated combined root.

## Conditional evaluation-soundness argument for review

This is a new proposed argument, not a reviewed full cryptographic theorem.
Assume each root determines an available word before alpha, all successful
column answers match that word, and transcript coins are ideal independent
interactive randomness. For the unpadded block-RS setting let k be both packing
and symbol width, n the encoded length in blocks, M the message length in
blocks, D=n-M+1 and t=floor((D-1)/3). Use the fixed-word RS argument in
`block-rs.md` on **all r source row matrices concatenated together**.

If the concatenated word has no common nearby source outside t column errors,
the joint Base random test lifts to a uniform symbol-field random combination
of all rows. Except with probability n(n+1)/|F|^k, its distance from every
codeword exceeds t. Any supplied coded response therefore disagrees on at
least t+1 columns. This reasoning does not treat roots as independent draws.

Otherwise a unique nearby decoded source exists for every row, with one common
error support of size at most t. The true common-query value of each source is
fixed before alpha. If any individual claim is false, at least one component of
the claim-error vectors is nonzero. A uniform E linear combination cancels that
component with probability at most 1/|E|, since all claims precede alpha. Outside
that event, the supplied structured response must differ from the correct
weighted decoded response (or fail the final finish check). At least one of its
Base coefficient codewords differs, giving at least D-t column disagreements
with the actual words. No field embedding is needed for this distance step.

Both messages precede column sampling. The near and far cases are disjoint;
shared columns can use the corresponding fixed mismatch set. A conservative
per-group upper bound is consequently

```text
n(n+1)/|F|^k + 1/|E| + (1-(t+1)/n)^Q.
```

This does not multiply the algebraic bound by r: the random test handles the
concatenated matrix and alpha handles the entire vector of fixed claims. Hash
availability/binding accounting still depends on all r roots. The statement is
conditional on the RS derivation and Merkle extraction assumptions, uses the
actual unpadded code geometry, and does not prove knowledge soundness, hiding,
Fiat-Shamir security or full-PBS composition. Existing full-PBS budget formulas
are deliberately unchanged.

## Validation and remaining integration

Tests cover decoded positive proofs for 1/4/16 distinct tables over BabyBear
with E degree six and Goldilocks with E degree three. Dense query matrices
explicitly fail to commute. Negative controls alter claims, query order, root
order, responses, column values, path lengths and root counts. Prover and
verifier post-proof transcript challenges match.

Fresh malicious proofs bind the requested false claims before sampling alpha,
then construct false response messages and genuine paths. A coded zero word
with a false claim has a response that passes the final claimed-value equation
but fails the authenticated column equation. A far half-zero/half-one word
with an identically zero structured query also fails the production equation,
isolating the joint random test. Both fields pass both cases, and transcript
states match after rejection. These are stronger controls than replaying an
honest proof under a changed transcript.

The next frontend work must bind the complete batch of PBS statements, roots
and key/endpoints before joint algebraic challenges, arrange compatible common
queries, then discharge terminal claims through this API. Independent proof
groups and this PCS component alone do not supply that full aggregation. Public
setup reuse, original FHE/key semantics, complete-protocol soundness, hiding,
security-matched benchmarking and promotion gates remain in scope.

## Component measurements

The release example `matrix_weighted_aggregate` compares decoded aggregate
packets with decoded vectors of ordinary single-root openings for the exact
same roots, common dense noncommuting query and individual claims. Source data
is synthetic. `--full` selects the complete prover's source geometry: BabyBear
nvars=18,width=8,left=3 and Goldilocks nvars=19,width=4,left=4. Both have 2^21
Base scalars per table and Q544. Preparation commits all sixteen tables and
computes claims before timing. The reported `complete_ns` is **opening plus
serialization only**, excluding commitment/setup and verification; it is not a
complete NAND/PBS time. Both modes have the same query count, not a reviewed
whole-security match.

Two 16-thread sessions reverse both mode order and field order. The final
parallel-verifier results for sixteen roots are:

| Field | Aggregate bytes | Independent bytes | Aggregate opening+serialization | Independent opening+serialization |
|---|---:|---:|---:|---:|
| BabyBear, session 0 | 34,930,423 | 67,339,647 | 163.69 ms | 274.03 ms |
| BabyBear, session 1 | 34,930,423 | 67,339,647 | 160.57 ms | 263.93 ms |
| Goldilocks, session 0 | 28,848,827 | 61,605,861 | 101.09 ms | 192.07 ms |
| Goldilocks, session 1 | 28,848,827 | 61,605,861 | 131.28 ms | 190.03 ms |

This is 48.1% / 53.2% fewer bytes and measured opening+serialization reductions
of 39.2–40.3% / 30.9–47.4%. Aggregate verification takes 91.41/91.35 ms versus
216.16/218.11 ms for BabyBear, and 60.24/56.05 ms versus 307.45/224.31 ms for
Goldilocks. These are two-session component observations, not confidence
intervals or a full-PBS speedup claim.

Small groups have different tradeoffs. For one root, BabyBear packets are 2.61x
larger and Goldilocks 1.65x larger than ordinary openings; both are slower.
For four roots, BabyBear saves 6.4% bytes but is slightly slower, while Goldilocks
saves 29.8% bytes and is faster in both sessions. The raw API is consequently
not enabled automatically in the existing complete prover. Its response cost
is one Base plus d Base-coordinate vectors instead of 2r independent vectors;
all r roots' authenticated columns remain necessary.

The first implementation verified columns serially, giving a 5–6x verifier
regression for sixteen roots. That baseline and its exact binary/source remain
under `target/performance/mw-multi-root/`. Parallel column checks fix that
regression without changing any of the 36 packet hashes or statement digests.
Final sources, exact binary, logs/resources, comparisons and validation evidence
are under `target/performance/mw-multi-root-parallel/`. Each run set has 36
serialized packets (twelve toy and twenty-four native-capacity), validating 252
root claims. The two run sets are separate evidence; all corresponding packet
hashes match. All fifteen targeted Rust tests, 79 Python tests and the workspace
check pass. No compile/test workload overlapped either measurement set.

A relation frontend now exists in `packed_relation::aggregate`, described below.
Its ZeroCheck terminal factor openings already share one matrix query. An opt-in
complete Hadamard integration is now described in `packed-aggregate-pbs.md`.
Common challenges across multiple PBS statements, full batch
binding and the security/hiding gates remain incomplete.

## Packed relation frontend

`snarks::packed_relation::aggregate` adds a separate proof type and transcript
domain. It validates trusted geometry and binds the parameter digest, shape,
extension degree and ordered canonical roots before ZeroCheck. It keeps the
ordinary packed ZeroCheck and its individual terminal factor values. After the
algebraic terminal check, it binds all those values and calls the multi-root PCS
with the common returned query. Verification receives only trusted parameters,
shape and roots, checks the ZeroCheck, then checks one aggregate opening.
The state-reference prover supports reuse of states owned by public-key setup
and witness oracles. The original relation API and complete PBS versions 2/3
remain unchanged; callers must explicitly select the new frontend.

Conditional composition adds the ordinary packed ZeroCheck error to the PCS
bound above, provided roots determine fixed words before the ZeroCheck coins.
That assumption now corresponds to the frontend's early root binding. Terminal
values and the query are fixed before the extension weights. This is a proposed
interactive evaluation-soundness argument, not a new full security certificate;
full-PBS budget formulas and promotion labels have not changed.

Two new roundtrip tests cover eighteen sum-of-products fixtures: 1/4/16 products
at lengths 1/7/73 over each field, with padding, decoded verification, state-reference
reuse, exact instrumented/default proof bytes and matching post-proof transcript
states. Controls alter caller provenance, shape, root order, claims and opening
data. Both legacy relation tests still pass.

Two additional tests build fresh fake-factor certificates under the requested
actual roots. The actual tables are a=b=1,c=0, violating a*b-c=0 on every row;
the prover runs valid ZeroCheck algebra on fake a=b=c=1 factors. It constructs
fresh aggregate responses after binding the requested roots and false terminal
claims, with genuine authentication paths for the actual tables. The decoded
certificate passes the algebraic setup but fails the production aggregate
linear equations. Prover/verifier transcript states match after rejection.
This tests the algebra-to-commitment link, not just honest-proof replay.

The release example `snarks/examples/packed_aggregate_relation.rs` measures the
whole relation, including ZeroCheck, terminal work, authentication and
serialization, with source commitment preparation and verification separate.
It uses dense synthetic sum-of-products tables at the same source capacity and
Q544 as above. Product groups 1/4/16 mean **3/9/33 factor roots**, not PBS batch
sizes. Two sessions reverse mode and field order. For sixteen products:

| Field | Aggregate bytes | Independent bytes | Aggregate relation+serialization | Independent relation+serialization |
|---|---:|---:|---:|---:|
| BabyBear, session 0 | 61,724,817 | 138,869,899 | 872.88 ms | 1,167.12 ms |
| BabyBear, session 1 | 61,724,817 | 138,869,899 | 901.42 ms | 1,061.00 ms |
| Goldilocks, session 0 | 53,893,256 | 127,026,140 | 585.34 ms | 855.68 ms |
| Goldilocks, session 1 | 53,893,256 | 127,026,140 | 620.06 ms | 801.80 ms |

These give 55.6%/57.6% fewer bytes and measured whole-relation reductions of
15.0–25.2%/22.7–31.6%. Verification takes 130.23/141.75 ms versus
471.18/463.15 ms for BabyBear, and 103.77/110.55 ms versus 440.01/425.08 ms
for Goldilocks. Four-product groups are smaller and faster in both sessions.
One-product BabyBear is larger/slower; one-product Goldilocks has smaller bytes
but mixed timings. These observations do not justify automatic selection for
every small relation or a complete-PBS performance claim. Whole-process peak
RSS is roughly 1.45/2.72 GiB and includes preparation and both modes.

All thirty-six measured relation certificates verify (twelve toy and twenty-four
native-capacity), with stable per-mode wire and statement digests across reversed
sessions. Six targeted Rust tests, 79 Python tests, release build and workspace
check pass. No compilation/tests overlap measurement. Source/binary snapshots,
commands, logs/resources and comparisons are under
`target/performance/aggregate-relation/`. A subsequent complete version-4
Hadamard integration is described in `packed-aggregate-pbs.md`. Cross-statement
aggregation, independent security review, hiding, Fiat-Shamir and
security-matched promotion remain open.
