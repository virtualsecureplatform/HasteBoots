# Block-RS matrix-weighted openings

This implements Algorithm 2 and the block-symbol layout of section 4.1 of the
supplied `refs/2025-719.pdf`. It is a non-hiding component, not a complete PBS
proof or a complete security certificate.

## Encoding contract

For an input row of `n` base-field scalars and symbol width `b`, use
`m = next_power_of_two(ceil(n/b))` coefficient blocks. Pad absent coefficients
with zero. Coordinate `c` is the polynomial whose coefficient `j` is the input
at `j*b+c`, or zero outside the input.

Choose `L = max(32, m*blowup)`, with power-of-two blowup at least two. Evaluate
each coordinate polynomial over the same length-L negacyclic NTT domain and
repack coordinate evaluations into L vector symbols. Arithmetic is exclusively
in the base field. The minimum size of 32 follows the concrete NTT backend.
Unsupported domains fail construction before commitment allocation. The
serialized code description binds the actual primitive domain root and modulus,
as well as coefficient and symbol dimensions.

At least one coordinate of a nonzero message is a nonzero polynomial of degree
less than m. It has at most m-1 roots on the L distinct domain points, so the
block-symbol relative distance is at least `(L-m+1)/L`. Using the flattened
base-scalar output length in this formula would be incorrect. Padding only
restricts the message space, so it cannot decrease this lower bound.

`RowCode` makes the symbol width and symbol count explicit. `ScalarRowCode`
preserves access to existing scalar encoders as width-one symbols. The default
block constructor uses the same symbol width as the packed challenge width;
the interface also permits separate widths for controlled experiments.

## Commitment and opening

Reshape a packed Boolean table into a matrix with `(2^left_vars)*k` scalar rows.
Each row's input length is `2^(num_vars-left_vars)`. Encode these rows and hash
each complete column symbol: all b coordinates of every row, in row-major order.
Queries sample symbol indices with replacement. Deduplication occurs after all
Q samples have been consumed, and every coordinate of every distinct queried
symbol is authenticated and checked.

The prover returns two k-row scalar responses: the random linear test and the
structured left-query aggregation. Base-linearity of the encoder allows the
verifier to encode each response and compare its queried symbol with the same
linear combination of authenticated column blocks, coordinate by coordinate.
Query selection follows transcript binding of both responses.

The structured response is finally folded through the right-query matrices.
This computes the same ordered expression as expanding all suffix matrix
weights, but takes O(k² times the number of columns) rather than O(k³ times the
number of columns). Noncommuting matrix order is preserved. Authentication and
column-consistency checks are independent after challenges are fixed and run in
parallel; transcript operations remain sequential.

The layout chooser minimizes an upper estimate of opening payload, including
both responses, whole-symbol openings and authentication paths. It does not
choose a security target. Q remains an explicit independently budgeted parameter.

## Context and validation

The v2 experimental transcript binds the field, shape, layout, repetitions,
encoding convention, serialized code/domain, commitment, query and claimed
value. Prover state retains a parameter digest and rejects mismatched contexts.
The experimental component's v2 openings do not claim compatibility with v1
reference openings. The existing complete artifact PCS is unchanged.

Tests compare encoding to direct polynomial evaluation over BabyBear and
Goldilocks, check base-linearity and zero padding, and reject changes to each
coordinate of an authenticated symbol. Opening tests cover arbitrary matrix
queries, all small row/column splits, serialization, malformed lengths, changed
parameters and partial packed lanes. Component tests exercise actual native
PBS traces as well as vector sizes matching batches of four and sixteen.

The `HB_COMPONENT` record captures the actual m, L, b, k, Q, relation degree and
domain size. `tools/packed_budget.py --component <log>` validates its padding and
NTT dimensions and evaluates the existing conservative interactive algebraic
model with symbol distance. That model still does not establish full PBS
composition, Fiat-Shamir knowledge soundness, or zero knowledge. Those remain
explicit requirements in [implementation-status.md](implementation-status.md).

## Source-to-implementation security audit boundary

The supplied [2025/719 paper](../../refs/2025-719.pdf), Section 4.1 and
Appendix B.2 (Theorems 2/5), derives correctness for ordered structured matrix
openings. Its evaluation-binding/knowledge argument delegates to reference [57],
[*Transparent SNARKs over Galois Rings*](https://eprint.iacr.org/2025/263.pdf)
(PKC 2025). The local paper states an
asymptotic random-oracle result; that statement alone is not a concrete 128-bit
bound for this complete PBS implementation.

The implementation binds the trusted parameters, commitment, query and claimed
value before sampling a fresh k-by-rows base-field random test. It appends both
the random-test response and structured evaluation response, then samples one
shared set of raw columns with replacement. Duplicate authentication paths are
removed only after the draws. Verification encodes both response matrices,
authenticates whole block symbols and tests both linear identities at every
sampled column before folding the structured response through the suffix query.
These steps are in `pcs/src/matrix_weighted.rs` (`open`, `verify`, `bind` and
`sample_columns`); the batch path follows the analogous order.

The paper describes separate testing and evaluation phases. This code shares
column challenges, permits unbalanced row/column splits and also opens the
matrix pullbacks of ordinary extension-field queries. The independent mapping
and encoding tests establish algebraic equality and order, not proximity or
knowledge soundness for these adaptations. A concrete review must establish a
common decoded source table from the committed word, bound the random-linear
proximity failure for base-linear whole-symbol RS encoding, and bound false
structured responses even when the query is derived adaptively from prior
transcript messages. Shared columns require a joint event analysis; a union
bound can combine valid event bounds without assuming independence, but cannot
replace those missing lemmas.

`full_pbs_budget.py` currently treats those component bounds as conditional
inputs, sums the actual complete-relation inventory and can sum 21 independent
proof inventories. Passing that numerical target does not supply the missing
extraction/proximity argument, Merkle/Fiat-Shamir reduction or complete-parent/
child composition theorem. The measured common-target lane/extension comparison
therefore remains an experimental conditional comparison. Promotion still needs
that analysis and the remaining ledger gates.

### Algebraic lifting step for the measured unpadded layouts

For the measured native layouts, block width equals k and the scalar row-message
length equals k times the number of message blocks: there is no partial final
symbol. Identify each F^k symbol with a field K of degree k over F using a fixed
basis e_0,...,e_(k-1). The available independently checked degree-eight BabyBear
and degree-four Goldilocks fields provide those bases. Coordinate-wise RS on
base-field domain points is exactly K-linear polynomial evaluation after this
identification. This symbol field is an analysis device, separate from the
lookup challenge field; no embedding of the degree-six lookup field into the
degree-eight symbol field is required.

Let the committed encoded rows be Uhat_i over K. For the implementation's k
independent base-field random-test rows R[a,i], define

```text
alpha_i = sum_a e_a * R[a,i].
```

The basis-coordinate map is a bijection from F^k to K for every i. Under
independent uniform interactive base-field coins, alpha is uniform in K to the
number-of-source-rows power. Write v_a for each supplied test response grouped
into K coefficients. If all k checks pass at a sampled column j, K-linearity
implies

```text
Enc(sum_a e_a * v_a)[j] = sum_i alpha_i * Uhat_i[j].
```

Thus acceptance of all base tests implies acceptance of the corresponding
single K-valued random-linear test at the same columns. This is a one-way
algebraic reduction, not an equivalence of acceptance events. The query remains
fixed before R; both responses remain fixed before the shared column draws.

`pcs/tests/block_rs_lift.rs` exercises the coefficient map and this identity
against independent Horner evaluation, with transposed-weight and corrupted-
column negative controls. The RS-specific fixed-word derivation below supplies
a candidate quantitative proximity step, including fixed structured responses
and shared columns. Merkle availability/extraction, full adaptive composition
and Fiat-Shamir still require analysis. The lifting check alone does not cover
partially padded symbols or certify concrete whole-proof security.

## RS-specific fixed-word bound: derivation for review

This is a new derivation, not a bound quoted from 2025/719 or its inaccessible
reference. It treats a fixed, available word with authentic column answers.
Merkle extraction, Fiat-Shamir and complete-PBS composition are outside the
claim. The argument below is intended for review, with a small-field symbolic
certificate audit in `tools/rs_proximity_certificate.py`.

Let K have q elements and C be the length-n Reed–Solomon code obtained by
evaluating polynomials of degree less than m at n distinct K-points. Let the
committed word have r rows U_i in K^n. A common error set of size at most t
means that every row agrees with a codeword outside the same set of at most t
columns. Assume n >= m+2t. A uniform alpha in K^r defines y_alpha=sum_i alpha_i U_i.

**Exceptional-challenge claim.** If no such common error set exists, then

```text
Pr_alpha[ distance(y_alpha,C) <= t ] <= n(n+1)/q.
```

A bound greater than one is simply trivial. This claim is not obtained by
union-bounding the exponentially many error supports.

1. Introduce independent formal variables T_i and work over the function field
   L=K(T_1,...,T_r). The word y(T)=sum_i T_i U_i cannot be t-close to RS over L.
   Otherwise choose m of its at least n-t good positions and interpolate there.
   The resulting polynomial is linear in T, with each coefficient polynomial
   over K of degree less than m. Agreement at all remaining good positions
   implies coefficient-wise agreement for every U_i, giving a common error set.

2. Form the Berlekamp–Welch matrix A(T) for
   Q(x_j)=y_j(T) E(x_j), with deg(E)<=t and deg(Q)<m+t. It has n rows and
   m+2t+1 columns; entries have total T-degree at most one. If its generic column
   rank is full, a nonzero maximal minor P(T), of degree at most n, vanishes at
   every t-close specialization: a nearby codeword supplies a nonzero kernel.

3. Otherwise let s be the generic rank. Select a nonzero s-by-s minor and one
   additional column. Signed minors give a nonzero polynomial kernel vector
   v(T) for the selected rows, supported on these s+1 columns. Since those rows
   span every row over L, A(T)v(T)=0 identically. Each coefficient of its E and Q
   parts has total T-degree at most s<=n. E is nonzero: a Q-only kernel would
   vanish at n points while having degree less than m+t<=n. Q is also nonzero:
   an E-only kernel would force y(T) to vanish at n-t positions, already a
   common nearby zero source.

4. At any t-close specialization with a nonzero kernel vector, write f for the
   nearby degree-<m polynomial. Then Q-Ef vanishes at at least n-t points and
   has degree less than m+t. Since n-t>=m+t, Q=Ef. Merely having a nonzero
   Berlekamp–Welch kernel is insufficient; rational functions can give spurious
   kernels for far words. For example, values 1/(x_j-a), with a outside the
   domain, have E=X-a and Q=1 even when far from the low-degree code.

5. Let d=deg_x(E) and v=deg_x(Q) over L. If v<d or v-d>=m, the product of the
   leading coefficients of E and Q is a nonzero exceptional polynomial of total
   T-degree at most 2s: at a nearby specialization one of those degrees must
   drop. Otherwise 0<=v-d<m. Generic divisibility E|Q would make y(T) t-close,
   contradicting step 1. Pseudo-divide Q by E without inverses. A nonzero
   remainder coefficient R_j(T) has degree at most (v-d+2)s. Multiplying it by
   the leading coefficient of E gives a nonzero P(T). At a nearby specialization,
   either that leading coefficient vanishes or Q=Ef forces the specialized
   remainder to vanish. Thus P vanishes on every nearby specialization. For
   t>=1 its degree is at most (m+t+2)s <= (n+1)n. For t=0 a constant E always
   divides Q, so this remainder case cannot occur.

6. In every case the nearby challenges lie in the zeros of a nonzero polynomial
   of degree at most n(n+1). Schwartz–Zippel gives the claimed bound. The audit
   retains formal polynomials, not polynomial functions modulo T^q-T: when the
   degree bound exceeds q, the probability bound must be allowed to be trivial.

**Opening consequence, conditional on an available fixed word.** Put
D=n-m+1 and t=floor((D-1)/3). The common nearby source, if it exists, is unique
because 2t<D. For a far word, except with probability n(n+1)/q the combined
random test is farther than t from every codeword. Every supplied coded response
then disagrees on at least t+1 columns. For a nearby word and a false claimed
matrix opening, at least one structured response differs from its correct
codeword; its mismatch on the committed word has at least D-t columns. This
uses only code linearity and a fixed linear opening query, not commutativity of
the query matrices. Both response messages are fixed before column sampling.
Therefore Q fresh draws with replacement give the per-opening upper bound

```text
n(n+1)/q + (1-(t+1)/n)^Q.
```

The same draws may test both responses: the committed word is either near or
far, and the appropriate mismatch set is fixed before the draws. No independence
between the two response events is assumed. Here D-t>=t+1 and t+1>=D/3.

For the unpadded block-RS lifting above, q=p^k. If k>=3 and n>=2, then
n(n+1)<=n^k. Thus the current `(n/p)^k` random-test term and
`(1-D/(3n))^Q` tail dominate this proposed fixed-word bound. This does not
validate partially padded symbols, other codes, all low-width API settings,
Merkle availability/extraction or complete transcript security. The existing
budget implementation and measured parameters are deliberately unchanged.
`tools/audit_rs_layouts.py` checks the stated geometry and numeric domination
against saved complete-proof layouts; it does not label a protocol promoted.

### Audit evidence and limits

The symbolic audit covers rank certificates, excess quotient degree and
non-divisible rational-function kernels, including a degree-two locator.
It checks 30,805 challenge vectors in five larger fixtures, plus every word of
a tiny single-row instance (625 words, 85 near and 540 far) and every matrix of
a tiny two-row instance (729 matrices, 225 near and 504 far). The far cases in
those two complete spaces add 7,236 challenges: 38,041 in total. These exhaustive
finite examples audit the derivation and certificate construction; they are not
a substitute for reviewing the universal proof.

The Rust adversarial tests construct genuine roots and authentication paths
under the requested transcript, serialize/decode the resulting opening, and
check matching post-opening transcript states. A far half-zero/half-one row
must fail even for an identically zero structured query, isolating the random
test. A coded zero word with a freshly bound false claim must fail the structured
response equations. Both BabyBear/eight-lane and Goldilocks/four-lane cases pass,
with valid controls. They reject at linear consistency, not at authentication.

The saved audit checks 12 actual complete-proof layouts: shifted-helper BabyBear
lanes, optimized BabyBear degree-six lookups and Goldilocks cubic/four-lane
lookups. Existing random-test and tail terms dominate the proposed bounds in all
12. The audit rejects legacy seed-expansion protocols and partial symbols, and
explicitly reports that width two is not covered by the existing random-test
coefficient. All 66 Python and 11 targeted Rust tests pass. Evidence is under
`target/performance/rs-proximity-audit/`. No production protocol, parameters,
performance budget formula or promotion label changes in this audit.

### Proposed Merkle availability reduction (random-oracle model)

The preceding fixed-word argument needs a word fixed before its random tests.
Collision resistance alone does not supply that word for an arbitrary root.
Here is a query-log extraction argument for review, with an explicit additional
random-oracle assumption. It is not yet a concrete SHA-256 or Fiat-Shamir proof.

Freeze the hash-query history when a root is declared, before the challenges
whose soundness uses its word. Include honest/verifier hash queries in the
history. Assume h-bit independent uniform outputs on distinct new inputs.
Exclude collisions among all queries. Each known digest then has a unique
queried preimage. Starting at the declared root, traverse that inverse map at
the trusted tree depth: an internal preimage must be exactly two digests; a
leaf preimage must be the exact tagged serialization of a column of the trusted
shape. Missing or malformed branches yield fixed all-zero columns. This defines
an available word W, even when the adversary never constructed a full tree.
It need not re-commit to the declared root: default-filled branches are a device
for fixing a word, not evidence that the malicious root commits to a codeword.
A depth-bounded traversal also handles repeated nodes or cycles.

Let A be the number of distinct pre-freeze queries and B the number of later
new queries, including those needed to verify answers. Fix a target set containing
the root and both child digests of every pre-freeze input of length 2h bits.
There are at most 2A+1 targets. Exclude any later new query whose output hits
this set. For any accepted opening, traverse its path downward from the root.
Its root-producing input must be in the frozen history: otherwise that new
query hit a fixed target. Uniqueness of preimages fixes its children. Inductively
the same applies at each child and finally at the tagged column leaf. Thus every
accepted column equals W at its index, outside the two excluded events.
This also explains why an arbitrary guessed root or unexplained subtree cannot
be filled after the challenges without a bad hash event.

For total distinct queries T=A+B, the union bound is

```text
Pr[bad hash event] <= T(T-1)/2^(h+1) + (2A+1)B/2^h.
```

The collision term is the birthday bound; the second term conditions on the
frozen history and uses fresh uniform oracle outputs. Repeated queries do not
count as new queries. Adaptive root selection from that history is allowed.
For several roots/freeze times, separately account for each target-hit term
and use a single global collision term. This is deliberately conservative.
No query budget has been selected here, so this expression does not establish
128-bit concrete security. In particular, a 256-bit hash's birthday term cannot
be treated as a free 128-bit allowance independent of the adversary's resources.

Source correspondence: `hash_column` hashes `HasteBoots/mw-column/v1` followed
by bincode serialization; internal nodes hash two concatenated digests without
a node tag. The PCS verifier checks the trusted column size and exact path
depth before authentication. Fixed depth determines the expected input type,
so this argument does not require changing the existing node encoding. For the
real leaf parser, require complete consumption and exact reserialization of the
specified field-vector shape. This is an extractor-side parser requirement;
accepted prover values are hashed by reserialization in the current verifier.
Multiple valid encodings of the same field value do not undermine functional
binding, but the proof must use the actual accepted field semantics.

`tools/merkle_availability_audit.py` is a small query-graph model with SHA-256
outputs and programmable bad-event fixtures. Five tests cover all eight leaves
of an honest tree, partial trees/default filling, a late preimage, guessed roots,
collisions, and malformed shape/index/path rejection. The model uses fixed-size
opaque leaf payloads, not Rust/bincode decoding. Existing Rust adversarial PCS
tests exercise genuine production authentication and equation rejection; this
model audits the extraction logic rather than replacing those tests.

Remaining obligations include an independent review of this reduction and the
RS derivation, exact multi-root commitment/challenge ordering, query-resource
accounting, Fiat-Shamir/parent-child transcript composition, and knowledge or
hiding properties beyond fixed-word evaluation soundness. Production hash,
protocol, parameters and budget formulas are unchanged.

#### Production-format and freeze-point checks

`pcs/tests/merkle_availability.rs` now exercises a test-only inverse-history
extractor with the actual serde/bincode field-vector encoding and production
SHA-256 Merkle trees. It checks all eight columns for BabyBear width eight and
Goldilocks width four, missing-leaf default filling, an owned frozen snapshot,
and exact rejection of trailing, truncated, wrong-tag, wrong-count and nonminimal
vector-length encodings. The latter must not be confused with valid Goldilocks
lazy field representations: a separate test verifies field-equal/byte-distinct
representations survive parsing with their authenticated bytes intact.
This closes the opaque-payload coverage gap in the earlier model; it does not
turn the test-only parser into a production proof extractor. The query-log model
also checks shared subtrees and depth-bounded traversal of a programmed cycle;
the cycle is a termination fixture, not a feasible SHA-256 attack.

The following source ordering is checked by inspection. These are distinct
freeze points; freezing every word only at its final PCS opening would be too
late to justify the earlier lookup algebra.

| Word / statement | Binding point | Subsequent relevant challenges |
|---|---|---|
| Extension-lookup source words | `packed_extension_lookup::bind` appends each trusted parameter digest and source commitment to the parent | Multiplicities are appended, then a 64-byte child seed is sampled; tuple hash/reciprocal challenges follow in the child |
| Coefficient-packed reciprocal helpers | After tuple challenges and helper construction, all helper roots are appended under `extension lookup reciprocal roots` | Sumcheck messages/challenges and identity points follow in the child |
| Final helper/source PCS opening words | `finish_child` appends the final algebra digest to the parent; `verify_many` then binds commitment, queries and claims | Batch random linear tests, then responses, then sampled columns |
| Standalone single PCS opening word | `Parameters::verify` binds parameters, root, query and claim | Random linear test, then responses, then sampled columns |

Source references are `snarks/src/packed_extension_lookup.rs` (`bind`, `child`,
`finish_child`, `prove`/`verify`) and `pcs/src/matrix_weighted.rs`
(`bind`/`bind_many`, `verify`/`verify_many`). The helper word may depend on tuple
challenges, but must be fixed before the later sumcheck randomness. Source words
must already be fixed before tuple challenges. Reusing a root in several roles
does not permit choosing a new word for it at a later freeze point. This table
is local ordering evidence, not a complete inventory or proof of every root in
the full PBS composition. Hash query resources and adaptive Fiat-Shamir seed
search still need an explicit reduction.

The expanded verification passes 72 Python tests and 14 targeted Rust tests
(three production-format extraction tests plus the previous eleven RS/PCS
tests). Sources, the pinned Cargo.lock and logs are archived under
`target/performance/merkle-production-audit/`. No performance rerun is needed
for this test/documentation-only increment.

#### Explicit hash resource worksheet

`tools/hash_query_budget.py` evaluates the proposed availability reduction with
exact rational arithmetic. It requires a global distinct-query budget T and a
root-declaration budget R; it does not infer either from elapsed time. Counts
include adversarial queries and honest/verifier queries to the modeled hash,
including other domains that use that same oracle. For an explicit freeze
schedule `(A_j,B_j)`, each entry satisfies `A_j+B_j<=T`; group equal freeze points
with a `roots` multiplicity. The calculator charges the global collision term
once and adds `(2A_j+1)B_j/2^h` for each root declaration. Repeated declarations
may be overcounted safely; queries are counted by distinct input, not calls.

Without a schedule, maximize each term separately. The integer quadratic
`(2A+1)(T-A)` is maximized at `A=floor(T/2)` and equals `T(T+1)/2`.
Consequently a schedule-independent conservative bound is

```text
[T(T-1) + R*T(T+1)] / 2^(h+1).
```

For R=1 this is exactly `T^2/2^h`. The worksheet also finds the largest integer T
whose hash-only bound is at most the requested threshold, using exact comparisons.
An optional JSON schedule can improve the bound. Example invocation:

```sh
python3 tools/hash_query_budget.py --queries 18446744073709551616 --roots 16 --target 128
```

The following are hypothetical resource illustrations, **not the actual PBS root
inventory or a selected adversary model**. Values are minus log2 of the hash
union bound with h=256; display rounding does not control threshold decisions.

| Root declarations R | T=2^20 | T=2^40 | T=2^64 |
|---|---:|---:|---:|
| 1 | 216.00 | 176.00 | 128.00 |
| 16 | 212.91 | 172.91 | 124.91 |
| 256 | 208.99 | 168.99 | 120.99 |

At R=1,T=2^64 the hash term alone uses all of a 2^-128 error allowance, leaving
no room for algebraic error. When a bound exceeds an allowance it means this
reduction does not certify that allowance; it does not demonstrate an attack.
Conversely a small conditional hash term does not establish whole-proof security.
Every report retains `whole_proof_security_certified: false` and lists the
missing obligations. No Fiat-Shamir loss is guessed or set to zero. Merlin's
transcript security is separate from the SHA-256 Merkle oracle modeled here.
The full interactive budget tool and promotion flags are unchanged.

Seven new tests cover independently enumerated small freeze schedules, global
collision accounting, grouping, monotonicity, explicit-schedule improvement,
exact maximum-query thresholds (including values too large for reliable float
comparisons), and rejection of inconsistent budgets. All 79 Python tests pass.
This is classical random-oracle accounting; it provides neither a quantum
reduction nor a concrete security reduction for unmodeled hash behavior.
Evidence is archived under `target/performance/hash-query-budget-audit/`.

#### Complete-proof root inventory

`snarks::packed_root_inventory::inventory` counts root slots from the actual
complete proof and its nested decomposition/lookup proofs. The performance
example emits `HB_FULL_ROOTS` only after decoding and successful public
verification; its iteration and proof SHA-256 link it to `HB_FULL_PBS`.
Categories cover every commitment field in the complete proof: main coefficient
and evaluation tables, decomposition inputs, accumulators, borrow columns,
reciprocal helpers, monomial evaluations, and final key-switch coefficient,
evaluation, borrow and reciprocal tables. Shared-root references in opening
proofs, Merkle siblings, child digests and trusted public-key roots are excluded.
Identical digests in distinct root slots are counted separately, conservatively.
The inventory API does not verify a proof; callers must verify first.

For blind-rotation digit count d, key-switch digit count s, and g helper roots
per comparison, the schema gives

```text
R = 6d + 3s + 15 + (2d+s)g.
```

The first part counts nonreciprocal roots; `(2d+s)g` covers two d-limb
decompositions plus the s-limb final decomposition. Extension lookups use one
helper per requested pair (`g=repetitions`); lane lookups use one helper per
full lane group (`g=ceil(repetitions/width)`). This count depends on the field,
radices and comparison profile, not the polynomial size or LWE dimension.
Thus toy-sized complete proofs can exercise the same root-slot topology while
remaining distinct from original-size performance or correctness evidence.

| Profile schema (radices 8 and 5 bits) | d | s | g | Root slots R |
|---|---:|---:|---:|---:|
| BabyBear extension, one pair | 4 | 7 | 1 | 75 |
| BabyBear lane16, width eight | 4 | 7 | 2 | 90 |
| Goldilocks extension, one pair | 8 | 13 | 1 | 131 |

These counts replace hypothetical R values when evaluating the selected proof
schema's hash worksheet. They do not determine T: total adversarial/honest hash
queries and the number of attempted proofs still need explicit resource bounds.
For a multi-proof analysis, count root declarations across the whole experiment
and charge one global collision term, rather than assuming each proof gets a
fresh hash oracle. The API inventories slots in a supplied proof, not a universal
bound on all commitments an adversary might try while grinding Fiat-Shamir.
It is neither a freeze schedule nor a concrete security certificate.

Validation passes all 14 complete lane/extension proof tests, including fresh
1/4/16 groups, decoded verification, independent digit-count inventory assertions,
duplicate-slot counting and genuine adversarial binding cases. All 79 Python
tests and the example compilation checks pass. Three fresh toy example proofs
emit the expected 75/90/131 slots. BabyBear degree-six and Goldilocks cubic
proof/statement/key hashes and byte lengths match archived fixtures exactly.
The Goldilocks historical log predates the helper-shift metadata, so that field
is not claimed as a matched historical field. No original-size timing comparison
was run: these debug correctness runs overlapped compilation/tests. Sources,
logs and digest-linked inventories are archived under
`target/performance/complete-root-inventory/`.
