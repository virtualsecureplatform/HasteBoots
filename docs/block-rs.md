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

### Fewer packed test rows than RS symbol coordinates

The opt-in helper-basis profile keeps RS symbol width b=8/4 but uses h=6/3
packed lanes and random-test rows. Equal encoders therefore do **not** imply
equal random-test entropy. Let K/F have degree b, with the same fixed basis
e_0,...,e_(b-1) used above, and define

```text
S = span_F(e_0,...,e_(h-1)),  |S| = p^h,
alpha_i = sum_(a=0)^(h-1) e_a R[a,i].
```

For independent uniform interactive F-coins, the basis-coordinate map is a
bijection F^h -> S for each input row. Thus alpha is uniform in S^r, even
though S need not be a subfield of K. Acceptance of all h base checks implies
acceptance of their K-linear combination, exactly as in the preceding lifting
identity. No embedding of the degree-six lookup field into the degree-eight
RS symbol field is used; S is only a set of code-field coefficients.

Given the nonzero exceptional polynomial P(T) of total degree at most n(n+1)
constructed in the fixed-word derivation below, finite-subset Schwartz–Zippel
therefore gives the conditional bound

```text
Pr_[alpha <- S^r][P(alpha)=0] <= min(1, n(n+1)/p^h).
```

This step requires no closure of S under multiplication. To see the finite-set
bound directly, view P as a polynomial in its last variable of degree j, with
nonzero leading coefficient of degree at most deg(P)-j in the others. Induction
bounds the leading-coefficient failure by (deg(P)-j)/|S|; otherwise a nonzero
univariate polynomial has at most j roots in S. Adding these bounds gives
deg(P)/|S|. The base case is the ordinary univariate root bound.

The changed denominator is p^h, not p^b. `pcs/tests/block_rs_lift.rs` now checks
both six-test/eight-coordinate and three-test/four-coordinate identities,
including independent Horner, transposed-weight and corrupted-column controls.
These tests support the algebraic map; they do not prove availability,
Fiat–Shamir, the exceptional-polynomial construction, or a complete PCS bound.
The comparison runner reports this per-opening fixed-word term separately from
all promotion/security flags, which remain false. A complete budget must still
include the unchanged sampling, structured-response and algebra errors, the
number of openings/proofs, and the unresolved adaptive/hash composition.

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

### Conditional padding-consistency step

The fixed-word argument can also account for partial final symbols and entire
unused coefficient blocks. Let the scalar message length be L, symbol width b,
and RS coefficient-block count m, so the encoder pads scalar coefficient
positions `Z = {L,...,b*m-1}` with zero. Identify symbols with a degree-b
extension K/F as above; the encoder is coordinate-wise RS over base-field
domain points. Suppose the fixed committed rows have unique common nearby
RS words, with a common error set of size at most t. Their decoded coefficient
vectors need not have zero entries on Z: being RS-near alone does not enforce
the source's message shape.

If a padded position is nonzero in at least one decoded source row, fix one
such position. Its coefficients across source rows form a nonzero vector over
F. Each of the h independent base-field test rows kills this vector with
probability exactly `1/p`; all h rows kill it with probability `p^-h`.
Requiring all padded positions to vanish can only reduce that probability.
The nearby words and this nonzero coordinate vector must be fixed before the
whole random-test matrix is sampled.

Otherwise some test row's correct linear combination of decoded RS words has
a nonzero padded coefficient. Every supplied random-test response has exactly
L scalar coefficients, and its verifier-side encoding pads Z with zero.
Therefore its RS codeword differs from that correct combination. Their block
distance is at least `D = n-m+1`. The random combination of the committed rows
differs from its decoded combination only on the common t-column error set,
so the supplied response disagrees with the authenticated committed combination
on at least D-t columns. This mismatch set is fixed before column sampling.
Shared sampling with the structured response does not remove this particular
rejecting set.

If every decoded source row already has zero padding, deleting Z gives a
well-shaped source table and the earlier false-structured-response argument
applies. Thus the fixed-word near case has error at most
`p^-h + (1-(D-t)/n)^Q`. For a far source, the earlier subspace/RS exceptional
bound applies. For `h<=b`, `n>=1`, and the selected
`t=floor((D-1)/3)`, the single conservative envelope

```
n(n+1)/p^h + (1-(t+1)/n)^Q
```

dominates both cases; near/far are properties of the fixed source before its
test, so this step does not sum their exceptional probabilities. When padding
is absent the extra near-case event is empty. This is still conditional on the
fixed-word RS lemma, unique nearby decoding, availability at the correct freeze
and ideal independent test/sampling phases. It supplies no complete
Fiat–Shamir or PBS knowledge theorem.

The production regression `matrix_weighted::padded_source_tests` commits genuine
RS columns with a nonzero forbidden padded coordinate. The structured query
is zero, isolating the random test. It checks real authentication paths and
decoded proofs, requiring rejection for a linear-response mismatch rather than
a path failure, alongside an accepted zero-source control. Both ordinary and
helper-basis test-row widths are covered over BabyBear and Goldilocks. These
finite controls support the implementation mapping, not the probability proof.

### Conditional row-code component state and shared batches

Work in an ideal fixed-word game with authentic column answers. Fix the
committed row matrix, trusted code/shape, ordered queries and all claimed
values before the random-test matrix. Each row has n block symbols over the
analysis field K; let h be the number of base-field test rows and b the symbol
width, with `h<=b`. Use `t=floor((D-1)/3)` as above. The false component relation
means that the rows are not jointly within t columns of uniquely decoded,
correctly padded source rows, or that some claimed opening differs from that
decoded source. This relation and decoding convention must be coupled to the
enclosing oracle relation separately.

Initially call the component state bad for a false component relation. After
the whole random-test phase, use this stronger intermediate predicate: for
every dimension-valid response packet, either its final claimed-value equation
fails or at least t+1 columns reject a linear-response check. The preceding
case analysis establishes this predicate except with probability at most
`min(1,n(n+1)/p^h)`:

* A jointly far source has a far projected test, outside the RS exceptional set.
  Any coded test response then disagrees on at least t+1 columns.
* A near source with nonzero decoded padding has a test response mismatch on
  at least D-t columns, unless all h test rows kill that padding residual.
* For a valid padded decoded source and a false claimed opening, a response
  agreeing with the decoded structured response gives the correct value and
  fails the claimed-value equation. Any other response differs by an RS
  codeword and rejects at least D-t columns.

These are cases of one fixed source, so the random-test escape bound is the
maximum of their exceptional probabilities, not a sum. The universal
intermediate predicate gives closure under the prover's response choice.
After responses, keep the state bad when the actual final equation fails or
the actual rejecting column set has size at least t+1. The set is fixed before
the complete with-replacement column-sampling phase, whose bad-to-good error
is at most `(1-(t+1)/n)^Q`. Duplicate-path transport after sampling does not
change that event. After sampling, an invalid final equation or any sampled
rejecting column keeps the state bad; ideal authentication prevents later
path responses from turning that state into acceptance.

For a batch with at least one false claim, select its first false claim under
the fixed decoded source before drawing the test matrix. Its left-prefix
response group is already determined by the bound query list. If that shared
response is correct, the selected false claim's final equation fails;
otherwise the same D-t argument supplies a rejecting set. This needs no
independence between claims, groups, the test response or the shared column
samples. Actual `bind_many` fixes the complete list, `get_vec_challenge` draws
one h-by-rows test matrix, and the response list is absorbed before
`sample_columns`. Group reuse checks exact ordered left-prefix equality.

This supplies component-level conditional transition bounds, including
padding and shared batches. It is not a state predicate for the whole PBS
proof, does not itself fix words at adversarial first-query times, and relies
on the RS exceptional-polynomial and semantic availability premises. Global
Merkle/link resources, Fiat–Shamir composition and witness extraction still
need to be supplied before a concrete security-qualified query count follows.
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

The table and formula above describe the legacy `inventory` proof schema.
Canonical v11 uses `canonical_shared_inventory`: for the selected one-pair
profile its outer private slots are 8d+4s+16, or 76 BabyBear / 132 Goldilocks.
The native observer confirms those counts and separately sees trusted-key
openings. These outer slots do not count PolyFRIM's internal ladder/rolling
roots or provide their freeze schedule. See `unmasked-polyfrim.md` for the
separate API-call observations and conditional per-owner query ceiling.

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

### Hash-output bound on single and batch verifier calls

For fixed trusted `BlockReedSolomonCode` parameters with N column symbols and
Q ordered draws, each call to `Parameters::verify` or `verify_many` produces at
most `1 + min(Q,N)*(1+log2(N))` outputs through its generic hash interface.
The one extra output is the trusted parameter-context digest. Shape checks
require a nonempty column list of size at most min(Q,N), exact symbol lengths,
and paths of length `1+log2(N)` before authentication. Each column hashes its
values once, then `MerkleTree::check` hashes at most log2(N) parent pairs.
All other operations in these two methods are arithmetic, encoding or transcript
operations. Counting every column bounds all joined parallel workers even when
one reports failure. A single malformed proof shape rejects before the context
hash; a batch shape rejects after its binding context hash. Malformed queries
can reject earlier still. The bound concerns every finite execution prefix and
does not require a field/column retry cutoff: a sampler that keeps running does
not introduce additional outputs through this hash interface.

The reusable `classical_hash_resources` counter test now checks 264 rejected
single/batch calls across both fields, v4/v5 and Q=1,8,40 with N=32. Cases cover
empty/oversized response or column vectors, short/long paths, changed symbol
values, changed leaf digests and changed sibling digests. Early shape failures
match the exact zero/one context-output counts; well-shaped authentication
failures satisfy the full bound. The accepted five-backend controls also pass.
This validates the component hash-output bound, not parent call counts, XOF
input/output bytes, all-stage work bounds or security admission. Frozen evidence
is under `rejected-brakedown-hash-resources-*` in the opening inventory.

### Transcript resources on rejected calls

The same rejected-call controls also pass with transcript observation enabled
and disabled. All 192 malformed-shape calls request zero transcript randomness.
The 72 later authentication failures complete one field phase with
`C = width^2 * 2^left_vars` base-field values, followed by its 64-byte receipt.
V4 consumes one eight-byte request per actual column candidate, retaining all Q
ordered accepted draws; v5 consumes one fixed `8*Q` byte block. The observer
checks actual raw field bytes against candidate counts and base-field widths,
as well as total returned bytes and reader counts. These checks use Q=40 above
the 32-symbol domain as well as smaller quotas.

For any single/batch call on trusted fixed parameters, one field raw reader
and its receipt contribute at most two XOF requests. Under the analysis stop
before a value exceeds R_F candidates, raw field output is at most `C*R_F*d`
bytes, where d is the sampler's masked field-candidate width. Under the v4
column stop, column requests/bytes are at most `Q*R_C` and `8*Q*R_C`.
V5 instead has one column request and exactly `8*Q` column bytes, with no
column-rejection stop. Prefixes ending at earlier rejection or analysis stops
cannot increase these totals. No production retry limit is added.

`classical_brakedown_resources.call_envelope` records these single-call bounds,
the unconditional hash-output bound, and the assumptions separately. Its
geometry-only arithmetic reconciles the existing native PCS request/hash
worksheets for all four roles, both fields and v4/v5 (16 combinations). It
does not evaluate soundness-probability powers to compute resource counts;
even a large valid v4 quota is handled as integer arithmetic. Parent call
ceilings, input-string construction and whole-verifier work remain excluded.
Frozen evidence is in `brakedown-call-resources-*` in the opening inventory.
