# Experimental unmasked canonical PolyFRIM

The original HasteBoots contract proves correct evaluation on ciphertexts using
public evaluation material. Its supplied SNARK definition does not require an
additional zero-knowledge simulation of the evaluation trace. The unmasked
backend preserves that contract; it does not claim zero knowledge. The masked
backends, existing defaults, proof formats and parameter sets remain available.

## Application knowledge with the original public evaluation material

Fix honestly generated native parameters and the original public evaluation
key ek, with trusted verifier preprocessing performed on that same ek. The
application statement is the NAND input/output ciphertext triple (x,y,z).
For the native trace relation, a witness is a valid evaluation trace taking
(x,y) to z under ek. Public auxiliary input ek is already available under the
original evaluation contract; it is not added to the serialized verifier setup.

Conditional on a soundness bound epsilon for accepting an output different
from native evaluation, there is a straight-line application extractor with
the same knowledge error: construct
`Evaluator::from_public_evaluation_key(ek)`, run `nand(x,y)` to obtain (z0,t),
and return t if z0 equals z componentwise, otherwise fail. The evaluator stores
only `EvaluationKey`, and its bootstrap method constructs modulus-switching,
blind-rotation, key-switching and extraction traces from public ciphertexts
and encrypted evaluation material. This computation has polynomial cost in
the public key and native computation sizes and uses neither the prover's
state nor a secret key. Its trace is a witness whenever z=z0. Consequently
the event "verification accepts and extraction fails" is contained in the
incorrect-native-output event, bounded by epsilon. Rewinding, challenge
forking and an additional extraction failure term are unnecessary for this
application relation. The full soundness bound epsilon is still unfinished.

This statement explicitly gives ek to the extractor. `VerifierSetup` alone
contains key roots/configuration, not the key ciphertexts, so the statement
does not establish extraction from that smaller input alone. Nor does it
extract tables matching arbitrary internal proof commitments: those roots
are proof messages, not part of the application's input/output statement.
A generic PCS knowledge claim or a relation exposing those roots requires
its own extraction argument. No change to FHE parameters, public evaluation
keys, output keys or the succinct verifier interface follows from this lemma.

## Implementation and interface

The version-twelve outer prefix is determined before its first randomized
stage. `classical::verify` validates the trusted field and requires both setup
and proof profile IDs to equal the caller-selected bundle. It constructs the
profile's parent transcript and selects `ClassicalShared` statically. In
`verify_inner`, the complete protocol version, setup/role compatibility and
endpoint representation are checked; the public statement is normalized and
the native rotation plan/initial accumulator are derived. `bind_inner` checks
the primary root-vector lengths and endpoint length, then absorbs one ordered
tuple containing version, extension degree, trusted setup, all 17 PCS contexts,
normalized statement, coefficient/evaluation/input/accumulator root vectors
and the final accumulator. NTT/decomposition child counts are checked before
entering the first randomized Hadamard stage. Thus malformed outer dimensions
do not reach a challenge phase.

For fixed trusted inputs and that absorbed tuple, the outer verifier's stage
order is deterministic: key-product Hadamard relation; 2d+1 NTT relations;
two decompositions using shared canonical lookups; accumulator transitions;
monomial rotations; final key-switch/extraction composition. Here d is derived
from the trusted field and radix, not supplied by the proof. This fixes the
primary source-word names and public native plan for a candidate first-query
history. It does not fix borrow/helper roots, monomial auxiliary roots or
final-stage source roots introduced later: their own child bindings must be
interpreted before using their challenges. Recovering the outer tuple alone
therefore cannot establish admissibility of every later candidate prefix.

For each shared decomposition, its first binding contains the trusted radix
configuration, modulus/extension identity, borrow/helper PCS contexts and
ordered source/digit root contexts. The verifier requires d+1 borrow roots
and absorbs that complete vector before entering the linear reconstruction
and zero-endpoint checks. Those checks bind their ordered oracle contexts
and normalized relations before the independent packed linear challenges.
The lookup registry is then deterministically the digits followed by borrows;
trusted comparison requests select slots in that order. Lookup preflight
binds the ordered canonical requests and each selected source context/root,
and the canonical opening registry is initialized before the child seed.

The lookup child has two distinct commitment boundaries. Grouped and flattened
multiplicity vectors are absorbed by the parent before its child seed, fixing
the source/count task before compression y and reciprocal r. In the child,
each request index is absorbed before its ordered challenge pairs. Helper
roots are absorbed only after all these pairs, but before any equality point
and batched sumcheck challenge. This is required: honest reciprocal helpers
depend on y and r. Their values therefore cannot be included in a bad-state
predicate requiring them to be fixed before those same challenges. The
rational/source mismatch predicate uses fixed sources and multiplicities;
the later helper-identity predicate uses roots fixed before equality points.
The existing first-reciprocal-rejection stopping bound handles unbounded r
retries separately. This ordering covers the decomposition lookup boundary;
it does not interpret every prior linear/PCS certificate or certify the whole
candidate history as an accepted verifier execution.

For the linear reconstruction and known-input checks, fix their decoded base
tables before sampling and choose the first false fixed equality. Its
difference is a nonzero packed residual table. At each `challenge_pair` fold,
one nonzero two-row block interpolates to a nonzero polynomial of degree at
most 2k-1. All k output coordinates use independent F challenges in that one
phase, so the probability that this block vanishes is at most
`((2k-1)/p)^k`. Track the first fold where the residual becomes zero; union
over its folds gives the existing fixed-table equality bound. There is no
extra factor for the number of equalities: the first false equality was fixed
before the challenges. If a terminal response differs from its source-table
evaluation, that is instead a PCS opening obligation. This uses the implication
from accepted checks to true terminal values; it does not condition the
challenge distribution on a future opening's acceptance.

The accumulator uses the same argument after expressing each check as a
fixed residual table. Its arithmetic checks are linear combinations; the
duplicated-half checks are fixed replication maps. Selected-row endpoint
checks use residual tables over coefficient/half variables, omitting unused
row phases. The carry-partition query sum is the fixed cyclic row shift:
the first-set-bit branches and wrap branch partition row indices and retain
matrix products in their original order. Its correction is a fixed sparse
table supported on the padded last and active last rows. Hence continuity is
also a fixed residual, without commuting matrices. Charging all source-variable
fold phases bounds the endpoint cases too. This lemma still requires the
decoded-table/availability/PCS coupling; tests of explicit query maps do not
establish that cryptographic premise.

The accumulator binds its trusted shape, normalized public initial/final
endpoints and all seven ordered source contexts/roots before sampling lane
challenge vectors. Its selected-row, carry-partition shift and half-selection
queries are deterministic functions of those vectors and the trusted shape;
proof response values are authenticated afterward. Proof value/opening counts
are checked after lane sampling. Thus rejected submissions can consume these
phases, and accepted-path observation counters alone cannot bound all-trials
verifier resources.

The monomial stage first binds the public native plan, native NTT root,
evaluation context and the two coefficient sources. It checks the auxiliary
packet dimensions and value representations, then binds both auxiliary NTT
roots before their two NTT verifications and the packed product check. These
roots are not supplied by the earlier outer header. Its target monomial
evaluations are computed from the public plan at the resulting query.

The final key-switch stage normalizes its public accumulator/output values
and binds the trusted expected key, extension degree, six contexts, endpoint,
output ciphertext, d+1 coefficient/evaluation roots and input root. NTT proof
count and extraction-value representation checks precede its known-input
challenge. The latter also binds the exact known input table derived from
the accumulator. The stage then verifies d+1 NTT relations, the key product,
the shared canonical decomposition and the extraction ZeroCheck with public
mask/target tables before authenticating the terminal coefficient value.
Here d is the key-switch digit count, distinct from the main radix count.
This completes the parent-stage binding inventory, not each child's complete
admissible-prefix grammar or an all-trials resource theorem.

`pcs::matrix_weighted::polyfrim::Parameters<F,E>` implements `CanonicalPcs`.
`new(logical_vars, width, blowup, queries)` fixes the source degree/domain and
sampling experiment; query counts do not imply security bits. Commitments are
deterministic. State retains the canonical base table and its extension-field
oracle; neither is a verifier input. There are no random masks, disclosure
limits or private opening counters. A constant table repeats once in a dummy
variable, queried last with `(I,0)`; other tables have no dimension padding.

Commitment uses Boolean-to-monomial conversion and ordered low-variable folds.
The root has exact order twice the encoded length. Native negacyclic NTT plans
supply this root; small domains square down an available size-32 plan root.
The existing coordinate encoder evaluates only nonzero base coordinates.

An ordered opening batch uses the existing non-hiding joint-query kernel. Every
query retains its authenticated matrix-consistency ladder; one projected rolling
FRI checks the ordered ladders. All virtual scalar originals are authenticated
against the actual packed roots. The adapter binds the backend context, expected
source root, complete ordered matrices and values in the parent transcript,
seeds a direct full-coordinate extension transcript and absorbs its final
32-byte fingerprint back into the parent. Its seven canonical domains differ
from Brakedown and all three masked backends. Parameters bind the base modulus,
extension degree and basis multiplication products in addition to geometry.

The generic complete version-11 entry points now accept this backend without a
new complete-proof spelling. Backend choice stays trusted, outside proof
metadata. All PBS stages and native public-key preprocessing are retained.
This is direct full-source packed PolyFRIM, not fragmented packed PipFRI.
Source/ladder storage still uses extension-field elements; sharing FRI does not
stream all query ladders or guarantee that native large batches fit memory.

## Algebraic reduction and security boundary

Let `pi:E->F` be polynomial-basis coordinate zero, so `pi(a)=a` for embedded
`a in F`. For any ordered query with matrices over F, coordinate-wise pi
commutes with each addition and matrix-vector multiplication. Consequently,

```
pi(M_v ... M_1 T) = M_v ... M_1 pi(T).
```

No two matrices are commuted. If a malicious committed extension table answers
a query with the fully embedded base claim, its projected base table answers
the same query. This also holds after selecting the dummy constant coordinate.
Thus base-coefficient membership of the malicious extension table is unnecessary
for this **projection contract**. This is conditional on extracting a single
fixed extension table from the authenticated low-degree source; it is not a
proof of that extraction assumption. Tests for the matrix convention and the
existing core's dense extension matrices support the arithmetic, not extraction.

For **exact** degree-bounded source and ladder polynomials, the difference
between the prescribed matrix fold and the claimed next polynomial is a vector
polynomial in the squared domain variable of degree less than half the previous
message length. If nonzero, one coordinate has at most that many zeros. Uniform
independent consistency samples therefore miss that fixed incorrect transition
with probability at most `blowup^(-queries)`. A conservative B-query union bound
is `B * blowup^(-queries)`. This statement assumes exact codewords and fixed
oracles/roots before the sampling challenges. It does not justify applying the
same bound to words that are merely close to codewords.

Likewise a fresh uniform E-valued projection row annihilates a fixed nonzero
vector at a fixed position with probability `1/|E|`. This pointwise statement
does not prove robust vector proximity: a decoder may select its nearby scalar
codeword after seeing the projection. It also does not establish a common
source for all adaptive queries. The existing fresh over-degree and substituted-
projection forgeries test the production rejection equations; they do not fill
this mathematical gap.

A conditional reduction for the lane-projection step is now explicit. Assume
the RS-specific fixed-word claim derived in `block-rs.md`. At layer l, place
every committed lane word in a row of U over E, concatenating query/lane rows
for the joint kernel. Let C_l be RS over E on its n_l distinct coset points,
with degree bound m_l. For any t_l satisfying n_l >= m_l + 2*t_l, that claim gives

```
no common <=t_l column-error set for U
  => Pr_lambda[distance(sum_i lambda_i U_i, C_l) <= t_l]
       <= min(1, n_l*(n_l+1)/abs(E)).
```

This follows by substituting K=E and the lane rows into that claim; it does not
assume that a nearby scalar codeword was selected before lambda. A common
nearby vector codeword, when present and 2*t_l < n_l-m_l+1, is unique and fixed
by U, independently of lambda. Repeated rows from a shared source cause no
problem: the fixed-word claim allows arbitrary rows, including duplicates.
The joint kernel samples one independent full-coordinate E-weight per
query/lane after binding every ladder root, then sums those weighted rows.
Thus this is its exact ideal-interactive projection experiment, not a claim
about a different independently committed scalar copy. A union over layers
adds their exceptional terms; independence of the failure events is unnecessary.

This narrows one obligation to the proposed fixed-word lemma and its review.
It still assumes available fixed vector words and genuinely uniform conditional
coins. It does not show that rolling FRI certifies every virtual scalar input
at these radii. The separate nearby-decoded-ladder calculation below charges
errors in both predecessor values and the successor word; the exact-codeword
`blowup^(-queries)` calculation above cannot be reused without those charges.
Adaptive/Fiat-Shamir compilation and the complete error union also remain open.
No parameters, acceptance equations or security flags change.

`unmasked-polyfrim/lane-projection-audit.py` and its JSON result exercise this
fixed-word interface using the existing symbolic certificate audit and an
independent exhaustive nearby-word decoder. Over F_101, n=6, m=2 and t=1,
30,603 weight vectors cover disjoint row-error supports (201 close projections),
a repeated far lane (101) and independent far lanes (one), each out of 10,201.
A common-nearby-vector control also succeeds. The disjoint-support case shows
why individual row proximity is insufficient. All exceptional projections lie
in the respective nonzero certificate's zero set. This tiny-prime audit is
neither a proof of the general claim nor a test of production FS/hash behavior.

**Nearby decoded ladder consistency, for fixed available words.** This is a
separate conditional argument for the actual production fold. Let m_0 be the
initial power-of-two polynomial degree bound, m_l=m_0/2^l, L=log2(m_0), and
n_l=blowup*m_l. Suppose every committed vector word W_l agrees with a
fixed vector polynomial P_l of degree <m_l outside at most t_l whole-vector
columns. Put P_L equal to the public terminal claim, m_L=1, and t_L=0; there
is no prover-chosen terminal word. All these words, matrices and the claim are
fixed before the consistency indices. Assume odd characteristic, distinct
nonzero antipodal cosets, and 2*t_l<n_l-m_l+1 so each nearby vector is unique.

The implementation first converts Boolean-table coefficients to monomials.
Consequently its fold is A_l*P_even(Y)+B_l*P_odd(Y), with
A_l=M_l.zero+M_l.one and B_l=M_l.one. It is not M_l.zero*P_even plus
M_l.one*P_odd. This preserves the original ordered Boolean matrix query and
requires no commutation of matrices. Define

```
H_l(Y) = A_l*P_l,even(Y) + B_l*P_l,odd(Y) - P_(l+1)(Y).
D_(l+1) = n_(l+1) - m_(l+1) + 1.
s_l = max(0, D_(l+1) - t_l - t_(l+1)).
```

If H_l is nonzero, one coordinate is a nonzero polynomial of degree
<m_(l+1). At least D_(l+1) distinct successor-domain points therefore have
nonzero H_l. A bad predecessor column can spoil at most one antipodal pair;
a bad successor column can spoil at most one successor point. Removing both
error sets leaves at least s_l rejecting pairs for the authenticated words.
At the last fold the successor is the fixed public constant, so t_L=0.

A uniform initial-domain index maps to a uniform antipodal pair at every fixed
layer: shifting it right by l+1 is a surjection with equal-size fibers. The
bit-reversed coset order is only a permutation of these pairs. Assigning fresh
uniform eight-byte coins to the production sampler's byte-challenge interface,
which masks by n_0-1, gives exact uniform draws for power-of-two domains in the
ideal interactive experiment. Independent
sampling with replacement therefore bounds acceptance of a fixed bad transition
by `(1-s_l/n_(l+1))^Q`. If the final claim differs from the ordered evaluation
of P_0, at least one H_l is nonzero. Select the first such layer from the fixed
words before sampling. The bound with the smallest s_l/n_(l+1) over layers
then applies without a union over layer events, even though the same indices
check every layer. For the joint kernel one can likewise select a fixed bad
query after all roots/claims are bound and before any of its consistency draws.
This argument concerns the near-word case itself; it does not condition the
coin distribution on subsequent FRI acceptance.

For example, choosing t_l=floor((n_l-m_l)/4) for committed layers and t_L=0
ensures a rejection fraction at least (1-rho)/4, where rho=m_l/n_l. At rate
1/2 this yields the conservative **near-word consistency** tail `(7/8)^Q`.
It is a different, weaker bound than the earlier exact-codeword tail and the
paper's scalar unique-decoding proximity tail. It is not a recommended
parameter profile: rolling FRI must separately certify proximity at every
chosen integer radius, including small layers, and all other errors remain.

`pcs/tests/polyfrim_nearby_folds.rs` checks the actual `fold_symbol` over
BabyBearExtension6 and GoldilocksExtension3, with non-base coefficients and
noncommuting matrices. At n_l=16,m_l=8,t_l=2,t_(l+1)=1, a degree-three
successor discrepancy is nonzero at five of eight points. Two predecessor
column edits and one successor edit hide exactly three, leaving two rejecting
pairs, attaining the local lower bound. The local test thus accepts six of
eight pairs, disproving reuse of a 1/2 exact-codeword miss bound for this
nearby-word component. A terminal-constant witness separately checks t_L=0.
These tests do not construct or validate a complete forged FRI/PCS/PBS proof.
The derivation still assumes fixed available words and uniform conditional
coins; it does not complete hash extraction, rolling-FRI or FS composition.

**Rolling schedule and radius transfer.** The original
[PolyFRIM paper, Protocol 1](https://www.usenix.org/system/files/usenixsecurity24-zhang-zongyang.pdf#page=8)
commits each folded word before adding the next fixed input with squared
challenge weight. The implemented `rolling_fri` uses the same recurrence:
D_(l+1)=Even(C_l)+alpha_l*Odd(C_l), followed by
C_(l+1)=D_(l+1)+alpha_l^2*V_(l+1). Its root commits D, while queried C values
are reconstructed from authenticated D and V. The virtual-all mode fixes V
through the enclosing roots and projection weights. This identifies the
semantic schedule; it does not prove that an arbitrary stronger proximity
premise follows from the paper's scalar theorem.

The required radius dependence has a production-verifier control. Use a
32-point source domain, degree bound 16, and one query; all other original
words, derived words and the terminal constant are zero. Set the first five
source symbols to one. RS distance is 17, so this word is distance five from
zero and at least twelve from every nonzero codeword. It is therefore outside
the prescribed radius four, while inside the rate-1/2 unique-decoding radius.
The five edits affect only three of sixteen antipodal pairs. Every query
outside those pairs accepts with genuine authentication paths and correct
later zero equations. Under ideal independent sampling, acceptance is at
least `(13/16)^Q`; the possible first-fold cancellation only increases it.
Consequently the rate-1/2 scalar tail `(3/4)^Q` cannot be substituted as a
uniform bound for this **stronger radius-four proximity premise**. This does
not contradict a guarantee whose extracted word may be within a larger radius,
and does not exhibit a false evaluation or complete PCS/PBS forgery.

`rolling_fri::radius_tests` checks the actual verifier over BabyBearExtension6
and GoldilocksExtension3 in ordinary and virtual-all modes. The virtual callback
verifies real original Merkle openings before comparing values; no authentication
is skipped. The transcript scan covers every initial-domain index, verifies
acceptance/rejection against the first-fold equation, and checks matching
post-verification transcript states. The probability comparison above follows
from exact pair cardinalities, not the empirical frequency of transcript seeds.
The new tests change no production verifier, parameters or proof bytes.
A valid epsilon_rolling for the conditional consequence below still requires
an analysis at the actual integer radii, or a different composition argument.

**Distance-sensitive rolling claim for review.** A conservative replacement
can be derived in the fixed-word ideal-interactive model, using the same
RS exceptional-polynomial construction. It is not the primary paper's numeric
bound. For three fixed rows a,b,c of an n-point RS code, repeat that construction
over E(T) for a+T*b+T^2*c. Generic proximity would interpolate a degree-two
polynomial in T and give a common error support for all three coefficient rows.
Otherwise the Berlekamp–Welch entries have T-degree at most two. The minor,
kernel and pseudoremainder argument in `block-rs.md` then gives a nonzero
exceptional polynomial of degree at most 2*n*(n+1). Thus a far joint row
matrix projects within radius t with probability at most 2*n*(n+1)/abs(E),
provided n>=m+2*t. A preselected multivariate minor must not simply be
substituted along the curve: it could become identically zero. The audit now
constructs the univariate matrix and certificate afresh.

Write C_i for the combined rolling word, V_i for the fixed original input,
and B_i for initial-domain indices whose path has failed a fold before layer i.
For a codeword h at layer i define the normalized potential

```
eta_i(h) = Pr_x[ x in B_i or C_i(x^(2^i)) != h(x^(2^i)) ],
eta_i = min_(h in RS_i) eta_i(h).
```

At the next layer the fixed rows are Even(C_i), Odd(C_i), V_(i+1), with the
last row zero at the terminal step. Put delta in (0,(1-rho)/2] and
t_i=floor(delta*n_i). If these rows have no common radius-t_(i+1) support,
the curve argument makes their random combination farther than delta from
RS except with probability 2*n_(i+1)*(n_(i+1)+1)/abs(E). A discrepancy between
the computed combination and the prover's next word enters B_(i+1), so its
potential to any codeword is at least that combination's code distance.

Otherwise choose the unique common nearby codewords h0,h1,h2 before alpha_i.
Their combined codeword is H=h0+alpha_i*h1+alpha_i^2*h2. Outside the common
agreement set a nonzero quadratic in alpha_i can vanish at at most two values.
A union over points charges at most 2*n_(i+1)/abs(E). On the complementary
event the combined word agrees with H exactly on the common agreement set.
For any codeword other than H, RS distance and delta<distance(RS)/2 make its
potential at least delta. For H, every old disagreement with
h0(X^2)+X*h1(X^2) either was already in B_i or has its square outside that
common agreement set. There the next word either differs from H or differs
from the computed combination and enters B_(i+1). This is a pointwise set
inclusion, giving eta_(i+1)(H)>=eta_i. Hence

```
eta_(i+1) >= min(eta_i, delta)
```

except with probability at most 2*n_(i+1)*(n_(i+1)+1)/abs(E), which dominates
both branch bounds. If V_(i+1) itself is farther than delta, the far branch
forces eta_(i+1)>=delta. The branch classification and its nearby words depend
only on the prefix before the fresh alpha_i; the next derived word may be
chosen adaptively after it. A sequential union therefore handles adaptive
prover messages. Starting from eta_0=distance(V_0,RS_0), any far original input
forces final potential at least delta outside the charged events. The terminal
word is constant, so its minimum potential equals the fraction of initial
indices with a bad fold. Independent final samples give the candidate bound

```
epsilon_rolling(delta) <=
    sum_(j=1)^L 2*n_j*(n_j+1)/abs(E) + (1-delta)^Q,
```

clipped at one. At delta=(1-rho)/4 the integer radii are those used in the
nearby-ladder argument. At rate 1/2 the tail is (7/8)^Q, consistent with the
radius-transfer control. This derivation assumes the RS exceptional-polynomial
claim and available fixed semantic words at every freeze point; it is for
review, not a reviewed concrete security theorem, hash/FS reduction or promotion.

The revised symbolic audit passes 11 tests, including all previous cases and
three curved families with every field challenge checked. A repeated far row
over F_103 has two cancelling curve parameters, demonstrating why a one-root
argument would fail. `tools/rolling_potential_audit.py` independently checks
262,144 nonexceptional near-case potential steps in a selected F_17 model,
covering all 256 past-error sets, all 17 challenges, four error triples and
16 binary successor perturbations. It minimizes over every predecessor linear
codeword and all relevant successor constants. Four cancellation challenges
are excluded explicitly. These finite audits support the derivation; they do
not prove it in general or test full PCS/PBS security.

**Conditional opening consequence.** For one ordered-query batch, suppose
(1) a fixed-word availability reduction with failure epsilon_available is
valid for the actual hash/freeze model, (2) the proposed fixed-word RS lemma
holds over E, and (3) the actual virtual-all rolling FRI certifies proximity of
every projected scalar input at the chosen integer radii, with failure
epsilon_rolling against adaptive prover messages. In the ideal interactive
coin model, the preceding arguments give the sufficient false-opening bound

```
epsilon_available + epsilon_rolling
  + sum_l min(1, n_l*(n_l+1)/abs(E))
  + max_l (1-s_l/n_(l+1))^Q.
```

Partition frozen words by whether all layers have common nearby vector
codewords. In the far case, a layer can have a nearby projected word only on
its exceptional-weight set, unless the rolling certificate accepts an input
outside its promised radius. In the near case, uniqueness fixes the source
and every decoded ladder independently of the weights. A false evaluation
then has a bad fixed transition and is bounded by consistency sampling above.
These two cases, plus availability failure, are charged by addition, without
assuming independent events. Duplicated source rows across queries have one
unique decoded source. Applying coordinate-zero projection gives the earlier
base-table contract for base-matrix queries; it does not prove extension-
coefficient membership. No additional independence between queries is used.

This is a reduction with explicit premises, not a proof of those premises.
In particular, epsilon_rolling is not assigned the paper's scalar expression
for a stronger radius promise. The distance-sensitive candidate above supplies
an alternative conditional on its RS/prefix hypotheses and review. Actual
availability/FS/PBS unions remain uncertified. The displayed bound must be
clipped at one; it is not a security-matched parameter selection.

A complete concrete bound must account separately for:

- robust vector proximity and a common decoded source, including query/lane
  projection, rolling aggregation and arbitrary extension-query pullbacks;
- consistency of all sampled folds with those decoded words;
- matrix sumcheck, lookup compression, poles, reconstruction, NTT and all public
  endpoint/key/product/extraction relations;
- adaptive opening composition, Merkle availability/knowledge extraction and
  Fiat-Shamir compilation of the parent and extension children.

These terms are not independent by default. A sum of valid conditional bounds
can be used; multiplying unrelated errors cannot. In particular, 128 consistency
queries with blowup two do not by themselves give 128-bit complete security:
there are many obligations and additional unbounded terms. The profiler marks
`whole_security_matched=false` and `performance_gate=false` for every record.
The supplied [PipFRI paper](../../refs/2025-1354.pdf#page=21), Appendix C's
knowledge-soundness case analysis (PDF page 21), has a scalar unique-decoding
proximity tail `((1+rho)/2)^q_prime`, separately from consistency, field-size
and hash terms. Substituting rate rho=1/2 gives `(3/4)^q_prime`. At 128 queries
this term is approximately 2^-53.1248, and exact rational comparison requires
at least 309 queries for this term alone to be <=2^-128. Multiple obligations
and the other errors require additional budget. These are properties of the
published scalar upper-bound expression, not an attack or a claimed 53-bit
security level for our packed implementation. Transferring even this bound
requires the unresolved same-root/vector argument. Thus the current 128-query
experimental profile cannot be called a 128-bit profile on the strength of
that published conservative analysis. No benchmark parameters are changed.
The paper's separate matrix-weighted composition result in
[2025/719, Appendix F.3](../../refs/2025-719.pdf#page=68) is asymptotic and
conditional on its component hypotheses; it does not fill the concrete full-PBS
resource/error inventory here.

**No complete 128-bit theorem or security-matched baseline is claimed.** Without
those, this candidate remains experimental regardless of measured timing.

## Reproduction and acceptance

```
cargo test -p pcs --release --locked --lib --test polyfrim_adapter --jobs 2
cargo test -p vfhe --release --locked --test packed_canonical_polyfrim_pbs --jobs 2
RAYON_NUM_THREADS=8 cargo test -p snarks --release --locked --lib _unmasked_ --jobs 2 -- --ignored --nocapture --test-threads=2
cargo build -p vfhe --release --locked --example canonical_polyfrim_pbs --jobs 2
RAYON_NUM_THREADS=16 target/release/examples/canonical_polyfrim_pbs goldilocks polyfrim --full --iterations 1 --warmups 0
```

The example supports `babybear|goldilocks`, `polyfrim|polyfrim-compact|brakedown`, `--full`,
`--iterations`, `--warmups`, `--queries`, `--cold`, `--parallel-oracles` and
`--validation-batches`.
The last runs exactly 21 fresh independent proofs in ordered groups 1/4/16,
covering all NAND inputs; these are not aggregated PBS certificates. Encryption
is outside the complete timer. Trace construction, proving, trace release and
serialization are inside it; decoding, public verification and decryption are
separate. Cold mode also includes repeated public-key commitment preprocessing.
An altered public output is rejected on every iteration. The evaluator is
constructed only from public evaluation material.

Freeze the executable and capture sources before measurement:

```
python3 tools/archive_sources.py /tmp/unmasked-sources.tar.gz
python3 tools/compare_canonical_polyfrim.py --executable target/release/examples/canonical_polyfrim_pbs --source-archive /tmp/unmasked-sources.tar.gz --output target/performance/unmasked-new --full
```

The runner fixes 16 threads, uses one warmup and ten measured fresh proofs per
configuration by default, reverses field/backend order in a second session,
captures per-process GNU-time peak RSS and terminal exits, and guards against
overlapping builds/tests/benchmarks. It checks native keys/FHE parameters and
every ordered statement across modes, plus exact per-backend proof/setup hashes
across sessions. `--correctness-only --iterations 1 --warmups 0` permits a smoke;
`--correctness-only --validation` selects fresh-input validation. Such runs
cannot establish performance gates.

The Brakedown control is complete canonical version 11 with balanced block-RS
layouts, not the separately optimized v9 frontend or the legacy in-memory
artifact wrapper. Its default 544 queries and PolyFRIM's 128 are experimental
choices, not a security match. Comparing against this control alone cannot
establish a gain over the fastest fork path. Archived v9 and legacy measurements
remain separately labeled in `joint-pbs-phases.md` and `performance-results.md`.
Promotion still requires a complete security argument and fair controls, at
most twice the security-matched baseline bytes and at least 10% lower complete
median latency in both independent sessions. Otherwise keep existing defaults.

## Recorded feasibility results

Both original-size single-PBS PolyFRIM smokes serialize, decode, verify and
reject altered outputs. Matched canonical Brakedown controls use exactly the
same original FHE parameters, native public key material and public ciphertext
statement. The following complete times are **correctness-run observations**,
not isolated/security-matched performance evidence. Build/test/validation work
overlapped the smokes; no promotion follows.

| Field | Brakedown bytes | PolyFRIM bytes | Byte ratio | Brakedown complete seconds | PolyFRIM complete seconds | PolyFRIM peak GiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BabyBear sextic / width 8 | 361,248,811 | 864,192,360 | 2.392 | 12.946 | 505.654 | 14.82 |
| Goldilocks cubic / width 4 | 546,161,304 | 980,814,131 | 1.796 | 25.369 | 391.449 | 22.61 |

The BabyBear experiment already exceeds twice the engineering control's bytes.
Neither field supplies a latency-win claim. The construction therefore remains
an opt-in research reference; no default is changed. A full isolated ten-proof
native timing comparison has not been run, and no security-matched baseline
or complete 128-bit security argument is supplied.

The complete source-preserving build snapshot for the smoke executable is
`target/performance/unmasked-polyfrim/implementation-sources.tar.gz`, SHA-256
`e348b727024b1e03f9f52a5904b377967f6782d9b8c30513b928332b5019d09f`.
The frozen executable is `native-smoke.bin`, SHA-256
`7a87ddb5cc8fdf8cc43128e0d39ac3d77a4d6a489a5b9fd76fe2a98d89013853`.
Raw native logs, GNU-time resources, terminal records and the workload-checked
summary are in that directory. Its complete strict fresh audit has four accepted
controls and 68 rejected attacks. Existing wire controls, Brakedown truth tables,
72 core tests (including both non-base projection tests), four adapter tests
and three Python reader tests pass; the workspace all-target check passes.

The fresh toy validation completes eight successful processes (168 decoded
complete proofs) in `toy-fresh-validation/`. All four NAND inputs, 1/4/16 ordered
fresh groups, native key/FHE/statement consistency across backends and exact
per-backend hashes across reversed orders pass the runner. The separate
`validation-sources.tar.gz` captures subsequent test/tool/documentation additions;
the executable's build snapshot is the earlier implementation archive above.
Native all-four-input validation with reused public keys is tracked separately
in `native-four-inputs/manifest.json` is complete: sixteen decoded native proofs
cover all four NAND inputs for both backends and fields, using reused keys.

## Arithmetic and dictionary follow-up

The original frozen native validation continues unchanged. A separate follow-up
adds two arithmetic choices and a separate compact wire format:

- `authenticated::Parameters::with_base_field_folds<Base>()` checks that every
  coefficient and matrix entry is embedded in Base before using Base arithmetic.
  Otherwise it runs the original full-field fold. It does not project away
  non-base coordinates. All 1/4/16-query reference packets and all 32 transcript
  bytes match over both fields, widths 1/2/4/8 and base/non-base input combinations.
- `with_parallel_oracles()` parallelizes independent large FFT lanes and leaf
  hashes, retaining indexed lane order and canonical values. Additional column
  buffers increase temporary memory. Existing callers retain sequential oracles
  unless they opt in, including the unmasked adapter. The benchmark exposes
  `--parallel-oracles` explicitly. Sequential/parallel word and
  complete Merkle-tree references cover both fields and dense/base coefficients.
- `polyfrim::compact::Parameters<F,E>` is a distinct trusted canonical backend.
  It retains the same source owner and commitment, replacing each repeated hash
  in a packet with a u32 dictionary index. All roots, paths, field values,
  independent samples and sample order are reconstructed before strict checking.
  Dictionaries have unique hashes in first-use order; unused, duplicate,
  out-of-range and noncanonical first-use entries reject before changing the
  parent transcript. Its seven domains are disjoint from all prior backends
  (42 canonical domains in total). Hash outputs require ordinary `Eq + Hash`
  for dictionary lookup; Merkle authentication still uses the original full
  cryptographic hashes. No hash is truncated.

For a trusted compact context c, let Expand be the partial deterministic codec
and V_c the full-packet verifier using that context. The compact verifier is
exactly `Expand(packet) succeeds && V_c(Expand(packet)) accepts`. The codec tests
recover the byte-identical full packet, including every sampled response. This
adds no algebraic test or sampling-error term to the underlying conditional
protocol; it supplies neither the missing robust-proximity theorem nor its
Fiat-Shamir/extraction argument. Ordinary full packets remain available under
their original trusted context and wire format.

The standalone fold kernel (2^15 cells, width eight, two reversed arithmetic
orders) observes about 0.051/0.052 versus 0.0029/0.0031 seconds for BabyBear and
0.027 versus 0.0023/0.0025 seconds for Goldilocks. These are component observations
with exact output checks, not complete-PBS performance claims. The optimized
BabyBear complete smoke also reproduces the entire earlier 864,192,360-byte
proof hash `17541cba7087bfc9389c78d0e5795db49ae6f470b777d5f5b0f7d6fa42a42f72`.
Its raw complete time is 372.43 seconds, excluded from speedup comparisons
because native validation, builds and toy checks overlapped.

Both compact encrypted toy truth tables pass decoded verification and mutation
checks. All 36 fresh complete compact v11 audit certificates pass: two controls
accepted and 34 attacks rejected with strict child/actual-root replay. The
compact toy 1/4/16 runner completes 168 decoded proofs. All four optimized
native smokes also verify. Compact native packets are 506,089,439 bytes
(BabyBear) and 543,449,011 bytes (Goldilocks), respectively 1.40x and 0.995x
the recorded Brakedown controls. The full Goldilocks packet preserves its earlier
proof hash too. Parallel-oracle raw complete times are about 371/617 seconds
for compact BabyBear/Goldilocks; overlapping workloads exclude these from
performance comparisons. Parallel oracles remain opt-in because these runs
do not establish a benefit. Terminal manifests are under
`compact-toy-validation/` and `optimized-native-smokes/`. The follow-up executable and exact build snapshot are in
`optimized-build/`; subsequent test-only changes are preserved separately.

```
# Same FHE settings and complete public verification; experimental compact path.
RAYON_NUM_THREADS=16 target/release/examples/canonical_polyfrim_pbs babybear polyfrim-compact --full --iterations 1 --warmups 0
python3 tools/compare_canonical_polyfrim.py --executable /path/to/frozen-binary --source-archive /path/to/executed-sources.tar.gz --output target/performance/compact-new --candidate polyfrim-compact --full
```

The runner's default candidate remains `polyfrim`. Compact support is explicit;
no existing backend is selected differently and no promotion gate is relaxed.


A separate pooled-sumcheck arithmetic change initializes products with coefficient
+1 or -1 by copying or negating the first affine factor. The remaining factors,
field equations and verifier are unchanged. Independent scalar-reference tests
cover both fields and batches 1/4/16, including repeated sources and affine
factors. An initial native pilot reproduces every complete Brakedown proof byte;
its single-sample improvements (about 4% BabyBear, mixed Goldilocks) do not meet
the 10% gate. `tools/compare_canonical_kernels.py` requires exact full-proof
fingerprints before comparing timing, and requires a warmup and ten measured
proofs unless explicitly used for correctness only.

The hoisted first-factor implementation also completes eight original-size
before/after proofs in two reversed field/mode orders. Every full proof digest,
parameter, key and statement matches the frozen unchanged Brakedown control.
Single-proof pilot times fall 12.791→12.139 / 12.730→12.159 seconds for BabyBear
and 17.502→17.043 / 17.265→16.810 seconds for Goldilocks (4.49–5.10% / 2.62–2.63%).
These are correctness-only pilots without warmups or ten measured samples;
they cannot certify a latency gain. Terminal evidence and exact source/binary
hashes are in `target/performance/unit-coefficient-pbs/hoisted-native-pilot/`.
The latest release sumcheck tests, eight complete/compatibility tests, seven
Python checks, formatting checks and locked workspace all-target check pass.


## Evaluated and removed: coefficient hoisting and degree extrapolation

A separate frozen candidate sums each d-factor term at only d+1 integer nodes,
scales the sum by its coefficient once, then recovers higher integer nodes with
finite differences. This preserves the polynomial mathematically, but
Goldilocks lazy representatives initially changed serialized proof messages.
The independent scalar test caught this with general extension coefficients.
A conservative field capability restricted reassociation to BabyBear and its
extensions; Goldilocks retained its earlier arithmetic. Both fields then passed
all scalar and complete tests, the workspace check, and eight decoded native
before/after proofs with identical full proof digests in two reversed orders.

The candidate did not demonstrate an improvement over the simpler retained
first-factor kernel. Compared with the original control, BabyBear pilot times
were 12.704→12.158 and 12.665→12.105 seconds (4.30–4.42%); Goldilocks was
24.213→23.871 and 24.296→23.877 seconds (1.41–1.72%). These correctness-only
single-proof pilots have no warmups or ten-sample timing claim, and their
Goldilocks controls vary substantially from earlier pilots. The additional
field capability and extrapolation machinery were removed from the worktree.
The stronger differential cases remain, and all 27 retained-kernel sumcheck
tests pass after removal. Exact candidate sources, binaries and
terminal records are preserved under
`target/performance/unit-coefficient-pbs/reassociation-build/` and
`reassociation-native-pilot/`. The retained native kernel is the preceding
`hoisted-build/` implementation; the final source adds test-only cases.

Further work should split complete lookup cost into preparation, helper
commitment, sumcheck, terminal evaluation and PCS openings before selecting
another arithmetic change. Neither pilot establishes the requested 10% gain
or the missing whole-proof security argument.


## Complete lookup cost breakdown

Complete canonical v10/v11 provers now accumulate existing lookup counters in
`packed_pbs::ProverStatistics::canonical_lookup`. These cover comparison
lookups in the two main radix decompositions, a subset of `decomposition`;
final key-switch lookups, borrow-root commitments and reconstruction proofs
are excluded. Default entry points preserve their signatures and forward to
`prove_with_statistics`. No counter is serialized or absorbed into a transcript.

The example emits `HB_CANONICAL_LOOKUP_PROFILE` per completed proof. It checks
that the sum of subphases fits the decomposition time and that shared sum/identity
checks use `sumcheck`, with `zero_check` zero. The optional
`tools.compare_canonical_polyfrim.read_lookup_profiles` reader checks scope,
ordered proof correspondence, finite nonnegative durations and time containment.
Eight Python tests include malformed profile rejection. All eight release
complete/compatibility tests and the locked workspace all-target check pass.

Two original-size Brakedown profiles verify and reproduce the full original
control proof digests. These single-proof diagnostics are not timing comparisons:

| Field | Preparation s | Helper commitments s | Sumcheck s | Terminal evaluation s | Openings s | Enclosing decomposition s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BabyBear | 1.751 | 2.108 | 1.287 | 0.461 | 0.671 | 7.800 |
| Goldilocks | 2.842 | 5.816 | 1.056 | 0.719 | 0.718 | 14.697 |

The next optimization target is helper commitment and preparation cost, rather
than further sumcheck arithmetic or source-terminal parallelization. In
particular, the current indexing loop allocates a tuple vector per source row;
that is a candidate to remove while retaining tuple hashing and order. Helper
commitment changes need separate memory and encoding measurements before
introducing additional concurrency.

Frozen binaries, exact build sources and both terminal native records are under
`target/performance/unit-coefficient-pbs/lookup-profile-build/` and
`lookup-native-profile/`. The profile reader tests were added after the Rust
build snapshot. The initial diagnostic checker incorrectly required floating
JSON syntax for zero; the corrected checker reused the successfully completed
BabyBear proof and ran Goldilocks once. No proof was rerun to repair that checker.
The manifest records this distinction. Whole-security and promotion remain open.


## Reused tuple buffers

Canonical shared lookup indexing now allocates one tuple buffer per trusted
request and reserves its row-index vector once. Each row overwrites the tuple
and borrows its slice for the existing `HashMap<Vec<F>, usize>` lookup; slice
and vector hashing/equality preserve the same tuple keys and public-table order.
Counts, scalar operations, child transcripts and source ownership are unchanged.

All eight release complete/compatibility tests pass. Eight native before/after
proofs in reversed field/backend orders match every full proof digest and setup
fingerprint. Main-lookup preparation in the single-proof pilots falls from
1.749/1.749 to 1.682/1.691 seconds for BabyBear and 2.833/2.843 to 2.703/2.708
seconds for Goldilocks. These are correctness-only diagnostics, not latency
certification; Goldilocks complete time is mixed between the two orders.
`tools/compare_canonical_kernels.py` now reports checked lookup subphase medians
when both frozen builds emit those diagnostics. Evidence and exact sources are
under `target/performance/lookup-buffer/build/` and `native-pilot/`.


## Zero-row Block-RS encoding

The Block-RS row encoder now fills the output with raw zero when every input
coefficient has the canonical raw-zero representation. The existing length,
NTT-domain and root checks still run first. Other inputs use the previous NTT
path, including noncanonical Goldilocks zeros. By linearity the zero polynomial
has zero evaluations. A retained pre-shortcut NTT reference additionally checks
exact raw output values over both fields, multiple domain sizes and sparse/dense
inputs, including a Goldilocks input whose raw value is the modulus. Output
buffers initially contain nonzero values, checking that the shortcut overwrites
the complete codeword.

All 90 PCS tests pass (two additional profiling tests remain ignored), along
with eight release complete/compatibility tests, eight Python checks and the
locked workspace all-target check. Eight native before/after proofs in reversed
orders preserve every complete proof digest and setup fingerprint. Compared
with the tuple-buffer build, single-proof BabyBear complete times are
12.051→11.964 / 12.044→11.966 seconds and Goldilocks
23.565→23.531 / 23.840→23.588 seconds. Helper-commitment timings also decrease,
but the complete improvement is small and these correctness-only pilots do not
establish a performance gate. Exact builds and terminal records are under
`target/performance/zero-row-encoder/build/` and `native-pilot/`.

This shortcut changes neither PCS parameters nor proof bytes. It does not
change source ownership, query counts, transcript domains, privacy or the
underlying protocol's unproved security obligations. A more promising next
commitment experiment is to hash identical columns of entirely zero tables
once, retaining every original Merkle leaf and strict authentication path.


## Canonical-zero guards and serialized reference checks

The archived first zero-row experiment used `Field::value()` in both its guard
and its reference comparison. Inspection found that Goldilocks normalizes that
accessor, so those tests checked mathematical values rather than exact wire
representations. The archived native full-proof byte comparisons remain valid
for their actual fixtures, but the earlier generic raw-value claim was too
strong. Current guards require both `is_canonical()` and equality to zero;
noncanonical Goldilocks zero inputs take the original path. Reference codeword
tests now compare bincode-serialized bytes directly. This correction introduces
no new parameters, transcript framing or accepted proof language.

The zero-table column-hash experiment checks canonical zero in the retained
input and the actual encoded output. Only then can all serialized column
preimages be identical: they have the same length and zero elements in every
position. It computes that leaf hash once, retains the full leaf vector and
runs the original Merkle construction. No sampled column, query or path is
removed. New reference tests reconstruct the previous row encoding and
per-column hashes, comparing serialized codewords, the entire Merkle tree,
all paths, depth and leaf count for zero, sparse, dense and noncanonical-zero
cases in both fields.


The corrected build passes 92 PCS tests (plus two ignored profiles), eight
complete/compatibility tests, eight Python checks and the locked workspace
all-target check. All eight native before/after proofs in reversed field/mode
orders preserve every complete proof digest. BabyBear pilot complete times are
11.980→11.855 / 11.907→11.770 seconds; Goldilocks is
16.888→16.073 / 16.486→16.546 seconds. These single-proof correctness pilots
show a small BabyBear change and mixed Goldilocks timings, not the required
10% gain. Exact build sources, binary hashes, final serialized-reference tests
and terminal records are under `target/performance/zero-column-hashes/`.
The initial guard-test build required a missing test-only Serialize bound; the
corrected full PCS run is `build/final-pcs-tests.log`, and complete regressions
are `build/final-complete-tests.log`. Earlier component logs do not replace those.

### Next larger experiment: helper basis width

The coefficient bridge already supports arbitrary helper widths at least the
extension degree; scalar source packing alone needs a power of two. An opt-in
trusted profile could retain source width eight/four while packing reciprocal
helpers at exactly degree six/three. It must use the helper's own width for
coefficient tables, helper queries and projection, while source pullbacks retain
the source width. The main decomposition, final key switch and complete verifier
must all bind and validate the separate trusted geometries. Existing defaults
and old fingerprints must remain intact.

Packed width and RS symbol width must remain separate. The current balanced
constructor uses the packed width for RS blocks too: blindly changing eight to
six or four to three can double the power-of-two RS domain and increase encoded
size. A first comparison should keep the old RS symbol width, row split, domain,
rate and query count, changing only meaningful helper lanes. The existing
`Parameters::new_encoded` supports those independent dimensions. Prove the
padding/projection commuting relation and re-audit concrete error terms before
calling profiles security-matched; the missing whole-proof argument remains.

Future isolated timings also need recorded CPU affinity. This host is an
Intel i9-12900K: allowed logical CPUs 0–15 report nominal maxima of 5.1–5.2 GHz,
while 16–23 report 3.9 GHz. Earlier pilots inherited affinity 0–23. This is a
potential source of variation, not an established explanation of any sample.
Both compared builds should use the same explicit CPU set, recorded with their
16-thread setting, warmup and ten measured proofs in both reversed orders.


## Opt-in helper basis packing

`canonical_polyfrim_pbs --basis-helpers` now offers a Brakedown-only experimental
layout with six/three helper lanes, retaining source widths eight/four. It
clones the original helper RS encoder and row split, keeping its symbol width,
message blocks, domain and query count. Source and final-source contexts and
keys are unchanged. No default profile or proof format is changed. The complete
verifier validates the actual helper width from trusted parameters and binds
its context; it accepts only the original source width or the extension degree.
Key preprocessing, which has no extension-type parameter, checks positive
bounded helper widths and the original scalar variable counts. The complete
extension-aware verifier supplies the stricter width check.

Coefficient queries and claims now use each helper's own width; source scalar
pullbacks keep their original width. For basis embedding P and projection E,
E P = I and M_k(a) P = P M_D(a). Products of the ordered multiplication matrices
therefore commute with appending/removing unused helper lanes. The zero-variable
post-projection handles constants too. Direct tests compare degree-sized helpers
against padded helpers with deliberately nonzero ignored lanes at dimensions
zero through four. This is evaluation of the same extension-valued polynomial;
it asserts neither field-membership of malicious extension coefficients nor a
new proximity theorem.

Both new encrypted NAND truth tables, the existing four PolyFRIM truth tables,
two ordinary Brakedown regressions and two frozen wire controls pass. Cross-layout
proof replay and undersized-helper parameters reject. Fourteen extension mapping/
lookup tests pass, including the two padding identities, and four RS lift tests
cover the changed number of random-test rows. The strict fresh full-certificate
audit passes 72 cases over versions 10/11 and both fields: four controls accepted,
68 attacks rejected. Its initial run exposed hardcoded source widths in the
independent replay; only helper-query/claim dimensions were corrected there.
The checker retains all its original reference and production acceptance checks.

`compare_helper_basis.py` freezes executables/sources, reverses field/layout
order, verifies fresh statement/key/setup equality and identical RS encoder
hashes, and permits only the helper packed widths to differ in layout metadata.
It requires explicit CPU affinity, a warmup and ten measured proofs for timing;
`--correctness-only` and `--validation` remain diagnostic modes. Per-layout proof
fingerprints must match across reversed orders. New metadata captures separate
source/helper widths, the full RS layouts, encoder digests and context digests.
All 168 fresh toy proofs in ordered groups 1/4/16 pass both layouts in both
orders, with all four NAND inputs and reused public-key preprocessing.

Removing padding also reduces random-test entropy. The finite-subset extension
in `block-rs.md` uses a fixed h-dimensional subspace of the b-dimensional RS
symbol field, giving p^h in the conditional fixed-word exceptional term rather
than p^b. The runner records these per-opening bits; it does not infer a full
128-bit argument from them. Availability, structured-response composition,
adaptive/Fiat–Shamir soundness and the complete error inventory remain required
before declaring a security match or promoting a profile.


Native four-input validation is complete: 32 decoded complete proofs cover all
NAND inputs, reused keys, both layouts, both fields and two reversed orders.
The padded default additionally matches all eight original native proof/setup/
statement fingerprints from `unmasked-polyfrim/native-four-inputs/`, before the
current arithmetic/layout work. `build/default-native-fingerprints.json` records
that comparison. The checked fresh audit is `build/checked-fresh-audit.json`.

| Field | Padded complete median s, orders 0/1 | Basis complete median s, orders 0/1 | Reduction | Maximum byte ratio |
| --- | ---: | ---: | ---: | ---: |
| BabyBear | 10.172 / 10.163 | 9.619 / 9.604 | 5.43% / 5.49% | 0.9763 |
| Goldilocks | 20.626 / 20.494 | 19.875 / 19.900 | 3.64% / 2.90% | 0.9792 |

These runs pin 16 logical CPUs (0–15 on this host), use four measured proofs and
no warmup, and are explicitly correctness-only. They do not establish the
required ten-proof timing gate, and observed reductions are below 10%. Do not
compare these seconds directly with earlier runs that inherited a different CPU
set. A cold comparison and the full timing/security gates remain incomplete.

The per-opening conditional fixed-word exceptional terms are 157.44/175.40 bits
for BabyBear main/final helpers and 162.00/181.96 bits for Goldilocks. They account
for the smaller p^h challenge set. They exclude opening/proof unions, sampling,
other algebra errors and adaptive/hash/Fiat–Shamir composition. Values above 128
here are not a certificate of 128-bit proof security or a security match.

Executed native build sources are `helper-basis/validated-build/`, executable
SHA-256 `7ce0e18aca29d7cb52200039cc86fb2e6408e94c0895487a1109f882a6762ffa`,
source archive SHA-256
`8ea5fed908e44a8a57ee8b36643c59889296ac97976bfaa2d56f1a66c45b697c`.
`native-four-inputs/manifest.json` and `toy-validation/manifest.json` record the
terminal runs and driver hashes. The initial `build/` binary/source pair was
caught overlapping a diagnostic-metadata edit and was not used for validation;
`build/provenance-note.json` explains its replacement. The toy executable in
`final-build/` has the same byte hash as the validated native executable; its
source snapshot predates test-only audit replay updates. Later driver metadata
also explicitly distinguishes requested defaults from the executed 21-proof,
zero-warmup validation schedule.

```
RAYON_NUM_THREADS=16 target/release/examples/canonical_polyfrim_pbs babybear brakedown --basis-helpers --full --iterations 4 --warmups 0
python3 tools/compare_helper_basis.py --executable /path/to/frozen.bin --source-archive /path/to/sources.tar.gz --output target/performance/helper-basis-new --cpus 0-15
# For correctness-only fresh groups, add --validation --correctness-only.
```

Column gathering now uses bounded adjacent-column tiles for domains of at least
128 columns. The tile is a power of two, capped at eight columns and selected
against a 32 KiB scratch target; one-column tiles retain the original path.
The encoded cache remains row-major. Every serialized leaf preimage, leaf
position, authentication path and proof byte is preserved. Reference tests
compare all leaves and paths against the original gather, including partial
tiles, sparse inputs and noncanonical zero representations in both fields.

The isolated eight-proof native pilot in
`target/performance/column-tiles/native-pilot/` compares this change against
`helper-basis/validated-build/`, with padded default helpers in both modes.
BabyBear improves 11.43%/10.51% and Goldilocks 9.83%/9.35% across reversed
orders. Every complete proof is byte-identical to its control. This pilot uses
one proof per process and no warmup, so it does not establish the timing gate.
The full warm comparison in `column-tiles/native-cumulative-warm/` instead
compares all accumulated prover optimizations against the initial frozen v11
control. It must not be described as the isolated effect of tiling. Both runs
pin CPUs 0–15 and preserve the original FHE parameters and output key.

The cumulative warm run is terminal and passes its engineering latency gate:
88 complete decoded proofs verify, all corresponding parameter/key/statement/
proof fingerprints match before/after and across orders, and proof bytes are
unchanged. Each of eight processes uses one warmup and ten measured fresh
statements, with 16 Rayon workers pinned to logical CPUs 0–15.

| Field | Control median s, orders 0/1 | Optimized median s, orders 0/1 | Reduction |
| --- | ---: | ---: | ---: |
| BabyBear | 16.0144 / 16.1634 | 9.5664 / 9.5346 | 40.26% / 41.01% |
| Goldilocks | 27.0741 / 26.9961 | 16.2260 / 16.2700 | 40.07% / 39.73% |

This is a cumulative execution comparison against the initial frozen complete
v11 control, with padded default helpers in both modes. It does not isolate
column tiling or compare against the fastest complete v9 fork. The warm timing
excludes reused public-key commitment preprocessing. The separate cold run is
`column-tiles/native-cumulative-cold/`. Complete security remains outstanding;
fastest-fork results follow below. `whole_security_matched` and `promotion_gate`
remain false.
The manifests and copied executed drivers are authoritative for provenance,
proof schedules, CPU affinity and terminal results.

The cumulative cold comparison is terminal and also passes the repeated
engineering latency gate. All 88 complete decoded proofs verify and preserve
exact proof/fixture fingerprints before/after and across reversed orders.
The CPU affinity, warmup and measurement schedule match the warm run; cold
adds public-key commitment preprocessing on every proof.

| Field | Cold control median s, orders 0/1 | Cold optimized median s, orders 0/1 | Reduction |
| --- | ---: | ---: | ---: |
| BabyBear | 16.6792 / 16.6834 | 9.7594 / 9.7846 | 41.49% / 41.35% |
| Goldilocks | 29.8475 / 29.8946 | 17.4309 / 17.4727 | 41.60% / 41.55% |

`column-tiles/native-cumulative-cold/checked-cold.json` independently replays
the log validators, fingerprint comparisons and reported medians and captures
all raw-log hashes. The matching warm check is `checked-warm.json`. These
176 warm/cold proofs establish engineering results for the identical v11
protocol, not whole security or a comparison with the fastest complete fork.

The fastest-fork comparison now has an explicit workload adapter and driver,
`tools/compare_canonical_v9.py`. The canonical example's `--v9-fixture` skips
the two initial encryptions exactly as the frozen complete-v9 benchmark does,
then encrypts fresh `(0,0)` inputs for each proof. Its metadata explicitly
records the selected fixture, and normal four-input schedules remain default.
The driver requires matching FHE parameters, evaluation-key fingerprints and
every encrypted statement/output, while allowing the two protocols' proof
bytes to differ. Both versions must pass their full decoded verifiers, and
each version must reproduce its own certificates across reversed orders.
One warmup and ten measured proofs per process, native parameters and explicit
CPU affinity are required for timing eligibility. Security matching and
promotion remain false even if engineering thresholds pass. All 40 Python
comparison checks pass, including the legacy toy dimensions. The first toy
preflight correctly rejected a 32-versus-21 LWE fixture mismatch; its
`toy-pilot/failure.json` records the terminal validation failure. The corrected
adapter uses dimension 32 only for the opt-in legacy toy fixture; default toy
and all native parameters are unchanged. The replacement release build passes,
and `canonical-v9/toy-pilot-v2/` verifies all 16 complete proofs with matching
keys/parameters/encrypted statements over both fields and reversed orders.
`canonical-v9/default-regression/` separately preserves every default-mode
proof byte in 16 toy proofs against the frozen column-tiling build. These
correctness-only runs do not establish latency gains. The full native warm
comparison in `canonical-v9/native-warm/` is now terminal: all 88 complete
proofs verify, and FHE parameters, evaluation keys and every encrypted
statement/output match across protocols. Each protocol's own proof bytes are
identical across reversed orders. All eight processes exit successfully, use
one warmup and ten measured proofs, and pin 16 workers to CPUs 0–15.

| Field | v9 median s, orders 0/1 | Canonical v11 median s, orders 0/1 | Reduction | Maximum byte ratio |
| --- | ---: | ---: | ---: | ---: |
| BabyBear | 15.4781 / 15.4953 | 9.7343 / 9.5784 | 37.11% / 38.19% | 1.13612 |
| Goldilocks | 26.7635 / 26.7612 | 16.2149 / 16.2911 | 39.41% / 39.12% | 1.38388 |

The engineering gate passes in both fields/orders. `checked-native.json`
replays the complete log validators, workload/repeated-wire comparisons and
median/byte calculations, verifies copied binary/source/driver hashes, and
records every raw-log hash. Both protocols remain conditional experimental
profiles: this is not a security-matched comparison or a completed 128-bit
argument, and promotion stays disabled. The v9 fixture uses fresh `(0,0)`
inputs; four-input correctness is covered by the separate native validation.
This run measures reused preprocessing. The separate repeated-preprocessing
cold comparison above is against the frozen v11 control, not v9.

```
python3 tools/compare_canonical_v9.py --v9-directory target/performance/parallel-scalar-native --v9-sources target/performance/parallel-scalar-messages/build-sources.tar.gz --canonical /path/to/new-frozen.bin --canonical-sources /path/to/new-sources.tar.gz --output target/performance/canonical-v9-new --cpus 0-15
# First validate the new build with --toy --correctness-only --iterations 2 --warmups 0.
```

## Completion audit for the agreed experiment

This audit preserves the full acceptance criteria. It is not a completion or
promotion claim; timing evidence and a cryptographic theorem are separate gates.
Paths below are relative to `target/performance/` unless they name source files.

| Requirement | Current evidence | Status |
| --- | --- | --- |
| Original FHE dimensions, output key and public evaluation contract | Native complete records require N=1024, input/output dimension 728 and matching FHE/key/statement digests; evaluator uses public evaluation material | Native correctness verified |
| Reconcile legacy wrappers versus standalone complete proofs | `performance.md`, this document and `implementation-status.md` distinguish decoded complete verification, in-memory wrappers and conditional security inventories | Documented |
| Implement unmasked canonical PolyFRIM without mask sessions | `pcs/src/matrix_weighted/polyfrim.rs`, strict adapter tests, separate trusted backend domains | Implemented and tested; experimental |
| Bind every PBS stage and evaluation key in complete v11 | Complete native four-input records and fresh audits: `unmasked-polyfrim/native-four-inputs/manifest.json`, `checked-fresh-audit.json` (72 cases) and `compact-fresh-audit-checked.json` (36 cases) | Correctness/attack tests pass; these do not prove soundness |
| Both fields, reused keys and all NAND inputs | Terminal native four-input runs plus the 88-proof cumulative warm comparison and default fingerprint checks | Verified for the recorded builds |
| Native warm latency >=10%, repeated reversed order with 1 warmup/10 measured proofs and <=2x bytes | `column-tiles/native-cumulative-warm/checked-warm.json`: 88 wire-identical proofs; 39.73–41.01% lower medians; byte ratio exactly 1 | Engineering gate passes against initial frozen v11 control only |
| Separate cold timing | `column-tiles/native-cumulative-cold/checked-cold.json`: 88 wire-identical proofs and 41.35–41.60% lower medians in both orders | Engineering gate passes against initial frozen v11 control only |
| Compare fastest complete fork fairly | `canonical-v9/native-warm/checked-native.json`: 88 complete native proofs, repeated 37.11–39.41% lower medians and <=1.384x bytes; adapter/driver pass 40 Python checks | Engineering gate passes; security matching unproved |
| Complete 128-bit proof security and security-matched baseline | Fixed-word/availability proposals and conditional inventories do not complete same-root vector proximity, adaptive/FS composition or the full error/resource argument | Not established; promotion disabled |
| Fragmented packed PipFRI and integer/convolution changes | Fragmentation is deferred; existing complete-path profiling puts NTT below lookup/decomposition cost | Deferred as agreed; no claimed speed benefit |

The original full-source PolyFRIM native experiment fails the intended speed
criterion by a large margin (about 39x/19x the original v11 control's medians
on BabyBear/Goldilocks), and BabyBear also exceeds twice its bytes. Compact
encoding reduces bytes but does not remedy the large proving-time cost.
Neither candidate is promoted. The successful execution optimizations retain
Brakedown's existing protocol and exact proof language; they cannot establish
absolute security of that protocol by themselves.

## Observed complete-verifier opening inventory

The benchmark's opt-in `--opening-inventory` wraps its trusted PCS parameters
with a delegating observer. It records successful `CanonicalPcs::verify` and
`verify_many` API invocations: role, logical variables, packed width, ordered
claim count, context fingerprint and actual public root bytes. It preserves
the underlying proof/state types and all backend domains, normalization and
verification equations. Prover calls delegate without recording. The log is
cleared immediately before the decoded complete verifier and captured before
the altered-output rejection replay. Calls inside a delegated backend are not
recursively counted as additional API invocations.

The separate `HB_CANONICAL_OPENING_INVENTORY` record declares this scope and
excludes altered-output replay. The strict reader checks ordinal/backend,
all four role geometries and contexts, root encoding, kinds and positive claim
counts. Repeated calls to one root remain separate observations. Instrumented
records require an explicit reader policy and are rejected by ordinary timing
readers; none of these correctness-only runs establishes timing or security.

The release build and example check pass, as do 42 Python comparison tests.
`opening-inventory/default-regression/` preserves every default proof byte
against the frozen pre-observer build in 32 toy proofs: both fields, all four
NAND inputs, before/after modes and reversed orders. In
`opening-inventory/toy-validation/`, 12 complete proofs compare observation
on/off for both fields and Brakedown/full/compact PolyFRIM. Every corresponding
proof, setup and statement fingerprint is unchanged, and all scope checks pass.

| Field | Successful calls, roles source/helper/final-source/final-helper | Distinct context/roots per role | Total calls |
| --- | --- | --- | ---: |
| BabyBear | 82 / 8 / 60 / 7 | 39 / 8 / 28 / 7 | 157 |
| Goldilocks | 141 / 16 / 102 / 13 | 66 / 16 / 46 / 13 | 272 |

These counts agree across the three backends in the recorded toy fixture.
They are **observed valid-trace counts**, not an adversarial upper bound, hash
freeze schedule or a complete error inventory. In particular, proof-root count
alone does not count repeated opening experiments. Native Brakedown tracing
now passes four on/off proofs and preserves both original archived native
fingerprints, including complete proof bytes, FHE/key/statement/setup digests.
Its observed counts differ from the toy fixture:

| Field | Native calls, roles source/helper/final-source/final-helper | Native distinct context/roots per role | Total calls |
| --- | --- | --- | ---: |
| BabyBear | 84 / 8 / 61 / 7 | 41 / 8 / 29 / 7 | 160 |
| Goldilocks | 146 / 16 / 103 / 13 | 70 / 16 / 47 / 13 | 278 |

Both native fields include a batch of 13 ordered claims. The two native
PolyFRIM observations are also terminal and match these counts and role
histograms. `native-polyfrim/original-native-fingerprints.json` verifies both
original full PolyFRIM proof/fixture fingerprints exactly. The observer does
not record backend-internal ladder/FRI root freeze points, so it cannot supply
a Merkle or Fiat-Shamir query-resource budget. The schedule ceiling below is
separate from these observed counts.

```
python3 tools/audit_canonical_openings.py --executable /path/to/frozen.bin --source-archive /path/to/sources.tar.gz --output target/performance/opening-inventory-new --cpus 0-15 --compare-disabled
# Add --full --backends brakedown for the native Brakedown observation.
```

## Candidate opening-term worksheet

`tools/polyfrim_opening_terms.py` revalidates completed observation logs and
sums the proposed vector-projection, distance-sensitive rolling and nearby-
consistency terms for each observed successful API call. It uses exact
fractions, the recorded E degree and logical geometry, the constant adapter's
dummy variable where necessary, and the terminal error radius zero. Repeated
calls are charged repeatedly. The rolling radius is 1/8 at rate 1/2; the
consistency term uses the exact integer radii and worst transition, rather
than only the asymptotic 7/8 miss fraction.

This is an **opening-part worksheet for observed valid traces**, not a full
security budget. It excludes availability/hash failures, algebraic PBS stages,
adaptive/Fiat-Shamir compilation and proof of a trusted-shape maximum. The
underlying RS/rolling derivations also remain for review. `--copies` repeats
the observed count pattern; it does not certify counts across other proofs.
`--queries` evaluates hypothetical queries without changing any recorded proof.
Every report keeps `whole_security_certified=false` and `promotion_gate=false`.

Six worksheet tests pass, covering the dummy constant, terminal handling,
the tested nearby-fold geometry, field-error persistence, schedule ceilings
and invalid inputs. Native hypothetical fractions can exceed Python's decimal
conversion limit; `hex-rational-v1` stores exact numerator/denominator pairs
in hexadecimal without disabling that guard. A >20,000-bit round-trip test
checks lossless reporting. Earlier decimal-form reports remain historical.
For 21 copies of the toy trace, the current 128-query profile does not reach
a 2^-128 target even for these terms alone. A hypothetical 768-query evaluation
puts these opening terms below that target, but this neither evaluates a new
proof nor establishes full security or a recommended/promoted profile. Native
terms must use native observations; the differing call counts above rule out
substituting the toy inventory.

```
python3 tools/polyfrim_opening_terms.py --run target/performance/opening-inventory/toy-validation --copies 21 --output /tmp/toy-opening-terms.json
# Optional --queries 768 is a hypothetical worksheet only.
```

With the completed native observations, 21 copies at the recorded Q=128 do
not reach the opening-term target. The hypothetical Q=768 evaluation does,
before the excluded terms, using observed calls. Neither result is a full
security conclusion or a measured 768-query proof.

### Conditional per-owner schedule ceiling

`--schedule-ceiling` instead charges the public per-owner allowances from
`Config::canonical_opening_budget` and all logical owner slots, without
subtracting aliases or relying on one execution's call count. It is limited
to the selected canonical-v11 one-pair profile with radix bits 8/5. Let d and
s be the respective field digit counts, k the packed width and
r=ceil(log2(LWE_dimension)). The resulting ordered-query ceilings are

```
source:       4*k*d + 6*k + 14*d + 24 + r
helper:       4*d
final source: (s+1)*(2*k+6) + s+2
final helper: 2*s.
```

The worksheet emits the owner categories, multiplicities and per-owner
allowances used in each sum. Main owners comprise 2d+1 coefficient tables,
2d+1 evaluation tables, 2d trusted key tables, two decomposition inputs,
2(d+1) borrows, four accumulator roles and two monomial evaluation tables.
Final owners comprise s+1 coefficient/evaluation tables each, s trusted key
tables, one input and s+1 borrows. Helper counts are 2d and s, with allowance
two per helper. Each API call has at least one ordered query; charging every
allowed query as its own batch overcounts calls and remains conservative
under aliasing/batching, **provided the existing per-owner allowances cover
every accepted verifier path**. That is an explicit review premise, not a
conclusion from the observed traces.

| Field | Role ceilings (source/helper/final-source/final-helper) | Sum |
| --- | --- | ---: |
| BabyBear native | 266 / 16 / 185 / 14 | 481 |
| Goldilocks native | 298 / 32 / 211 / 26 | 567 |

Observed ordered-query counts and distinct roots are checked against this
model. The outer private root schema is checked as 8d+4s+16 (76/132), with
2d+s additional trusted key slots; this differs from the older complete-v9
inventory. The ceiling-mode hypothetical Q=768 calculation for 21 copies
still puts these opening terms below 2^-128, under the stated derivations and
schedule premise. It does not cover the excluded hash, FS or other PBS errors
and selects no new parameters. Reports remain unpromoted and uncertified.

```
python3 tools/polyfrim_opening_terms.py --run target/performance/opening-inventory/native-polyfrim --copies 21 --queries 768 --schedule-ceiling --output /tmp/native-opening-terms.json
```

### Additional canonical key-switch input equality term

The canonical final key-switch verifier also authenticates its public input
table against a private input commitment. `public_input_query` in
`snarks/src/packed_key_switch/canonical/protocol.rs` binds the commitment,
context and normalized public table before drawing k base-field challenges
per variable. `verify_public_input` then checks the public table's evaluation
with a PCS opening. The older complete-PBS budget calculator does not include
this extra commitment and must not be applied unchanged to v11.

Conditional on a fixed available committed table and an evaluation-binding
PCS, a different input table passes this equality check with probability at
most `min(1, n*((2*k-1)/p)^k)` for n variables and independent uniform
interactive challenges. To see this, subtract the two tables. At any fold
before the difference first becomes zero, at least one pair of packed blocks
defines a nonzero interpolation polynomial of degree at most 2k-1 on the
alternating Boolean/lane nodes used by `challenge_pair`. All k independent
lane evaluations must be roots for the entire folded difference to vanish.
That conditional probability is at most `((2*k-1)/p)^k`. Union over the n
possible first-vanishing folds. A nonzero constant table cannot pass, so n=0
has zero algebraic error. PCS opening errors are charged separately.

`tools/packed_budget.py::fixed_table_equality_bound` records this term without
assuming an RS geometry or a particular PCS. Its small-field tests enumerate
all 624 nonzero two-lane, one-variable tables over F_5 and all 25 challenges;
the worst error exactly attains 9/25. Two-variable controls also enumerate all
625 challenge sequences, including intermediate collapse. These checks support
the local derivation; they do not establish availability, adaptive Fiat–Shamir
composition or the other algebraic terms of the complete PBS argument.

For the observed native final-source layouts, n=8/k=8 for BabyBear and n=9/k=4
for Goldilocks. This term remains an explicit additional obligation when
assembling a canonical-v11 budget, regardless of the chosen PCS query count.
The exact-rational record and source hashes are in
`target/performance/opening-inventory/key-switch-input-equality.json`.
The respective one-proof bounds are approximately 2^-213.00 and 2^-241.60;
union over 21 proofs gives approximately 2^-208.61 and 2^-237.21 for this
term alone. The 21 budget tests pass. No proof parameters have changed.

### Canonical NTT algebraic terms

`tools/packed_budget.py::canonical_ntt_algebraic_bounds` separately records
the non-PCS terms of `packed_ntt::verify_canonical`. With n source variables,
packed width k and polynomial size N, let c=log2(N/k) and r=n-c. All are
derived from the canonical source geometry, including padding. For L links,
the terms are

```
row identity:             L * min(1, (r/p)^k)
coefficient compression:  L * 2*k * min(1, c*((2*k-1)/p)^k).
```

For a false fixed transform relation, a nonzero coefficient of its row-folded
residual is a multilinear polynomial in r row variables, of total degree at
most r. Each of the k row points is drawn independently. Schwartz–Zippel
therefore bounds simultaneous annihilation by `(r/p)^k`. This is a tensor
test; a `1/p^k` dense-vector bound does not apply. If r=0, a false relation
cannot be hidden by a row fold.

After drawing row points, the verifier binds all k claimed coefficient and k
claimed evaluation polynomials and checks their exact local transforms.
If any differs from its true row fold, its subsequent packed compression
check is bounded by the fixed-table equality lemma with c variables. Union
over all 2k polynomials gives the second term; sharing the compression query
requires no independence for this union. Source availability and PCS binding
remain separate premises. For c=0, equality is checked exactly.

The canonical verifier has 2d+1 main NTT links, two monomial links, and s+1
final key-switch links. Native r=11/c=7 for BabyBear's main and monomial
tables, r=11/c=8 for Goldilocks, and r=1 for each final-source profile.
`target/performance/opening-inventory/partial-canonical-algebra.json` records
these terms plus the final input equality term, with exact rationals and
source hashes. It explicitly excludes ZeroChecks, lookups, accumulator
linkage, every PCS error and adaptive Fiat–Shamir compilation. It is not a
full budget. All 23 budget tests pass, including exhaustive nonzero
bivariate multilinear polynomials over F_3 and the prior F_5 equality checks.

### Direct canonical ZeroChecks and reproducible partial worksheet

The canonical-v11 main Hadamard, monomial product, final key-switch product
and extraction relations each invoke the base-field packed ZeroCheck with
maximum product degree two. The two main relations use the main source's
variable count, and the two final relations use the final source's count.
Summing several products inside a public `PackedShape` does not add a random
extension-field aggregation step. In particular, the cancellation term of
the older aggregated-Hadamard variants is not part of this verifier.

`zerocheck_algebraic_bound` now exposes the existing conservative Theorem 3
round union independently of any row-code geometry. For product degree d,
it is `(n+2)*(max(n,d*(2*k-1)+1,(2*k-1)*(d+1))/p)^k`. The assumption that
the paper's reduction applies to this implementation, authenticated terminal
factors, and ideal interactive coins remain explicit. The legacy component
calculator uses the same helper; existing budget tests retain their results.

`tools/canonical_algebra_terms.py` combines those four ZeroChecks with the
NTT and public-input equality terms above. It replays the strict observation
reader, validates observation log hashes and source geometry, and records
current source hashes. It rejects unsupported protocol versions, batches,
lookup profiles and root schemas. It does not apply the old full-PBS budget
to v11. Reproduce the native partial worksheet with:

```
python3 tools/canonical_algebra_terms.py --run target/performance/opening-inventory/native-polyfrim --copies 21 --output /tmp/canonical-partial-algebra.json
```

The checked native report is
`target/performance/opening-inventory/native-polyfrim/partial-algebra-with-zerocheck.json`;
the toy report is under `toy-validation/partial-algebra-with-zerocheck.json`.
For 21 copies, these included terms sum to approximately 2^-193.01 for
BabyBear and 2^-227.52 for Goldilocks. These are **partial conditional
subtotals**, not whole-proof security levels. Lookup/decomposition,
accumulator linkage, every PCS/hash error, availability and adaptive
Fiat–Shamir compilation remain excluded. The 23 existing budget tests and
three additional canonical worksheet tests pass. No production protocol or
proof parameters changed.

### Accumulator linear linkage

The canonical accumulator verifier checks seven vector equations at one
common packed base query: external input equals monomial product minus input
accumulator; output equals input plus sum product; the two duplicated external
halves equal their decomposition inputs; input and output endpoints equal
their public polynomials; and shifted input equals output with the endpoint
correction. All seven are linear relations between fixed source tables and
public data. The query maps implement selection, half duplication, cyclic
row shift and sparse endpoint correction in the original matrix order.

Conditional on fixed available tables and authenticated query values, each
equation is the packed evaluation of a fixed residual table. Therefore a
conservative union contribution is
`7*min(1,n*((2*k-1)/p)^k)` using the fixed-table equality bound above. The
common base query does not require independence between equations for this
union. The shifted-input query is the sum of disjoint carry branches, not an
additional randomly aggregated identity; no challenge is sampled per branch.
Row selectors and endpoint corrections likewise change the deterministic
query map, not the underlying equality-test lemma.

The worksheet now includes this contribution and checks source geometry:
`n=log2(N/k)+ceil(log2(LWE_dimension))+1` and
`n_final=log2(N/k)+1`. These checks reflect the two concatenated ciphertext
halves and padded round domain. The noncommuting query-map and genuine-opening
binding tests in `snarks::packed_accumulator` provide implementation controls;
they are not substitutes for the stated availability and PCS premises.

The updated reports use the filename `partial-algebra-with-accumulator.json`
under each observation directory. Lookup/decomposition, PCS/hash availability
and adaptive Fiat–Shamir composition remain outside the subtotal.

### Decomposition linear reconstruction and borrow endpoints

Each canonical shared decomposition calls `packed_linear::verify_canonical`
on three relations: the radix-weighted digits reconstruct the source, the
initial borrow table is zero, and the final borrow table is zero. The source,
digit and borrow roots and the public relation coefficients are bound before
the common packed query is drawn. Each relation is therefore a fixed-table
equality under the same availability and PCS premises as above. Conservatively
union over all three equations, both main decompositions and the final one:

```
main decomposition linear terms:  6 * min(1,n*((2*k-1)/p)^k)
final decomposition linear terms: 3 * min(1,n_final*((2*k-1)/p)^k).
```

This does not establish that digits are in range or that borrow transitions
are valid; those obligations belong to the extension-field tuple lookups.
The current reproducible worksheet includes these linear terms and the
accumulator contribution. Its latest checked native and toy reports are
`partial-algebra-with-linear-linkage.json` in their observation directories.
The source hash list includes the decomposition, packed-linear and accumulator
implementations. Remaining exclusions are the lookup comparisons, PCS/hash
availability and adaptive Fiat–Shamir composition.

### Canonical shared lookup algebra

The worksheet now includes the lookup algebra for the selected one-pair
canonical-v11 profiles (BabyBear extension degree six and Goldilocks degree
three). This updates the exclusions of the earlier partial reports above;
PCS/hash availability and adaptive Fiat–Shamir composition remain excluded.
Let q=p^D, v=n+log2(k), T=2*2^b, and ell be the logical scalar length.
There are 2d main requests at b=8 and s final requests at b=5. The current
profiles use ell=2^v: main length is twice N times the padded round count,
and final length is twice N. Each request has three tuple columns.

For C requests and R repetitions, the conditional algebraic terms are:

```
rational identity: C * (2*T/q + (ell+T-1)/(q-T-1))^R
sumcheck: C*R*v/q
identity equality reduction: C*R*v/q
identity sumcheck: C*R*3*v/q.
```

For a fixed invalid tuple, compression collides with one of T valid tuples
with probability at most 2T/q. Otherwise the reciprocal rational identity
has a nonzero numerator of degree at most ell+T-1. The reciprocal challenge
excludes zero and the negatives of the compressed public table, at most T+1
points. Using denominator q-T-1 remains conservative when exclusions collide.
Fixed multiplicities and source roots precede these challenges. The worksheet
requires ell+T-1<p, preventing characteristic wrap in this argument.

Each committed helper is then checked by its scalar sum and reciprocal
identity. Helper roots precede independent equality points; the latter
reduce the identity to a sumcheck. The batch verifier retains separate degree
one sum equations and degree three identity equations. Shared challenges do
not require independence for the equation/round unions. A masked logical
prefix would require degree four; the standalone lookup helper handles that
case, while the selected canonical profiles have no logical prefix mask.
The canonical backend authenticates each helper and source packet separately;
there is no extension-field packet aggregation cancellation term to add here.

`extension_lookup_algebraic_bounds` supplies these terms independently of
PCS geometry. The native and toy reports are
`algebra-terms-with-lookups.json` under their observation directories, produced
by the same `canonical_algebra_terms.py` command. For 21 copies the included
native terms sum to approximately 2^-157.05 and 2^-162.61 respectively.
These remain conditional algebraic subtotals, not security certifications:
the paper reductions, source availability, PCS bounds and adaptive transcript
composition must still be justified together. All 23 budget tests and four
canonical worksheet tests pass. Production parameters remain unchanged.

### Internal Merkle declarations and freeze ordering

The opening worksheet now inventories internal Merkle declarations in addition
to outer PBS roots. For a PCS batch with a ordered claims, L physical rounds
and one shared rolling certificate, its internal declarations are
`a*(L-1)` matrix-ladder roots and `L-1` scalar rolling-derived roots. The source
root is already counted in the enclosing PBS inventory. The L projected
identifiers are virtual handles: the rolling verifier authenticates their
values through the packed roots, not through independent Merkle paths. They
are explicitly reported but excluded from the Merkle-word count. Constant
tables use the adapter's physical L=1 dummy-variable geometry.

The relevant production ordering is:

| Words or values | Binding point | Subsequent challenge |
| --- | --- | --- |
| Source commitment, ordered matrices and claims | Adapter `begin` binds context/root/queries/values and derives the extension child seed | All child PCS randomness |
| All per-query matrix ladder roots | Joint proximity `begin` binds every ladder before the member loop | Each consistency member's indices, then joint lane weights |
| Joint virtual projections | `project` binds the packed roots, samples lane weights and hashes the identifiers | Rolling fold challenges |
| Rolling derived word i+1 | `verify_mode` appends its root after alpha_i | alpha_(i+1) and every final rolling sample index |
| Rolling terminal scalar | Appended after the last fold challenge | Every final rolling sample index |

Source references are `pcs/src/matrix_weighted/polyfrim.rs`,
`pcs/src/packed_polyfrim/authenticated/proximity/batch.rs` and
`pcs/src/rolling_fri.rs`. Rolling words may depend on preceding fold
challenges; the distance-sensitive argument must use the prefix available at
each subsequent challenge. Treating all derived words as fixed before the
first alpha would assert a stronger ordering than the code provides.

In ceiling mode, charging each allowed ordered query as a separate API batch
maximizes both ladder and rolling declarations. Add the outer private and
trusted slots, conservatively charging reused keys again for every proof.
For native one-proof profiles this yields:

| Field | Observed internal declarations | Conditional ceiling internal declarations | Outer slots |
| --- | ---: | ---: | ---: |
| BabyBear | 7,827 | 12,554 | 91 |
| Goldilocks | 10,798 | 15,904 | 161 |

For 21 proofs the corresponding total ceilings are 265,545 and 337,365.
These are schema-derived declaration counts, not observed hash-query epochs,
distinct roots or completed availability reductions. The conditional ceiling
still depends on the per-owner schedule premise. A hash resource argument
must include all adversary, honest and verifier hash queries, all root freeze
points and one global collision term. It cannot infer that resource budget
from the timing measurements. Current reports are
`opening-terms-with-root-inventory.json` and
`opening-terms-q768-ceiling-with-root-inventory.json` under the native PolyFRIM
observation directory. The latter's Q=768 remains hypothetical.

### Combined candidate terms with explicit hash resources

`tools/canonical_candidate_budget.py` combines the opening worksheet, the
identified algebraic terms and the proposed classical random-oracle Merkle
availability bound. It requires matching observation manifests and copy
counts, all identified algebraic stage terms, the conditional per-owner
schedule ceiling, internally consistent exact subtotals and root counts, and
an explicit global hash-query budget. It uses SHA-256's 256-bit digest width.
The hash budget includes adversary, honest and verifier queries across all
copies; it is an assumption, not a measured benchmark property. A single
global collision term is charged, plus worst-freeze target-hit terms for all
Merkle declarations. Individual displayed bit counts are never added.

Reproduce an explicitly hypothetical Q=768 diagnostic with:

```
python3 tools/canonical_candidate_budget.py --openings target/performance/opening-inventory/native-polyfrim/opening-terms-q768-ceiling-with-root-inventory.json --algebra target/performance/opening-inventory/native-polyfrim/algebra-terms-with-lookups.json --hash-queries 281474976710656 --output /tmp/canonical-candidate.json
```

| PCS query setting | Global Merkle hash-query assumption | BabyBear candidate subtotal | Goldilocks candidate subtotal |
| --- | --- | --- | --- |
| Implemented Q=128 | 2^48 | Above 2^-128 | Above 2^-128 |
| Hypothetical Q=768 | 2^48 | Approximately 2^-131.44 | Approximately 2^-133.52 |
| Hypothetical Q=768 | 2^56 | Approximately 2^-126.92 | Approximately 2^-126.62 |

The corresponding reports are `candidate-q128-hash2p48.json`,
`candidate-q768-hash2p48.json` and `candidate-q768-hash2p56.json` under the
native PolyFRIM observation directory. **These are candidate subtotals, not
security levels of the implemented proofs.** The RS/rolling and availability
reductions and per-owner ceiling remain review premises. Adaptive Fiat–Shamir
compilation remains missing; the tool explicitly lists it rather than
assigning it a zero error. The security-matched baseline is also unresolved.
Every report keeps whole-security certification and promotion disabled. No
new query setting, hash function, FHE parameter or default backend is selected.

### Transcript primitive and the remaining compilation obligation

The pinned `Cargo.lock` selects Merlin 3.0.0. Its source uses `Strobe128`,
whose security configuration is explicitly 128-bit, and Keccak-f1600. This is
separate from the SHA-256 oracle modeled by the Merkle worksheet. The parent
canonical verifier uses `Transcript::new_direct`; lookup children use direct
extension transcripts seeded from 64 parent bytes, and the PolyFRIM adapter
uses a 32-byte parent seed. Direct extension sampling binds the characteristic,
degree and basis multiplication table and samples canonical base coefficients
in explicit basis order. These are framing/sampling facts, not a compilation
theorem. In particular, 64 seed bytes do not imply a 512-bit security claim,
and increasing an extension degree alone does not strengthen the transcript
primitive's security configuration.

`target/performance/opening-inventory/transcript-model-audit.json` records the
pinned package/checksum and hashes of the dependency and protocol source files
used for this inspection. Candidate reports now explicitly mark the transcript
primitive model as separate, leave the Fiat–Shamir error and query budget
unset, and state that accepted-proof root counts do not cover all grinding
trials. This does not assert that the implementation is insecure; it prevents
the conditional Merkle subtotal from being used as a transcript bound.

The multi-round Fiat–Shamir result of
[Attema, Fehr and Klooß](https://ir.cwi.nl/pub/32771/32771.pdf) distinguishes
general multi-round security losses from stronger results requiring
special-soundness hypotheses. Neither a constant loss nor a linear loss may
be imported here without establishing its hypotheses for this composition.
The reference packed-MW paper's asymptotic compilation claim likewise does
not supply the missing concrete argument for this modified backend.

The next proof obligation is a state/prefix argument for the whole parent and
child transcript: identify the fixed words at each first challenge query,
show that false claims can reach acceptance only through a charged bad
transition, account for previously queried prefixes and seed/finish-digest
collisions, and bound all adversarial trials. Alternatively, a suitable
special-soundness reduction must be proved. Available full-interactive tail
bounds cannot simply be multiplied by an arbitrarily chosen query factor.
Both routes also require a separate Merlin/STROBE primitive assumption and
resource bound. No numerical Fiat–Shamir error is assigned until one is
justified.

### Conditional fresh-prefix reduction, without choosing a query budget

The following elementary reduction isolates a sufficient property; it is not
yet established for the whole implemented protocol. Consider an **ideal
challenge-phase oracle** indexed injectively by the complete statement,
protocol/domain, phase number and preceding transcript. On a fresh index its
answer has exactly the interactive verifier's challenge distribution for that
phase. Distinct indices have independent answers. Repeated indices return
their original answers. Include any new oracle calls made by final verification
in the total Q_fs. This model is stronger and more specific than assuming
collision resistance of a transcript digest.

Suppose there is a deterministic state predicate `Bad(x,tau)` satisfying:

1. It is true initially for every false statement x.
2. For any reachable bad prefix and any next prover message, the measure of
   challenge answers that make the extended prefix non-bad is at most e_j
   for that phase j. The predicate and exceptional-answer set must be fixed
   before the fresh oracle answer, conditional on the complete prior oracle
   history. Prover messages cannot bypass this condition.
3. A complete accepting transcript is non-bad. Oracle answers on the accepting
   path are the answers at their actual indexed prefixes.

Then, outside separately charged modeling/binding failures, acceptance of a
false statement has probability at most `min(1,Q_fs*max_j(e_j))`. More finely,
sum e_j over the types of all fresh indexed challenge queries. The familiar
looser `Q_fs*sum_j(e_j)` also follows, but is useful only when each e_j really
has the conditional property above.

Proof: expose the adversary's oracle queries in their actual order, including
the verifier's calls. At each fresh query the prefix and adversary's previous
history are already fixed, so the probability of an exceptional answer at
that index is at most its phase bound. Union over the at most Q_fs fresh
indices. Any accepting false-statement path starts bad and ends non-bad, so
it has a first bad-to-non-bad transition. If its index was queried earlier,
its same exceptional answer is charged at that earlier first query; replaying
an old answer does not create a new probability trial. This argument requires
the state/exceptional set at that earlier query to be well-defined with the
same fixed words and prefix. It cannot freeze words retroactively at final
verification or select the exceptional set after seeing the answer.

This gives a concrete checklist for applying the reduction here:

| Component | Candidate state information | Remaining conditional-prefix obligation |
| --- | --- | --- |
| Packed ZeroCheck | False running claims for fixed factor tables | Apply the paper's round-by-round state predicate to actual authenticated tables and first-round framing |
| NTT / linear relations | Nonzero fixed row or packed residual | Fix sources before row coins and folded-polynomial claims before compression coins |
| Tuple lookup | Fixed invalid tuple/rational identity, then fixed reciprocal residual | Freeze sources/multiplicities/helpers at their separate challenge phases and handle conditioned reciprocal domains |
| Joint lane projection | Fixed vector words and fixed exceptional-weight set | Make the fixed-word RS lemma and source extraction hold at the first projection query |
| Rolling proximity | Distance-sensitive prefix potential | Establish each exceptional-curve bound uniformly for all prior oracle histories and available derived words |
| Consistency and rolling sampling | Fixed rejecting index sets | Justify treating the full no-prover-message sampling phase as an ideal challenge block, despite multiple stream squeezes |

The last row matters: a Q-sample miss probability is a whole-phase tail, not
automatically a per-squeeze error. An emulation of the phase oracle by the
actual Merlin stream, with its own resource/modeling bound, is still needed.
Likewise, seeded child indices are not literally full parent prefixes.
Their parent-history binding and child-finish fingerprints need collision/
target accounting before the injective-index premise can be used. SHA-256
word availability at those earlier queries, including all grinding trials,
also remains separate. Consequently this lemma does **not** authorize
multiplying the current candidate subtotal by Q_fs or emitting a final
Fiat–Shamir bound. It replaces a vague compilation requirement with explicit
uniform-prefix, oracle-emulation and binding obligations, parameterized by
Q_fs rather than assuming a resource budget.

### Explicit no-message index-sampling phase

The consistency prover and verifier now both call `sample_indices` immediately
after binding the ladder statement. The verifier collects all Q indices before
checking any authentication path or invoking a virtual-source callback. Rolling
FRI already collects its complete index vector before checking paths. This
exposes the sampling phase directly in the implementation rather than relying
on an inspection that interleaved checks never modify the transcript.

The prover draws exactly the same labeled eight-byte challenges in the same
order as before, so its roots, indices, openings and serialized proof are
unchanged. An accepting verifier consumes the same challenge stream. A
certificate rejected during path/transition checks now consumes the complete
index vector before returning its error; callers must discard that failed
verification transcript. Shape/canonicality preflight checks still precede
the sampling phase. This is a verifier execution change, not a new protocol
identifier or a claim of Fiat–Shamir security.

Conditional on independent uniform challenge bytes, each index is uniform on
the initial power-of-two domain: masking a uniform 64-bit integer by N-1 is
exactly uniform for the supported N. Thus a fixed rejecting subset of relative
size delta is missed with probability `(1-delta)^Q`, with replacement. Its
subset must be fixed before the **first** draw. No per-index independence is
asserted after conditioning on an adversary's successful search across several
phase prefixes. The fresh-prefix reduction, if established, must charge those
search trials separately. Nor does collecting the vector prove that Merlin's
stream emulates the ideal challenge-phase oracle; that primitive-modeling
obligation remains open.

The release authenticated-PolyFRIM suite passes 38 tests (two existing
expensive tests remain ignored), including both fields, matrix ladders,
virtual/joint projections, fresh false-word controls and prover/verifier
transcript agreement. The log is
`target/performance/opening-inventory/explicit-sampling-phase-tests.log`.

### Version-12 native correctness validation

The `classical_native_validation` example exercises original-size encrypted NAND
with reused native public keys and trusted setup. Every generated proof is
serialized, decoded and publicly verified; an altered output must be rejected.
Its default one-query profiles are correctness fixtures, not parameters justified
by a complete classical security bound. The harness intentionally reports no
benchmark timings. The base-field source storage is a private prover layout;
it does not restrict the verifier's extension-field oracle language.

Build and run all five variants over both fields from the repository root:

```sh
cargo build -p vfhe --release --example classical_native_validation
python3 tools/run_classical_native_validation.py \
  --runner target/release/examples/classical_native_validation \
  --output target/performance/my-classical-native-validation
```

The runner requires Linux `taskset` with CPUs 0-15 available and fixes
`RAYON_NUM_THREADS=16`. It runs jobs sequentially. Add `--fresh-21` for the
1/4/16 reused-key schedule (21 separate proofs per field/variant); these group
sizes are schedules, not a single aggregated proof. Select a subset with
`--fields babybear` or `--backends polyfrim fragmented`, for example.

Use `--queries Q` for a uniform count, or `--role-queries A,B,C,D` for separate
counts in source, main-helper, final-source, final-helper order. The options are
mutually exclusive and all counts must be positive. The trusted descriptor
binds each count; these flags do not derive or certify security parameters.
Uniform proof records retain the scalar `queries` field. Nonuniform records
use `queries: null` and a four-element `role_queries` array, checked against
the independently decoded descriptor header when present. Use
`--require-profile-header` to require that additional check for new binaries.

`--atomic-phases` selects trusted descriptor version 3, which draws the entire
joint PolyFRIM projection matrix in one canonical extension-vector phase and
also uses the atomic NTT row schedule. It is mutually exclusive with the
version-2 `--atomic-ntt` option. Versions 1 and 2 retain their previous
projection streams; changing schedule changes the trusted profile ID. This
removes a phase-grouping obligation for the new profile, but does not itself
qualify security or choose query counts.

`--atomic-zerocheck` selects descriptor version 4. It includes version 3's
atomic NTT/projection schedule and additionally groups each packed ZeroCheck
equality-point block and its mixing/first-row coins. It is mutually exclusive
with the other two schedule flags. All previous constructors/suites remain
available. The feasibility grid accepts this flag too, optionally with
`--helper-basis`. Its version-4 phasewise analysis is conditional on the source
and transcript coupling described below; the flag does not certify security.

For geometry validation, the harness and runner also accept `--width` (BabyBear
8/16, Goldilocks 4/8), `--blowup` (2/4/8), and `--fragment-vars`
(8/10/12/14/16 for native fragmented profiles). Defaults remain width 8/4,
blowup 2 and fragment cap 12. Use separate output directories for each geometry;
the trusted profile and setup fingerprints bind the selected parameters. A
nondefault geometry still needs its own correctness and security analysis.

`--extension-degree` selects an existing trusted field type: BabyBear 4/5/6/8
or Goldilocks 2/3/4/5. Defaults remain 6 and 3. The runner checks that each
requested field supports the selected degree before creating its output
directory; select fields explicitly for a degree supported by only one field.
Proof records must report the requested degree, and diagnostic descriptor
decoding checks the corresponding complete basis table. Source width must
still admit the chosen extension degree (in particular Goldilocks degree 5
requires width 8). Field size alone does not qualify proof security.

For Brakedown or direct PolyFRIM, `--helper-basis` selects helper-table width
equal to the extension degree while retaining the selected source width. This
can reduce unused helper lanes. The option is rejected for fragmented variants,
whose scalar bridge requires helper width equal to source width. With the
runner, explicitly select nonfragmented backends, for example
`--backends brakedown polyfrim dictionary --helper-basis`. Helper packing changes
the trusted profile/setup and requires its own validation; it is not a timing
or security qualification. The default grid inventory below uses source-width
helpers; pass `--helper-basis` to that example to inventory extension-degree
helper packing for nonfragmented backends separately.

The grid example also accepts `--atomic-phases`, optionally together with
`--helper-basis`, to inventory version-three profile IDs and all four parameter
factories. Each record reports `descriptor_version`; the default remains
version one. Admission still checks geometry only and supplies no justified
query counts, even when the atomic schedule is selected.

`cargo run -p vfhe --example classical_profile_grid` inventories trusted
parameter construction at the original PBS geometry across all existing
extension degrees (BabyBear 4/5/6/8, Goldilocks 2/3/4/5), both approved widths,
all three blowups, and all five fragment caps where applicable. It constructs
all four role parameters per candidate and reports admission errors and profile
fingerprints. Its one-query inventory checks domain/geometry feasibility only;
it neither runs encrypted PBS nor supplies security-qualified query counts.
The default remains one query per role. To construct candidate profiles at
other counts, use `--queries Q` or `--role-queries A,B,C,D` (mutually
exclusive, all positive). Counts are supplied to the actual four factories
and change the profile ID. Nonuniform records report `queries:null` and
`role_queries:[A,B,C,D]`; a uniform vector keeps the scalar representation.
For example, `--atomic-zerocheck --role-queries 2,3,4,5` checks geometry for
those explicit counts without asserting their security. The grid does not
derive counts or override the native verifier's selected trusted profile.
Add `--emit-descriptors` to include `descriptor_bincode_hex` for admitted
candidates, or null for rejected candidates. The bytes come from the exact
profile whose four parameter factories just succeeded. Default grid output
is unchanged. A caller can decode/check those bytes and pass a selected raw
descriptor file to `tools/classical_candidate_terms.py --descriptor`; this
produces a conditional calculation, never verifier parameters or a promotion.

PolyFRIM parameter setup uses `NTTField::get_ntt_root` to obtain the exact
native negacyclic root. BabyBear and Goldilocks retain only the root per
domain, reusing an existing transform plan or creating and dropping one on
the first request. Repeated parameter factories therefore avoid allocating
another full plan just to read its root. This is a private setup optimization;
native roots, serialized parameters and trusted profile versions stay the
same. It does not establish a proving-time performance gate.

Classical extension challenges cache the immutable encoded basis multiplication
table by the Rust `(base field, extension field)` type pair. A cache hit avoids
repeating the D-squared products, D-cubed coefficient encoding and temporary
table allocation. Every challenge still absorbs the complete original table
bytes; field sampling, labels, receipts and profile IDs are unchanged. Cold
construction occurs outside the shared lock and concurrent callers reuse the
same retained entry. The eight supported types retain 18,320 table payload
bytes in total if all are used, excluding cache/Arc overhead. This is an
implementation optimization, with no native speedup or security-gate claim.

Use a new output directory each time. Each job records its actual process exit
code, binary fingerprint and log fingerprint. A successful status requires the
full requested schedule and all correctness checks. Interrupted or failed jobs
require inspection; a partial log is never promoted to success. Avoid rebuilding
the executable during a run; the runner checks its fingerprint before and after
each job. For durable comparisons, copy the executable to a separate path first.

For two completed runs of the same schedule/profile, exact record comparison is:

```sh
python3 tools/compare_classical_native_validation.py reference.log candidate.log \
  --output comparison.json
```

This requires equality of setup, statements, proof lengths and proof hashes,
along with the other validation records. It does not measure speed, establish
knowledge soundness, choose security-qualified query counts, or satisfy the
security-matched performance gate.

New harness builds also emit one separate `HB_CLASSICAL_PROFILE` diagnostic
containing the serialized trusted descriptor, its hashes, schedule version and
role geometry. The Python reader checks canonical bincode integers, the native
field basis table, suite identifiers and both descriptor fingerprints, then
compares the displayed geometry with the decoded bytes. The runner additionally
checks the descriptor against its requested native geometry and schedule.
`--require-profile-header` rejects runners that lack this diagnostic. Older
frozen logs remain readable without it, with header validation marked absent.
This diagnostic decoder is for validation evidence; it never supplies a Rust
verifier's trusted profile, and the four-proof record schema is unchanged.

### Classical work-cost arithmetic

`tools/classical_work_cost.py` implements a conditional work-cost calculation
without selecting an arbitrary adversarial query cutoff. Its input must be an
already justified, uniform all-trials bound
`Pr[success within T charged work] <= min(1, sum_{k>=1} a_k T^k)` with
nonnegative exact rational coefficients. It does not derive that bound from
profile names, field sizes, passing tests, or the existing partial worksheets.
In particular, hash queries and transcript queries need a justified relation to
the same charged classical work unit before coefficients can be combined.

For a fixed positive integer budget T, the resulting lower bound on work per
success is `T / min(1, error(T))`. Before saturation, `error(T)/T` is
nondecreasing because every coefficient is nonnegative; after saturation,
success per work is `1/T` and decreases. The minimum therefore occurs at one of
the two integers bracketing the first saturation, or at T=1 if already
saturated. The tool finds that bracket by exact doubling/binary search and
compares both costs as fractions. A purely linear bound has the same cost at
all budgets below saturation, so the same rule applies. To extend this result
to repeated or adaptive attempts, the supplied bound must hold conditional on
each prior attack history: each attempt's success probability is then at most
its charged work divided by the computed minimum, and summing conditional
expectations charges retries as well.

For example, a linear coefficient `2^-128` alone and a quadratic coefficient
`2^-256` alone each produce a conditional minimum of `2^128`; combining both
coefficients yields a smaller minimum and fails that target. This is why
separately checking contributions at a convenient cutoff is insufficient.
These closed-form cases and 56 exhaustive small-budget comparisons have been
checked. The tool always leaves protocol security qualification false: the
modified protocol's complete all-trials coefficients remain unproved.

The calculator also accepts a nonnegative exact `--constant` term and a proved
`--minimum-budget` lower bound on potentially successful attacker work. This
matters because global hash/XOF query counts include honest setup and final
verification: those queries cannot silently be charged as attacker work.
One needs explicit envelopes such as `hash_queries <= a*T + H0`, with T in
attacker work and H0 covering the appropriate honest/verifier contribution.
Expanding nonnegative polynomial envelopes can produce a constant success
term. All such envelopes, including adversarial output/input processing and
any amortized prefix reuse, must be justified separately. Observed benchmark
durations and one accepted proof's query count do not supply them.

With `error(T)=c+sum a_k*T^k`, success per work before saturation is
`c/T + a_1 + a_2*T + ...`, a convex function on positive T. Its maximum on
the unsaturated interval is at the permitted minimum budget or at the
saturation boundary. The exact integer calculation therefore checks the
minimum budget and both integers bracketing saturation; a pure constant
model is handled directly. This also covers the original zero-constant case.
Ignoring the low-budget endpoint is unsound in general: for
`error(T)=1/4+T^2/16`, the minimum work-per-success bound is `16/5` at T=1,
smaller than either saturation-neighbor cost. The minimum-budget option may
only represent an independently proved lower bound, such as a correctly
modeled output-processing cost; it is not a cutoff chosen to force a target.
Conditional-history requirements for retries and the distinction between a
fixed-budget success bound and an expected-work adversary remain obligations
of the supplied model. The tool still certifies no protocol.

### Conditional fragmented-bridge algebra bound

Fix a source table, an ordered matrix-query list, and all claimed lane vectors
before drawing the bridge's independent extension-field coefficients. Let
`ν = source_vars + log2(width)` and let `E` be the extension field. This paragraph
assumes ideal independent uniform challenges and an injective embedding of the
base field into E. It supplies an algebraic reduction for one opening, not
availability, extraction or noninteractive security of its committed source.

If any claimed lane is false, the vector of residuals has a nonzero coordinate.
The compressed residual is `sum rho[j,lane] * residual[j,lane]`. Fixing all
coefficients except one attached to a nonzero residual leaves exactly one bad
choice for that coefficient. Thus the probability that compression turns a
false batch into a true scalar claim is exactly `1/|E|`. There is no factor of
the number of claims or lanes: this statement uses independent coefficients,
not powers of one coefficient, and requires the residual vector to be fixed
before the coefficient phase.

On the Boolean cube, define the kernel as the sum of the ordered matrix-query
linear functionals weighted by those same coefficients, and extend its values
multilinearly. The source's multilinear extension times this kernel has degree
at most two in each variable. If its sum is false, each sumcheck round either
rejects immediately or supplies a claimed univariate different from the true
one. That difference is nonzero of degree at most two, so at most two choices
of the fresh round challenge can erase the false running claim. A union over
ν rounds gives `2ν/|E|`. This argument remains valid for adaptive round messages
because each message is fixed before that round's challenge. When ν=0 there
are no sumcheck challenges and the terminal equation is checked directly.

Consequently, outside the above algebraic events, accepting a false matrix
batch requires accepting a false scalar source opening at the final point.
The conditional one-opening error is bounded by
`(1 + 2ν)/|E| + scalar_opening_error`, capped at one. Both reference and virtual
fragmented adapters implement this bridge: they bind roots/queries/values
before `get_vec_challenge`, verify sumcheck with `max_multiplicands: 2`, verify
the scalar opening, then check the ordered terminal kernel equation. Streaming,
compiled matrix actions and base-field private storage preserve that relation.

To use this term in the whole proof, source extraction must fix the same table
before the first coefficient query, scalar opening security must handle the
adaptive point, and the challenge distributions must be justified for the
actual framed transcript and all adversarial trials. None of those premises
follows from this algebraic argument. In particular this is not a complete
round-by-round state predicate or a license to multiply an interactive subtotal
by an arbitrary Fiat–Shamir query count.

### Conditional partial-word extraction from a fixed-depth Merkle root

This is a derivation in a classical random-oracle model for complete hash
inputs, not a statement that SHA-512 is an ideal oracle. It isolates the
availability step from RS decoding and Fiat–Shamir. Count every distinct query
to that modeled hash, including context/profile hashes, adversarial work and
final verification; repeated inputs reuse their original answers. Fix a root,
its expected tree depth, and its expected indexed leaf encoding at a freeze
time before the relevant challenge answer. The encoding must recover a unique
semantic leaf vector from any valid encoded byte string. Shape, context and
index checks belong to that encoding premise.

Let A be the number of distinct oracle queries already exposed at that freeze.
Outside an output collision, each queried digest identifies at most one known
preimage. Starting from the root, unroll known internal preimages only when
their length is exactly twice the digest length, splitting them into the
ordered child digests. Stop at the trusted depth. A terminal digest yields an
available leaf only when its known preimage is a valid encoding for that exact
context and index; otherwise mark the leaf unavailable. Unknown internal nodes
make their descendant leaves unavailable. Reusing the same digest at several
positions is allowed: extraction is depth- and index-dependent, not an
assumption that the query graph has distinct nodes. Fill unavailable positions
with a fixed zero vector to define a complete mathematical word before the
challenge. This completion need not hash back to the root; only the available
positions are authenticated by the extracted graph.

Consider any later accepted opening whose semantic value differs from this
completed word, or whose position was unavailable. If its entire path and leaf
preimages were already known at the freeze, the unique-preimage walk would
have extracted the same available leaf, a contradiction. Otherwise take the
first previously unknown preimage encountered while walking the accepted path
down from the root. Its digest is either the root itself or a child digest
inside a previously known internal preimage. Therefore a post-freeze hash
query must hit a digest in a set fixed at the freeze: the root and the at most
2A child digests in known internal preimages. A verifier's first hash of an
unqueried proof value counts as such a query too. Knowing a preimage already
but withholding its oracle query does not avoid this charge.

For at most B later distinct queries, each fresh random-oracle output hits that fixed
set with probability at most `(2A+1)/2^h`, conditional on its preceding query
history. Union over those queries gives `(2A+1)B/2^h`. An output collision is
charged separately, once globally: with at most T total distinct queries, its
probability is at most `T(T-1)/2^(h+1)`. No independence between different
roots, openings or target-hit events is used. For roots frozen at possibly
different adaptive times, a valid union bound is consequently

```
T(T-1)/2^(h+1) + sum_roots (2*A_root+1)*B_root/2^h
```

The displayed probability bound requires declared deterministic upper bounds
on query/declaration counts and on the summed target exposures, or a bound on
the expectation of their predictable exposures. Substituting realized counters
from an adaptively stopped or successful transcript is not justified.
Each freeze and target set must be defined before the later fresh outputs to
which its conditional argument is applied. The sum includes every adversarial
root declaration used by the reduction, including abandoned grinding trials;
roots in one accepted proof are not an upper bound on that sum. This explains
the proposed arithmetic in `hash_query_budget.py` without inferring a global
root count or a work budget from an honest execution.

Applying this derivation to the implemented PCS still requires auditing the
actual fixed-depth leaf encodings and semantic decoder premise at every role,
locating each freeze at the first relevant transcript query, and relating T
and root declarations to charged work. It supplies neither RS proximity nor
coefficient extraction from an RS word. In particular, a zero completion of a
partially available source is not evidence of an RS codeword, and scalar
rolling proximity does not automatically certify every vector coordinate.
The untagged internal-node hash used by the current Merkle utility is handled
here by fixed-depth, position-dependent parsing; a proof must not silently
assume independent leaf/internal hash domains. Full protocol security and
qualification remain unestablished.

### Shared predictable target set across Merkle roots

The preceding per-root union is valid but needlessly recounts the same unknown
child digests for many roots. In the same ideal h-bit hash model, assume
deterministic envelopes of H distinct global hash queries and R distinct
declared root values across all candidate histories and trials. Include honest
setup and verifier hash queries in H. A declared root includes its appearance
in a candidate first-challenge query, not just its eventual proof transmission.
Reusing a value in several roles does not require several copies in a set.

Maintain a predictable set S containing every root value declared so far and
both digest-sized halves of every previously exposed hash input of length 2h
bits. Its cardinality is at most R+2H. Inputs of other lengths add no internal
child targets, though their outputs and possible collisions still count in H.
It is harmless to include halves from a leaf/context input that happens to
have internal-node length: the actual untagged utility can interpret those
bytes as a node, and adding extra targets only loosens the bound.

Outside a global output collision, any post-freeze accepted opening not
available in its frozen graph has a first unknown preimage on its root-to-leaf
walk. Its digest is that declared root or a child inside an input already
known at the freeze. Therefore, when the unknown preimage is first queried,
its output hits S as it existed before that answer. This remains true for
adaptive freezes, repeated roots, overlapping trees and role-dependent leaf
parsing. If the root was itself selected from an earlier oracle output, its
preimage was already available; a different later preimage is instead charged
as an output collision. The argument does not need a union over roots for
this target event.

Each fresh answer hits the prior set with conditional probability at most
`(R+2H)/2^h`. Union over at most H such answers and one global collision event
gives the conservative envelope

```
H*(H-1)/2^(h+1) + H*(2*H+R)/2^h.
```

H and R here are proved global resource caps. Using observed successful-run
counts, or multiplying expectations as if they were deterministic caps, is
not justified. With random resource bounds one instead needs an appropriate
bound on the expected predictable target exposures and collision exposures.
Root fields hidden behind a guessed child seed still need the separate
parent/child link coupling before their freeze can be identified this way.

`hash_query_budget.py --global-targets` exposes this optional calculation;
the existing per-freeze calculation remains the default. Its
`global_work_coefficients` helper takes separately justified affine envelopes
`H <= a*T+H0` and `R <= b*T+R0`, with T in attacker work. Replacing H(H-1) by
H^2 gives nonnegative constant/linear/quadratic coefficients

```
c0 = (5*H0^2 + 2*H0*R0) / 2^(h+1)
c1 = (10*a*H0 + 2*a*R0 + 2*b*H0) / 2^(h+1)
c2 = (5*a^2 + 2*a*b) / 2^(h+1).
```

These can be passed to the conditional work-cost arithmetic with its explicit
constant term. The helper does not establish a,b,H0,R0, charge input/output or
prefix-reuse work, count all candidate links, or supply the other protocol
error terms. It therefore makes no whole-security qualification claim.

### Production leaf-encoding audit for the availability premise

The current version-12 facade fixes SHA-512 and a trusted profile before proof
verification. The underlying leaves have the following actual encodings; the
Merkle utility itself hashes ordered pairs of raw digest bytes without a node
tag. All bincode entries below use `config::standard()`.

| Oracle | Hashed leaf input | Checked semantic shape |
| --- | --- | --- |
| Brakedown column | Literal `HasteBoots/mw-column/v1` followed by bincode of the base-field column | `(2^left_vars * role_width) * block_width` values; exact trusted tree path length |
| Packed PolyFRIM pair | Bincode of `(packed PolyFRIM pair leaf v2, pp, layer, index, values)` | `2 * width` extension values and the layer's exact pair-tree path length |
| Rolling FRI pair | Bincode of `(rolling FRI pair leaf v1, pp_context, role, layer, index, [a,b])` | Two extension values; trusted layer/index range and exact path length |
| Packed PipFRI source | Bincode of `(PipFRI packed pair leaf v1, pp_context, index, pairs)` | One two-value extension pair per fragment; exact packed-source path length |

The Brakedown leaf does not contain the profile or index. Its fixed tree
position supplies the index, while `bind`/`bind_many` separately bind the
trusted parameter-context digest, root, queries and claims before challenges.
The other encodings carry context and positions inside the hashed input.
The virtual fragmented protocol reuses the packed PipFRI source leaf encoding;
its combined initial word has no independent Merkle tree. Direct PolyFRIM's
compact dictionary changes authentication-path transport, not the expanded
leaf values or hashed preimages.

For a known query preimage, the theoretical extractor can match the expected
literal/serialized prefix, decode the remaining typed values under the fixed
field representation, require the expected dimensions and full consumption,
then re-encode and require byte equality. Only preimages passing all these
checks yield available leaves. Re-encoding is necessary: accepting any decoder
spelling as the canonical hash input is not justified. A verifier hashes the
typed values' serialization, rather than the raw bytes of the enclosing proof.

For the concrete selected field types, a serialized base-field integer has one
semantic interpretation. BabyBear enforces its Montgomery representative
range during deserialization. Goldilocks permits raw u64 representatives with
the field's modular interpretation; distinct representatives can denote the
same element, but a fixed byte string still determines one element. This
argument requires unique interpretation of bytes, not a claim that every field
element has only one serialized spelling. The extension serialization writes
a sequence of exactly D base coefficients in basis order. The decoder now also
requires exactly D, rejecting both shortages and extras; the existing valid
serialization is unchanged. Source-storage optimizations preserve these leaf
encodings, including raw representatives, rather than normalizing them.

This audit identifies the leaf-shape/interpretation premises for the
partial-word extraction derivation. It does not yet identify every adaptive
first-query freeze or bound the declarations across all grinding attempts.
Nor does it show that completed words are RS-near, that a vector projection
fixes all coordinates, or that the parent/child transcript satisfies the full
noninteractive knowledge reduction.

For the first-query availability coupling, a useful conditional construction
is to freeze each digest at its **first declaration anywhere**, rather than
choose a new completion separately for each accepted branch. Register every
64-byte window of each candidate complete XOF input before answering it. At
the first registration of a digest r, snapshot the already exposed SHA-512
preimage database. For any independently trusted role geometry/context g,
define W(r,g) by following that snapshot's root-to-leaf graph at the trusted
depth, applying the exact leaf interpretation above, and filling unavailable
positions with a fixed zero column/pair. A global output collision is excluded
as in the availability argument. Hence the snapshot graph has at most one
preimage for each node digest; completion is deterministic. Different roles
can interpret the same digest differently, but W(r,g) for the same pair is
never refrozen in a different grinding branch.

Whenever r is literally present in a challenge input, its W(r,g) is fixed
before that input's first answer, even if the adversary has not yet queried
the input's earlier transcript phases. If r is inherited through a compressed
child seed, the separate link-ordering premise below is needed to expose the
parent input that declares r before following that dependency. This statement
does not assume that arbitrary earlier receipts in a candidate history have
already been validated.

Outside the global availability bad event, every subsequently accepted
opening at r must agree with W(r,g). Indeed, a newly exposed path portion has
a first unknown preimage after this snapshot; its output hits the registered
root or an already exposed child target, exactly the predictable-target event
already charged above. A preimage different from a snapshot preimage instead
gives the global collision event. Thus the same completed vector word can be
used consistently across all later candidate queries and reused-root branches;
one need not condition fresh challenge distributions on a future successful
authentication event. Complete words need not hash back to the root at filled
positions: only agreement at subsequently accepted openings is asserted.

This construction charges root declarations by the global candidate-input
window count, not by one proof's commitment count. It supplies a conditional
fixed-word interface to the earlier algebraic component lemmas. Applying it
to the whole implementation still requires auditing that each component's
source/derived roots is declared before its relevant challenge (including
linked children), defining compatible whole-protocol bad states on candidate
histories, and proving resource/knowledge bounds. It does not establish those
additional obligations merely by constructing the completions.

The following source audit identifies PCS declarations in the current
implementation. It establishes ordering of these literal bindings, not the
whole-protocol bad-state or knowledge theorem. Both prover and verifier paths
must use the indicated bindings; a prover's local state alone is insufficient.

| Component | Declaration before its relevant coins | Scope and remaining obligation |
| --- | --- | --- |
| Brakedown single/batch | `matrix_weighted.rs::bind` / `bind_many` absorb trusted context, root, ordered queries and claims before the random row matrix | The full response packet is then absorbed before the one column-index phase; fixed-word completion applies to the declared source root |
| Direct/dictionary PolyFRIM matrix adapter | `matrix_weighted/polyfrim.rs::begin` absorbs context, source root, ordered queries and claims before the classical child seed | Child coins inherit this dependency through the checked seed link; dictionary transport does not replace the roots used in the transcript |
| Joint PolyFRIM consistency | `authenticated/proximity/batch.rs::begin` absorbs every query ladder's roots before any consistency-member index phase | Each member also binds source/following roots, query and claim in `authenticated.rs::bind`; all relevant roots are fixed before its sampling |
| Joint PolyFRIM projections | `batch.rs::project` absorbs parameters and all root lists before lane weights | Versions 1/2 use separate extension-vector phases per layer/member and still need a justified phase emulation or conditional state analysis; version 3 draws all layer/member/lane weights in one phase |
| Ordinary/virtual fragmented matrix bridge | The corresponding `begin` absorbs context, root, all ordered queries and values before the classical child seed | The child draws every claim/lane rho in one extension-vector phase before the degree-two sumcheck; source completion precedes rho under link ordering |
| Scalar virtual fragment combination | `pipfri/virtual_source.rs::bind` absorbs parameters/context, packed root, point, value and all fragment evaluations before gamma | The combined initial word is a function of the fixed packed source and gamma, not an independently completed root |
| Scalar virtual public-point folds | The complete following-root ladder is absorbed before entering virtual-initial rolling FRI | The adapter's virtual initial identifier is a context digest, not an actual source-word Merkle root; its word must be coupled through authenticated packed fragments |
| Rolling original words | `rolling_fri.rs::bind_mode` absorbs context and all original-root identifiers before the first alpha | Virtual identifiers require their upstream definition; they must not be interpreted as ordinary extractable roots |
| Rolling derived words | Each next derived root is absorbed after its preceding alpha and before the next alpha; terminal is absorbed before index sampling | This matches the adaptive derived-word game, rather than requiring derived words to be fixed before all folding coins |

In particular, freezing every byte window does not turn a virtual identifier
into an authenticated word, or turn the version-1/2 sequence of projection calls into one
fresh independent matrix challenge. Version 3 explicitly uses one such phase. Those are separate interfaces in the
composition. Parent PBS and lookup-child source/helper declarations also need
their own phase audit; the PCS table above does not establish their ordering.

For the **atomic-NTT schedule only**, the NTT check also has the following
conditional component state, assuming two fixed decoded source tables whose
authenticated linear evaluations are the ones used by the PCS. Let k be the
source width and r the number of row variables. If the NTT relation is false,
one coefficient of its residual is a nonzero multilinear polynomial in the
r row variables. The single row phase samples k independent points, so all
k residual polynomials vanish with probability at most `(r/p)^k` (zero when
r=0). Outside that event, at least one actual folded coefficient/evaluation
pair violates the public NTT relation.

The verifier next absorbs all 2k claimed folded polynomials before coefficient
compression and checks their NTT relations. A passing packet must then differ
from an actual folded source in at least one polynomial. Choose its first
nonzero difference in a fixed ordering before the compression coins. During
each subsequent packed coefficient fold, keep the state that this difference
is nonzero. A fixed nonzero block gives a nonzero interpolation polynomial of
degree at most 2k-1. The phase's k independent evaluations annihilate it with
probability at most `((2k-1)/p)^k`; if it survives, the next residual is again
nonzero. At the end, the compressed claim for that source is false. Prover
messages cannot repair the earlier packet, since the compression query comes
after its binding and the source words stay fixed.

This yields either public rejection, a false PCS evaluation claim, or a
charged transition. With c coefficient-fold rounds, a conservative interactive
component union is `(r/p)^k + c*((2k-1)/p)^k`; the existing worksheet uses the
looser 2k factor for compression. For a fresh-prefix argument the individual
phase bounds, rather than this union multiplied by a guessed query budget,
are relevant. The statement requires the atomic row phase and the fixed-word
PCS interface; it is not a claim that the old separate-row schedule has the
same first-query bound, or that proximity already supplies those decoded
tables for every candidate parent history. Source extraction, all-trials work
and the other parent relations remain separate composition obligations.

For shared canonical tuple lookup, the current source declarations are also
explicit. `canonical/shared.rs::preflight` binds ordered requests and calls
`canonical.rs::bind` on each request, absorbing its configuration, extension
degree, helper context and each source context/root. The canonical opening
registry then binds all slots, including unused slots. `child_shared` binds
grouped multiplicities and `child` also binds their flat spelling before the
checked classical child seed. Only then does `all_challenges` generate tuple
hash and reciprocal challenges. Both prover and verifier absorb the complete
helper-root list before their equality points and separate scalar equations.
Terminal helper values are reused in the sum and reciprocal equations and
are subsequently authenticated, rather than independently chosen per equation.

Here is a conditional bad-state argument for one fixed invalid request and
one of its repetitions. It assumes fixed decoded base-field source tables,
fixed multiplicities, characteristic p, logical length L<p, public table
size M, C tuple columns, and a genuine extension field of size q. Select the
first invalid source tuple before the tuple-hash phase. For any public tuple,
equality of its power-series compression with that invalid tuple is a
nonzero polynomial of degree at most C-1 in y. Thus except with probability
at most `M*(C-1)/q`, the selected compressed source value lies outside the
compressed public table. This fixes a nonzero rational sum discrepancy: its
outside-table pole has a positive source occurrence count at most L, hence
nonzero in characteristic p, regardless of the proposed public multiplicities.
After clearing distinct denominators, the numerator degree is at most L+M-1.

For each **raw reciprocal draw**, an admissible r can make that discrepancy
zero with probability at most `(L+M-1)/q`. Public-table poles and r=0 cause
another raw draw and do not themselves remove the bad state. A source-only
pole instead makes the corresponding reciprocal equation impossible. If
describing the accepted r in the interactive game, the usual looser
`(L+M-1)/(q-M-1)` bound follows from conditioning on its admissible domain.
An all-trials first-query argument must count every raw draw, including
rejections, rather than silently charge one oracle query per accepted r.

More precisely, in the fresh-output reference game fix y and let
`B_y = {0} union {-t : t in compressed_table(y)}`, with `f=|B_y|<q`.
The framed state strictly extends after each receipt, so distinct retry inputs
receive independent uniform field outputs in that reference game. For every
admissible a, the probability that the first accepted draw is a is
`sum_{j>=0} (f/q)^j / q = 1/(q-f)`. Thus the accepted point is exactly uniform
on the admissible set; the attempt count N has `Pr[N>m]=(f/q)^m` and
`E[N]=q/(q-f)`. A fixed nonzero degree-d numerator has at most d admissible
roots, giving `min(1,d/(q-f))` for the accepted-point bad event. Here m is a
variable in a tail identity, not an implemented retry or attacker-query limit.
These are conditional reference-game statements. Adaptively selecting a
prequeried Fiat-Shamir prefix still requires the separate all-trials/joint-work
argument; this calculation does not grant security admission by itself.

Once helpers are committed, either their pointwise reciprocal identity is
false, or their sum differs from the public rational sum. In the padded case
the implemented residual is `r*h + mask*g*h - mask`; outside the logical rows,
the excluded-zero condition on r forces h=0. Thus unused helper rows cannot
silently compensate the sum. A nonzero Boolean residual gives a nonzero
multilinear polynomial in the equality point, with total degree at most the
number n of scalar variables. The whole equality-point vector phase loses
that residual with probability at most n/q. Otherwise at least one of the
separate sumcheck equations is false. A fixed first false equation, selected
before the common round coin, can become true in a degree-d round with
probability at most d/q, where d is 1 for the sum and 3 or 4 for the identity
according to its public mask. Other equations sharing the coin do not repair
that equation. Surviving false terminal factors give false source/helper PCS
claims through the actual coefficient bridges.

This describes phasewise state transitions for one invalid request; it does
not justify importing the interactive product over repetitions into a
first-query error bound. Choosing one fixed repetition suffices for the
conditional transition argument above, while any stronger repetition gain
requires its own compilation argument. Decoded-table/bridge coupling, valid
receipts and linked histories, all-trials resource caps, other parent
relations and knowledge extraction remain prerequisites for whole security.

### Conditional packed ZeroCheck state with atomic schedule four

Version four adds two atomic blocks in `sumcheck/src/packed_zero.rs`:
`sample_points` draws all k equality points in one phase, and
`first_challenges` draws the k-by-k mixing matrix and k first-round row
challenges in one phase. The batched reduction uses the same helper, with
distinct batch labels. Versions one through three retain their prior calls.
The following argument assumes fixed decoded base-field factor tables and
their correctly coupled PCS evaluations, not merely prover-owned tables.

Let p be the characteristic, k the packed width, n>=1 the number of Boolean
variables, d the maximum factor multiplicity, and s=2k-1. The public shape
checks ensure interpolation degrees fit the field. If the pointwise relation
is false, choose a nonzero Boolean residual at one fixed first-variable/lane
boundary. Its remaining-variable multilinear extension is a nonzero polynomial
G of total degree at most n-1. If the true first-round polynomials for all k
equality points vanish at every checked boundary, then G vanishes at all k
independently sampled points. The probability is at most `((n-1)/p)^k`, clipped
at one. For n=1 the equality vectors are empty and this error is zero.

Outside this event, some true first-round polynomial H_b differs from the
claimed polynomial h_b: `check_first` requires every h_b to vanish on all 2k
boundary nodes. Both have degree at most D1=s*d. All h_b are absorbed before
the joint mixing/row phase, so their difference vector Delta is fixed and
nonzero at that phase. For each row a the discrepancy is
`sum_b M[a,b]*Delta_b(r[a])`. Choose one nonzero Delta_b. Its roots occupy at
most D1/p of the field. At any other r[a], the vector Delta(r[a]) is nonzero,
and its dot product with an independent uniform matrix row is zero with
probability 1/p. Thus a row discrepancy vanishes with probability at most
`(D1+1)/p`. The k row tuples are independent in the single complete phase,
giving `((D1+1)/p)^k` for annihilating the whole discrepancy. Otherwise the
reduced packed sumcheck starts with a false claim for the actual folded
factors and the verifier's mixed equality table.

In each remaining round, a polynomial message is fixed before the vector of
k row challenges. If the running claim is false but the public boundary-sum
check passes, the message differs from the true round polynomial. The
difference is nonzero and has degree at most D2=s*(d+1), including the equality
factor. All k independent evaluations vanish with probability at most
`(D2/p)^k`. Outside that transition the next running claim stays false. At
termination the verifier recomputes the public equality factor using the
actual ordered query and mixing matrix. A passing terminal identity with a
false running claim must therefore use at least one incorrect private factor
evaluation, yielding a false PCS claim against an already declared root.

The conditional interactive union is

```
e_equal + e_first + (n-1)*e_round,
e_equal = min(1, ((n-1)/p)^k),
e_first = ((s*d+1)/p)^k,
e_round = (s*(d+1)/p)^k.
```

For a fresh-prefix argument, use the respective phasewise transition terms,
not an arbitrarily selected query multiplier on the interactive union.
`packed_budget.atomic_zerocheck_phase_bounds` requires explicit schedule four;
the old conservative interactive worksheet is unchanged. A batch can track
one fixed first false equation, since its messages and sum claims remain
separate despite shared round coins. Other equations do not repair that
equation. This does not require independent challenges between equations.

The grouping matters for the conditional argument: after conditioning on an
earlier equality point being a zero, the final separate point need not have
the complete block's amplified error. Likewise, a previously exposed mixing
matrix with a zero row can leave fewer independent row tests. Small-field
model checks demonstrate both distinctions; they are not complete forgery
attacks against the older schedules. The new blocks give the needed fresh
distributions directly. Fixed-word/virtual-source coupling, valid linked
histories, all parent obligations, all-trials resource envelopes and knowledge
extraction remain necessary for whole-protocol security.

### Static opening ceilings for shared parent stages

`polyfrim_opening_terms.shared_stage_schedule` now counts the shared verifier's
stage loops directly, without assuming the old per-owner lifetime allowances.
The scope is the selected radix-8/radix-5, one-lookup-pair composition. Let d
and s be the main/final digit counts, k the source width, and
r=ceil(log2(lwe)). The four-role ceilings are:

| Role | PCS invocations | Total ordered queries |
| --- | ---: | ---: |
| Main source | 16d+22 | (4d+6)k+12d+r+21 |
| Main helper | 2d | 2d |
| Final source | 8s+8 | 2(s+1)k+6s+6 |
| Final helper | s | s |

For the main role, the invocation count sums the 2(2d+1) NTT source openings,
4d+1 key-product factors, 2(2d+2) decomposition linear sources, at most
2(2d+1) used lookup-source groups, seven accumulator sources, four monomial
NTT source openings and two monomial product factors. Each NTT source call
has k ordered queries. Accumulator queries consist of seven base queries,
two endpoint selections, two duplicated-half selections and r+1 carry/wrap
queries, totaling r+12. Lookup source grouping cannot exceed its number of
used digit/borrow slots; an unused original-input slot creates no claim.

For the final role, count one known-input opening, 2(s+1) NTT source calls,
2s+1 product factors, 2s+2 linear sources, at most 2s+1 used lookup groups and
one extraction opening. Helpers have one opening per request/repetition.
The verifier checks the relevant proof-array counts before accepting; root
aliases and duplicate claims can reduce these totals. Honest zero-root
aliasing must not be used as a universal maximum for adversarial tables.

The default native widths give call ceilings [86,8,64,7] for BabyBear and
[150,16,112,13] for Goldilocks. Ordered-query ceilings are [255,8,176,7] and
[279,16,196,13]. Archived native observations lie below both sets. Their
smaller counts are evidence for the implementation path, not the derivation
of these bounds. The source-width choices 16/8 change NTT query counts while
preserving call counts; helper-basis packing does not change this stage graph.

For direct/dictionary PolyFRIM there is one consistency-index phase per
ordered query and one rolling-index phase per invocation. Brakedown and
virtual fragmented PipFRI use one final sampling phase per invocation;
ordinary fragmented PipFRI uses two. These counts do not by themselves bound
all XOF/hash calls or charged attacker work. The report option
`--stage-ceiling` applies the new ceilings, remains mutually exclusive with
the old `--schedule-ceiling`, and retains disabled whole-security/promotion
flags. Its hypothetical query override does not change a recorded proof or
select a trusted security profile.

### Deterministic canonical digits and the native parent contract

The decomposition's integer implication is separate from its probabilistic
linear and lookup checks. Let B be the radix, m_i the digits of p-1, d_i the
claimed digits, and b_i the borrow bits. Membership in the actual public
transition tables gives `0<=d_i<B`, `b_i in {0,1}`, and
`b_(i+1) = [d_i+b_i>m_i]`. Put
`r_i=m_i-d_i-b_i+B*b_(i+1)`. Then every r_i is in [0,B-1], and telescoping gives

```
sum_i B^i*r_i = (p-1) - sum_i B^i*d_i - b_0 + B^d*b_d.
```

The authenticated zero endpoints b_0=b_d=0 therefore force the integer digit
string D into [0,p-1]. Its field reconstruction equals x, so D is the unique
canonical representative of x and its digits are the native radix digits.
In particular, field-congruent strings p and p+1 cannot pass the borrow
conditions for x=0 or x=1. This reasoning uses the integer meaning of the
public tuple entries; it does not infer integer ranges from field equations
alone. Both main and final decomposition configurations cover their complete
source capacities, respectively `2*n*next_power_of_two(lwe)` and `2*n`.

The new native-contract tests use the production comparison tables and native
`Polynomial::decompose_lsb_bits_inplace`, for both fields and both radix sizes
5/8. Boundary values, negative inputs including zero, and congruent integer
aliases are checked. Both tests pass. Their role is implementation agreement;
the telescoping argument supplies the general integer implication.

Assuming truthful checks on consistently decoded tables and honest public-key
preprocessing, the parent constraints imply the supported native computation:

* The shared exact modulus-switching helper fixes the public rotations and
  initial accumulator from the two ciphertexts. `bind_inner` fixes all primary
  coefficient/evaluation/input/accumulator roots and the final accumulator
  before the first algebraic challenge.
* At each active blind-rotation row, the monomial check fixes M_i from A_i and
  the public rotation. Accumulator checks enforce U_i=M_i-A_i, identify its
  two duplicated decomposition inputs, and enforce V_i=A_i+T_i. Canonical
  digits, the NTT identities and the key sum-product relation fix T_i to the
  native gadget external product. The initial/continuity/final identities
  then give the native final accumulator by induction on active rows.
* Final key switching binds that same endpoint, the public output, and its
  new primary roots before its checks. The known input is the duplicated
  negative a-polynomial, matching the native gadget routine's negation before
  decomposition. Canonical digits and the NTT/key product checks fix its
  sum-product polynomial T. The extraction constraints impose
  `a_out[0]=T_a[0]`, `a_out[j]=-T_a[n-j]` for the original output coordinates,
  and `b_out=T_b[0]+final_b[0]+floor(p/8)`. These are the native extraction and
  bias operations for the supported ring/output geometry.

This also gives a conditional parent-case split fixed at the initial binding:
either the declared final accumulator differs from native blind rotation, or
it agrees and the output differs from native key switching. In the former
case some blind-rotation obligation is false; in the latter the final-stage
task stays false for every choice of its later auxiliary roots. Within a
decomposition, after borrow roots are bound, either a linear reconstruction/
endpoint obligation is false or some transition lookup is invalid. The first
such obligation can be selected before its coins; later helper choices do not
repair the already fixed primary digit string. Monomial auxiliary NTT roots
admit the analogous split into a false NTT or product obligation.

These are deterministic semantic implications, not yet an end-to-end
first-query theorem. They require the fixed decoded-table interface and
truthfulness of the component checks. Root availability/proximity, receipt
recovery, compressed-child linkage, phasewise failure bounds, all-trials work
and the requested knowledge statement still need to be composed explicitly.

### Conditional emulation of one framed challenge phase

Model the XOF as an oracle mapping each complete input byte string to an
independent infinite uniform byte stream, with deterministic replay on repeated
inputs and consistent prefixes when reading different output lengths from the
same input. This is an explicit ideal-XOF assumption, not a concrete SHAKE256
security theorem. Expose adversarial queries to arbitrary complete inputs,
including those not made through the transcript API. The relevant freeze is
the first query to a challenge input, not merely the honest verifier's later
API call.

For the supported 64-bit target, the frame consists of a kind byte, LE64 label
length, label bytes, LE64 message length, and message bytes. The encoding is
injective over those inputs. A challenge-phase input is the complete preceding
framed history followed by its request frame. Distinct such input strings have
independent XOF streams when first queried; a previously queried string reuses
its answer. Querying a shorter input string reveals no bytes of a different
longer input in this model. This statement concerns complete XOF inputs rather
than collisions in the concrete sponge's internal state.

The implementation maps those streams to ideal challenge distributions as
follows, without a prover message inside the phase:

* Byte challenges bind their requested length before reading that many bytes.
  They absorb the output in a subsequent receipt frame.
* Prime-field phases bind the prime and total coefficient count. With
  `b = ceil(log2(p))`, each candidate is uniform on `[0,2^b)` after masking;
  rejection of candidates at least p leaves an exactly uniform value in the
  prime field. Successive accepted coefficients are independent, since each
  consumes fresh bytes from the stream. Termination is almost sure; charged
  work must include rejected candidates, not only accepted coefficients.
* Extension-field phases additionally bind the field/basis descriptor and
  sample D independent base coefficients per value in basis order. Under the
  trusted field-type assumptions this is uniform on E, independently across
  vector entries. Basis irreducibility is not proved by transcript framing.
* Index phases bind a power-of-two domain and the requested byte-vector length.
  Masking each independent 64-bit word gives independent uniform indices with
  replacement. Duplicates are part of this distribution, not extra entropy.

For field phases, the receipt binds the consumed byte count and a 64-byte XOF
fingerprint of the consumed stream, including rejected candidates. That
fingerprint's raw input starts with the distinct literal namespace
`HasteBoots consumed field bytes v1`; challenge histories start with a frame
kind of zero, so the two input namespaces are disjoint. Receipt fingerprints
do not replace the earlier framed history. The phase has already fixed all
its requests before reading, so this deterministic receipt processing cannot
retroactively select a different challenge distribution.

This constructs the ideal whole-phase oracle used by the conditional
fresh-prefix reduction from an ideal XOF, for inline transcript histories.
Seeded children still compress parent history: their input contains the
profile, child label/context and 64-byte parent seed. Their return is bound by
a 64-byte child finish fingerprint, and the API also checks a 64-byte parent
checkpoint. Distinct histories that collide in these compressed fingerprints
must be charged separately. Under the ideal-XOF model, collisions among at
most M distinct XOF inputs have a union
bound `M(M-1)/2^513`, using a global deterministic envelope and including all
adversarial trials. This term concerns those fingerprints, not all field or
index outputs, which are deliberately shorter and may repeat. Profile hashes
use the separate SHA-512 model and its own global query accounting.

Output collisions alone do not cover guessed links. An adversary may query a
child history containing an arbitrary proposed parent seed before querying the
parent seed input, or query a parent continuation containing a proposed child
finish value before querying that child's finish input. Such guesses require
a separate late-target bound. At each first fingerprint query, freeze the set
of already proposed linking values in prior candidate-history queries; a fresh
64-byte output hits that set with probability its cardinality divided by
`2^512`. Sum these predictable target exposures, using a deterministic bound
or an expectation bound. The inventory must count all proposed link slots and
their byte-processing cost, not just completed forks or one accepted proof.
No numerical total for this term is assigned here.

One conservative way to make that link inventory independent of a candidate
transcript parser is to register **every 64-byte window** of every complete
XOF input before exposing its answer. Let B bound the total number of such
windows across all distinct candidate inputs, including verifier queries, and
let M bound the number of distinct XOF inputs exposed. Repeated inputs need
no new window or output charge. Both are global deterministic resource caps,
not counts from an accepted proof. Registering unrelated windows only enlarges
the target set. A fresh 64-byte fingerprint output hits previously registered
windows with probability at most B/2^512, conditional on the entire prior
history. Thus the union of output collisions and guessed links is at most

```
M*(M-1)/2^513 + M*B/2^512.
```

This is a link-ordering lemma under the stated ideal-XOF model, not a full
protocol reduction. In particular, suppose a correct candidate child input
containing its parent seed was queried before the seed-producing input. The
seed bytes were then already a registered window when that fresh seed was
answered, giving the second event. If the seed-producing input had already
been queried, the dependency was available in order. The same dichotomy holds
for a parent continuation containing a child finish fingerprint. If two
different producing histories share a fingerprint, the first event applies.
Outside these events, compressed links of any subsequently accepted transcript
can be followed to their producing inputs in query order, with exact replay
permitted. Framing prevents two distinct full histories from being the same
input. This argument applies to arbitrary proposed candidate histories; it
does not require the adversary to use the transcript API.

The implemented child seed and finish values are inserted as contiguous raw
64-byte fields, so window registration covers their proposed values. It does
not prove that a candidate's earlier field/index receipts are consistent with
their generating streams, assign a bad-state predicate to the whole PBS, or
establish a knowledge extractor. Those obligations cannot be replaced by
link ordering. Nor is B bounded by the number of oracle calls alone: a single
arbitrarily long input can contain arbitrarily many proposed windows. A
work-cost use therefore must charge processed input bytes (including a
justified treatment of shared prefixes) and honest/verifier offsets. This
gives a symbolic bound for the previously unspecified link term while leaving
its actual attacker-work envelope unassigned.

There is a further useful **inline receipt-recovery** step in this ideal-XOF
model. At the first query to a candidate framed phase input, freeze the known
XOF input/output database. For analysis, record the first 64 bytes of each
queried stream. A byte-challenge receipt already contains its proposed earlier
coins. A field receipt instead contains a 128-bit consumed length and a
64-byte fingerprint. Resolve that fingerprint to a known producer input in
the distinct `HasteBoots consumed field bytes v1` namespace. Outside output
collisions that input is unique. Its suffix supplies the raw consumed bytes.
Replay the trusted prime's masking/rejection sampler, require exactly the
requested coefficient count and exact exhaustion of those bytes, and check
the consumed length. The preceding trusted kind/basis descriptor determines
whether these are prime values or grouped extension coefficients.

This recovers the candidate prefix's **proposed** prior field challenges even
if their own phase inputs have not yet been queried. It does not assert that
those proposals equal their producing streams' eventual outputs. Such equality
is required when the actual verifier follows a complete accepting path. If
the receipt producer was not available in the frozen database but the prefix
later appears on such a path, its subsequent fresh fingerprint output hits a
previously proposed 64-byte window, or a different producer causes an output
collision. Those are exactly separately charged events above. A known producer
with invalid namespace, consumed length or replayed sampling shape cannot
describe that actual prefix outside the same collision event.

Consequently one must not require all inline challenge queries to occur in
protocol order, or freeze their semantics retroactively. The proposed coins
can instead be interpreted from their known receipt preimages at the actual
first query. Later discovery of a preimage cannot repair that earlier query's
snapshot. The receipt model tests check this distinction, rejected candidates,
length/count mismatches and zero-count requests against the existing receipt
format; they do not test the probability of guessing a fingerprint.

This is an interface for defining component states at candidate prefixes.
It still requires a protocol-specific admissible-prefix interpretation,
including which typed messages/roots affect each state. Seeded children need
the compressed-link argument in addition to inline receipt recovery; virtual
identifiers need their upstream word definitions. No whole security or
attacker-work certificate follows from receipt reconstruction alone.

To obtain a full protocol bound one must still supply a state predicate with
uniform bad-transition bounds at every actual first-query prefix, account for
all parent/child fingerprints and first-query availability freezes, and relate
XOF reads and query counts to charged classical work. Replacing concrete
SHAKE256 by the assumed ideal XOF is also a separate primitive-modeling step.
Thus this phase-emulation argument removes neither the remaining rolling/vector
proximity obligation nor the noninteractive knowledge/extraction obligation.

### Conditional rolling component state predicate

The distance-sensitive rolling induction above can be expressed as a component
state predicate in an **ideal fixed-word game**. This still assumes its
exceptional-polynomial lemma uniformly for every prior history. All original
words V_i must be fixed before the first rolling challenge; each derived word
may be chosen arbitrarily after the preceding challenge. A hash/virtual-oracle
reduction must couple the implementation to this game separately. Conditioning
challenge probabilities on the absence of a future hash failure would not be
a valid substitute for that coupling.

Choose delta as in the induction, use integer radii `floor(delta*n_i)`, and let
eta_i be its minimum error potential over initial-domain indices. Immediately
before fold challenge i, call the component state bad when

```
eta_i >= delta OR some original V_j with j>i is farther than delta from RS_j.
```

For a false proximity statement this holds initially: a far V_0 gives the
first disjunct, and any later far input gives the second. Original-word
availability is a premise of the game, so these future-input distances cannot
be changed by later prover messages.

If a far original remains strictly later than the next layer, the second
disjunct persists with no probabilistic loss. Otherwise either eta_i is already
at least delta or the newly introduced V_(i+1) is far. Apply the far/near branch
argument above to the fixed triple `Even(C_i), Odd(C_i), V_(i+1)` (with the last
row zero for the terminal fold). Except on its exceptional alpha set, the
computed next combined word W has minimum potential at least delta. The
exceptional set is determined before alpha_i, even when C_i depends on all
earlier messages and oracle history. Its conditional measure is at most
`2*n_(i+1)*(n_(i+1)+1)/|E|`, capped at one.

The prover then chooses its next derived word, giving a claimed combined word
C'. Let B be the old bad-path set and M the paths on which C' differs from W.
For every candidate next codeword h, pointwise on initial-domain indices,

```
B union {W != h} subset B union M union {C' != h}.
```

The right-hand side is exactly the next potential's rejection/disagreement
set. Therefore **every** prover choice preserves the lower bound once W has
it. This supplies the between-challenge closure step; an honest derived word
is not required. Before that message, use W's potential for the intermediate
state, then use the displayed inclusion after the message. The same argument
handles a prover-chosen terminal constant, treated as the final claimed word.

At the terminal layer the word is constant, so its minimum potential is the
measure of bad paths itself. There are no remaining future inputs. If the
state is bad, this measure is at least delta. The complete final index-vector
phase misses every bad path with probability at most `(1-delta)^Q`, since the
Q indices are uniform with replacement and fixed before prover responses.
After the vector is drawn, keep the state bad when a sampled path is bad.
With ideal authentication no subsequent opening response can turn such a path
into an accepting transcript. This identifies the final bad-to-good event and
the final prover-message closure.

Thus, under the fixed-word and uniform exceptional-set premises, the component
has explicit per-fold transition bounds and a final whole-phase sampling bound,
rather than only a full interactive tail estimate. A sequential union recovers
the earlier conditional rolling bound. Applying the fresh-prefix lemma still
requires these semantic states at the actual first XOF queries, not only at
the verifier's call times. The RS exceptional-polynomial premise, virtual
vector-source coupling, global availability/link accounting and knowledge
extraction for the entire PBS composition remain separate obligations.

### Opt-in atomic NTT row schedule

`ClassicalProfile::new_atomic_ntt` constructs descriptor version two with
transcript identifier `framed-shake256-canonical-rejection-atomic-ntt-v2`.
`ClassicalProfile::new` retains descriptor version one and its original
schedule. The outer classical PBS proof encoding remains version 12; its
independently trusted profile identifier distinguishes these schedules.
The version-two parent also absorbs a schedule marker, and linked children
inherit the schedule selection. It is never selected by a proof packet.

For version two, `packed_ntt::row_points` samples all `width * row_variables`
base-field coefficients in one labeled XOF phase, then partitions them into
the independently sampled tensor row points. This places the full no-message
repetition block at one challenge boundary for the intended amplified bound.
The zero-row-variable case still returns width empty points without dividing
into zero-size chunks. Version one and all legacy transcripts retain the
original repeated calls. The coefficient-compression schedule is unchanged.

The native harness and sequential runner expose this opt-in as `--atomic-ntt`.
It changes the trusted profile and proof transcript, so its proofs are not
expected to match version-one fingerprints. Source geometry, FHE parameters
and public inputs remain selected independently as before. This addresses a
challenge-phase boundary needed by the analysis; it does not establish a
whole security bound or promote any query count. Focused tests and end-to-end
validation of the new profile are still required before using it as evidence.

### Conditional unmasked fragmented scalar-opening bound

This argument is in the ideal fixed-word/challenge game. It assumes the
RS exceptional-polynomial construction and the rolling induction above,
uniformly conditional on prior histories. It does not identify every actual
hash/XOF freeze or complete the PBS knowledge reduction.

Let there be f source fragments, each encoded on n0 points with degree bound
less than m0, rate `rho=m0/n0`, and extension field E of size q. Put
`theta=(1-rho)/4`. A well-formed source for this argument has fragment words
jointly within `floor(theta*n0)` positions of a unique tuple of RS codewords.
Their coefficient vectors, interpreted under the trusted coefficient/Boolean
basis convention, define one scalar table independent of the opening point.
The opening point may be chosen adaptively after this fixed source. The
claimed value and fragment evaluations u must be fixed before gamma, as the
implementation's `bind` requires; their high-point aggregation is checked first.

**Scalar virtual-source interface to availability.** Fix the trusted scalar
parameters and one packed source root before the fragment batching challenge.
Assume the global availability event supplies a single complete packed word
A indexed by positions 0 through N/2-1, with exactly f pairs per position,
and every accepted source authentication returns A at its requested position.
This premise is about every possible later opening, not just positions seen
in the eventual proof. Define W_j(2s+b)=A(s)[j][b] for b in {0,1}; a missing
leaf in the availability completion is the zero vector of this exact shape.
After gamma is fixed, define W_gamma(x)=sum_j gamma^j W_j(x) on the entire
initial domain. This definition is independent of all rolling challenges,
derived roots and query indices. It does not use the virtual identifier as a
Merkle root and does not assert that any W_j is a codeword.

In `virtual_source::verify`, `bind` absorbs the source root, point, value and
all claimed fragment evaluations before gamma. `powers` has exactly f
entries. The authentication callback requires exactly f source pairs, checks
the position-specific packed leaf and full Merkle path at s=index/2, and
compares both coordinates of their weighted combination with the rolling
original pair. Therefore every accepted first-original pair equals
[W_gamma(2s),W_gamma(2s+1)]. `rolling_fri::verify_mode` calls this callback
for every sample and rejects a supplied virtual Merkle path. The subsequent
public-point checks reuse those same original pairs. Thus, conditional on
availability and the correct interpreted pre-gamma history, the scalar
implementation supplies precisely the fixed virtual initial-word oracle
required by the rolling argument. Repeated indices need no new independence
assumption: every callback is constrained to the same complete word.

Following public-point ladder roots are genuine commitments and are all
absorbed before the first rolling challenge. Their availability completions
supply the remaining fixed originals. Each derived root is instead absorbed
after its preceding fold challenge and before the next challenge; it must
use its own earlier-declaration completion. This scalar interface does not
establish the global availability premise, admissible first-query histories,
low-degree proximity of source fragments, or matrix-bridge/source extraction.
Those obligations remain in the complete composition.

**Power-weighted projection.** For fixed fragment words W_j, the combined word
is `W_gamma=sum_j gamma^j W_j`. Work over E(T) and construct the univariate
Berlekamp–Welch matrix afresh for `sum_j T^j W_j`. If it were generically
theta-near, interpolation at its good positions and independence of the formal
monomials `1,T,...,T^(f-1)` would give common nearby codewords for every W_j.
For a jointly far source this is impossible. Every matrix entry has T-degree
at most `d=f-1`; scaling the minor/kernel/pseudoremainder degree accounting by
d gives a nonzero exceptional polynomial of degree at most `d*n0*(n0+1)`.
Thus W_gamma is theta-near with probability at most that degree divided by q.
For f=1 the word does not depend on gamma and the exceptional probability is
zero. Substitution into a preselected multivariate minor is not this argument.

For a near source, let g_j be its fixed decoded fragment polynomials. The
combined word is theta-near `G_gamma=sum_j gamma^j g_j`, which is its unique
nearby polynomial. If the claimed scalar value is false, at least one u_j is
wrong: otherwise its checked high-point aggregation would be correct. Hence
`sum_j gamma^j (g_j(low_point)-u_j)` is a nonzero polynomial of degree at most d.
It vanishes with probability at most d/q. Near/far are properties fixed before
gamma, so `d*n0*(n0+1)/q` dominates either gamma escape, rather than requiring
independent weights or summing the two mutually exclusive cases.

**Virtual initial word, version two.** The initial rolling original is exactly
W_gamma, authenticated by the packed-fragment callback. Following public-point
fold words are fixed before the first rolling challenge. Apply rolling
proximity with radius theta. If any original is farther than theta, the rolling
state argument applies. Otherwise all original polynomials are uniquely fixed.
Outside the gamma escape, a false evaluation forces at least one incorrect
decoded public-point fold, including the terminal target if necessary.

At transition i let the next domain have n' points and degree bound m', and
let the two word error bounds be t_i and t_(i+1). A nonzero decoded fold
difference has at most m'-1 zeros. At most t_i antipodal pairs touch a current
word error and at most t_(i+1) positions touch a next-word error. Therefore at
least `n'-(m'-1)-t_i-t_(i+1)` pair positions reject. With radii theta and constant
rate, their fraction is at least `1-rho-3*theta >= theta`. For the final fixed
target use t_terminal=0. This argument uses field equalities and works for both
coefficient and Boolean-evaluation fold weights.

The very same Q indices test rolling folds, source authentication and public
folds. Condition on the prior prefix, not on a future acceptance event: in the
far-original case the bad rolling paths have measure at least theta outside
the charged fold exceptions; in the all-near case the bad public-fold paths
have measure at least theta. Acceptance must miss the applicable set. No
independence between checks at one index is required. A conservative
conditional scalar-opening bound for virtual version two is consequently

```
(f-1)*n0*(n0+1)/q
  + sum_(j=1)^L 2*n_j*(n_j+1)/q
  + (1-theta)^Q
```

clipped at one. The first term is a gamma transition bound, each summand is a
rolling-alpha transition bound, and the tail is one final whole-phase bound.

**Materialized initial reference.** The ordinary reference commits a separate
combined initial word and checks its equality to W_gamma by independent
consistency samples. It is insufficient simply to assume both words are near
at the same radius: their error supports can consume the entire guaranteed
initial-link gap. Keep source radius theta but use rolling radius
`delta=theta/2=(1-rho)/8`. A far source makes W_gamma farther than theta outside
the gamma exception. If the committed initial word is delta-near, their
disagreement measure is greater than theta-delta=delta, giving at least delta
rejecting pair measure. If the source is near but its decoded combined
polynomial differs from the committed initial word's decoded polynomial, the
initial-link pair rejection fraction is at least
`1-rho-2*(theta+delta) >= delta`. If those polynomials coincide, a false target
forces a bad later public fold. Far rolling originals are handled by the
rolling state as before. A safe reference bound uses the same field terms
and `2*(1-delta)^Q`, unioning its two sampling phases without assuming
independence. This looser reference bound is not assigned to the virtual mode.

Source decoding is fixed before the point in this ideal game, so the argument
allows adaptive points. Extending it to matrix openings also needs the bridge
bound and coordinate-zero projection contract stated earlier. Applying either
scalar bound to the real proofs still requires the availability/link coupling,
all-trials work accounting, the RS premise and full parent/child composition.
These formulas do not certify the current one-query correctness profiles.

The symbolic audit now covers power curves of one, four and eight fragments.
Repeated far rows over F_97 give respectively zero, three and seven cancelling
gamma values, checked at every field challenge. This tests that all possible
power-polynomial roots are charged; it is not a native-size security proof.
A two-point, zero-radius eight-fragment control has seven nearby challenges,
already exceeding `n0*(n0+1)=6`; dropping the power-curve degree factor would
therefore give an incorrect bound even in this tiny instance.

The shared tuple-lookup reciprocal loop has no deterministic iteration cap.
For a bounded-history reduction, define an analysis-only stopping event at
the first rejected reciprocal draw. Conditional on its compression challenge,
the public compressed table is fixed. The rejected set is zero together with
the negatives of its entries, hence has cardinality at most M+1 for M table
rows, including collisions and a table entry equal to zero. A fresh uniform
extension-field draw hits that set with probability at most (M+1)/q. For P
pairs encountered before the stop, a union bound is P(M+1)/q; it needs no
independence across requests or compression challenges. Outside the stop,
each pair uses one compression and one reciprocal scalar phase. The actual
verifier continues retrying; the stopped analysis pays for every discarded
execution rather than treating its cost as bounded.

For all-trials use, the reciprocal stopping event must be included in the
conditional error for each eligible adversarial phase query and each verifier
submission. Charging it only once for the final accepted proof is invalid.
Recovering admissible earlier histories and bounding their candidate phase
queries are still prerequisites. Canonical field rejection consumes bytes
inside one phase and is a separate resource issue; this lemma does not bound
XOF bytes. `packed_budget.lookup_first_retry_bound` implements this arithmetic;
finite-field model tests include duplicate compressed entries and zero.

`tools/fragmented_opening_terms.py` evaluates these conditional phase terms
with exact rational arithmetic for an explicitly supplied role geometry and
query count. It mirrors the scalar adapter's logical/physical constant padding,
fragment cap and power-weight degree, and keeps ordinary versus virtual radii
and sampling-phase counts distinct. For example:

```sh
python3 tools/fragmented_opening_terms.py --prime 2013265921 --degree 6 \
  --source-vars 21 --width 8 --fragment-vars 12 --blowup 2 --queries 1 \
  --mode virtual
```

The example is the helper geometry of a one-query correctness fixture. The
tool reports bridge, gamma, per-fold and per-sampling-phase terms plus their
conditional interactive union and maximum component phase error. It assumes
trusted field/domain validity; it does not replace the Rust constructors.
It neither selects a query count nor supplies the excluded hash/link,
first-query coupling and whole-PBS knowledge/work analysis. Its security and
performance qualification flags always remain false.

## Conditional composition of parent and PCS obligations

Work in the available-word, ideal fresh-phase game of the component lemmas,
with one immutable word per root and trusted parameter context. Define a
single source-table assignment for each such pair, shared by every opening:
for Brakedown use the unique jointly near, correctly padded block-RS decoding;
for direct PolyFRIM use the coordinate-zero projection of the unique near
vector-RS decoding; for fragmented PipFRI reconstruct the unique near fragment
tuple's scalar table under its trusted basis and project coordinate zero.
If the required decoding promise or Brakedown's encoded zero-padding promise
fails, assign the all-zero table of the trusted shape. For a zero-variable
direct/scalar source, first restrict the decoded physical table to dummy bit
zero, as the verifier does, then project; unused dummy entries need not repeat. The assignment does not depend on an opening query, claimed
value, or later challenge. In the extension cases a false base-field claim
under this projection is necessarily a false embedded claim under the decoded
extension table, since projection commutes with the ordered base matrices.
Honest trusted key commitments have exact promised codewords, so their
assignments are the original public-key tables used by the native contract.

Call a PCS task false if its source is outside the relevant decoding promise
or any ordered claim differs from this fixed assignment. The opening lemmas
bound acceptance of that task uniformly over the enclosing history. The
zero fallback is not an assumption that an invalid source opens as zero:
an accepted opening of an out-of-promise source is already a PCS failure,
whatever its claimed value. Roots with different trusted contexts retain
different assignments even if their digest bytes happen to match.

Assume no accepted false PCS task occurs. Every terminal value used by an
algebraic check then equals evaluation of its assigned table. Start from an
incorrect native output. The deterministic native/canonical contract above
implies that the primary tasks cannot all hold: main products and NTTs,
canonical decompositions, accumulator transitions, public monomial action and
the final key-switch/extraction relation would otherwise reproduce that output.
All primary table assignments and the public endpoint are fixed at the outer
binding. Select the first false primary task in verifier order.

Auxiliary commitments do not invalidate this selection. For a false canonical
decomposition, every borrow assignment leaves a false reconstruction/endpoint
identity or an invalid transition tuple; helper choices cannot repair an
invalid source tuple except through the bounded compression/reciprocal escape
or a false helper identity. For a false monomial action, every auxiliary NTT
assignment leaves a false transform or product check. For a false final native
key switch, every intermediate assignment leaves a false known-input, NTT,
product, canonical decomposition or extraction check. Those intermediate
source roots are bound before the first relevant challenge. Each local
reduction either rejects deterministically or retains a false child task,
uniformly over the allowed response packet. The lookup helper boundary is
after its defining challenges, as required by its separate rational/helper
case analysis. No table is decoded anew to suit a later query.

Track the first false-to-true transition of that task through the conditional
phase lemmas. Their bounds apply before each fresh phase, not conditional on
eventual proof acceptance. A union bound over the trusted stage multiplicities,
plus accepted false PCS tasks, yields

```text
Pr[accepted incorrect native output]
 <= min(1, parent_phase_union + sum_role charged_openings_role * pcs_error_role).
```

Shared Brakedown and fragmented batches charge PCS calls. The direct PolyFRIM
calculator conservatively charges every ordered query as a separate opening,
covering its member consistency phases as well as its shared rolling phases.
Aliases may reduce actual calls but do not increase these stage ceilings.
Independence between tasks, openings, source roots or complete proofs is not
used. This is the composition represented by `classical_candidate_terms`.

This theorem is conditional on the stated fixed-word, decoder and fresh-phase
interfaces and their component lemmas. Coupling those interfaces to actual
hash/XOF queries, complete admissible histories, all attacker trials and
resource/work accounting is still required. It is not a noninteractive 128-bit
certificate. The application extractor with the original public key can use
the resulting native-output soundness bound when those remaining premises
are established; extraction from key roots alone is a different statement.

## Analysis-only canonical-sampler byte bound

Let b=(p-1).bit_length(), U=2^b and r=(U-p)/U for the trusted base
characteristic. The sampler masks each uniformly drawn byte chunk to b bits,
so r<1/2 (or zero for p=2). For a phase requesting at most n coefficients,
define an analysis-only stop when one coefficient requires more than R
candidate draws. Its probability is at most min(1,n*r^R), by a union bound.
Outside that event the consumed stream has at most n*R*ceil(b/8) bytes;
the receipt producer input additionally has its fixed namespace prefix.
This does not impose an iteration limit on the implementation.

For any accepted value v and draw number t, the joint probability is
r^(t-1)/U = Pr[number of draws=t]/p. The accepted value is therefore uniform
and independent of its rejection count. Applying the per-coefficient stop
preserves independent uniform accepted values conditional on no stop, rather
than silently replacing the sampler by a biased bounded-retry algorithm.
Its stopping error must still be charged over all eligible first queries and
verifier invocations when using the resulting resource bound.

`classical_sampler_resources` derives a per-phase coefficient ceiling from
trusted call shapes: packed equality/mixing and lookup points in the parent;
h-by-(h*2^left_vars) base tests for Brakedown; full layer/member/lane extension
weights for direct PolyFRIM; or ordered claim/lane weights for the fragmented
bridge. Role-wide query ceilings conservatively bound each individual call.
The default analysis uses R=512; production still retries until acceptance.
This supplies a per-phase byte envelope and exceptional event, not a total
oracle-query count or all-trials work certificate. Byte challenge outputs,
identity/receipt/link producers and complete admissible histories remain
separate parts of that accounting.

Brakedown's `matrix_weighted::sample_columns` uses a separate byte-rejection
loop, including in the classical profiles. For domain N it sets
L=(2^64-1)-((2^64-1) mod N), accepts x<L, and returns x mod N.
There are L/N accepted representatives per column, so accepted columns are
uniform. The rejection probability is r=(2^64-L)/2^64. In particular, for
power-of-two N the existing implementation rejects N values, giving r=N/2^64;
it does not use the zero-rejection masked index sampler. Each rejected
candidate also absorbs a receipt and makes the next byte challenge a distinct
query. The selected profile schedules remain unchanged.

In the ideal fresh-challenge game, stopping after R candidates for any of D
column draws costs at most D*r^R. Outside the stop there are at most D*R byte
challenge queries and 8*D*R output bytes. The same accepted-value/draw-count
factorization as above proves uniformity conditional on no stop. Candidate
reports use R=8 and charge all role call ceilings before deduplication of
transported columns. These bounds exclude field phases, child links and
other transcript calls. They still need the actual first-query coupling and
all-trials composition; they are not security qualification.

### PCS XOF invocation accounting

The candidate evaluator separately counts PCS-only XOF invocations for schedule
four. A field phase costs two invocations: the challenge stream and consumed
bytes fingerprint, even for an empty extension-identity phase. A detached
extension child adds seed and finish byte queries, two checkpoint invocations,
and that identity phase. Repeated identical inputs are conservatively counted
as repeated invocations rather than deduplicated.

For A opening calls and C ordered claims in one role, direct/dictionary
PolyFRIM with R=max(1, variables) uses at most A*(R+2) field phases,
2*A checkpoints and 3*A+C byte queries: seed/finish, one rolling-index phase,
and one consistency-index phase per ordered claim. Dictionary transport does
not alter these counts. For scalar dimension nu and R=min(max(1,nu), cap),
fragmented modes use A*(nu+R+3) field phases (identity, rho, bridge, gamma,
folds), 2*A checkpoints, and 4*A ordinary or 3*A virtual byte queries.
Brakedown uses A field phases and the separately stopped column-byte loop,
without extension children. Index phases emit 8*Q bytes; seed, finish and
checkpoint invocations emit 64 bytes each. Field stream byte lengths are
accounted for separately by the coefficient/rejection envelope.

These are upper bounds on an invocation, including prefixes that reject early,
using the trusted call/ordered-claim ceilings. They exclude parent algebra,
lookup children, outer initialization and serialized input/frame lengths.
They do not yet justify a complete verifier or all-trials resource bound.

The verifier query envelope adds the parent phase inventory to these PCS
ceilings. The two main decompositions and final key decomposition each use
one shared lookup child, regardless of the number of requests in that child.
Besides the inventoried nonempty field phases, these children add three empty
identity phases, six seed/finish byte queries and six checkpoint invocations.
The prime outer transcript constructor only absorbs data. Lookup scalar
sumchecks use one common challenge per round, without an extra equation-batch
mixing challenge. The reciprocal loop is counted only up to the first rejected
reciprocal; its exceptional event is already explicit in the lookup phase
inventory. Thus this count applies in the stopped ideal game and to rejecting
prefixes, not unconditionally to arbitrarily long production retry executions.
The candidate reports retain those stop conditions and keep complete resource
qualification false. Input/frame lengths, sampler stream lengths and actual
first-query/all-trials composition still need separate bounds.

The output envelope combines the verifier phase count F with the maximum
per-phase coefficient ceiling n. Its additional field-sampler stop error is
at most F*n*r^512, and raw field output is at most F*n*512*ceil(b/8) bytes.
It adds 64*F fingerprint-output bytes, the counted byte-challenge outputs and
checkpoint outputs. The receipt producer inputs total at most F times the
per-phase namespace-plus-raw-input ceiling. Empty identity phases are charged
the same maximum n, conservatively. Brakedown column stopping errors are
summed over all role call ceilings; the lookup first-retry error remains in
the parent lookup union and must not be added a second time. These statements
assume fresh independent ideal streams and the previously stated stops. They
do not bound framed transcript input sizes or adversarial/all-trials resources.

### Additional PCS frame accounting

For A calls, C ordered claims, R rolling rounds and nu scalar variables,
the PCS frame envelope counts both absorbed frames and the two ephemeral
checkpoint frames per detached child. Brakedown has four frames per prime
field phase and at most three statement/response frames per call. Version-four
column byte candidates use two frames each; the version-five atomic column block
uses three frames total. A detached extension child adds twelve non-field frames: fork,
seed request/receipt, six child initialization messages, finish request/receipt
and parent finish link. Regular extension requests have five frames, including
the typed scalar/vector request marker. Direct empty child identities omit that
marker and retain four frames. Every masked index phase has
three frames: domain, request and output.

Direct/dictionary PolyFRIM adds (4+R)*A+2*C metadata frames: ordered claims,
joint proximity, projection and rolling bindings, R derived-root/terminal
messages, and member/consistency bindings per claim. Fragmented modes add
(6+nu+R)*A metadata frames: ordered claims, sumcheck info and nu round
messages, scalar adapter mode, scalar claim, public roots, rolling binding and
R roots/terminal messages. The sumcheck-info term overcounts the zero-variable special case.
Virtual mode removes three index frames per call. Registry and enclosing
parent messages are outside these PCS increments.

On the stated 64-bit runtime, each successfully constructed label/message
slice has at most 2^64-1 bytes. One frame is therefore at most
17+2*(2^64-1) bytes. Multiplying by the additional frame ceiling bounds PCS
input increments across parent, children and checkpoint snapshots. This is
deliberately loose and does not bound pre-existing parent prefixes. Raw
receipt-producer inputs use their separate sampler bound. Complete parent
framing and all-trials/source-prefix composition remain required.

The parent-frame envelope now supplies the remaining typed native increments.
Prime phases have four frames; regular extension lookup phases have five,
and the three direct empty identities have four. The three lookup children add 36 non-field link
frames and six ephemeral checkpoint frames. Metadata contributions are listed
individually in candidate reports: eight constructor/schedule/profile frames and one
outer binding; two messages per NTT relation; v+3 messages per single
ZeroCheck of v variables; product bindings/terminals; monomial roots/binding;
final key mode/binding/known-input; accumulator binding; and shared radix /
lookup messages. Each comparison with d digits and n helper variables adds
11+2*d+n non-registry metadata messages. Its registry adds initialization,
seal and at most 2*d+1 caller-derived source claims. There are comparisons
(d,n)=(d_main,21),(d_main,21),(d_switch,11). Source aliases can only reduce
their actual registry claims and PCS calls.

Adding parent and PCS frames, including frames on all child branches and
checkpoint snapshots, overcounts any single framed query prefix. Multiplying
by the successful-slice frame byte bound yields a finite maximum prefix
length. Taking its maximum with the separate raw receipt producer input bound
covers both XOF input formats in the stopped verifier. An input of at most L
bytes contains at most max(0,L-63) overlapping 64-byte windows. These are
typed verifier bounds under the stated analysis stops, not yet bounds on all
adversarial candidate inputs or a proof that every candidate prefix determines
the required fixed source/task. That coupling and all-trials composition remain
separate obligations.

For the XOF-only all-trials polynomial, let V bound producer invocations per
stopped verifier, L bound eligible input bytes and h be an explicitly supplied
honest producer offset. If adversarial oracle queries and verifier submissions
are each at most charged work T, then M <= (1+V)*T+h. If every relevant
eligible input obeys L, the predictable window count is at most
B <= max(0,L-63)*M. Inputs rejected by the filter still contribute producer
outputs to M; only their proposed link windows are omitted. The filter must
therefore be proved to preserve all relevant producers before applying this
conditional arithmetic to the real protocol.

`bounded_input_xof_work` substitutes these affine caps into the existing
512-bit collision/link envelope, using M^2 in place of M*(M-1). The native
wrapper requires the caller to supply h and leaves eligibility/resource
coupling false. This removes a free query-budget assumption from the formula;
it does not establish the remaining filter/source proof, include algebraic /
sampler stops or Merkle errors, or supply whole-proof security qualification.

Length filtering preserves producer recovery for a stopped trace with inputs
bounded by L, outside distinct-input collisions of the first 64 XOF output
bytes. Suppose a verifier receipt/link has actual producer input s and a
known input u has the same fingerprint. Collision freedom implies u=s,
so u is also bounded by L. Removing larger producer inputs therefore removes
no genuine known producer for this trace. Filtering retains original global
first-query indices; it must not assign a later query a new earlier snapshot.
This applies recursively to seed, finish and field-receipt producers.

If the actual producer was not known when a candidate input first proposed
its fingerprint, that proposal is a 64-byte window in the candidate input.
For a relevant bounded input, the window is registered despite excluding
larger inputs. A subsequent fresh producer that matches it is exactly the
late-link event already charged. Oversized producers remain included in M,
so their output collisions have not been discarded. This proves length-filter
preservation for bounded actual traces; it does not prove that an arbitrary
bounded framed candidate is a valid application stage or determines the
required source/task. That semantic first-query coupling remains unfinished.
The executable structural model tests an oversized earlier unrelated producer,
preserved recursive seed/finish recovery under a sufficient bound, rejection
under an insufficient bound, and unchanged original query chronology.

### Standalone PCS hash outputs including bindings

In addition to authentication, Brakedown hashes its adapter context once per
call. Direct PolyFRIM hashes one adapter context, R virtual layer identifiers
and one rolling context; dictionary PolyFRIM adds one nested adapter context.
Thus their additional counts are 1, R+2 and R+3 respectively. Ordinary and
virtual fragmented scalar openings have three and six binding hashes beyond
their authentication formulas, respectively; their matrix adapter adds one
context hash, giving four and seven per call. The candidate evaluator charges
these against opening-call ceilings, separately from ordered claim ceilings.
Parent calls to parameter contexts and preprocessing are still excluded.

`pcs/tests/classical_hash_resources.rs` counts SHA-512 output invocations in
actual verification for both native fields, blowups 2/4/8, batches 1/2/4 and
all five adapters (90 verifications). Direct/dictionary and fragmented totals
match exactly; Brakedown's deduplicated transported columns fit its stated
upper bound. The global test counter is owned by one test and includes joined
Rayon authentication work. These checks support the standalone PCS formulas,
not a complete all-trials protocol hash bound.

Parent context hashes are now inventoried by stage and role. Outer validation
runs twice (once directly and once inside the outer binding), each time
checking parameter contexts and both original key contexts. The outer binding
also hashes its seventeen role references. Remaining counts include key
context checks, factor contexts, both NTT contexts per relation, shared radix
bindings and reconstruction sources, every lookup request's three source
contexts and helper context, registry slots and source-alias checks, accumulator
sources, monomial inputs and the final key stage's preflight/binding/public-input.
For d main radix digits and s switch digits, role context-call ceilings are
[28*d+64, 2*d+7, 14*s+39, s+8]. Dictionary contexts each produce two hashes;
all other selected contexts produce one. The public classical wrapper also
computes the profile identifier twice using SHA-512 directly. Adding these to
standalone PCS hashes supplies the typed verifier invocation hash ceiling;
honest preprocessing and all-trials/source coupling are separate obligations.

The context audit also corrects two framing contributions: parent construction
absorbs the trusted-profile message in addition to the seven base constructor /
schedule frames, and a Brakedown single opening uses separate context and
claim bindings, whereas its batch opening uses one. The frame model charges
the larger three-message statement/response shape to every Brakedown call.

The joint filtered oracle worksheet additionally overregisters root declarations
as every digest-sized window in eligible inputs to either oracle family. Let
H <= a*T+h and M <= b*T+m, with a=1+V_hash and b=1+V_xof. If eligible hash
and XOF inputs have at most L_h and L_x bytes, define w_h=max(0,L_h-63)
and w_x=max(0,L_x-63). With a separately supplied honest root offset r,
R <= (w_h*a+w_x*b)*T + w_h*h+w_x*m+r. This includes declarations across
all candidate inputs and verifier submissions, rather than accepted-proof
roots alone. Collisions still count outputs of ineligible inputs. The root
filter must preserve every declaration relevant to the fixed-source argument;
this obligation is explicit and not established by the worksheet.

`candidate_oracle_work` binds these conditional Merkle/XOF polynomials to the
exact descriptor and requires all three honest offsets. Its hash-input ceiling
uses the larger framed-prefix bound, which also covers a successfully encoded
64-bit Vec plus fixed hash namespaces or two digest children. It does not cap
arbitrary adversarial inputs. Downscaled worksheet tests derive window width
from the selected digest width; native SHA-512 uses 64 bytes. The resulting
oracle components still require algebraic/opening/sampler error composition,
actual prefix/source/filter coupling and knowledge/performance qualification.

### Opt-in version-five atomic Brakedown columns

The version-four Brakedown verifier samples each column with a separate
eight-byte challenge and retry loop. Its iid interactive sampling bound does
not by itself give a single fresh-phase bound for an arbitrary first-query
prefix containing intermediate byte receipts. The analysis must either prove
that sequential-byte composition or use an explicitly different schedule.
This observation is a proof obligation, not an established attack.

`new_atomic_columns` / `new_classical_atomic_columns` introduce schedule five,
retaining the three earlier atomic field schedules and binding an additional
`atomic Brakedown columns v5` schedule marker. Brakedown uses the existing
power-of-two index primitive to request all 8*Q bytes in one phase, draw Q
independent uniform positions with replacement, then sort/deduplicate only
the transported columns. There is no column-byte retry loop in this schedule.
The profile ID binds version five and its distinct transcript suite; versions
one through four preserve their previous constructors, flags and byte paths.
Detached and scoped version-five extension children inherit the atomic flags.
The version-five factory rejects unrepresentable byte-vector sizes.

The Rust core has block/deduplication, profile separation, inheritance and
decoded batch-proof tests for both fields. The native harness, grid and runner
accept the mutually exclusive `--atomic-columns` option. Strict descriptor
tooling checks its suite and representable byte counts. Resource models count
one column index phase per call, no column-retry error, and the additional
schedule frame; inherited field/algebraic bounds are unchanged. Actual grid
exports validate all 702 unique admitted profiles against IDs, bases, metadata
and candidate resource reports. Complete fresh/native schedule-five validation
is still pending. It is not the default and has no security or performance
promotion. Schedule-four reports retain an explicit sequential-column coupling
obligation for Brakedown.

### Combined conditional classical work worksheet

`candidate_classical_work` requires schedule five and explicit honest hash,
XOF and root offsets. Let e be the maximum parent phase or PCS per-opening
error, plus the maximum per-phase canonical-sampler stopping error, clipped
at one. Let v be the conditional parent/PCS union plus the whole-verifier
sampler stop union, again clipped at one. Adversarial phase queries and
verifier submissions each cost at least one unit of work T. The phase
component is bounded by h_xof*e+(e+v)*T; the constant conservatively charges
honest XOF outputs as phase opportunities too. Lookup first-retry error is
already in the parent terms, and atomic column sampling has no retry error.

The worksheet sums that component with the descriptor-bound Merkle and XOF
constant/linear/quadratic components before minimizing
T/min(1,P(T)) over all positive integer T. It uses exact rational arithmetic
and hex output, without an attacker query cutoff or decimal-size assumptions.
The CLI exposes it via `--classical-work` and requires all three
`--honest-hashes`, `--honest-xof-outputs`, `--honest-roots` arguments. Missing
offsets reject before creating output. `--target-bits` defaults to 128 in this
mode. Ordinary candidate reports retain their previous mode.

The reported work target is conditional on a uniform fixed-task first-query
reduction, source/window-filter preservation, trusted verifier ceilings and
justified offsets. Complete actual prefix/source/filter and soundness/knowledge
composition is not established. Even a passing numerical scenario keeps
protocol admission, security, promotion and query-selection flags false.
Tests cover weak sampling, fields that cannot be repaired by more queries,
large honest offsets, both native fields/all five variants, and summation
before work minimization.

### Initial primary-task prefix interpretation

The outer-prefix audit now recovers the first primary product's trusted
shape and ordered (context, root) handles from the canonical outer binding.
For d bootstrapping digits the factor sequence is
ev_0,key_0,...,ev_(2d-1),key_(2d-1),ev_(2d). Its shape is the trusted packed
relation sum_i ev_i*key_i-ev_(2d), with 4d+1 factors. Evaluation contexts
come from the trusted evaluation parameters and key contexts from the trusted
key parameters; root bytes alone do not identify a source assignment.

Given the fixed source assignment interface, these handles determine the
initial residual table before the first equality-point phase. The unbound
first response and later proof suffix cannot change that table. Their shape
or encoding guards can remove continuations, but cannot change a surviving
prefix's source handles or trusted product shape. At the first mixing phase,
the first response has additionally been absorbed; the equality coins are
the preceding phase's inline receipt values. Complete candidate receipt /
source interpretation beyond this boundary remains a separate obligation.

The executable audit covers both native base fields, all five PCS variants
and schedules four/five (20 combinations). It commits actual constant-valued
evaluation tables and uses the original zero-key setup, explicitly checks a
nonzero product residual, reconstructs the binding from recovered handles and
compares the first equality/mixing phases against the production relation
verifier. A malformed later sumcheck suffix forces the same deterministic
rejection after those phases. Replayed transcript tails match. The audit also
retains canonical outer-count, version, trailing-data and oversized-count
rejection checks. This establishes an executable initial-task interface, not
the full adversarial prefix/source or all-stages security theorem.

The initial-task interpreter now also recognizes the complete first challenge
input: exact framed constructor/schedule/profile header, canonical outer
message, trusted relation and ZeroCheck bindings, typed vector marker, prime
field marker and the modulus/count request descriptor. It rejects trailing
bytes, a different requested count and mismatched repeated source roots. An
independent SHAKE256/rejection implementation reads the reconstructed raw input
and matches the production equality-point block for all 20 combinations. No
prior challenge receipt or compressed child link is needed at this initial
boundary. This is the first phase's candidate-input interpretation; later
inline receipts, nested links and source-word coupling still require completion.

This independent check exposed a missing `typed request kind` frame in the
earlier worksheet. Prime and regular extension counts are now four/five rather
than three/four; direct empty identities remain four. Query/output counts and
protocol bytes were unchanged. Historical frame/work inventories retain their
recorded source revisions; revision-three input/work reports include the
corrected typed markers. Engineering Q=768 factory scenarios are explicitly
separate from the Q=1 native correctness controls and enable no admission.

The candidate-input interpreter extends through the first primary ZeroCheck's
remaining sumcheck challenges. At a requested round it resolves the earlier
equality and mixing receipts from the caller's frozen producer-history view,
reconstructs the reduced shape (one additional equality factor, one fewer
variable), and derives the mixed first claim. It requires exact canonical
shape/claim bindings and degree-bounded round messages whose paired boundary
values sum to the preceding claim. Earlier round receipts determine subsequent
claims by interpolation; the current prefix must end at the exact prime-vector
request. The independent interpolation uses direct Lagrange products.

The audit fixture constructs nonzero consistent round messages from an
independent raw-XOF stream and compares each reconstructed challenge matrix
with the production packed verifier. Inconsistent round sums and surplus input
are rejected. The whole ZeroCheck dispatcher is also compared against the
reconstructed phases, including its reduced shape and first-message reduction.
These checks cover only the first primary ZeroCheck under a supplied valid
producer-history view. They do not establish the producer-history filtering
theorem, bind complete source words, authenticate the returned PCS obligations,
or interpret later application stages or nested PCS transcripts.

The round interpreter also returns the ordered prior matrix query, mixing
coefficients and current expected claim. Under an explicitly supplied fixed
assignment of a base-field table to every (trusted context, root) handle, its
`RoundTask` materializes the original factors folded by that prior query.
The public equality factor is built from the recovered equality points and
mixing matrix on the remaining variables, then folded by the later matrices
only: the special first matrix applies to original factors, not this equality
table. The residual is the reduced relation's Boolean sum minus the parsed
expected claim. Source tables must validate against trusted dimensions; an
unassigned handle or a dimension mismatch prevents materialization.

This construction consumes no current challenge value. Its tests change a
current response polynomial while preserving its boundary sum, recover both
candidate tasks and compare their assigned residuals. Nonzero residuals of
the false-source fixture remain visible even though its proof messages obey
the algebraic recurrence. The reconstructed equality table's final fold is
compared with the independent public-equality computation in production
ZeroCheck. This is a conditional source-assignment interface. The supplied
assignments still need to be justified by the full Merkle-word and decoding
argument before this can support a protocol security claim.

`pcs/tests/classical_word_history.rs` supplies an executable test of the
first-declaration completion interface on real SHA-512 preimages. A recording
hash wrapper collects production commitment queries, including joined Rayon
workers. Each candidate input registers all 64-byte windows against one
immutable preimage snapshot; a root's first registration is retained. At a
trusted depth, the interpreter follows exact 128-byte internal-node inputs,
uses the typed leaf grammar and fills unavailable leaves with zero symbols.
The tests cover Brakedown columns and the packed PolyFRIM/PipFRI source-pair
grammars for both native base fields (extension degrees six/three). Re-encoded
leaves reconstruct the actual production roots. Trusted count checks precede
allocation; complete consumption and element re-encoding are required.

For Brakedown, the extracted columns also match independently assembled encoder
output. Withheld leaf preimages remain unavailable after later exposure and
repeated root declarations. The history records these late exposures as hits
on already registered root/child targets: children of each 128-byte preimage
are conservatively registered, at most two per hash query. An honest recorded
commitment has no such hit. These concrete checks exercise the conditional
availability construction; they do not prove its adaptive ideal-oracle bound.
No near-codeword decoding, virtual-word derivation, global linked-child
ordering or complete application coupling follows from this test alone.

The executable word audit now includes a reference fixed-assignment decoder
(`pcs/tests/support/classical_decode.rs`). For each coordinate it solves
Q(x_i)=y_i E(x_i), with monic degree-t E and deg(Q)<k+t. Free variables in
rank-deficient systems are set to zero; fewer than t errors are valid cases.
Exact polynomial division must produce a degree-<k polynomial. Finally it
counts the union of differing whole columns across every coordinate and
requires at most t. Independent scalar nearness alone is not the promise.

For distinct points with n>=k+2t, if a degree-<k source differs in at most t
positions, Q-E P vanishes at at least n-t>=k+t points and has degree<k+t.
It is therefore zero for every solved locator, including rank-deficient
solutions. Exact division recovers P. Conversely the final shared-support
check witnesses joint nearness. Two distinct vector polynomials cannot both
pass, since a nonzero differing coordinate has at most k-1 roots, whereas
the union of the two error sets has at most 2t<=n-k positions. This justifies
the reference decoder's unique-assignment interface; it does not establish
the protocol's proximity or adaptive Fiat-Shamir claims.

The Brakedown interpretation reconstructs original table indexing from row/
block coordinates and rejects nonzero padding even when the word is an exact
RS codeword. Direct PolyFRIM reverses Boolean-to-monomial conversion and
projects extension coordinate zero. PipFRI instead concatenates decoded
fragment coefficients in scalar-table order, then projects; its Boolean
tensor interpretation does not add a monomial conversion at commitment.
Clean words and radius-corrupted words recover the expected semantic table;
coordinatewise-near but jointly-far words return the zero fallback. Comparisons
of decoded Goldilocks assignments use field equality, because linear solving
may choose different raw representatives. Merkle leaf re-encoding checks
still preserve the exact original representations.

The tested geometries include Brakedown widths three/four (padding/no padding)
and both native fields, and packed/fragment source formats over BabyBear degree
six and Goldilocks degree three. Other field bases/geometries, constant dummy
padding, virtual-word derivation and all-stage coupling still need coverage.
These are analysis tests and introduce no production proof-admission path.

The assignment audit now runs all eight extension bases: BabyBear degrees
4/5/6/8 and Goldilocks degrees 2/3/4/5, with ordinary and zero-variable
source geometries for both extension-backed source formats. Brakedown adds
zero-variable source geometry on both base fields, for 38 reference cases.

Constant-source restriction is deliberately distinct from an encoded padding
promise. Direct PolyFRIM lifts a constant into one physical variable and
appends `(I,0)` to its query; scalar PipFRI appends a zero Boolean point. Their
honest encoders repeat the entry, but their verifiers select the first physical
entry and do not require an unused entry to repeat. The assignment therefore
restricts to that first entry before projecting coordinate zero. Tests alter
unused decoded entries by both a base-field component and a higher extension
component and retain the same promised logical assignment. Requiring full
dummy repetition (or a zero high monomial coefficient) would incorrectly
classify valid selectable sources as outside the promise. Brakedown instead
retains its actual encoded coefficient-padding requirement. The conditional
composition definition above has been clarified accordingly.

`classical-complete-basis-constant-assignment-tests.log` passes; its exact
source/log revision is recorded in
`opening-inventory/classical-all-basis-constant-assignment-audit.json`. These
reference geometries do not replace native-size validation, virtual derived
word coupling, global link ordering or the full application security proof.

The source-word audit now checks the virtual initial PipFRI word explicitly.
After freezing the packed source, it opens/verifies the production virtual
protocol in a typed version-five child, replays the exact source/root/point/
claim/fragment-evaluation binding and obtains its production gamma. From the
frozen source symbols it constructs W_gamma[j]=sum_c gamma^c W_c[j]. An
independent Horner evaluation of the combined source coefficients matches
this entire derived word. For each production rolling query, the packed
leaf index is recovered from its authenticated indexed preimage; source
pairs match the frozen completion and the virtual initial pair matches
W_gamma. Its Merkle path is empty. Changing that pair causes the production
`virtual fragment combination` rejection. Prover/verifier continuations agree.

The audit also reconstructs the virtual identifier's exact metadata preimage
and finds the matching actual SHA-512 query. Interpreting that identifier as
a Merkle root does not yield a word from the frozen graph. The component's
initial word must therefore be inherited through the source/gamma definition,
not independently completed from that identifier. All eight extension bases
pass on the (length,fragment-count) geometries (4,4) and (2,1). Evidence is
`opening-inventory/classical-virtual-derived-word-audit.json`, with test log
`classical-virtual-derived-word-tests.log`. This establishes executable
reference compatibility for the derived-word interface, not the global
root-ordering, nested-link or whole-application security theorem.

The structural query-history model now carries root-window declaration
indices through recursive seed and finish recovery. It independently encodes
a parent, child and grandchild while comparing every append/fork/query/finish
state with production `ClassicalTranscript`. A grandchild candidate recovers
a root present only in an ancestor; after both children finish, a resumed
parent recovers roots declared only in descendants. Reversed query orders
fail at the original first-query snapshots even after the missing producers
are queried and candidates are repeated. All 32 helper tests pass.

For a fixed length filter, the declaration map uses the first **eligible**
global input containing a window. Ineligible windows are omitted from this
map but their queries retain original global indices and collision accounting.
The test distinguishes an unfiltered root declaration at index zero in an
oversized unrelated query from its first bounded declaration at index one.
Filtering never renumbers index one to zero, and recursive producer recovery
uses its original chronology. This is the filtered version of the earlier
unbounded first-declaration construction; the two constructions need not
choose the same frozen word. The filter and its bound must be fixed before
defining these assignments.

Every recovered dependency index strictly precedes its consumer, since a
link resolves only in that consumer's frozen producer view. Thus the closure
is acyclic, and a literal root at a dependency index j has first eligible
declaration no later than j. Source words can be inherited from this earlier
fixed declaration instead of being refrozen in the child. This structural
statement assumes that the relevant source is actually among the interpreted
ancestor/descendant messages. Complete stage grammars, role contexts and
joint hash/XOF eligible-root filter preservation still require the separate
application coupling argument. Evidence is
`opening-inventory/classical-inherited-root-ordering-audit.json`.

### Joint eligible-root word interface

The recorded word-history model now registers every eligible SHA-512 input
window before its response as well as every eligible XOF input window. Both
oracle families use the same first-declaration map and global event chronology.
Frozen graph snapshots retain eligible known hash preimages only. Ineligible
inputs keep their oracle invocation counts and known outputs/preimages for
collision accounting; they neither declare windows nor enter a frozen eligible
word graph. Tests distinguish these games, exercise declarations in each
oracle family and detect late preimages as prior-target hits. The existing
38 source-assignment and 16 virtual-word cases still pass.

A bounded-path filter lemma makes the word interface precise. Fix the two
input bounds before defining assignments, with L_h>=128. Assume each hash
input on a subsequently accepted authentication path is bounded by L_h and
has the trusted typed interpretation. Complete each declared root/context
from the eligible preimage snapshot at its first eligible declaration, filling
unavailable leaves with zero. Exclude distinct-input hash-output collisions
and fresh hash outputs hitting registered eligible roots or child digests.
Then every subsequently accepted bounded opening agrees with that completion.

To see this, follow an accepted path from the declared root. A different
preimage for a snapshot digest is an output collision. An input known earlier
only through an oversized producer cannot equal the accepted bounded input;
the same digest would again require a distinct-input collision. If a needed
preimage was unavailable at declaration, take the first unknown digest along
the snapshot-known path. It is the registered root, or a child in a known
128-byte node input. Such a node is eligible, so its child is already a
registered window. The accepted bounded producer's first subsequent response
therefore hits this prior target. Outside those events, every needed preimage
was in the eligible snapshot; exact leaf interpretation gives the claimed
agreement. Zero-filled positions need not form a tree hashing to the root.
The proof concerns agreement at accepted openings, not such a rehash property.

The same argument covers a declaration in a SHA input: its windows are
registered before that input's response. A response equal to a newly declared
root while its preimage was absent is itself a charged target hit. The
existing conservative child-target term remains an upper bound even when
those children are also counted among eligible SHA windows. Outputs of
ineligible queries still participate in collisions and target hits.

This conditional lemma does not establish that every real application hash
input obeys a particular worksheet bound, that every task's source root is
eligibly declared before its challenge, or that the complete stage semantics
match the component games. Those are the remaining application/resource
premises. Seed/finish dependencies must use the earlier frozen-query rules;
virtual initial words must be derived from their upstream source. Test scope
and fingerprints are in `opening-inventory/classical-joint-root-history-audit.json`.

### Explicit native SHA input ceiling

The selected native SHA helpers use at most two byte slices between resets.
Metadata/leaf helpers hash one serialized vector, Brakedown contexts/columns
add a fixed namespace, Merkle nodes hash two 64-byte digests, and profile IDs
hash contiguous serialized data with at most one separate namespace. Each
output resets the hasher. These constructions cover the parent context and
profile-ID calls as well as the five selected PCS adapters.

Rust bounds valid byte slices and vector allocations by `isize::MAX` bytes
([slice requirements](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html),
[vector allocation guarantee](https://doc.rust-lang.org/std/vec/)). On a runtime
with pointer width at most 64, each such slice is therefore at most 2^63-1
bytes and their two-update concatenation is at most L_h=2^64-2 bytes. This is
a bound on successfully constructed verifier hash inputs. It does not limit
arbitrary adversarial SHA inputs, which still count toward output collisions
and target hits even when omitted from eligible-window registration.

The hash-resource wrapper now asserts the two-update construction during
actual committing, proving and verification. Its 90 standalone verifications
cover both fields, five adapters, three blowups and three batch sizes, while
retaining the existing exact hash-output inventory checks. All pass. The
candidate evaluator uses this explicit SHA ceiling separately from the much
larger stopped framed-XOF bound; the oracle worksheet also reports their
distinct window counts. All 52 classical-tool tests and 13 oracle-budget tests
pass. The source/call inventory and fingerprints are in
`opening-inventory/classical-native-hash-input-audit.json`.

Revision-four native input/work inventory recomputes ten actual factory
engineering-Q768 descriptors with the same explicit hypothetical offsets.
It keeps these scenarios separate from Q1 native correctness controls and
sets no query selection or security-admission flag. This resolves the selected
SHA input-construction ceiling, not remaining XOF/stage/source interpretation,
honest offsets, complete work/knowledge composition or performance gates.

The first-primary interpreter now extends through the terminal-value boundary
before its first PCS body. It replays the final sumcheck receipt, reconstructs
the complete ordered matrix query and final public equality vector, and parses
exactly the trusted number of factor vectors at the trusted width. Each vector
passes the selected backend's public-value validation. The reduced terminal
relation must equal the expected sumcheck claim after equality multiplication;
wrong terminal equations and oversized vector counts are rejected. The opening
obligation retains the original ordered (context,root) source handles.

The fixture constructs terminal values satisfying the algebraic equation while
its first opening claim is explicitly false for its assigned committed source.
Running the full production relation verifier matches direct verification of
that recovered first PCS task: rejection errors and subsequent transcript
continuations agree. This demonstrates that the recovered task reaches the
actual first opening rather than being replaced by some proof-selected source
or query. The 20 field/backend/schedule combinations pass in
`classical-first-false-opening-prefix-tests.log`; source/log fingerprints and
precise scope are in `opening-inventory/classical-first-opening-boundary-audit.json`.
This boundary interpretation authenticates no source by itself and does not
yet parse each backend's complete first-query input or later PCS/application
phases. Those remaining grammars are required for full all-trials composition.

The initial Brakedown opening now has exact candidate-input interpreters for
its two challenge boundaries. The row input must extend the recovered primary
opening with the trusted row-code context, the exact commitment/query/value
tuple, typed vector/prime markers and modulus/count descriptor. Its row count
is derived from trusted left split and width (k^2*2^left coefficients), not
from a candidate field. Independent SHAKE/rejection replay matches production
row coins on both fields and schedules four/five. Altered root/count and
surplus bytes fail interpretation.

For schedule five, the column interpreter replays the row receipt from the
frozen known producer view, parses two response vectors of trusted size and
requires the exact index-domain binding and 8Q-byte atomic request. The domain
is the trusted block-RS message geometry, blowup and minimum-32 domain. Missing
row producers and altered requests fail. Independent SHAKE words match every
production index in the Q-draw block before transport deduplication. Replaying
the responses and index schedule also matches the full PCS rejection
continuation, tying these raw inputs to the production first opening.

Both focused tests pass, preserving all 20 existing field/backend/schedule
cases while adding four row-query and two version-five column-query cases.
The schedule-four index replay checks byte compatibility only; it does not
supply the missing multi-query grinding argument for that older schedule.
Scope and fingerprints are in
`opening-inventory/classical-brakedown-two-phase-prefix-audit.json`, with log
`classical-brakedown-two-phase-prefix-tests.log`. Other PCS families, later
openings and later application stages still require their candidate grammars.

The first-primary opening interpreter now recognizes the exact parent seed
inputs for direct/dictionary PolyFRIM and ordinary/virtual fragmented PipFRI.
It inherits the parent-derived source/query/value obligation, applies the
backend's actual normalization rule, and requires the exact ordered-claim
binding, child label/context and 64-byte seed request. Direct/dictionary
claims use their canonical matrix/value representation; the fragmented
bridges preserve their existing representation. Source, request or trailing
byte changes reject. Direct and dictionary use the same child label but their
trusted contexts/profile identities remain distinct.

Independent SHAKE evaluation of this input supplies the proposed seed. The
audit reconstructs raw child constructor frames, profile ID, label/context/
seed, complete extension multiplication basis, zero-count identity request
and empty consumed-byte receipt. A probe from that reconstruction matches
the production typed child fork. Parent continuation also matches the actual
first PCS verification attempt. In particular the direct empty identity has
no regular typed-vector marker, consistent with the earlier four-frame
identity resource accounting. The 16 non-Brakedown cases across both native
fields and schedules four/five pass; all 20 existing baseline cases remain
green. Exact scope and fingerprints are in
`opening-inventory/classical-first-pcs-child-seed-audit.json`, with log
`classical-first-pcs-seed-prefix-tests.log`. This does not yet interpret each
child's nonempty challenge input or the subsequent application stages.

The ordinary/virtual fragmented first-projection input interpreter now follows
the seed to the parent opening obligation. It requires the seed producer in
the child's frozen view, verifies its SHAKE output and reinterprets that parent
input using the parent's own first-query producer snapshot. It never substitutes
the later child's database for that snapshot. A test removes a parent equality
receipt producer from the earlier view while retaining it in the child's later
view; the child candidate remains rejected. Missing seeds and missing empty
identity-receipt producers also reject. The empty identity is not treated as
a freely known fingerprint when defining the candidate state.

After exact child profile/label/context/seed and typed constructor checks, the
interpreter requires the backend's projection label, vector kind, full basis
and modulus/coefficient-count descriptor. The first opening has one ordered
claim, so it requests k independent extension rho values (k*D base coefficients).
An independent prime rejection stream on the complete raw child input matches
every production extension coefficient in order. Reconstructed consumed-byte
receipts and a subsequent probe match too. Both fragmented variants, both
native fields and schedules four/five pass (eight projection cases), preserving
all 20 existing prefix cases. Evidence is
`opening-inventory/classical-first-fragment-projection-audit.json`, with log
`classical-first-fragment-projection-prefix-tests.log`. This supplies the first
projection boundary under supplied correct frozen histories; degree-two bridge
rounds, scalar opening phases and later application stages remain unfinished.

The first fragmented opening's candidate interpreter now covers every
degree-two bridge sumcheck round. It derives the initial compressed claim
from the recovered rho vector and parent values, and requires the exact
polynomial descriptor with max multiplicands two and variable count
source-vars+log2(width). Round messages have exactly three extension values;
prior receipts are replayed coefficient-wise under the trusted basis, and
quadratic interpolation determines each next claim. The current input ends
exactly at a scalar extension request for that round.

Production scalar sumcheck samples all rounds before checking their
recurrences. The interpreter's earlier recurrence check is an admissible-prefix
filter: an inconsistent prefix has no accepting continuation outside the
receipt/collision events. It does not change production's rejection timing
or reduce the resource inventory charged to rejected verifier executions.

The fixture constructs nonzero consistent messages using the independent
raw-XOF coefficient stream. Reconstructed prefixes recover the same source,
rho, prior point, expected claim and message at every round. Inconsistent
messages and missing prior coin producers reject. Running the complete
production MLSumcheck on those messages yields the same full point, terminal
evaluation and transcript continuation. All eight ordinary/virtual bridge
sequences across both fields and schedules four/five pass, preserving the
20-case baseline. Evidence is
`opening-inventory/classical-fragment-bridge-round-audit.json`, with log
`classical-fragment-bridge-round-prefix-tests.log`. Scalar PCS calls, their
gamma/rolling phases and later application stages still require coupling.

The first fragmented opening interpreter now reaches the scalar gamma query.
It recovers the final bridge receipt and complete point, reconstructs scalar
fragment/domain/query geometry and both trusted parameter-context hashes from
the immutable profile, and checks the exact ordinary/virtual adapter and
scalar claim bindings. The source root and point must be the inherited values.
The scalar value has its typed extension encoding and the fragment vector has
exactly the trusted count; Boolean aggregation at the high point must equal
that value before the scalar extension gamma request is recognized. The
bridge's expected terminal is retained for the later matrix-kernel check.

The source fixture now makes its first evaluation table nonconstant; zero key
factors and the constant final table preserve the original false-product
residual. Real scalar adapter commitments must reproduce that first parent
root. Ordinary/virtual scalar proofs verify, their fragment evaluations vary,
and prover/verifier continuations agree. Shifting every fragment claim by one
while retaining the scalar value is rejected. An independent raw coefficient
stream matches gamma from the reconstructed complete input.

The honest scalar proof is also placed behind the fabricated but internally
consistent degree-two bridge and passed through the actual matrix adapter.
It gets through scalar verification and rejects specifically at the terminal
ordered-matrix equation. Thus the audit checks the recovered scalar point and
gamma context inside the real adapter path as well as in isolated scalar calls.
Eight gamma cases across both fields and schedules four/five, plus all 20
existing prefix cases, pass in `classical-complete-scalar-gamma-prefix-tests.log`.
Evidence is `opening-inventory/classical-scalar-gamma-prefix-audit.json`.
Rolling/index challenge grammars and later application stages remain separate
obligations; passing these tests is not a full security certificate.

The first ordinary/virtual fragmented scalar opening interpreter now covers
all rolling alpha and index challenge inputs. It resolves gamma, checks the
complete public ladder and rolling statement before alpha zero, and recovers
prior alpha receipts. Each derived-root message must carry its exact next
layer index after the preceding alpha and before the following alpha. The
virtual first original identifier is derived from the inherited scalar
context/source/point/gamma and remains a virtual word, not an independently
completed Merkle root. Wrong layer indices and missing prior producers reject.

The final terminal is bound before the rolling index request. Trusted domain
and draw count determine its exact raw byte request; independent SHAKE replay
matches all draws before any transport deduplication. Ordinary mode additionally
interprets its inline rolling-index receipt and separate consistency-index
request. Replaying every alpha, root/terminal binding and sampling phase
produces the same final continuation as real scalar proving and verification.
All eight sequences and the 20-case baseline pass. These complete the nonempty
challenge grammars for this first fragmented opening under the supplied frozen
histories, not later openings, other PCS children or later application stages.

Counting the reconstructed frame stream exposed a worksheet omission: ordinary
and virtual fragmented calls have six fixed metadata frames (parent ordered
claim, polynomial info, scalar adapter mode, scalar claim, public roots and
rolling binding), plus nu sumcheck messages and R derived-root/terminal
messages. The current envelope is therefore (6+nu+R)*A; zero-variable bridges
may omit polynomial info, so this remains an upper bound. A Rust frame count
checks the actual prefix plus its parent binding, and Python checks the
corresponding role envelopes. This corrects the earlier five-frame worksheet;
protocol bytes, query counts and sampler probabilities were unchanged.

All 53 classical tooling tests, 13 oracle-budget tests and the focused Rust
prefix tests pass. Revision-five input/work inventory recomputes the same ten
factory-Q768 scenarios with one extra frame per fragmented opening call,
retaining hypothetical offsets and no admission. Evidence is
`opening-inventory/classical-first-fragment-rolling-and-index-audit.json` and
`opening-inventory/classical-native-verifier-input-and-work-inventory-v5.json`.
Historical inventories retain their recorded source revisions.


The first direct/dictionary opening interpreter now shares the typed child
header/seed/empty-identity parser with fragmented openings. It resolves parent
receipts using the parent's own first-query snapshot. For nonconstant first
sources it derives trusted core geometry and the base NTT root, lifts the
normalized ordered matrix claim into the extension field, and parses exactly
one public ladder of the trusted length. The ladder's first root must equal
the inherited source. The joint binding, member-zero marker, consistency
binding, index domain and atomic 8Q-byte request must all agree before any
sampling output is available. Root counts are checked before allocation;
candidate lengths do not determine trusted geometry.

This recognizes the first direct/dictionary consistency-index task under the
supplied histories. A candidate ladder can be adversarial: later authentication,
matrix transitions, projections and rolling proximity remain separate proof
obligations. The current application fixture has nonconstant first sources;
this parser deliberately excludes zero-variable dummy-coordinate geometry.
It does not establish the full application Fiat–Shamir or knowledge theorem.


Eight direct/dictionary boundary sequences across both fields and schedules
four/five match independent raw SHAKE sampling and production transcript
continuations. Negative cases cover wrong source roots, inconsistent duplicate
ladder bindings, truncated/oversized root counts, absent seed producers, late
parent receipts and trailing bytes. All 20 prefix baseline combinations pass
in `classical-direct-first-index-prefix-tests-final.log`; fingerprints and
scope are recorded in `opening-inventory/classical-direct-first-index-prefix-audit.json`.
These boundary fixtures use synthetic adversarial ladders and do not substitute
for a full direct-adapter proof replay or whole-protocol composition argument.


The first direct/dictionary interpreter additionally recognizes the atomic
joint lane-projection request for schedules four/five. It consumes the exact
length inline consistency-index output, rebinds the same complete ladder and
checks the typed extension-vector request for rounds*width coefficients over
E (rounds*width*D over F). The task remains fixed even if the candidate's
inline earlier index bytes change: those bytes do not determine its ladder.
Their validity belongs to the earlier phase and authentication obligations;
interpreting this current task must not evaluate an unknown previous oracle
input merely to enforce an unnecessarily restrictive prefix filter.

Eight boundary sequences independently replay every base rejection candidate,
extension coefficient order, consumed-byte receipt and subsequent continuation.
The actual joint consistency verifier, given a structurally valid packet with
invalid pair authentication, consumes exactly the independently reconstructed
index query and rejects at authentication. Its continuation matches the raw
prefix; this ties that query to a production verifier path rather than just
manual binding calls. The projection continuation is checked through production
sampling after explicit bindings. These are synthetic adversarial ladders,
not complete accepted adapter certificates. All 20 baseline combinations pass
in `classical-direct-projection-prefix-tests-final.log`; scope and fingerprints
are in `opening-inventory/classical-direct-projection-prefix-audit.json`.
Direct rolling phases and full application composition remain open.


The first direct/dictionary rolling interpreter consumes the atomic projection
receipt through the supplied frozen producer view and recovers exactly
rounds*width extension weights. For each layer it derives the virtual identifier
from the core parameters, layer number, complete ordered ladder and that
layer's projection row. These identifiers denote projected words from the
already fixed packed roots; they are not independently completed Merkle words.
The virtual-all rolling binding must contain these exact identifiers and the
trusted FRI parameter context before alpha zero.

Each later alpha prefix consumes earlier scalar receipts and a derived-root
binding carrying exactly the next layer index. The final alpha is followed by
a bounded canonical terminal and the trusted domain/8Q-byte index request.
This is the same fixed-task ordering needed by the conditional projected-word
and rolling lemmas: packed words precede rho, virtual projections precede
alpha zero, and each derived word precedes the alpha that tests it. It does
not discharge earlier consistency authentication, later application openings,
or the complete all-trials Fiat–Shamir/knowledge composition.


Eight direct/dictionary rolling sequences across both fields and schedules
four/five match independent raw alpha sampling and every atomic index draw,
then reproduce the production transcript's final continuation. Missing prior
producers and wrong derived-layer indices reject; terminal/index trailing
bytes reject. Counting actual metadata gives 6+R for A=C=1, agreeing with
(4+R)*A+2*C. No resource-envelope change is required. The 20-case baseline
passes in `classical-direct-complete-rolling-prefix-tests.log`; evidence and
scope are in `opening-inventory/classical-direct-complete-rolling-prefix-audit.json`.
The roots and terminal here are synthetic adversarial boundary values, and
rolling replay uses production transcript sampling with explicit bindings.
This is not a fully accepted direct adapter certificate or a full geometry,
later-opening, application-composition or security-admission proof.


The primary relation's inherited PCS seed-task interpreter is now indexed over
its complete ordered factor list, rather than only factor zero. The terminal
relation prefix fixes every source handle, the common matrix query and every
claimed value. Each factor selects the same evaluation/key parameter role as
the production relation verifier (even indices use evaluation parameters;
odd indices use key parameters), including backend claim normalization.
Earlier completed children contribute exact seed-output and finish frames of
trusted 64-byte lengths. Their contents mix the transcript but cannot select
a different source, query or claim for the next fixed factor. This interpreter
therefore leaves their proof/finish validity to earlier obligations instead
of requiring another oracle evaluation to identify the current task.

Typed child-header interpretation accepts the factor index explicitly and
resolves the parent's seed-producing input in that parent's own first-query
producer view. It checks the backend label/context, seed, profile, extension
basis and known empty-identity receipt before returning the inherited task.
Later producer availability in a child cannot repair a missing parent receipt.
This generalizes the parent/child task origin across the primary factor list;
it does not yet generalize all backend sampling grammars to those later
factors or establish acceptance of earlier opaque child proofs.


Sixteen ordered chains (two fields, four child-based backends, schedules
four/five) exercise every trusted factor index. Actual linked child creation,
probe, finish and final parent continuation match independent raw SHAKE
replay. Wrong current source bindings, out-of-range indices, trailing seed
bytes, truncated earlier finishes, missing seeds and late parent receipts
reject. Changing an opaque earlier finish preserves the inherited next task.
The focused tests and 20-case baseline pass in
`classical-ordered-factor-seed-and-child-prefix-tests.log`; fingerprints and
scope are in `opening-inventory/classical-ordered-factor-seed-and-child-prefix-audit.json`.
The linked-child fixture does not assert acceptance of earlier fabricated PCS
proofs, and backend sampling grammars for later factors remain separate work.


Direct/dictionary sampling-prefix interpretation now accepts an explicit
primary factor index throughout consistency, atomic projection, rolling alpha
and final-index parsing. The typed child resolves that factor's own parent
seed and frozen parent view, and normalization uses its evaluation/key
parameters and corresponding terminal value/root. In the classical factory,
all primary evaluation and key factors share profile role-zero geometry;
the role-one helper geometry is not selected by odd factor indices. The
existing factor-zero entry points are wrappers of this indexed implementation.
Zero-variable dummy coordinates still require their separate geometry audit.

The ordered-factor fixture can drive each direct/dictionary linked child
through all sampling phases before its probe/finish. Consequently later factor
seeds include actual earlier sampling continuations, rather than only an
initialization probe. The ladder, derived roots and terminal remain synthetic
adversarial boundary values; a transcript replay of those values does not
assert acceptance of its PCS authentication and proximity obligations.


All primary direct/dictionary factors in eight ordered chains now replay
consistency indices, atomic projections, every rolling alpha and final indices
against independent raw SHAKE sampling. Each phase checks the indexed inherited
root/claim and frozen receipts; removing the previous producer rejects.
Later factors cannot be parsed as factor zero. Every sampled child then
reproduces its probe and linked finish, and the complete parent continuation
matches production. All sixteen child-backend seed chains and the 20-case
baseline remain passing. Evidence is
`opening-inventory/classical-all-primary-direct-factor-sampling-audit.json`
and `classical-all-primary-direct-factor-sampling-tests.log`.
This covers the positive-dimensional primary direct/dictionary sampling
prefixes under the supplied histories. It does not assert acceptance of the
synthetic PCS bodies or cover later fragmented-factor sampling, Brakedown
continuation, zero-variable/native geometries or later application stages.


Primary child interpretation now derives the selected factor from the bounded
ordered parent seed grammar. Explicit-index callers additionally require that
index to match; fragmented callers inherit the derived index automatically.
The selected factor is carried through bridge claim compression, scalar-root
binding and virtual initial-identifier derivation. This prevents later key or
evaluation openings from silently retaining factor zero's source/value while
preserving the parent's own frozen-view requirement. Earlier opaque completion
bytes select no new semantic source: the trusted loop order determines it.

The fragmented ordered-chain fixture drives each factor through lane
projection, all bridge rounds, scalar gamma, public rolling roots, every alpha,
terminal and final indices (including ordinary consistency indices). The bridge
uses independently constructed linear round polynomials and then checks their
point/evaluation through the actual multilinear sumcheck verifier. Subsequent
scalar claims/roots/terminal are synthetic task-boundary values and do not
assert a fully accepted adapter certificate. Linked probe/finish replay ties
later factor seed inputs to the complete earlier sampling state.


All primary ordinary/virtual fragmented factors in eight chains now match
independent raw projection, bridge, gamma, rolling and index sampling, including
ordinary consistency queries. The actual MLSumcheck verifier reproduces each
bridge point and expected evaluation. Missing preceding producers reject at
bridge and rolling boundaries. Together with direct/dictionary coverage, all
sixteen ordered child-backend sampling chains reproduce their complete child
probe/finish and final parent continuations; the 20-case baseline passes.
Evidence and scope are in
`opening-inventory/classical-all-primary-fragment-factor-sampling-audit.json`
and `classical-all-primary-fragment-factor-sampling-tests.log`.
The later scalar claims, roots and terminal are synthetic boundary fixtures,
not evidence of fully accepted PCS certificates. Brakedown continuation,
zero-variable/all native geometries, later application stages and full
Fiat–Shamir/knowledge/security admission remain open.


Version-five Brakedown primary continuation parsing now indexes the complete
trusted factor order. For each completed earlier factor it checks the exact
row binding/request, an 80-byte field receipt, two canonical response vectors
of the trusted cell count, the atomic column request and its exact 8Q-byte
inline output. These earlier values are opaque when deriving the next row
task: their proof validity is separate and cannot select a different inherited
source/claim. The current row query requires full consumption. Its column
query additionally recovers the current row coins from a producer already in
the supplied frozen view and checks the current bounded response and domain.
All primary factors use role-zero geometry in the classical factory.

The continuation fixture drives each factor through the production prime-field
and atomic-index transcript samplers and independently reconstructs consumed
bytes, receipts and the final parent continuation. Synthetic linear responses
exercise the query boundaries; they do not assert valid authenticated column
openings or complete PCS acceptance. Version-four separate byte-candidate
sampling remains compatibility-only and is not promoted into this version-five
all-trials argument.


Every version-five primary Brakedown factor now matches independent row
rejection, consumed-byte receipts and every atomic column draw, followed by
the same final parent continuation as production transcript sampling. Negative
cases reject wrong sources, out-of-range factors, trailing row/column bytes,
missing current row producers, truncated previous outputs and oversized
response counts. Altering an opaque earlier output preserves the next fixed
task. Both field tests pass while retaining all sixteen child-backend sampling
chains and the 20-case baseline. Evidence is
`opening-inventory/classical-all-primary-brakedown-factor-sampling-audit.json`
and `classical-all-primary-brakedown-factor-sampling-tests-final.log`.
The synthetic responses are boundary fixtures, not accepted authenticated PCS
certificates. Later application stages, full geometry coverage and complete
Fiat–Shamir/knowledge/security admission remain open.


A completed-primary prefix interpreter now connects the primary relation to
the first NTT row request. It consumes every trusted factor's completion:
version-five Brakedown uses shared bounded response/atomic-output parsing;
the four child backends use exact seed/finish framing. Earlier authentication
and finish provenance remain separate obligations; these fixed bytes cannot
choose new coefficient/evaluation roots for the next stage.

The first NTT task recovers coefficient/evaluation roots from the canonical
outer statement, derives the trusted NTT shape and native transform root, and
checks backend domain, field, contexts and source commitments. The terminal
request must be the prime-vector atomic row request with exactly
width*row_variables coefficients and no trailing bytes. The task therefore
fixes its two source handles and transform geometry before the row coins.
The associated production-verifier fixture supplies empty folded polynomials,
so it must sample the row request, bind those polynomials and reject their
malformed dimensions before consuming any PCS opening. This tests the stage
boundary and row receipt/continuation, not accepted NTT authentication or the
later compression and batch-opening tasks.


All 18 eligible first-NTT boundaries (both fields, every version-five backend
and the four version-four child backends) reach the production verifier's
expected folded-dimension error. Their independent raw row receipt and final
continuation match production. Wrong roots, request counts, trailing bytes
and absent earlier receipts reject. Both focused tests pass with the 20-case
baseline and all prior primary sampling chains retained. Evidence and scope:
`opening-inventory/classical-first-ntt-row-prefix-audit.json` and
`classical-first-ntt-row-prefix-tests.log`. Owned dummy PCS packets are never
consumed by this verifier path. This covers the first row task, not an accepted
NTT certificate, its compression/opening tasks, later stages or whole-proof
security admission.


The first NTT coefficient-compression interpreter recovers the atomic row
receipt, parses exactly width*N coefficients and evaluations with both array
counts checked before allocation, applies the backend value contract and
checks each native transform identity. Each compression request binds a
width-element prime vector; prior receipts reconstruct the exact packed
challenge matrices before interpreting the next task. Nonzero valid folded
arrays succeed; false transforms, oversized inner counts, missing prior
producers and trailing bytes reject.

The production fixture now uses valid folded polynomials and proceeds through
all compression phases to its first coefficient-opening error, rather than
stopping at the earlier empty-folded dimension check. Independent source
queries append the row-point diagonal matrices after compression matrices;
compressed values use the corresponding folded table. Raw receipts and the
post-error continuation match all 18 cases. Brakedown and fragmented parent
metadata/seed expose the exact derived opening statement in ten cases;
eight direct/dictionary cases reject earlier at packet-count preflight.
Both field tests and the 20-case baseline pass in
`classical-first-ntt-compression-prefix-tests.log`; fingerprints/scope are in
`opening-inventory/classical-first-ntt-compression-prefix-audit.json`.
Owned dummy packets do not establish accepted NTT authentication. The batch
PCS sampling grammars, later NTT/components, complete geometry coverage and
full Fiat–Shamir/knowledge/security admission remain separate obligations.


The first NTT batch-task interpreter now consumes the final compression
receipt and reconstructs the complete ordered source queries. Each query
places the coefficient-compression matrices first and then the row-point
diagonal matrices; compressed coefficient and evaluation values come from
their respective bounded folded tables. Both source handles retain the
contexts and advertised roots recovered from the outer statement.

The coefficient opening's next query is interpreted separately by backend.
The four child backends bind the complete ordered statement, including direct/
dictionary claim normalization, before their 64-byte child seed request.
Version-five Brakedown checks its complete batched statement and trusted
prime-field row-request geometry. Missing final producers or trailing request
bytes cannot produce a task. These are fixed source/query/value obligations;
the subsequent child/batched-column authentication and the evaluation opening
remain separate work.

The production fixture uses correctly shaped batch packets for a different
zero-source root, replacing the earlier one-query packet-count preflight
fixture. It therefore reaches an opening-bound query in every backend. On a
failed child, only the parent binding and seed remain in the parent state;
Brakedown additionally consumes its row and column sampling phases. The replay
accounts for these states without claiming the mismatched-source packet was
accepted or that a complete NTT certificate has been proved.


All 18 first-NTT cases now reconstruct the inherited batch task and reach an
opening-bound production query. Four child backends check the complete seed
input and Brakedown checks its batched-row request; missing final compression
producers, trailing and malformed requests reject. Correctly shaped packets
for a different source root replace the former direct/dictionary count-only
preflight. Independent replay includes every parent-visible effect through
that failed coefficient opening: the child seed, or Brakedown row receipt,
linear-response binding and column output. Both field tests pass with the
20-case baseline retained. Evidence is
`opening-inventory/classical-first-ntt-batch-opening-task-audit.json` and
`classical-first-ntt-batch-opening-task-tests.log`. A discarded unused local
binding was cleaned up after compilation; behavior was unchanged.
Subsequent batch child/column task grammars, the evaluation opening and later
components/stages remain separate from this task-origin check. No accepted
NTT certificate or whole-proof security admission is asserted.


First-NTT Brakedown column interpretation now recovers the current batch row
receipt and derives representative queries from equality of their first
left_vars matrix pairs, matching the production row grouping. It parses one
bounded test vector and exactly one bounded evaluation vector per derived
representative before the atomic column request. The vector count therefore
comes from the fixed query prefixes, not from an attacker-declared outer
length or the number of distinct complete queries.

Typed child-header parsing is shared between primary and NTT origins. The NTT
child checks the same profile, labels, context, seed, extension basis and empty
identity receipt, then reconstructs its ordered batch from the seed-producing
parent's own frozen view. A receipt available only in the later child view
cannot repair a missing parent producer. Primary and NTT task families remain
separate: an NTT seed prefix cannot be reinterpreted as a primary factor seed.

A controlled proposed-row-coin fixture gives all NTT queries the same left
prefix while preserving different right parts. It must produce one response
group; two evaluation responses must reject. These are synthetic frozen
producer inputs for task interpretation, not accepted NTT certificates.


Both field cases now interpret the first-NTT Brakedown column task, including
current row-coin recovery, derived response-group count and trusted domain.
A controlled same-left/different-right case yields exactly one representative
and rejects two response groups. Missing current producers, oversized counts
and trailing bytes reject. Sixteen NTT child-origin cases check parent-own
frozen views, missing seed/identity producers, late parent receipt repair,
wrong labels and exclusion from the primary-factor family. Shared parser
refactoring retains all primary-origin checks and the 20-case baseline.
Both focused tests pass in
`classical-first-ntt-column-and-child-task-tests-final.log`; scope/fingerprints
are in `opening-inventory/classical-first-ntt-column-and-child-task-audit.json`.
NTT child headers remain structural fixtures; this does not establish full
batch-child sampling, evaluation authentication, later stages or security
admission. The controlled grouping case is a proposed-receipt task fixture,
not an accepted NTT proof.


The first-NTT fragmented projection interpreter now binds one extension
coefficient per ordered claim/lane pair, with base coefficient count
queries*width*D. The initial bridge claim compresses coefficient values in
query-major, lane-minor order. The number of bridge variables remains
source_vars+log2(width), not an extra query-selector dimension. Every bridge
prefix checks the trusted degree-two polynomial info, bounded three-value
message, sum recurrence, typed scalar request and prior frozen receipts.

Projection/bridge fixtures initialize the public classical transcript primitive
with the same typed child header and independently replay its coefficient
streams and final continuation. They cover both the zero folded-data path
and a proposed nonzero folded-data prefix with a valid native NTT transform.
The latter exercises nonzero multi-claim compression; its earlier field
receipts are proposed frozen producers and do not assert an accepted proof.
The seed-producing parent snapshot is captured before adding the child seed
or identity producers. These are primitive/prefix checks, not a complete
production NTT bridge-dispatch or scalar-authentication certificate.


Sixteen ordinary/virtual batch-bridge sequences across both fields and
schedules four/five match every raw projection/bridge coefficient and the
public classical primitive's final continuation. Nonzero proposed folded data
has a valid native transform and a nonzero multi-claim compression. Missing
preceding producers, malformed projection counts and trailing bridge bytes
reject. Both focused tests pass with the 20-case baseline retained; evidence
is `opening-inventory/classical-first-ntt-fragment-bridge-task-audit.json` and
`classical-first-ntt-fragment-bridge-task-tests-final.log`.
The parent view is captured before child-only producer additions. The nonzero
prefix is a proposed-receipt fixture, and the primitive replay is not a complete
production NTT bridge dispatch or scalar authentication certificate. Later
PCS/evaluation openings, stages and full security admission remain open.


The first-NTT fragmented interpreter now reaches the scalar gamma request.
It consumes the final bridge receipt, completes the point and expected bridge
evaluation, and requires the backend's exact scalar mode/context and inherited
coefficient-source root/point binding. The fragment vector has the trusted
physical count; its Boolean aggregation over the remaining point coordinates
must equal the bound scalar value before gamma is sampled. This scalar task
origin remains separate from later scalar authentication and the enclosing
terminal-kernel equation.

The fixture uses nonconstant fragment claims and computes their value by an
independent Boolean-basis weighted sum, rather than the interpreter's pairwise
folds. Adding one to every fragment while retaining the value must reject;
so must an oversized fragment count, a missing final bridge producer or
trailing bytes. The public classical primitive replays gamma's coefficient
stream, receipt and continuation. These remain synthetic boundary values and
proposed-receipt prefixes, not complete accepted NTT certificates.


Sixteen zero/nonzero ordinary/virtual sequences now interpret gamma after the
NTT batch bridge and match its raw coefficient stream, consumed-byte receipt
and public-primitive continuation. Nonconstant fragments match independent
Boolean-basis evaluation. Wrong aggregate offsets, oversized counts, absent
final bridge producers and trailing bytes reject. Both focused tests and the
20-case baseline pass in `classical-first-ntt-scalar-gamma-task-tests.log`;
fingerprints/scope are in
`opening-inventory/classical-first-ntt-scalar-gamma-task-audit.json`.
This establishes scalar task origin under the supplied frozen histories,
not accepted scalar authentication, later rolling/evaluation openings or
whole-proof security admission.


First-NTT ordinary/virtual scalar rolling tasks now use the same rolling-data
parser as primary fragmented openings. After the fixed gamma receipt it
checks public original roots, the trusted FRI context and, in virtual mode,
the initial identifier derived from the NTT source, point and gamma. Derived
root indices must follow earlier alpha receipts in order. The final terminal
precedes the exact rolling index request; ordinary mode additionally parses
its inline rolling output and separate consistency request.

Sixteen zero/nonzero ordinary/virtual sequences match every raw alpha,
pre-dedup index draw and the public primitive's final continuation. Missing
prior producers, wrong layer indices and trailing index bytes reject. Both
field tests pass with all primary checks and the 20-case baseline retained
in `classical-first-ntt-fragment-rolling-task-tests.log`; fingerprints/scope
are in `opening-inventory/classical-first-ntt-fragment-rolling-task-audit.json`.
The ladders, roots and terminal are synthetic boundary values, and the earlier
nonzero prefix uses proposed receipts. This does not assert accepted scalar/
NTT authentication or complete later-stage/security admission.


First-NTT direct/dictionary child interpretation now includes the complete
joint ladder binding, every ordered consistency-index request and the atomic
joint projection request. Normalized base statements are lifted to the trusted
extension field. The root matrix has the trusted number of queries and rounds,
and every ladder starts at the inherited coefficient-source root. Per-member
bindings must match that matrix before their exact index requests; earlier
inline index outputs have exact lengths but remain prior-phase obligations.

After all members, projection metadata rebinds the complete root matrix and
requests rounds*queries*width extension weights, in layer/query/lane order.
The core geometry constructor and projection-count framing are shared with
primary direct openings. Synthetic ladder fixtures use the public classical
primitive to replay every draw and projection coefficient. This identifies
fixed tasks under supplied histories, not authenticated accepted ladders or
the later rolling-proximity certificate.


Sixteen zero/nonzero direct/dictionary sequences across both fields and
schedules four/five now interpret every NTT batch consistency member and joint
projection request. Independent raw SHAKE draws, extension coefficient order,
projection receipt and the public primitive's final continuation match.
Wrong member order, out-of-range members, trailing bytes, missing seeds and
malformed projection counts reject. Both field tests pass with all previous
checks and the 20-case baseline retained in
`classical-first-ntt-direct-batch-projection-tests-final.log`; scope/fingerprints
are in `opening-inventory/classical-first-ntt-direct-batch-projection-audit.json`.
Synthetic ladders and proposed nonzero prefixes do not assert authentication
or accepted NTT certificates. Direct rolling, evaluation openings, later
stages and full security admission remain separate work.


Direct rolling-data parsing is now shared between primary and first-NTT batch
origins. It recovers the full rounds*queries*width projection vector from its
frozen receipt and groups it in layer/query/lane order. Each virtual original
identifier hashes the trusted core parameters, layer, complete ladder matrix
and that layer's rows. The trusted virtual-all FRI binding must match before
alpha zero. Earlier alpha receipts and derived-root indices determine each
later fold task; the final terminal precedes the exact atomic index request.

The first-NTT direct/dictionary fixture extends its public-primitive replay
through every alpha, derived root, terminal and final index block. Synthetic
ladders/roots/terminal and proposed nonzero parent receipts still do not assert
accepted batch authentication. Sharing the parser also retains primary-source
coverage of the one-query specialization.


Sixteen first-NTT zero/nonzero direct/dictionary sequences now interpret every
rolling fold, terminal and final index request. Independent raw alpha streams,
all pre-dedup index draws and the public primitive's final continuation match.
Missing projection/alpha producers, wrong derived-layer indices and trailing
index input reject. The shared parser retains primary-opening checks and the
20-case baseline. Both field tests pass in
`classical-first-ntt-direct-batch-rolling-tests.log`; scope/fingerprints are in
`opening-inventory/classical-first-ntt-direct-batch-rolling-audit.json`.
These remain synthetic boundary/proposed-receipt fixtures, not accepted NTT
authentication. Evaluation openings, later components/stages and full native
geometry/security/performance qualification remain open.


The first-NTT child-opening interpreter now selects the evaluation source after
consuming the ordered coefficient child seed and fixed-length finish frame.
Selection carries the evaluation root, compressed values and normalization
parameters through direct/dictionary consistency, projection and rolling, and
fragmented/virtual bridge, scalar and rolling interpretation. Earlier completion
bytes are checked for bounded framing only; they do not certify acceptance of
the preceding opening. Both field fixtures exercise the evaluation continuation
for all four child backends and both profile versions, including missing/short
finish frames and trailing-byte rejection. These synthetic continuations do not
establish complete NTT acceptance. Brakedown evaluation continuation, later NTT
components/application stages, native geometry coverage, complete security
admission and matched performance qualification remain unfinished.

Validation: `cargo test -p snarks outer_prefix_interpretation --lib` passed
both field tests (20 baseline combinations, 16 evaluation child continuations)
in 182.88s. Evidence: `classical-ntt-evaluation-prefix-tests.log` and
`opening-inventory/classical-ntt-evaluation-child-prefix-audit.json`. The
version-5 BabyBear fragmented fresh-proof group also independently passed its
21-proof control comparison, bringing audited version-5 coverage to 84/210.


Extended the first-NTT Brakedown v5 interpreter to the evaluation opening.
Advancing past the coefficient opening requires an 80-byte row receipt,
canonical response arrays bounded by trusted geometry and left-prefix query
grouping, the exact atomic column request, and its 8*Q-byte output. The next
binding must select the inherited evaluation root and compressed values. Its
row receipt is independently replayed before column selection; missing current
producers and trailing input fail. Earlier completion frames establish source
ordering only, not acceptance of their responses or authentication paths.
Both field tests passed on the final revision (20 baseline combinations, two
new Brakedown evaluation sequences) in 190.77s; rustfmt check passed. Evidence:
`classical-ntt-brakedown-evaluation-prefix-final-tests.log` and
`opening-inventory/classical-ntt-brakedown-evaluation-prefix-audit.json`.
All five backend families now have first-component evaluation sampling
interpretation. Remaining NTT components, later application stages, complete
accepted-certificate/native geometry coverage, security admission and matched
performance qualification remain unfinished.


Extended the NTT sampling/source-origin interpreter across every configured
component in the canonical verifier's ordered 2*d+1 loop. It recovers the trusted
component count and source arrays from the outer statement, requires the exact
coefficient/evaluation pair at each task, and advances only after both earlier
opening completions have bounded framing. Compression and batch construction
are shared helpers, so traversal does not recursively re-enter the outer parser.
Coefficient fixture roots are now distinct by component (evaluation roots were
already distinct); substituting component zero's coefficient or evaluation root
for any later source fails. Every component exercises atomic row points,
compression rounds and both child-seed or Brakedown row/column boundaries.
Both focused field tests passed in 215.36s, retaining 20 baseline combinations
and exercising 18 full ordered-component chains (v4 Brakedown remains the retry
compatibility case). Rustfmt check passed. Evidence:
`classical-ordered-ntt-distinct-components-tests.log` and
`opening-inventory/classical-ordered-ntt-components-audit.json`.
These are synthetic sampling/source-origin fixtures. Earlier child finishes and
Brakedown completion responses do not certify prior PCS acceptance; no complete
NTT certificate, all-native-geometry coverage or full adaptive knowledge theorem
is asserted. Later application-stage coupling, complete security admission and
matched performance qualification remain unfinished.


Extended the executable prefix interpreter from complete ordered NTT framing
into the first shared radix decomposition. The transition requires the trusted
last NTT component and both completed openings. The stage binds input[0], the
first configured coefficient digit slice, borrow/helper contexts and exactly
d+1 bounded borrow roots. Reconstruction and zero endpoint relations are derived
from the trusted radix, normalized in the original input context, then bound
with the full source registry before every linear matrix challenge. Previous
round receipts are independently replayed; missing producers and trailing bytes
fail. An isolated invocation of the actual shared decomposition verifier reaches
its post-linear dimension rejection and matches the independent raw transcript
continuation after all challenge rounds. Both field tests passed in 233.20s
(20 baseline combinations, 18 new stage sequences); rustfmt check passed.
Evidence: `classical-decomposition-linear-prefix-tests.log` and
`opening-inventory/classical-decomposition-linear-prefix-audit.json`.
The outer NTT completions are synthetic framing fixtures. This does not assert
accepted earlier openings or a complete decomposition certificate. First-stage
PCS/lookup coupling, second decomposition, accumulator/monomial/final-stage
coupling, full native geometry coverage, security admission and matched
performance qualification remain unfinished.


Extended first-decomposition linear interpretation across every ordered PCS
source handoff: original input, configured digit slice, then borrow roots.
The complete common matrix query is recovered before claim metadata, and
parameter selection follows the source role. Each metadata claim has a bounded
width, expected root/context and normalized query/value representation. Brakedown
v5 row requests and all four child-backend seed requests are interpreted for
every source. Typed children recover the task from their own frozen parent view;
wrong roots, missing seed producers, trailing bytes and reinterpretation as a
primary-relation child fail. Synthetic zero claim vectors satisfy all three
linear relations; earlier finish/response bytes establish bounded order only.
Both field tests passed in 262.40s (20 baseline combinations, 18 stage sequences)
and rustfmt check passed. Evidence:
`classical-decomposition-opening-origin-tests.log` and
`opening-inventory/classical-decomposition-opening-origin-audit.json`.
These checks do not establish accepted earlier PCS openings or complete backend
sampling for decomposition. Those sampling phases, lookup coupling, the second
decomposition and later stages, native geometry coverage, full security admission
and matched performance qualification remain unfinished.


Extended direct/dictionary sampling interpretation to every first-decomposition
linear source. Opening tasks now carry an explicit primary/decomposition family;
parameter selection uses the verified origin and registry position. The shared
direct entry accepts either separately interpreted origin, while the primary-only
child entry remains separate. The same sampler and fixture cover consistency
indices, atomic joint projections, all rolling challenges, terminal binding and
final indices. Existing primary fixtures retain the production Transcript;
synthetic decomposition children use a test-only public-ClassicalTranscript
adapter, whose final continuation matches independent raw replay. Both field
tests passed in 422.01s (20 baseline combinations, eight new direct/dictionary
stage chains, every input/digit/borrow source) and rustfmt check passed. Evidence:
`classical-decomposition-direct-sampling-tests.log` and
`opening-inventory/classical-decomposition-direct-sampling-audit.json`.
The ladders and terminal are synthetic sampling fixtures, not accepted complete
PCS certificates. Fragmented/virtual decomposition sampling, Brakedown column
sampling, lookup and later-stage coupling, native geometry coverage, full
security admission and matched performance qualification remain unfinished.
The native version-4 Goldilocks dictionary group also passed its independent
21-proof control comparison, bringing audited version-4 fresh coverage to
168/210; Goldilocks fragmented is running. These remain correctness-only runs.


Extended shared fragmented/virtual sampling interpretation to every first-
decomposition linear source. The common child entry retains the explicit
primary/decomposition task family, then the existing sampler and fixture cover
lane projections, every degree-two bridge coin, scalar gamma, all rolling
alphas, terminal binding, rolling indices and ordinary consistency indices.
Synthetic child replay uses the public ClassicalTranscript primitive and
bounded canonical decoding of each three-evaluation round before independent
quadratic recurrence checks. Existing primary fixtures still call the actual
production MLSumcheck verifier. Decomposition claims now use nonzero sources,
digits and interior borrows while preserving reconstruction and both zero
borrow endpoints; retained direct/dictionary chains exercise those claims too.
Both field tests passed in 708.88s (20 baseline combinations, eight fragmented/
virtual and eight direct/dictionary stage chains, all registered sources), and
rustfmt check passed. Evidence:
`classical-decomposition-fragment-sampling-final-tests.log` and
`opening-inventory/classical-decomposition-fragment-sampling-audit.json`.
These are synthetic source/sampling fixtures with proposed scalar ladders and
terminal values, not complete accepted PCS certificates. Brakedown decomposition
column sampling, lookup and later-stage coupling, native geometry coverage,
full security admission and matched performance qualification remain unfinished.


Extended first-decomposition Brakedown v5 sampling interpretation through the
atomic column request for every input/digit/borrow source. The source walker
retains a pending row boundary; the column interpreter independently replays
its current receipt, decodes both response vectors under trusted dimensions,
and requires the exact index domain and 8*Q-byte request. Fixtures use nonzero
response vectors and raw-SHAKE column outputs for subsequent framing. Wrong
roots, missing current producers, oversized response counts, changed request
descriptors and trailing input fail. The existing profile factory is shared by
two focused field tests; both passed in 15.09s and rustfmt check passed. The full
all-backend outer-prefix suite was not rerun for this Brakedown-specific change.
Evidence: `classical-decomposition-brakedown-columns-tests.log` and
`opening-inventory/classical-decomposition-brakedown-columns-audit.json`.
All five backend families now have first-decomposition sampling interpretation,
with v4 Brakedown still a separate retry-compatibility case. These are synthetic
source/sampling fixtures, not accepted authenticated opening certificates.
Lookup and later-stage coupling, native geometry coverage, full security
admission and matched performance qualification remain unfinished.


Extended the first-decomposition interpreter through completed linear openings
into shared lookup registry binding, the multiplicity-bound child seed and its
first tuple-hash challenge. Completed mode checks every reconstruction/zero-
endpoint relation before exposing the digit-then-borrow registry. Comparison
requests and limb slots come from the trusted radix configuration; normalized
tables, helper context and all registry roots bind before bounded grouped
multiplicities and their exact flat view. The typed child recovers its seed task
from the parent's own frozen producer view. Its first hash coefficients and
continuation match public-primitive and independent raw replay. An isolated
actual lookup verifier confirms preflight/registry framing, stopping at absent
helper packets before the child seed; no full production lookup acceptance is
asserted. Oversized multiplicities, missing seed producers and trailing child
input fail. The full focused field tests passed in 726.27s (20 baseline
combinations, 18 lookup-entry sequences), and rustfmt check passed. Evidence:
`classical-decomposition-lookup-entry-tests.log` and
`opening-inventory/classical-decomposition-lookup-entry-audit.json`.
The earlier PCS completions and lookup multiplicities are synthetic fixtures.
Reciprocal rejection/retries, later request/repetition challenges, helper roots,
equality points, batch algebra and lookup authentication, the second
decomposition and later stages, native geometry coverage, full security admission
and matched performance qualification remain unfinished.


Extended first-decomposition lookup interpretation across every ordered request
and repetition's hash/reciprocal schedule. The walker recovers each hash receipt,
derives its compressed public table, rejects r=0 and every public-table pole,
and remains in the same reciprocal phase until an admissible candidate appears.
Each retry consumes input; there is no arbitrary retry/attacker-query cutoff.
It distinguishes pending hash, pending reciprocal and completed schedules,
retaining prior accepted pairs for subsequent helper/equality tasks. Natural
hashes/reciprocals and final continuations match public-primitive/raw replay for
all 18 inherited stage sequences. Two focused field tests additionally use two
requests with two repetitions each and proposed receipts forcing zero and table
poles before acceptance; these proposed draws are not actual SHAKE outcomes.
Those two tests passed in 0.01s, and both full field tests passed in 751.61s
(retaining all 20 baseline combinations); rustfmt check passed. Evidence:
`classical-lookup-reciprocal-retry-tests.log`,
`classical-decomposition-lookup-compression-tests.log`, and
`opening-inventory/classical-decomposition-lookup-compression-audit.json`.
The reference-game note now states the exact admissible-domain uniformity and
geometric retry law, explicitly separated from adaptive Fiat-Shamir lifting.
No complete accepted lookup certificate or security admission is asserted.
Helper roots, equality points, batch algebra and lookup authentication, later
application stages, native geometry coverage and matched performance
qualification remain unfinished.
Two native version-5 groups also passed independent audits: BabyBear virtual
against its field control, completing all five BabyBear groups; and Goldilocks
Brakedown against its frozen version-4 control, including both binaries/logs and
all 21 case identities. Audited version-5 fresh coverage is now 126/210.
Goldilocks PolyFRIM (v5) and fragmented (v4) are running; these are correctness
runs only, with no security/performance qualification.


Extended first-decomposition lookup interpretation through the full helper-root
array, every equality-point vector and every shared scalar sumcheck round.
Helper counts come from the accepted request/repetition schedule; root decoding
is bounded before allocation and binds all roots before any equality draw.
Helper context/geometry and prior equality receipts are recovered explicitly.
Rational public sums and full/padded equation degrees are derived from trusted
requests and multiplicities; serialized metadata is compared against a test-only
observer of the actual private production inverse/sum/degree helpers. This check
preserves Goldilocks scalar multiplication and individual-inverse operation
order rather than substituting algebraically equivalent lazy representations.
Every individual recurrence is checked before the common challenge; fixtures
include nonzero higher-degree terms. Independent raw/public-primitive replay
matches all points and the full continuation. An isolated actual batch verifier
also matches the generated points, terminal subclaims and transcript state.
Oversized root counts, missing earlier receipts and a bad individual recurrence
fail. Both full field tests passed in 804.34s (20 baseline combinations, 18 lookup
stage sequences); both retry regression tests passed in 0.01s; rustfmt checks
passed for both changed audit files. Evidence:
`classical-decomposition-lookup-equality-batch-final-tests.log`,
`classical-lookup-equality-batch-retry-regression.log`, and
`opening-inventory/classical-decomposition-lookup-equality-batch-audit.json`.
The fixtures do not assert complete accepted lookup certificates or padded-
degree-four/native-geometry coverage. Terminal source/helper consistency,
helper/source PCS authentication, later application stages, full security
admission and matched performance qualification remain unfinished.
The native version-4 Goldilocks fragmented group independently passed all 21
fresh-proof control comparisons, increasing audited version-4 coverage to
189/210. Goldilocks virtual (v4) and PolyFRIM (v5) remain live correctness jobs.


Extended first-decomposition lookup interpretation through terminal consistency
and the linked parent handoff. The last scalar receipt completes the shared
point and all terminal subclaims. Source/helper arrays are decoded under trusted
counts and widths; source parameter validation and canonical helper scalars are
checked before every sum/helper and reciprocal-identity predicate. Scalar source
pullback, coefficient-helper queries and normalized helper claims are derived
from the recovered common point. Constructed terminal claims satisfy the reduced
algebra, and a test-only observer of the actual production terminal checker
agrees; changing a source or helper claim and oversized metadata fail. These
claims are not asserted to authenticate against the earlier committed words.
The finish fingerprint matches public-primitive/raw replay. Returning to the
parent requires the exact seed input, matching seed/finish digests, matching
child origin and the child's own frozen finish view. Missing finish producers,
missing frozen views and altered digests fail. Both focused Brakedown field tests
passed in 29.04s; both full field tests passed in 800.18s (20 baseline combinations,
18 lookup stage sequences); rustfmt checks passed for both changed audit files.
Evidence: `classical-decomposition-lookup-terminal-focused-tests.log`,
`classical-decomposition-lookup-terminal-tests.log`, and
`opening-inventory/classical-decomposition-lookup-terminal-audit.json`.
The positive terminal fixtures use full logical domains and one repetition per
request. Padded/multiple-repetition terminal witnesses and full native geometry
are not covered. Helper/source PCS authentication, the second decomposition and
later stages, full adaptive security admission and matched performance
qualification remain unfinished; no complete accepted lookup certificate is
asserted.


Extended the closed first-decomposition lookup into every ordered helper PCS
handoff. An explicit LookupHelper task family selects the trusted helper
parameters and role-one geometry. Helper roots, coefficient query and normalized
claims come from the checked lookup terminal/finish; helper context equality is
required. All child-backend seed requests and typed origins are interpreted.
Their own frozen parent views must retain the ancestor lookup finish producer;
a producer available only in the later child view cannot repair its absence.
Missing seeds and reinterpretation as a decomposition-linear child fail.
Brakedown row/column framing now has explicit role-based geometry, while existing
source callers retain role zero. Helper row receipts and nonzero responses are
replayed; using main-source row counts or response dimensions fails. Every
helper completion has bounded ordered framing, without asserting earlier PCS
acceptance. Both full field tests passed without warnings in 871.63s (20 baseline
combinations, 18 helper-stage sequences); rustfmt check passed. Evidence:
`classical-lookup-helper-role-tests.log` and
`opening-inventory/classical-lookup-helper-role-audit.json`.
Direct/dictionary and fragmented/virtual helper-body sampling, original-source
PCS authentication, later stages, native geometry coverage, full security
admission and matched performance qualification remain unfinished.
The native version-4 fresh matrix is independently complete: 210/210 proofs in
ten groups, driver terminal exit 0 (session 95581). Every log, metadata and frozen
binary fingerprint, v4 descriptor/header, original n=1024/LWE=728/output=728
geometry, 1+4+16 fresh single-proof schedule, decoded verification, altered-output
rejection, key/setup reuse and field-control identities were re-audited. Evidence:
`classical-native-validation/zerocheck-fresh21-complete-audit.json`. All profiles
use Q=1 correctness settings; no security/performance qualification follows.


The first-decomposition lookup sampler audit now covers every ordered helper
opening for the fragmented and virtual adapters using helper-role geometry.
Both focused field fixtures pass (BabyBear extension degree 6 and Goldilocks
extension degree 3; descriptor v5; four field/backend combinations). They replay
lane projections, the degree-two bridge, scalar compression, rolling folds and
indices against independent raw SHAKE and the public transcript primitive.
Source-role bridge dimensions and missing receipts are rejected. Frozen evidence
is in `target/performance/opening-inventory/classical-lookup-helper-fragment-sampling-audit.json`.
These n=32/LWE=21 synthetic prefixes do not assert authenticated helper/source
words, complete accepted lookup certificates or native security/performance
qualification. Original-source claim registration is being coupled separately.


Direct/dictionary helper sampling also passes the two full field audits across
v4/v5 (eight helper field/backend/schedule combinations); frozen evidence is
`target/performance/opening-inventory/classical-lookup-helper-direct-sampling-audit.json`.
After helper handoffs, the original-source obligation interpreter now derives
used slots, trusted parameter contexts, alias consistency, normalized claims and
the count seal. Focused Brakedown v5 field fixtures match the production registry
bytes, including suppression of consistent aliases, and reject conflicting
aliases, context substitution, duplicate claim blocks and altered seals.
Evidence: `target/performance/opening-inventory/classical-lookup-source-obligations-focused-audit.json`.
The combined all-backend regression is still running. These results establish
metadata and sampling checks for the stated synthetic fixtures; source/helper
PCS word authentication and the full adaptive security argument remain open.


Original-source opening tasks now retain the original registry slot and select
trusted coefficient/borrow parameters from that slot. Every source inherits its
root, normalized query and claim from the closed lookup; typed child seeds and
frozen parent origins route into direct/dictionary or fragmented/virtual samplers.
The Brakedown source path preserves its batch-opening grammar even for a single
claim. Both focused Brakedown v5 field fixtures pass, rejecting single-opening
metadata, flat batch responses and missing row receipts. Evidence:
`target/performance/opening-inventory/classical-lookup-source-openings-focused-audit.json`.
The full source-child sampler regression is running; accepted lookup certificate
and helper/source word-authentication claims remain unestablished.


The source/sampling audit now enters the second decomposition only after the
first lookup's complete ordered source-opening framing. Input 1 and coefficient
roots[d..2d] are fixed by that parent position. Both focused Brakedown v5 field
fixtures pass every linear round and reject first-half or duplicated bindings
and missing prior receipts. An isolated actual production verifier agrees on
the post-linear transcript continuation. Frozen evidence:
`target/performance/opening-inventory/classical-second-decomposition-linear-focused-audit.json`.
The all-backend regression is running. These prefixes do not establish earlier
PCS acceptance, complete second-decomposition verification, native geometry
coverage or the full adaptive security argument.


Focused Brakedown v5 field fixtures now pass all second-decomposition PCS
handoffs and row/column sampler phases; completed framing checks reconstruction
and both borrow endpoints. Frozen evidence:
`target/performance/opening-inventory/classical-second-decomposition-pcs-focused-audit.json`.
Child-backend runtime coverage remains pending. A separate second-lookup origin
and compression compiler is now under validation, anchored after that PCS
sequence; it preserves the existing reciprocal rejection loop without a retry
cutoff. Word authentication and complete second-lookup verification remain open.


Second-lookup metadata, frozen child origins and complete compression scheduling
pass both focused Brakedown v5 field fixtures. Evidence:
`target/performance/opening-inventory/classical-second-lookup-compression-focused-audit.json`.
The two lookup children now share the existing equality/batch/terminal algebra
checks through separately anchored origins, and a shared finish parser checks
the second lookup's return to its parent. That combined revision has compiled
and is under focused/full regression. Superseded intermediate full runs were
explicitly cancelled and are not passing evidence. Helper/source PCS, word
authentication, native coverage and the full security/performance gates remain
unestablished.


The source-obligation all-backend audit passes both fields across v4/v5, covering
all four first-lookup helper child samplers and source claim/alias/seal framing.
The second lookup's focused equality/batch/terminal and parent-finish fixtures
also pass, including actual production algebra observers and frozen finish
origins. Evidence is preserved in
`classical-lookup-source-obligations-full-audit.json` and
`classical-second-lookup-terminal-focused-audit.json` under the opening inventory.
Separate second-lookup helper/source families now route both stages through
shared PCS geometry and sampling parsers; the combined revision is under
focused/full regression. Word authentication, complete native coverage and the
security/performance qualification gates remain open.


The two-stage Brakedown helper/source PCS prefix fixtures now pass both focused
field tests; frozen evidence is in
`target/performance/opening-inventory/classical-second-lookup-pcs-focused-audit.json`.
Accumulator source and lane compilation now follows that ordered second source
sequence. Its independent row/shift/wrap/half query maps match production at
300 valid toy/native geometries across all eight extensions, both schedules and
five backends (blowup 2, cap 8, Q=8); 20 incompatible packing combinations are
explicitly rejected. This is isolated map coverage with synthetic roots/endpoints,
not accepted native certificates. Evidence is in the accumulator geometry audits.
A test-only, bounded memoization of pure lookup equations retains all history
and producer checks, matches the uncached calculation under input changes and
eviction, and does not impose a protocol query limit. The current full-prefix
regression is running; accumulator arithmetic/PCS and global word/security/
performance qualification remain open.


Accumulator opening audit update: the ordered collector binds all seven
accumulator sources and their exact query/value groups, Brakedown batch row
and column request framing, and typed child origins. Its isolated map/arithmetic
regression passes both fields with 300 valid toy/native geometries and 20
expected packing rejections. Evidence is frozen in
`target/performance/opening-inventory/classical-accumulator-openings-arithmetic-audit.json`.
Focused/full ordered-prefix regressions are still running. This does not
establish child PCS body validation, committed-word authentication, complete
native geometry coverage, security admission or performance qualification.

The subsequent accumulator direct/dictionary consistency revision reuses the
NTT role-zero batch parser after recovering the accumulator child's exact
source/query/value task from its own frozen parent view. Member count comes
from the selected source's query group, rather than from packing width.
Fixtures enumerate every member across all seven sources and reject changed
member values and invalid member indices. Compilation passes without warnings;
full ordered-prefix runtime validation is pending. This adds consistency
request interpretation, not projection/rolling or committed-word acceptance.

The next frozen accumulator revision adds direct/dictionary joint projections
and every rolling FRI fold/final index request using the existing independent
receipt replay and rolling-layer compiler. Projection cardinality is derived
from the exact selected source group, including single-claim and multi-claim
groups. Fixtures cover each source, missing projection/fold producers, changed
request bytes, and trailing input. Compilation/runtime validation is pending;
this remains conditional sampler evidence rather than word authentication.

Accumulator fragmented/virtual projection requests and every degree-two bridge
round now use a shared multi-claim kernel with the NTT sampler audit. The
selected source determines the claim count; every extension coefficient of
every claim/lane challenge is replayed. Per-source fixtures reject missing
receipts, changed sumcheck messages, invalid rounds and trailing input.
Compilation/runtime validation is pending. Scalar PCS contexts and their
rolling/source-query checks remain to be coupled; no word acceptance or
security admission is claimed. Source snapshots are frozen under
`accumulator-fragment-bridge-source-manifest.json`.

Accumulator scalar-gamma request interpretation now shares the trusted scalar
mode/source/point grammar and bounded fragment evaluator with the NTT audit.
It consumes the final bridge receipt from its producer view, preserves the
bridge terminal expectation, and checks fragment evaluation at the full point.
Fixtures use a separate Boolean-basis reference and reject changed roots,
inconsistent fragments, oversized counts, missing producers and trailing input.
Compilation/runtime validation is pending. This does not yet check scalar
rolling/source queries, the final bridge-to-word identity, or word authentication.

Accumulator scalar rolling and source-consistency requests are now linked to
the selected accumulator scalar task. The parser reuses independent rolling
data compilation for public ladders, gamma, virtual source/point/gamma identity,
fold challenges and numbered derived roots, then parses terminal and index
request framing. Per-source fixtures check every fold, replayed rolling indices,
missing producers, changed layer numbering, changed requests and trailing bytes.
Compilation/runtime validation is pending. Word authentication and the final
bridge-to-word equation remain separate unfinished obligations.

The accumulator necessary terminal bridge predicate is now implemented,
separately from earlier challenge interpretation. Its forward matrix/column
kernel matches explicit Boolean enumeration across all eight extension fields;
noncommuting order changes and malformed dimensions are rejected. The focused
test passes (one test covering eight extensions), with evidence in
`classical-accumulator-terminal-kernel-audit.json`. Full ordered-prefix runtime
validation is pending. Committed-word authentication and coupling this predicate
to completed accepted scalar openings remain open.

Accumulator assigned-word evaluation now binds all seven source context/root
identities and trusted table geometries, evaluates their exact query maps and
normalizes claims with each source's parameters. The geometry suite passes
150 nonzero toy word-chain cases against both arithmetic predicates, rejects
changed input words, missing assignments and wrong dimensions, and retains
150 native map/arithmetic cases plus 20 expected packing rejections. Evidence:
`classical-accumulator-assigned-words-audit.json`. The caller must supply the
word assignments from authenticated decoding; this evaluator does not establish
Merkle availability, word authentication, security admission or performance.

Word-assignment routines are now shared analysis-test support. Brakedown
completion accepts a frozen preimage map and verifies available SHA-512
internal/leaf preimages before canonical whole-column parsing, retaining fixed
zero completion for unavailable or malformed paths. The all-field word-history
suite passes, including first-declaration/late-repair cases and a new
hash-inconsistent frozen-root case. Evidence:
`classical-shared-frozen-word-audit.json`. Accumulator consumption of this shared
decoder and a complete authentication/reduction argument remain open.

Accumulator Brakedown word consumption now joins the shared frozen preimage
completion and joint RS decoder to exact source query-map evaluation. A focused
fixture independently builds canonical column leaves and binary Merkle parents,
compares its root with production commitments, then decodes and checks a
nonzero accumulator recurrence for both base fields under v4/v5. Missing views
and a hash-inconsistent root are negative cases. The focused test passes all
four field/schedule cases with warning-free compilation; evidence is frozen in
`classical-accumulator-frozen-brakedown-audit.json`. Frozen
view timing remains a caller obligation; direct/fragmented consumption and the
whole-protocol authentication/reduction argument remain unfinished.

The accumulator Brakedown decoder now reconstructs the full expected parameter
context from trusted profile geometry and preflights all seven sources before
requesting a frozen view. Tests pass four field/schedule cases and 32 geometry,
context, source-count and base-dimension substitutions, all rejected with zero
view callbacks. Evidence: `classical-accumulator-frozen-geometry-audit.json`.
A nominal blowup change that leaves the minimum-32 RS domain unchanged is not
a distinct word-geometry substitution; the regression changes the actual domain.
This does not complete first-declaration history coupling or security admission.

The shared frozen direct-source parser now binds source layer zero, each
pair index, complete core parameters and canonical +/- lane vectors; the
all-field history suite passes, including wrong-parameter, corrupted-preimage
and malformed-domain cases. Evidence: `classical-frozen-polyfrim-symbol-audit.json`.
Accumulator direct/dictionary consumers now derive expected source contexts,
coset points and the joint-nearness promise from the trusted profile before
decoding and evaluating source words. Production-root and recurrence fixtures
pass all eight field/schedule/backend cases, including 56 commitment-root
comparisons (`classical-accumulator-frozen-polyfrim-audit.json`). Their independent Horner evaluations must be canonicalized
before leaf hashing, matching the production encoding contract. Full history
binding and security admission remain unfinished.

Brakedown and direct/dictionary accumulator consumers now reuse the first
decoded assignment and nearness promise for repeated exact context/root
aliases within one invocation. Each source slot still evaluates its own ordered
queries. The production-root fixtures contain aliases and reject repeated view
callbacks while retaining all seven promise entries. Both focused tests pass
all 12 field/schedule/backend cases; evidence is frozen in
`classical-accumulator-frozen-alias-audit.json`.
This local stability does not establish first-declaration timing across separate
consumer invocations, full history binding, security admission or performance.

The shared packed-fragment parser now verifies actual source leaves against
the scalar parameter context, pair index and canonical fragment count. The
all-field history suite passes both source configurations across all eight
extensions (`classical-frozen-fragment-symbol-audit.json`). Ordinary/virtual
accumulator consumers now preflight trusted contexts, decode frozen packed
words, reuse exact aliases and evaluate each slot's queries. Their focused
fixture passes eight field/schedule/backend cases using production SHA-512
preimages, including Rayon parent hashes, and standard/recorded root agreement.
The combined five-backend consumer check passes all three tests and 20
field/schedule/backend cases (`classical-accumulator-frozen-all-backends-audit.json`).
This does not establish
global first-declaration history binding or the full authentication/reduction.

Trusted-profile substitution regressions now cover all five accumulator word
consumers. The combined three-test run passes 20 field/schedule/backend cases
and 112 preflight mutations, each rejected before any frozen-view callback.
The direct/fragmented cases substitute query counts, actual code rate, variable
count, packing width and backend; Brakedown retains its additional source/context
shape cases. Evidence: `classical-accumulator-all-decoder-preflight-audit.json`.
Global history binding, native geometry qualification and security/performance
gates remain open.

First-declaration analysis history is now shared test support with private
state and immutable `view(root)` access. The all-field PCS history suite passes
its filtered declarations, late exposure and pointer-identity checks through
this API. Accumulator fixtures now obtain positive views from that registry
and test repeated decoder invocations before/after late graph exposure.
All three consumer tests pass across 20 field/schedule/backend cases
(`classical-accumulator-first-declaration-history-audit.json`). These fixtures replay synthetic legal oracle
histories; complete production verifier event capture and the adaptive reduction
remain open.

The opt-in `transcript-audit` feature (forwarded by snarks) exposes
`helper::classical_transcript::audit::observe`; retain its guard while tracing.
It reports exact SHAKE inputs before output-reader construction, including
field-receipt fingerprints and child/checkpoint queries. No input tracking or
callbacks are compiled into the default build. All 32 helper tests pass with
the feature off and on, the observer integration test passes independent-output
and on/off compatibility checks, and the snarks feature build check passes.
Evidence: `classical-transcript-observer-audit.json`. Full production Hash/XOF
event capture and the adaptive security argument remain unfinished.

A real accumulator-stage event fixture now captures generic PCS SHA-512
queries and pre-answer transcript SHAKE inputs during commitment, proving and
production verification. All 20 representative field/schedule/backend cases
pass. Ordered replay reproduces first source views, decoded words match actual
accepted proof claims, and unobserved verification has the same continuation.
Honest fixtures record zero availability hits. Evidence:
`classical-production-accumulator-event-audit.json`. This is a small standalone
accumulator trace, not complete encrypted PBS capture, native geometry coverage
or a completed adaptive security reduction.

Observer registration is now local to the root-creating thread, with inherited
tokens for children, moved states and receipt hashes. This avoids unrelated
concurrent transcript roots contaminating a logical trace. Guards remain on
their owner thread and disable retained descendants when dropped. The worker
fork/receipt, thread-isolation and independent-observer integration test passes,
as do all 32 helper tests in both builds. Evidence:
`classical-thread-scoped-transcript-observer-audit.json`. The actual accumulator
event regression is still running; full-PBS capture remains open.


### File-backed generic receipt replay at observed first queries

The complete-PBS streamed audit additionally checks the generic framing layer
before inserting the current XOF answer into its producer map. For each
completed byte phase (kind 2/3), the request and response labels must agree,
the descriptor must give exactly the response length, and the response must
match the independently recomputed request stream. The exact request input
must already have an earlier producer: a matching 64-byte output prefix alone
does not suffice, because its recorded input span is compared byte for byte.

For each field phase (kind 4/5), the descriptor must contain the trusted base
prime and requested count. The 80-byte receipt must resolve to an earlier
producer with the consumed-field-byte domain and exact recorded byte length.
Those bytes must equal the beginning of the earlier request stream. Canonical
masked candidates are replayed without a retry cutoff; exactly the requested
number must be accepted, and no bytes may follow the final acceptance. The
count-zero identity therefore requires an empty consumed-byte sequence.

A linked-child finish (kind 7) must match the preceding parent fork label,
context and sampled seed. Its 64-byte value must already have a producer whose
input identifies that exact child and ends with the 64-byte child-finish
request. Child identity and seed-origin checking still apply independently to
the producer's own earlier event. Application messages, extension-basis
semantics and the algebra/PCS body are not interpreted by this generic layer.

For a fixed captured ordered trace on which the checker succeeds, the following
invariant follows by induction over its events. Every completed generic phase
in a checked framed input has its matching request and (for fields) consumed
byte producer available before that event. Every linked-child finish has an
earlier producer for the same initialized child. The current answer cannot
serve as its own dependency, since insertion follows checking. Repeated inputs
cannot repair a failed first occurrence, since checking stops at that failure.
All producer input spans refer to their first occurrence and the enclosing
checker rejects distinct-input collisions of their 64-byte XOF prefixes.

The namespace prefix caches preserve this invariant. Only receipts wholly
contained in an identical earlier validated prefix are skipped. Their request,
response and fork bytes are unchanged; their producers were available at the
earlier event and remain earlier at the current event. A receipt crossing the
common-prefix boundary is checked again. Parsing still checks full framing;
there is no probabilistic prefix digest or maximum-query cutoff.

This invariant is a deterministic captured-trace statement, not the adaptive
ideal-oracle filtering theorem. It supplies generic phase consistency when
those histories are used, but it does not authenticate source words, interpret
arbitrary application bodies, establish a uniform false-task probability, or
finish the all-trials knowledge/work reduction.


The streamed generic parser also checks field-request typing at the request
frame itself, even when that request has no response yet. A prime application
must bind the exact trusted prime-field identity. Each prime phase must have
its prime-vector marker and typed scalar/vector request marker. A scalar
requests exactly one coefficient. An extension application must first perform
the zero-count extension-identity phase. Every extension request binds the
complete trusted degree and multiplication table, requests a multiple of that
degree in base-field coefficients, and uses the extension-vector marker. Later
scalars request exactly one extension element; ordinary vectors may request
any nonnegative integral number of extension elements. Repeated identity
phases and unknown typed request markers reject. This interprets a pending
request without consuming or allocating its requested output.

The generic field metadata are independent of application relation/PCS frames.
Binding them does not establish that the relation's requested point count,
source roles or algebraic task are correct. Those require the stage-specific
interpreters and their frozen source assignments. Nor does a finite accepted
trace prove the probability of an arbitrary adversarial first-query history.


### Generic parent-fork ordering in captured query syntax

The streamed generic replay additionally checks local ordering of the typed
API's frames. Every byte or field request followed by another frame must be
followed immediately by its matching response. A parent fork must be followed
by the 64-byte child-seed request and its response. Once that seed is bound,
the parent may only finish that child or issue the terminal parent-checkpoint
query used by the detached-child API. A second fork cannot overwrite an
unfinished fork, and ordinary parent messages cannot occur before the finish.
A checkpoint frame has the exact reserved label, empty body and terminal
position: it is queried on a clone, never absorbed into the continuing parent.
These checks concern the reserved HasteBoots typed namespaces; they do not
restrict external adversarial oracle queries or change production bytes.

Together with exact producer-input comparison and earlier-record requirements,
these rules give a deterministic generic dependency invariant. In any finite
trace accepted by the checker, each completed response depends on an earlier
request, each field fingerprint on an earlier consumed-byte producer, each child
seed on an earlier matching parent-fork request, and each parent finish on an
earlier matching child-finish request. The enclosing child checker also checks
the child's initialized typed identity. Every dependency follows a strictly
earlier record; replay at a later occurrence cannot supply a missing dependency
at its first occurrence. An induction over the record order therefore embeds
the checked generic prefixes into an acyclic typed dependency graph. Shared
prefix reuse preserves this argument because skipped complete responses were
already validated at an earlier record with exactly the same prefix bytes.

This invariant interprets generic phase and link syntax, not the application
messages carried between completed phases. It does not assign authenticated
source words, prove that a PCS claim is the required algebraic task, or give the
uniform false-task probability needed for the adaptive all-trials reduction.


### Query endpoints and conditional captured byte inventory

The generic captured-query parser now rejects frame kinds outside 1..8 after
the constructor header, including repeated kind-zero domain frames. A framed
XOF input must end at its byte request, field request or terminal checkpoint;
ending at an opaque application message or a completed response is not an
owned API query. These structural checks run even for cached prefixes. They
do not restrict arbitrary external oracle queries: such candidate strings need
the protocol's admissibility/phase-emulation treatment rather than a claim that
they cannot be queried.

An independent saved-stream projection checks these boundaries while auditing
all SHA512 preimages and the complete expected file fingerprint. It classifies
current queries into byte, prime, extension and checkpoint requests. For each
field receipt input it counts canonical candidate widths and masked accepted
values. Under completed trusted API calls and matching receipt/stream replay,
the logical consumed XOF bytes equal the sum of byte-request lengths, consumed
field-receipt raw-byte lengths, and 64 bytes for each receipt fingerprint and
checkpoint query. These are logical reader bytes, not CPU timings or internal
sponge-block evaluations. The projection reports unknown inventory when there
are unclassified inputs or incomplete field-receipt counts; aggregate acceptance
counts must agree with requested coefficients when the inventory is closed.
It does not itself verify that a proposed receipt's raw bytes match its sampling
request's stream, so this premise remains separate and explicit.

The strict request-producer ordering checked by honest captured replay is not
implied by availability of a receipt fingerprint alone. An adversary can first
query a fingerprint for chosen raw bytes, then place that proposed receipt in
another candidate input before querying the implied sampling request. Later
consistency with that request must be handled by the phase-emulation and
first-bad-transition argument, not silently excluded as a 512-bit availability
failure. The earlier proposed-receipt interpreters and scalar/vector source
interfaces therefore remain necessary. The captured acyclic dependency
invariant is conditional on passing the strict replay checker; it is not an
admissibility theorem for all adversarial candidate inputs.


### View-bound proposed field receipts

`proposed_phase_audit::field_proposal` provides a separate test-support interface
for proposed past field coins. It binds the candidate bytes to the history's
original query view, requires the supplied request to be their exact prefix,
and requires the next absorbed receipt frame to match the trusted label and
supplied receipt bytes. The caller still supplies enclosing stage admissibility
and a trusted base-coefficient count. The request tail binds that count and the
trusted prime. A receipt fingerprint must resolve to a producer strictly before
the original view. Only that known producer is passed to the existing canonical
receipt decoder; a count larger than its actual candidate capacity rejects
before the decoder reserves output storage.

The result returns the proposed coefficients, request input and raw bytes as
an explicit consistency obligation. `request_was_queried` records only timing,
not consistency. Later recording the request cannot change an earlier view or
a repeat of its candidate. A later candidate can observe the earlier request
while still proposing incompatible raw coins; the interface does not silently
promote those coins to actual oracle output. Its optional comparison operation
requires the caller to provide the trusted actual stream prefix for that exact
request. Interpretation itself queries no sampling stream and consumes no
current challenge value.

The real typed-child regression illustrates the zero-count case. It records
an ordinary extension-child construction, removes only the unused zero-element
sampling request from its analysis history, and retains the actual seed,
checkpoint, empty fingerprint and next query. The existing typed-child prefix
interpreter and proposed-field interpreter accept the same candidate without
an XOF availability/collision hit. Empty raw consumption is consistent without
querying that unused stream. Both native base fields/extensions are exercised.
This is an API-prefix control, not a false accepted PBS proof or a probability
claim. The strict honest replay path continues to enforce its original ordering.

These interfaces make proposed coins measurable from candidate input and its
frozen producer view under the caller's stage-admissibility premise. They do
not prove the complete phase-emulation/first-bad-transition theorem, source-word
authentication, uniform local error bounds or all-trials work composition.


### Proposed byte runs and the conditional family-entry bound

The test-support `proposed_phase_audit` module now also interprets inline byte
receipts and consecutive no-message byte-request runs at their original query
views. Each prior response is bound to its exact request, label and trusted
length. Intervening prover messages or changed descriptors reject. Inline
bytes need no fingerprint producer; seed and finish links retain their separate
producer obligations. Interpretation does not read the current answer or
assert that proposed prior bytes equal the corresponding streams.

For v4 columns, the interpreter uses the production rule
`limit = u64::MAX - u64::MAX % length`, accepting exactly samples below limit
and mapping them modulo length. It retains repeated accepted indices, rejects
prefixes that already completed the trusted count, and imposes no rejection
cutoff. In particular, even power-of-two domains reject the top bucket under
this rule. Tests include 513 consecutive rejected proposals, accepted repeats,
boundary samples, and changed-message/descriptor rejection. The enclosing
protocol must still determine the unique run root and authenticate its word.

A conditional ideal-oracle lemma states the missing composition obligation
precisely. Suppose request inputs are partitioned into disjoint, canonically
identified sampling families. A family contains every possible request along
its rejection-sampling tree. At its first query, its source word and rejecting
subset must already be determined by the prior history and the current input,
without reading the current answer. No earlier query may belong to that family.
Its ideal stream table must be independent of that history; querying other
families must not reveal entries of this table. These are hypotheses, not facts
established by the byte-run parser or the captured traces.

For a family with domain size N, Q accepted draws, and rejecting subset of size
at least delta*N fixed at entry, the event that its canonical completed run
misses that subset has probability at most `(1-delta)^Q`. To see this, expose
the entire previously untouched ideal table at entry only for analysis. Every
next request strictly extends its predecessors and is distinct, so its draw
is fresh. Each raw sample is uniform on 64 bits; conditioning on acceptance
makes its residue uniform because the accepted interval is a multiple of N.
Acceptance has positive probability, hence each draw terminates almost surely,
without a deterministic retry cap. The accepted indices are independent and
uniform with replacement. An adversary can query a proposed descendant first,
but that does not change the distribution of the completed canonical run in
the untouched table. A descendant inconsistent with that run does not witness
a miss by the actual run.

For adaptively entered families j with entry-measurable bounds epsilon_j,
a union bound gives `Pr(any entered family misses) <= E[sum_j epsilon_j]`.
Apply the finite union bound to the first m entries and then monotone
convergence. This formulation imposes no arbitrary global query cutoff; it is
useful only after the expected sum is bounded by charged work. If every bound
is epsilon and the expected number of entries is finite, the expression is
at most epsilon times that expectation. It is not a per-byte bound and does
not justify replacing an adaptive source by a fixed source after entry.

Applying this lemma to PBS remains open: prove canonical disjoint family
membership, first-entry source fixation, link/receipt consistency on accepting
paths, and the work charge for each entry. Field phases, adaptive rolling
transitions, knowledge extraction and verifier resource accounting need their
own composition. The lemma is conditional ideal-oracle reasoning, not a
security certificate for the current implementation.


The separate `canonical_column_run_proposal` entrypoint removes caller choice
of a descendant root within a contiguous v4 run. It parses complete frame
boundaries and selects the maximal trailing chain of eight-byte column
requests and matching inline responses. Thus the same candidate cannot reset
its accepted-draw counter by supplying its last request as a new root. Label
bytes embedded in a message body do not create frame boundaries. This is a
syntactic family identifier relative to the candidate's parsed history;
authenticating the preceding stage and preventing alternate histories from
representing the same semantic source remain separate obligations. The
low-level supplied-root interpreter remains available with its explicit
caller-side root-selection requirement.


For scalar v4 openings, `linear_column_run_proposal` additionally decodes the
immediate preceding `mw linear responses` frame into canonical test and
evaluation vectors of trusted size. It returns the exact earlier stage prefix
for separate authentication. A root after an intervening message, a different
response label or a malformed response vector fails this boundary check.
This binds the proposed linear responses before every draw in that run;
it does not authenticate the commitment, query, random linear test receipt,
source oracle or the trusted dimensions supplied by the caller. Batch and
aggregate response shapes require their own interpreters.


### Uncapped single-family column resource moments

Let a be the production v4 acceptance cutoff divided by 2^64, r=1-a,
and Q the trusted accepted-draw count. Under the independent-stream family
hypotheses above, the total raw draw count T has
`E[T] = Q/a` and `E[T^2] = Q*(Q+r)/a^2` (both zero when Q=0).
These follow by summing Q independent geometric waiting times, each of mean
1/a and variance r/a^2. This is almost-sure termination, not a deterministic
runtime guarantee, and includes all rejection draws and accepted duplicates.

For an initial request of B bytes, every subsequent request adds exactly 86
bytes: a framed eight-byte response and another framed eight-byte request,
each with the 18-byte `mw unbiased column` label. Therefore logical consumed
reader bytes have expectation `8*E[T]`, and the sum of all queried input lengths
has expectation `B*E[T] + 43*(E[T^2]-E[T])`. This counts complete input bytes
per request, not an implementation's cached-prefix CPU work or sponge calls.
Root construction and work outside this family are separate costs.

The calculator `column_run_expected_resources` returns these exact rational
values without a retry stop. Its reduced-support test parameter changes only
the sample distribution; the eight-byte framed API remains unchanged. Applying
these finite moments across adaptive family entries still requires the source,
freshness, entry-count and work hypotheses of the family-entry argument.
Expected costs alone do not establish deterministic verifier bounds or a
128-bit all-trials work certificate. The existing stopped envelopes remain
separate calculations with their original explicit stopping premises.


The first primary v4 scalar entrypoint now composes this boundary with the
existing initial-relation/terminal-value/first-opening interpreter. It supplies
column dimensions from the trusted profile and resolves earlier field receipts
from `History::producers` at the exact candidate view. The selected commitment,
context, query and claims therefore come from that interpreted task, rather
than caller-provided response counts alone. The row request/receipt pair is
additionally returned through the proposed-field interface, retaining an
explicit stream-consistency obligation. The current answer is not used.
This remains a partial application-prefix interpreter: first-declaration source
assignment, other opening families, consistency of all earlier proposed phases
on an accepting path, and the complete first-bad transition proof are separate.


### First primary v4 task values from frozen source views

`primary_frozen_values` assigns the interpreted first primary task from the
SHA history's per-root first-declaration views. It first checks every source's
context and parameter geometry against the trusted Brakedown role, along with
query and claim shapes. Each distinct context/root alias is completed to the
existing canonical whole-column word, decoded with the existing fixed
Brakedown assignment, and evaluated at the task's matrix query. Missing or
malformed paths retain the existing zero-column completion rule. Nearness
promises and assigned values are returned separately; neither is proof
admission. Duplicate aliases reuse one assignment and evaluation.

This interface takes the word history rather than an arbitrary current-view
callback. Later hash preimages cannot replace a root's first-declaration view.
The caller still must synchronize the SHA and XOF histories and account for
availability/collision exceptions. In particular, deliberately declaring a
root before its graph is known and exposing that graph later illustrates an
immutable zero completion, not a successful attack outside the exceptional
events. A separate control exposes the graph first, checks its root against
the production commitment, and recovers the nonzero table's true values.
This supplies fixed values for one opening family; the full adaptive state
predicate, error bound and knowledge/work composition remain separate.


### Fixed-word scalar column failure predicate

`scalar_column_failures` evaluates the production scalar equations on every
column of a fixed completed word. It expands the left matrix query into its
structured row weights, encodes the proposed random-test and evaluation
responses with the trusted row code, and marks a column when either dot product
fails in any lane/block coordinate. Separately it folds the evaluation response
through the right query and checks the opening claim. Merkle authentication,
stream consistency and source timing are premises outside this local predicate.
`primary_column_failures` supplies these inputs from the parsed first primary
v4 run and its selected root's immutable first-declaration view. Neither
calculation reads the current column challenge.

Under the earlier independent-family hypotheses, if B of N columns reject and
the final value equation holds, the canonical run misses the rejecting set
with probability exactly `((N-B)/N)^Q`, where Q counts accepted draws before
sorting/deduplication. A repeated bad draw still leaves a bad distinct column
for verification, so deduplication does not weaken this condition. If the final
value equation fails, the actual scalar verifier rejects regardless of which
columns were sampled. Authentication must bind the actual opened values to the
fixed completed word outside its separately charged exceptional events.

This is an input-dependent failure-set bound, not the required uniform local
soundness bound: it does not prove a lower bound on B for every false assigned
claim, charge an adversary's choice of row coins, or establish the family-entry
hypotheses. Those require the row-randomness/RS proximity argument and full
first-bad transition composition. The predicate therefore adds no security
admission claim.


### Near-word case of the implemented column predicate

For the predicate above, suppose the fixed completed row word U agrees outside
a common set E, |E|<=t, with the encoding of a correctly padded table V.
Let D be the block code's minimum distance, and let the fixed query's claimed
value differ from V's value. This is a deterministic hypothesis on the source
and claim, not an assumption about the prover's response or random-test coins.

If the proposed evaluation response equals the left-query aggregation of V,
its suffix fold equals V's opening value by linearity and the matrix query's
ordered folding semantics. It therefore fails the final equation for the false
claim. Otherwise at least one lane's response differs by a nonzero vector-valued
RS codeword. Some coordinate is a nonzero polynomial of degree less than m,
so the responses disagree in at least D=N-m+1 whole columns. Outside E, the
structured dot product on U equals that on Enc(V). Removing E leaves at least
D-t columns marked by `scalar_column_failures`. The additional random-test
check can only enlarge this set. This reasoning holds for every response and
every random-test matrix; it requires no independence between the two checks.

Thus, under authentic frozen answers and the independent whole-run sampling
hypotheses, this near, correctly padded false-claim case has error at most
`(1-(D-t)/N)^Q`. In the selected radius t=floor((D-1)/3), this is bounded by the
conservative t+1-column tail used in the existing component worksheet. The
far-word and forbidden-padding cases still need their random-row exceptional
bound and the common first-query phase composition. The control perturbing a
fixed t-column set tests the decoder/predicate mapping, not the probability
statement or a complete adversarial certificate.


### Executable universal row-state predicate

`scalar_row_state` defines the intermediate state without a prover response.
It uses the fixed source word's canonical assignment and the random row matrix
only. For a near, correctly padded source, a false opening claim keeps the
state bad deterministically, using the D-t structured-column argument above.
For an invalid source, the state stays bad when the projected random-test word
has no common nearby, correctly padded RS decoding at radius t. A far RS
projection disagrees with every coded response on at least t+1 columns. A
near projection with forbidden padded coefficients disagrees with every
validly padded response on at least D-t columns. The implementation returns
t+1 conservatively in either invalid-source case.

Consequently, whenever this predicate stays bad, every dimension-valid pair
of responses either fails the final claimed-value equation or rejects at least
the returned number of columns. Response choice cannot repair this state.
`primary_row_state` and `primary_column_failures` share the same reconstructed
trusted parameters and immutable selected-source word through
`primary_fixed_word`, and take proposed row coefficients from the parsed run.
They do not consume current sampling coins.

The predicate deliberately allows an invalid source to escape when its row
projection has a nearby valid decoding. For example, zero row weights hide a
reciprocal far word from the random-test component. This is an event to bound,
not candidate syntax to reject, and not a claim that the complete structured
opening would accept. Under the fixed-word exceptional-polynomial lemma in
`docs/block-rs.md`, independent uniform row coefficients, a symbol field with
the specified basis, and h<=b, the far-source escape probability is at most
`min(1,N*(N+1)/p^h)`. The forbidden-padding near case has probability at most
p^-h, and the valid-source false-claim case has zero row escape. These are cases
of one fixed source, so the same maximum covers them. This remains conditional
component reasoning: the universal quantifier over responses is represented
by the state, but first-query freshness, phase emulation, all-family semantics
and knowledge/work composition are not established by computing it.

The reciprocal-word controls use values 1/x at the nonzero RS domain points.
An agreeing degree-<m polynomial f would make X*f-1 vanish at those points;
this nonzero degree-<=m polynomial has at most m roots. The word is therefore
farther than t whenever N-m>t. An exposing row matrix preserves that far word
in a projected coordinate, while zero weights give a valid zero projection.
These finite controls exercise both branches of the predicate, not their
probability or a complete adversarial proof.


The row-state controls now separately expose `projected_test_rs_near` and
`projected_test_near_and_padded`. In eight/four-test-row, eight/four-symbol-width
controls, a constant forbidden coefficient gives an RS-near projection that
fails padding. A zero structured query isolates its random-test rejection.
Nonzero row matrices that annihilate the offending source row produce a valid
zero projection and remain allowed escape choices, as required by the kernel
probability argument. Reciprocal far-word controls in the same widths exercise
the genuinely RS-far branch. These finite controls validate branch mapping,
not independent randomness, exception probabilities or original-size PBS.


### Earliest syntactic sampling-family entry

`primary_family_entry` selects the earliest recorded member of a column family
before attempting semantic interpretation. Membership uses the canonical
maximal trailing run, trusted dimensions/count and exact root-request bytes.
It depends on input syntax, including proposed prior byte responses, rather
than receipt-producer availability. A member after an already completed draw
count is excluded by the existing run interpreter. Thus two different selected
roots cannot describe the same member under one trusted profile.

`History::first_query_matching` minimizes original query epochs among matching
inputs at or before the supplied frozen view. It returns input/view metadata,
not an oracle answer. Repeats retain their original epoch, future queries are
excluded from older views, and foreign views reject. The family selector then
interprets that first input with its own original producer view and computes
its row state against immutable source views. A descendant can be the first
member even when the root request has not yet been queried.

The distinction matters when the first member contains an unavailable field
receipt fingerprint. Querying its producer later may make a fresh root or
descendant parse, but the first family classification remains unavailable:
producer lookup still uses the original first view. The control deliberately
arranges this late-producer hit and checks its availability-window accounting;
it is not an estimate of how likely an adversary is to cause it. Ordinary
controls continue to admit proposed row coins whose sampling request was not
queried, as long as their receipt producer was available at family entry.

The selector scans the recorded query database and introduces no query-count
cutoff or mandatory observer timing. Its cost is analysis work, not a native
performance claim. Complete synchronized XOF/SHA history is still a premise:
it cannot repair omitted oracle events or late source declarations in an
incomplete capture. The implementation supplies first-entry interpretation
for this one family, not the complete availability/phase-emulation theorem or
all-trials knowledge/work bound.


### Pre-row state at the actual original request view

`primary_row_query_state` binds the first primary scalar row request to its
original XOF query view and the trusted profile. The existing first-opening
interpreter recovers the task using only producers strictly before that view;
its exact tail supplies the trusted coefficient count. The fixed source
assignment supplies the selected source's near/padded flag and assigned query
value. The pre-row false relation is that the source is invalid or its claimed
value differs from that assignment. No current challenge answer, proposed row
vector or later producer is read to define this state.

Controls query the row request after column-family requests and compare two
trusted histories with identical prior producers but different current answers.
Their pre-row source values and false-relation flags agree. A referenced earlier
receipt can instead be withheld until after the row query: a legacy parse with
the enlarged producer map then succeeds, but both a wrong later view and a
repeat retaining the original view fail the guarded interpreter. The deliberately
late producer is an availability-window hit, not a successful uncharged attack.

This defines the first-primary pre-transition object. Supplying actual stream
coins to the post-row predicate, proving consistency with later proposed
receipts on accepting paths, and composing all first-query transition charges
remain distinct obligations. Repeats retain the original classification; they
must not be counted as new independent trials. Complete synchronized source
and XOF histories, the ideal-stream model and all other application families
remain premises or unfinished work.


### Captured-word row transition and explicit stream consistency

The pre-row object now owns the trusted scalar parameters and completed
selected-source columns obtained at its original interpretation. The post-row
transition takes no source history or producer callback: later events cannot
replace that word. Its stream-output argument explicitly names the request,
accepted coefficients and complete consumed raw bytes. Exact request/count
checks and the shared canonical raw decoder verify that those raw bytes yield
those coefficients with exact exhaustion. The decoder bounds allocation by
actual raw candidate capacity before reserving the trusted count.

`primary_row_transition` evaluates the row state on this captured word and
supplied coefficients, checking that the source's pre-row relation is unchanged.
`primary_row_proposal_consistent` separately binds the later proposed request,
coefficients and raw bytes to that same output. An extra rejected candidate
before a stream can leave every accepted value unchanged. The transition is
then valid for that counterfactual stream, but the original proposed receipt
is inconsistent because its consumed bytes differ. Trailing bytes after the
last accepted coefficient reject canonical consumption outright.

The stream-output argument must come from the trusted sampler for the named
request. Internal shape and raw decoding cannot establish that provenance and
must not be treated as proof admission. Controls compare actual fixture streams
with proposed receipts and reject mismatched request/count/value/raw bindings;
they also deliberately supply a counterfactual stream to test this distinction.
This implements a component transition interface, not the full accepting-path
stream-consistency or first-bad event theorem.


### First-primary verifier clause review and one-variable residual case

Source review compares the interpreter with `ClassicalShared` outer binding,
`packed_relation::verify_inner`, ZeroCheck verification, packed-sumcheck round
checks and scalar PCS binding. Version 12 and source dimensions match the
classical mode. Relation contexts/roots precede equality sampling; the first
ZeroCheck message has the same dimensions and zero boundary as `check_first`.
The atomic mixing/query coins, residual claimed sum, per-round paired sums and
interpolation updates use the same helpers/equations. Canonical serialization
checks constrain transcript inputs, which the verifier creates by serializing
its decoded values; they are not an extra demand on proof-wire integer encoding.

The review found a real scope omission: the old first-opening interpreter
required `num_vars-2`, although production supports a one-variable ZeroCheck.
`first_reduced_prefix` now handles the shared first reduction. One-variable
instances enter the zero-round residual sumcheck directly; larger instances
continue through their normal rounds using that same reduction.

The public equality vector is also the same algebraically. The interpreter
starts from E(b)=sum_c M[:,c]*prod_j eq(r[c,j],b[j]) and folds each remaining
matrix pair. Linearity moves the sum outside each fold and replaces its vector
by `((1-r)*P_zero+r*P_one)*vector`. Iterating gives exactly production's public
vector recurrence, in the same matrix order, without assuming commutativity.
The special first query is excluded from both equality constructions. With
zero remaining variables, both give sum_c M[:,c]. The terminal product/equality
identity is then the verifier's `ZeroSubclaim::check` equation.

Both fields' new one-variable controls use genuine production ZeroCheck proofs
with nonzero first-message polynomials, comparing query, expected value and
equality vector. Missing receipts and an incorrect residual claim reject.
The existing larger-shape controls also pass. This checks the zero-round
reduction, not an entire one-variable PBS setup/proof. Clause/source snapshots
are in `first-primary-verifier-clause-review.json`; the review does not establish
all arbitrary-prefix, availability, phase-emulation or knowledge/work premises.


### Observed first-query and family ledger

`primary_query_ledger` enumerates distinct XOF input/original-view metadata at
a supplied temporal boundary. It counts row-shaped inputs, admitted first row
queries and false pre-row relations separately. It also counts canonical
syntactic families, admitted first-family entries and bad row states at entry.
Unclassified rows/families remain explicit; they are not silently assigned a
zero error contribution. Input enumeration exposes no oracle answers. The
boundary selects an observed history prefix, not an adversarial query cutoff.

Repeated inputs appear once through their original query metadata. Descendants
share one exact canonical root and are charged once as a family. Each family's
classification uses its earliest member's own view. Older boundaries exclude
future distinct inputs even when evaluated after more events have been recorded.
The implementation scans the history without a maximum-query/family parameter;
its analysis cost is not a native performance result.

Both field controls retain zero-completion cases and construct the actual
nonzero selected-source graph, verifying its root against the production
commitment. The latter exercises one false row and one bad admitted family.
Malformed row/family entries remain unclassified, and a later malformed row
increases only the appropriate observed counts. These are finite component
controls, not an all-trials probability certificate. Turning predictable counts
into error/work charges requires the uniform transition lemmas, accepting-path
coverage of unresolved entries, oracle availability/collision terms, honest and
verifier work offsets, and the other opening families.


### Conditional first-component composition with expected query counts

Fix one trusted scalar Brakedown geometry and let
`e_R = min(1,N*(N+1)/p^h)` and
`e_C = (1-(t+1)/N)^Q`, as in the fixed-word component argument.
Let N_R count distinct admitted first row requests whose pre-row relation is
false. Let N_C count distinct admitted first column-family entries whose row
state is bad. The predicates must be determined before their respective fresh
answers. Both counts cover the complete experiment, including verifier queries;
the finite ledger is an observation of these quantities, not an upper bound on
their expectation for an arbitrary adversary.

Let O be the relevant oracle availability/collision event. Let U include false
acceptance outside O for which an entry is unclassified or the admitted tasks,
fixed words, requests or actual/proposed coins do not align on the accepting
path. These are distinct obligations: setting U to zero needs a coverage and
consistency proof; setting O to zero needs an oracle argument. A malformed entry
that can never lie on an accepting path need not cause U, but an unresolved
entry must not simply be omitted from its analysis.

Assume the fixed-word uniform row-transition lemma, disjoint canonical families
with fresh ideal tables at first entry, and the whole-family miss bound. Then

`Pr(false first-component acceptance) <= Pr(O) + Pr(U) + e_R*E[N_R] + e_C*E[N_C]`.

Outside O and U, the accepting path has the same false source/task at its first
row request and the same coefficients at its column-family entry. If its actual
row output escapes the bad row state, charge that first row request. Otherwise
its family entry has a bad row state. Every valid response either fails the
final equation or fixes at least t+1 rejecting columns. Acceptance then requires
the family's canonical run to miss them, so charge that first family entry.
This dichotomy holds when a descendant is queried before the root or before
the row request: first-entry semantics are frozen syntactically, and actual/
proposed consistency is part of the coverage premise rather than an assumed
producer-query ordering.

For each row event, conditional expectation bounds its escape indicator by
`e_R` times the predictable false-row indicator. At a family entry, expose its
previously untouched ideal table only for analysis; the miss indicator has
conditional probability at most e_C. Proposed ancestor bytes in a descendant
input do not change the fixed root responses or rejecting set. Distinct roots
partition the request trees, including arbitrary non-protocol queries with the
same syntax. Sum the bounds over the first m query/entry positions, apply the
union bound, and pass to the limit by monotone convergence. This imposes no
arbitrary adversarial query cutoff. Infinite expectations give only a trivial
bound; finite expected work must separately bound both expectations.

An observed count from one completed trace cannot replace E[N]. For example,
an abstract independent-family experiment with miss probability s can stop at
its first miss with success probability one and E[N]=1/s, without any
deterministic query ceiling. The expectation-weighted charge s*E[N]=1 is correct.
Converting these charges to 128-bit work security additionally needs proved
bounds such as E[N_R]<=a_R*T+b_R and E[N_C]<=a_C*T+b_C, with correct honest and
verifier offsets. Oracle terms also depend on processed input windows/bytes,
not just these component query counts. Complete source-history/filter coupling,
all other component families and knowledge extraction remain unfinished.

`brakedown_opening_terms::first_query_terms` implements only this exact-rational
arithmetic. It requires explicit expectation, oracle-exception and coverage-
failure bounds and marks their verification/work/security flags false. A unit
coverage-failure bound yields the trivial bound one. Tests of the arithmetic
and stopping identity do not discharge the uniform RS, fresh-family, coverage,
or primitive-model premises and do not promote a native profile.


### Unclassified-entry diagnostics and missing-fingerprint windows

The ledger now partitions unresolved rows/families into header mismatches,
unavailable framed field fingerprints, and other failures. Header comparison
uses the fixed trusted parent constructor's exact bytes. Missing-fingerprint
diagnosis scans actual frame boundaries and returns the digest and its exact
64-byte offset in the original input. Opaque prover-message bodies are not
interpreted as nested frames. Old views remain unavailable after a producer is
learned, and family diagnosis uses its earliest member's view.

Under the complete ideal-oracle history premise, a missing witness has a useful
necessary consequence. If a later accepting path uses that field receipt, the
trusted sampler must obtain its fingerprint as an XOF answer. No such answer
was available before the witnessed input. The first return of that digest is
therefore at the current or a later event, after the witness window was declared,
and is an availability hit. For a column family, field receipts precede the
root request: its suffix contains only matching byte responses/requests. The
witness is consequently in the common root prefix even if the first queried
descendant is never on the accepting canonical run. The claim needs complete
window registration and the trusted receipt/stream convention; it is not a
bound on the hit probability or its work cost.

Fingerprint availability alone is deliberately weaker than admission. It does
not check producer namespace, consumed length, canonical raw sampling, trusted
descriptor counts, basis metadata or enclosing stage semantics. A malformed
frame, an available but invalid producer, or another unsupported prefix remains
in the other-failure category unless the header already mismatches. That
category cannot be assigned zero coverage error without further proof.

Both fields' controls check exact missing offsets, short/truncated frames,
foreign views, opaque receipt-like payloads and later-producer stability. The
existing real-source ledger cases classify their malformed entries as header
mismatches; separate late-producer cases retain missing-receipt rows/families.
These are diagnostic/component controls, not a complete accepting-path coverage,
oracle-work, source/phase or knowledge certificate.


### First-primary v5 atomic column query and transition

The shared pre-row, frozen-word and source-assignment interfaces now accept
both trusted schedules four and five. `primary_atomic_column_query` adds a
separate v5 entrypoint: exact original view, existing complete first-scalar body
interpretation, available proposed row receipt, trusted index domain and exact
8*Q-byte request. It computes the row state and rejecting set from the fixed
source without reading the current atomic output. Row proposals still need no
prior sampling-request query, and later receipt producers cannot repair the
original query view.

`primary_atomic_column_transition` takes explicitly supplied stream bytes for
that exact request, checks their length, and masks each little-endian u64 by
N-1 under the trusted power-of-two domain. It retains all Q ordered draws,
including repeats. The state after sampling is bad if the final value equation
fails or any drawn index belongs to the fixed rejecting set. Sorting/deduplication
for path transport does not change that condition. Stream provenance is a
trusted-caller premise, as for the row transition.

New first-primary-only v5 fixtures compare these draws with actual production
`get_index_challenges` outputs and the independently replayed request bytes.
They validate the real source root, false row state, shared row-stream/receipt
consistency, row-after-column ordering, duplicate draws, wrong request/length
bindings, malformed request counts and delayed-receipt unavailability. Both
fields pass along with the existing v4 controls. The common source-graph builder
is reused by both schedules. Existing broad fixtures still default to their
full scope; only the new explicitly scoped tests stop after the first primary
opening. No broad pass is inferred from that narrower new test scope.

For v5 the conditional fixed-set tail applies to a single fresh 8*Q-byte atomic
phase; the v4 rejection-run family tree is unnecessary for that phase. The v5
first-query ledger and full accepting-path, all-family, availability/work and
knowledge composition are still unfinished. These synthetic controls do not
qualify an original-size encrypted profile or benchmark.

### V5 first-primary ledger extension

The first-primary query ledger now supports schedules four and five. Each
distinct v5 atomic column request is a singleton sampling family. Candidate
matching uses the trusted byte-count suffix, leaving malformed headers and
index domains visible as unresolved entries. Repeats retain their original
view; later receipts cannot repair the recorded classification. V4 keeps its
existing canonical rejection-run family grouping. These observed counts are
not expectation bounds or an adversarial query cutoff.

Both field controls check admission before a row query, row-after-column
ordering, repeat deduplication, old boundaries, malformed header/domain
partitions and late-receipt diagnostics. Eighteen proposal and four history
tests pass; source and log hashes are frozen in
`v5-first-primary-ledger-tests-passed-audit.json` and
`v5-first-primary-ledger-source-manifest.json`. This supersedes the earlier
statement that v5 first-primary ledger integration is unfinished. Full
accepting-path, all-family, knowledge and oracle-work composition, and the
security-matched native benchmark remain open. Admission flags remain false.

### Predictable ideal-XOF prefix exposures without a query cutoff

For the complete classical ideal-XOF experiment, enumerate fresh input queries
only. Before revealing the first 512 output bits of query i, register every
64-byte window in that query's input and every other relevant input already
submitted, including external hash inputs. Let T_i be the set of registered
window values and O_i the set of distinct earlier XOF prefix outputs. Both sets
are measurable before the fresh output Y_i is revealed. Repeated queries reveal
no new output and contribute no fresh trial. Under conditional uniformity,

`Pr[Y_i in T_i union O_i | pre-answer history] <= (|T_i|+|O_i|)/2^512`.

This deliberately double-counts overlaps, giving a safe sum rather than requiring
an independence assumption between the two sets. It includes windows in the
current query itself. A window first declared after an output is known is not
retroactively charged at that output; if used to claim a previously unavailable
producer, it still needs a fresh current/later prefix hit. The collision term
covers a fresh input sharing an earlier output. The first availability hit and
all fresh-input collisions are therefore included in this union event.

For any adaptive stopping time, define the nonnegative exposure sums
`S_T = sum_i |T_i|` and `S_O = sum_i |O_i|` over fresh queries actually reached.
Apply the conditional union bound to each finite truncation with its predictable
reach indicator, then use monotone convergence. With independently justified
finite expectation bounds A >= E[S_T] and B >= E[S_O],

`Pr[prefix availability hit or output collision] <= min(1,(A+B)/2^512)`.

No deterministic maximum query count is needed. If the expectations are
infinite, this argument supplies only the trivial bound one. Observed values
from a completed run are not expectation bounds. A stopping process that queries
until its first hit of one fixed target has E[S_T]=2^512 and success probability
one, illustrating why unrestricted attempts cannot be assigned a fixed small
failure probability without resource accounting.

`classical_xof_history::Exposure` records realized fresh-answer, target-pair and
prior-output-pair sums. Target registration precedes the increment, and neither
the current answer nor later inputs determine that increment. External input
declarations add targets without creating fresh answers. Repeats and inconsistent
repeat attempts do not add exposure. Diagnostic counters use checked host-sized
arithmetic; they impose no production protocol or adversary query cap.

`xof_expected_exposure_bound` performs the conditional exact-rational arithmetic
from mandatory supplied expectation bounds. Its configurable output width is
for finite exhaustive controls; protocol prefix width remains 512. Its tests
check adaptive target choices/stopping, exact fractions, missing/invalid bounds,
and geometric stopping with unbounded support. The history controls also check
self-input windows, deduplicated targets, post-answer declarations, collisions,
repeats and answer-independent exposure. These controls do not establish that
all protocol inputs have been registered, fresh outputs have the stipulated
ideal distribution, or the expectations are bounded by charged attacker work.
They do not cover arbitrary overlapping reader-output windows, Merkle hash
exceptions, the complete accepting-path coupling, or knowledge extraction.

### Shared-string window construction and conditional work accounting

Counting the full input length at every query would overcharge reuse of a
previously built prefix or a cloned hash state. An alternative explicit cost
model charges string construction: one unit per literal byte, one per
concatenation, one per slice, and one per oracle submission. Immutable strings
may be shared freely. A clone of an existing prefix refers to the same string;
appending a suffix is a concatenation. This permits reuse without charging the
logical prefix length again, even if repeated shared concatenations make that
length exponential in construction work. Model handles are trusted accounting
objects, not certificates accepted from an adversary.

For w-byte windows, a literal of length n introduces at most max(0,n-w+1)
window values. Concatenating lengths a,b introduces at most

`max(0,a+b-w+1)-max(0,a-w+1)-max(0,b-w+1) <= w-1`

new window values: all other windows already occur in an operand. A slice
introduces none. Induction over the shared construction graph bounds all
window values ever exposed by `max(1,w-1)*C`, where C is the charged
construction work. Submitting or reusing the same constructed string adds no
new values. Previously constructed but not yet submitted windows may be counted
early as an overestimate. The argument requires each relevant oracle input to
be represented by this construction history; uncharged external strings need
an explicit offset. This is a specified primitive model, not yet a reduction
from arbitrary attacker code or actual SHA/Keccak instruction counts.

For w=64, suppose the complete experiment at charged budget T satisfies the
separately justified affine bounds `Q <= a*T+h` for fresh XOF prefix answers
and `C <= b*T` for string construction. Let w0 bound additional window values
from explicit honest/setup/verifier offsets. The exposure sums obey
`S_T <= Q*(63*b*T+w0)` and `S_O <= Q*(Q-1)/2 <= Q^2/2` pathwise. Hence the
conditional prefix exception bound is at most the minimum of one and

`((a*T+h)*(63*b*T+w0) + (a*T+h)^2/2)/2^512`.

Its constant, linear and quadratic coefficients can be passed to the existing
all-trials work optimizer. This parameterizes every charged budget T rather
than fixing an adversarial query cutoff. Deterministic budget bounds avoid
incorrectly replacing E[T^2] by E[T]^2 for random stopping. A variable-work
experiment instead needs justified moment/exposure bounds. Costs for all
verifier submissions, rejected paths, factory/setup activity and oracle reader
work remain explicit obligations; they cannot be filled from one honest trace.

`classical_window_work.WindowWork` implements length-only construction
accounting and `shared_window_xof_polynomial` supplies the exact-rational
substitution. Output bit width must equal eight times window byte width.
Exhaustive small binary strings check all concatenation boundaries against
actual window sets. Other controls check prefix forks, slicing, exponential
logical length, foreign handles, missing/invalid caps, polynomial substitution
and use with the work optimizer. This model does not establish the complete
protocol's cost mapping, phase coverage, Merkle exception bound or knowledge
argument, and does not qualify a native profile or benchmark.

### V5 first-primary row/column path coupling

`primary_atomic_path_transition` joins the existing pre-row and pre-column
interfaces for a single trusted first-primary task. The caller supplies actual
row and atomic-column stream outputs from the same complete experiment and
trusted constructor. The check requires exact row request, canonical consumed
row bytes, coefficient agreement with the column's proposed receipt, and exact
agreement of the two completed source-column arrays. It recomputes the row
transition and compares every row-state field with the pre-column state. This
prevents matching coarse near/bad flags from concealing a different completed
word. The exact row request binds the common trusted opening task and geometry.

Before classifying the sampled path, the check also verifies that a bad row
state with a valid final value equation has at least the stated minimum number
of rejecting columns. Atomic output binding/length and ordered indices use the
existing transition. For the resulting conditional path record define

`row_escape = false_relation and not bad_after_rows`,

`column_miss = bad_after_rows and not bad_after_sampling`.

The events are disjoint. If the task is false and its supplied scalar equations
pass (`not bad_after_sampling`), one of them occurs. This is the deterministic
path implication used by the conditional first-component probability bound;
it does not supply a probability estimate by itself. Neither a source mismatch
nor a row-state mismatch yields a classified path record.

The interface does not verify Merkle paths or infer whole-verifier acceptance.
Authenticated columns must separately be coupled to the completed word, and
actual primitive-stream provenance, complete temporal histories, common
experiment/constructor provenance and first-entry ledger coverage remain
premises. In particular, the stream arguments are not proof-supplied evidence.
The function does not establish all-family accepting-path coverage, knowledge
extraction or whole-protocol attacker-work bounds.

### Authenticated v5 first-primary column transport

`primary_atomic_authenticated_columns` sorts and deduplicates the ordered
atomic draws exactly as production transport does, requires the exact distinct
column count, and checks each column shape and path depth. It hashes canonical
encoded column values with the production `HasteBoots/mw-column/v1` prefix and
uses the production Merkle path checker against the selected commitment root
at the sampled index. Empty/truncated paths are rejected before the unchecked
path check is called.

Every authenticated column is also compared with the same indexed column in
the retained fixed word. A valid root path with a different completed column
returns that index as an explicit source mismatch. It is not silently discarded
or assumed to be a hash collision: an earlier incomplete frozen tree can also
make source availability relevant. Discharging such mismatches requires the
separate temporal hash/source argument.

`primary_authenticated_path_transition` composes these transport checks with
the common-word row/column path transition. An empty mismatch list connects the
path's scalar rejection predicate to the authenticated columns at all sampled
indices; repeated draws retain their original sampling multiplicity although
only one authenticated column is transported per index. A nonempty mismatch
list leaves that source-coupling obligation unresolved. The interface still
requires actual sampler-output provenance and the same complete experiment and
trusted constructor. It is not a whole-verifier or knowledge certificate.

The adversarial first-primary fixture changes sumcheck messages while reusing
its earlier opening packet. That packet's paths target a different sampling
request; both field controls reject it at the new transport interface. The
positive control regenerates paths for the actual new ordered draws from the
unchanged complete committed source tree. It checks the reconstructed tree root
against the production commitment, preserving the original source and responses.
The initial failed run is retained as evidence of the stale fixture paths and
is not counted as a passing authentication test.

The fixture supplies a freshly replayed production transcript at the exact
pre-opening boundary. The final cross-check passes the regenerated packet to
the unchanged production Brakedown verifier, with the same responses, query,
claim and commitment. Its failure status must agree with the coupled scalar
predicate; any error must be a linear-response or final-value rejection, not
authentication failure. This distinguishes a validly authenticated false-task
control from the intentionally stale original packet. It remains a synthetic
first-primary control rather than native/full-adaptive admission evidence.

### Authenticated paths at the root's first-declaration boundary

`classical_history::History::frozen_path_status` validates a supplied concrete
SHA512 path, including the exact encoded leaf input, root, index range and path
orientation. It reconstructs the parent preimages and walks them from root to
leaf at the root's original first-declaration boundary. Its result separates:

- all path preimages known strictly before that boundary;
- the first missing preimage, with digest, expected input, declaration event,
  optional first-answer event and immutable root boundary;
- a known different preimage of the same digest, as a collision witness;
- a preimage excluded by the caller's hash-input length filter;
- a required child digest absent from the registered declaration history.

Malformed paths and undeclared roots do not produce a classified path. The
routine does not declare or answer any oracle query. Later answers annotate the
same original missing witness; they do not change it into an earlier-known path.

For a complete eligible history, the first missing digest has already been
declared by the boundary. If it is the root, this is the boundary's definition.
Otherwise its parent was known before the boundary and that parent's input
contains the child digest as a 64-byte window; registration preceded the parent
answer. A first answer at or after the boundary therefore hits a previously
registered target, including the same-event pre-answer convention. If a known
preimage differs from the supplied authenticated one, the two inputs witness a
same-output collision instead. Length-filter failures and absent registrations
are explicit unresolved premises, not assigned zero error.

When every preimage is earlier-known, a canonical Brakedown leaf input is the
same one used by frozen column completion, so its decoded column agrees with
that completion. Thus an authenticated canonical column that differs from its
frozen column must encounter one of the explicit missing/collision/filter/
registration cases. This argument requires the same root, geometry, canonical
leaf convention and complete event history; the path routine alone does not
establish those caller invariants or a probability/work bound for the events.

The authenticated v5 path result now carries `AuthenticatedSourceMismatch`
records with the sampled index and optional frozen-path status, rather than
only index numbers. A missing status stays unresolved; a `Known` status beside
a differing column would signal an inconsistent captured word, geometry or
history and cannot be classified as an availability event. Callers must keep
those cases in coverage failures until their common-history invariants are
established.

Both field controls construct row and column states from the same genuinely
incomplete history after declaring the full column request, instead of editing
state flags to mimic a different source. Their valid authenticated columns differ
from its zero completion and return missing-root witnesses. Revealing the root
preimage produces an availability hit; recomputing the path result preserves
the mismatch and original missing boundary while adding the late-answer event.
Complete-source controls return no mismatch and earlier-known path statuses.

### Hash exposure sums and the joint ideal-oracle exception term

The source hash history now records `HashExposure`: the number of hash requests,
the sum of registered target-set sizes before answers, and the sum of distinct
prior hash-output counts before answers. Eligible current-input windows are
registered first. Hash outputs from ineligible inputs still enter the prior
output set, since a length filter must not discard their collision contribution.
External/XOF input declarations add targets without adding hash answers.

Unlike the XOF fresh-input ledger, this diagnostic conservatively charges hash
repeats as well. A repeated input cannot create a first-answer availability event
or a distinct-input collision, so its conditional bad-event probability is zero;
adding its nonnegative exposure only loosens the bound. This avoids retaining a
second complete input index merely to avoid recharging repeats. The counters do
not inspect the current output to decide an increment. A later target declaration
does not retroactively increase an earlier increment. Their checked arithmetic
is diagnostic bookkeeping, not a production or adversary query cutoff.

For the same complete classical experiment, supply upper bounds A_H, B_H on the
expected hash target/output exposure sums and A_X, B_X on their XOF counterparts.
Conditional uniformity of each fresh hash output and XOF prefix given the full
joint history, consistency at repeats, and complete relevant target registration
give the union bound

`Pr[first-answer registered-window hit or within-oracle output collision]`
`<= min(1,(A_H+B_H+A_X+B_X)/2^512)`.

The separate conditional bounds and monotone-convergence argument apply without
independence between the bad events or a maximum query count. Both oracle
families and all four expectation bounds are mandatory in
`ideal_oracle_expected_exposure_bound`. It returns exact separate contributions
and their capped sum; observed history counters are not substituted for the
required expectations. Unregistered cross-oracle coincidences, unclassified
accepting paths, invalid source/stream provenance, all-family coverage failures
and knowledge/work obligations are not silently included in this term.

Controls check equal-window deduplication, current-input registration, repeats,
post-answer declarations, filtered inputs' output contribution, exact separate
scaling, missing/invalid expectation bounds, and exhaustive interleaved adaptive
oracle choices with stopping on a small output support. This supplies a joint
conditional accounting component, not an established protocol bound or a claim
about concrete SHA512/SHAKE instruction costs.

### Joint shared-window work coefficients for hash and XOF queries

`joint_shared_window_oracle_polynomial` now connects the shared string
construction model to both oracle exposure families. All hash/XOF query rates
and offsets, the common construction rate, and the common window offset are
mandatory. Let `Q_H <= a_H*T+h_H`, `Q_X <= a_X*T+h_X`, and let constructed
64-byte target values satisfy `W <= 63*b*T+w0` in the same whole experiment.
The pathwise exposure relaxation gives the joint oracle polynomial

`((Q_H+Q_X)*W + (Q_H^2+Q_X^2)/2)/2^512`.

Both oracle types see the same constructed window set. Construction is charged
once; targets can be tested against answers from either family. Collision
exposures remain separate within each oracle. Replacing their sum of squares
by `(Q_H+Q_X)^2` would additionally charge cross-oracle coincidences, a
conservative but unnecessary term for the stated event. Cross-oracle events
needed by a different reduction must be supplied explicitly rather than assumed
to be covered by this narrower within-oracle polynomial.

The helper emits exact constant/linear/quadratic components named `merkle` and
`xof` for compatibility with the existing optimizer. The `merkle` key includes
all ideal fixed-output hash requests admitted by the supplied cap, including
context and binding hashes; its name does not restrict the cap to tree nodes.
The oracle components cannot be passed alone as a complete proof bound:
`composed_report` still requires an explicit phase component covering all other
relevant failures. The helper records that it supplies no phase component and
establishes no input caps, attacker-work reduction or whole-proof security.

`WindowWork.submit` now separately inventories hash and XOF submissions while
retaining one common construction ledger. Prefix references can be submitted
to either oracle without recreating the string. New tests check exact affine
substitution, the omitted cross-oracle collision term, separate submissions
using a concrete shared-prefix trace, mandatory exact inputs, and explicit
phase composition. The caller must still prove caps across all attack trials,
verifier submissions, setup/factory work and rejected paths, with no uncharged
resource accumulation between trials. These conditional coefficients do not
promote a native profile or satisfy the security-matched benchmark gate.

### Stopped typed-verifier construction caps for the joint work model

`native_stopped_joint_window_work` now derives conservative construction inputs
from the existing candidate's stopped typed-verifier envelopes, without loading
or certifying Rust parameters. Write V_H,V_X for per-verifier hash/XOF query
ceilings and L_H,L_X for their maximum input lengths. Representing every submitted
input as a separate literal costs at most

`V_C = V_H*L_H + V_X*L_X`

construction units in the specified ideal string model. Prefix sharing can
reduce this representation cost; the bound does not assume that every prefix
must actually be reconstructed. It is an upper bound for a possible verifier
representation, not a lower bound on concrete attacker CPU work.

If a verifier submission costs at least one charged unit, at budget T there are
at most T submissions. Separately bounding adversarial hash queries, XOF queries
and construction by T gives the affine substitutions

`Q_H <= (1+V_H)*T+h_H`, `Q_X <= (1+V_X)*T+h_X`,

`C <= (1+V_C)*T`, `W <= 63*(1+V_C)*T+w0`.

The honest hash/XOF output offsets h_H,h_X and initial window offset w0 are
mandatory caller inputs. They must include the full setup/factory and other
uncharged initial activity of the same experiment. The wrapper passes these
substitutions to the joint shared-window polynomial and preserves its separate
hash/XOF components. No maximum adversary query count is selected.

The inherited ceilings are for the stopped analysis game, including early
rejection under the stated typed-shape premises. The report retains the first
lookup retry condition, canonical-field candidate ceiling and schedule-four
Brakedown column-candidate ceiling where applicable. It carries the additional
sampler-stop union as a per-verifier-invocation quantity, not an all-trials
probability. With at most T submissions, that contribution must be charged at
most T times in the separate phase component; lookup stopping already included
in parent terms must not be omitted or silently treated as production behavior.
Production sampler loops are unchanged and uncapped.

Tests cover twenty typed descriptor cases: both native field/width geometries,
schedules four/five and all five backends. They compare the exact affine
substitution, preserve schedule-specific stops, require all offsets, reject
inexact inputs, and check offset monotonicity. These are arithmetic controls on
existing conditional envelopes. Complete adversarial-prefix cap justification,
physical/primitive cost mapping, all-phase/knowledge composition and native
performance qualification remain unresolved; admission flags remain false.

### Explicit remaining-failure composition and verifier sampler stops

`native_stopped_joint_work_report` composes the native stopped joint oracle
components with a mandatory `other_failure_polynomial`, then invokes the existing
integer-work optimizer. The supplied constant/linear/quadratic coefficients must
cover every remaining non-oracle event across the complete experiment: algebraic
and opening transitions, adversarial sampler stops, lookup stopping, source/stream
inconsistency and all unclassified accepting paths. They exclude only the
additional verifier field/column sampler contribution added by this entrypoint.
No omitted polynomial is defaulted to zero.

Let beta be the candidate's additional sampler-stop union per stopped verifier.
Under a proved split between fresh sampler phases first exposed by the verifier
and phases already exposed to the adversary, fresh verifier stop events contribute
at most beta times the number of charged submissions, hence at most beta*T.
The implementation adds beta to the phase polynomial's linear coefficient before
combining all three components and minimizing work. There is no fixed submission
count or adversarial query ceiling and no independence assumption between stop
events.

The fresh/prequeried distinction is required. An adversary can choose a submission
using a previously inspected rare stream; its stop probability conditional on
that history need not equal the fresh-stream probability. Such events must be
charged when exposed in the supplied other-failure bound, rather than justified
by beta per selected submission. The report explicitly records that this split
and the supplied bound are not established. Canonical whole-stream completion,
first-query task binding, output-reader exposure and work accounting remain
premises of any complete use of this composition.

Controls use a deliberately large synthetic beta to verify that repeated
submission charges change the optimizer input and resulting work bound. They
also check that unknown remaining coverage supplied as constant one yields only
the trivial bound, that the remaining polynomial is mandatory/exact, and that
negative or greater-than-one stop probabilities reject. The first control run
failed inside the generic probability encoder while trying to manufacture a
negative test value; the corrected control supplies the invalid exact-rational
record directly to exercise this entrypoint's validation. That initial log is
preserved and is not passing evidence. These conditional composition checks do
not establish full soundness, knowledge extraction or native admission.

### Exclusive sampler boundaries and exact-input exposure classification

The XOF history now provides a separate `Checkpoint` type for the instant before
a verifier phase. Its event boundary is exclusive: a query first made at the
checkpoint's next event was fresh at that boundary. This differs from the
existing original-query `View` used by inclusive first-entry ledger iteration;
the types cannot be interchanged accidentally.

`query_exposure_at(checkpoint,input)` reads only input/original-view metadata.
It returns `Fresh` if the exact input had no query strictly before the saved
boundary, or `PreviouslyQueried` with its unchanged original view otherwise.
Later queries, repeated queries, additional target declarations and different
answers at other inputs do not alter the saved classification. A checkpoint
from another history returns no classification. Target registration and an
available receipt producer do not by themselves query the sampler input.

For a trusted actual sampler phase with complete query history, this gives the
deterministic fresh/prequeried partition needed by the verifier-stop argument.
Fresh phases may use the appropriate conditional whole-stream sampling bound
once their request/task is fixed before the new answer. Prequeried phases map
to their earlier original input view; repeated verifier submissions do not
create new fresh opportunities for that same stream. The corresponding stop
event must be charged through its first exposure, or retained as an unclassified
coverage event if that first entry cannot be interpreted.

The partition is metadata, not an entropy or cost certificate. Any prior query
of the input's prefix is conservatively treated as exposure even if later
sampling consumes more bytes. Uniform whole-stream completion, actual reader
provenance, first-entry stage/actor interpretation, adaptive task/source binding
and reader work charges remain separate premises. The work report's
`fresh_vs_prequeried_sampler_split_established` flag remains false until those
premises and all relevant sampler families have been justified.

Controls check exact-boundary queries, declarations without answers, original
view recovery, later queries/repeats, unrelated later inputs and foreign
checkpoints. The real v5 first-primary fixture additionally records boundaries
for column and row requests, including a row sampler first queried after its
receipt was already proposed in the column request. Its earlier column boundary
stays fresh while a later replay boundary points to the original column query.

### Immutable first-query actor attribution

The XOF history now records `QueryActor` at an input's first query: unknown,
adversary, verifier or setup. `query_with_actor` takes trusted recorder
attribution. The existing `query` entrypoint records unknown, preserving earlier
callers without guessing their origin. An input's actor is fixed alongside its
original view; later repeats by another actor, including better-informed callers,
do not relabel it. Rejected inconsistent repeats also leave it unchanged.

`first_query_actor` accepts only the exact original input/view from the same
history and returns its recorded actor without reading output bytes. Combined
with the exclusive pre-phase checkpoint classification, a prequeried verifier
stream can now retain evidence that its first exposure was adversarial, an
earlier verifier event or setup. Unknown stays an explicit unresolved case.
This is attribution supplied by the event recorder, not authentication of the
recorder or a deduction from transcript syntax.

The v5 first-primary control labels the initial proposed column query as
adversarial, then replays it with a verifier label and checks that its first
actor remains adversarial. It labels the later fresh row query as verifier
origin, while earlier unlabeled receipt producers remain unknown. General
metadata controls also cover setup/verifier first queries, attempts to upgrade
unknown attribution, wrong views/inputs, foreign histories and inconsistent
answers.

A complete sampler-stop reduction still needs a faithful event recorder covering
all actual exposures, whole-stream/reader completion, first-entry task admission,
conditional bad-transition bounds and charges or honest offsets for each actor.
An unknown actor cannot silently receive an adversarial work charge or a fresh
verifier phase bound. The new metadata does not establish those premises or
change the work report's false certification/admission flags.

### Actor-resolved first-primary opportunity counts

The first-primary ledger now partitions all distinct inputs, false-row entries
and bad-family entries by immutable first-query actor. Unknown remains a separate
count. A v4 rejection-run family is attributed at its earliest syntactic member's
original view, not at a later root request or replay. V5 singleton families use
the atomic request's original actor. Replaying an adversarial query from a verifier
therefore adds neither a distinct query nor a verifier-origin first opportunity.

The actor subtotals sum to each existing ledger total. Within an actor, false-row
entries and admitted bad-family entries inject into disjoint distinct inputs.
An admitted row ends in the trusted field request, whereas an admitted family
entry ends in a column byte request; full framing keeps these cases disjoint.
Canonical maximal run roots make the v4 family mapping unique, while v5 families
are already singleton distinct requests. Thus for each actor a,

`N_false_rows(a) + N_bad_families(a) <= Q_distinct_inputs(a)`.

This concerns admitted false/bad opportunities, not all syntactic suffix matches
or unresolved entries. Debug assertions check the subtotal and injection bounds
for every computed ledger. Nonnegative expectation and local-error weighting can
use this pathwise count inequality once complete event provenance, predictable
states and the conditional transition bounds have been proved. It does not turn
one observed actor count into an adversarial budget or an expected count bound.

The v5 controls separately retain one verifier-origin false row and one
adversary-origin bad atomic family, while receipt producers recorded without
attribution remain unknown. An actor's identity alone does not prove the
corresponding charged-work rate or honest offset. Unclassified accepting entries
and missing actor provenance must still be covered explicitly in the full
reduction; no admission flag is promoted by the actor partition.

### Syntactic field-request superclass and first-query stop charge

`field_stop_request` recognizes a conservative superclass of typed field sampler
inputs for a fixed trusted profile and modulus. It checks the complete frame
boundaries, one of the prime/extension/child application headers, the exact
profile ID, and a final kind-four descriptor containing the base modulus and
flat u64 coefficient count. A supplied trusted coefficient ceiling separates
oversized requests. It does not interpret opaque prover-message bodies, validate
an extension basis, recover receipt producers or admit an application stage.
Those checks are unnecessary for the purely raw canonical-rejection event.

This superclass may include syntactically valid requests with no valid primary
or other verifier task. Counting those extra queries is conservative. Coverage
still requires every actual bounded verifier field request to be included:
trusted frame construction fixes the descriptor before reading its stream,
extension sampling uses its total base-coefficient count, and the chosen
ceiling must cover every relevant trusted call. Malformed/foreign/oversized
requests are not thereby granted semantic admission or silently certified safe.

`field_stop_ledger` counts each recorded distinct input once at its original view,
partitions eligible requests by first actor, sums the requested coefficient
counts, and keeps above-ceiling inputs separate from other noneligible inputs.
It reads no current output. A verifier replay does not recharge an adversary's
syntactic request. Zero-count requests are eligible but have coefficient weight
zero. No coefficient vector is allocated from an untrusted descriptor count.

Let r=(2^k-p)/2^k for k=ceil(log2 p), and fix a positive analysis rejection
threshold R. For an eligible first input with m requested coefficients,
virtually complete its independent ideal output stream using the canonical
sampler. The event that one of its first m accepted values requires more than
R candidate attempts has probability at most m*r^R: each coefficient would
need its first R candidates all rejected. This event is defined on the same
latent stream even when only a prefix was actually read; later uses cannot
create a new stream or change the count in the original descriptor.

For arbitrary adaptive querying/stopping, if A_a bounds the expectation of the
sum of those coefficient counts at distinct eligible inputs first attributed
to actor a, the conditional union bound and monotone convergence give

`Pr[an eligible field stream exceeds the analysis stop] <= min(1,r^R*sum_a A_a)`.

No adversarial query cutoff is needed. `field_stop_first_query_bound` performs
this exact arithmetic with mandatory expectations for adversary, verifier, setup
and unknown actors. Observed ledger sums are not substituted for those bounds.
The proof needs independent ideal whole-stream completion at each first input,
faithful complete query recording and inclusion of every actual bounded request;
it does not prove a physical reader-work mapping or any soundness/knowledge
statement for the enclosing stage. Production rejection loops remain uncapped.

Both native-field first-primary controls check their actual row request, a byte
request, zero/oversized counts, wrong modulus/profile and malformed framing.
They deliberately count an adversarial syntactic request with no valid primary
body, retain its original actor after verifier replay, and check the exact total
coefficient weight. Independent arithmetic controls exhaust a small masked
sampler, retain unknown-actor weight, and show that unbounded geometric grinding
until a stop gives the trivial success bound one.

### Fixed maximum budgets versus expected stopping work

The integer optimizer's quantity is now explicitly labeled
`work_measure = fixed_maximum_budget`. It minimizes the maximum budget T divided
by the capped success bound at that budget. Existing numeric values and the
legacy `minimum_work_per_success_bound` key are preserved; the clearer
`minimum_budget_per_success_bound` alias is also emitted. Candidate/native
reports inherit the fixed-budget interpretation and explicitly do not certify
unrestricted expected work.

This distinction matters even for ordinary early stopping. For independent
uniform draws from a set of size 16, the collision union bound `T^2/32` gives a
minimum fixed-budget ratio of 6. Stopping at the first collision takes about
5.704 queries on average and eventually succeeds with probability one. The
fixed-budget result therefore cannot be reused as an expected-runtime lower
bound. This is a distinction between resource measures, not a change to the
existing conditional integer-budget optimization.

`expected_work_bound` adds a separate conservative calculation. Suppose F(t)
is a uniform bound on success by charged work t for every truncation of the
same complete experiment, every successful run costs at least m, and actual
success probability q is at least a supplied p>0. For t>=m,

`Pr[W>t] >= Pr[success]-Pr[success and W<=t] >= q-F(t)`.

For t<m, the successful-run minimum cost gives `Pr[W>t]>=q`. Summing the
nonnegative tails yields `E[W]>=L(p)`, where

`L(p) = m*p + sum_{t=m}^infinity max(0,p-F(t))`.

Moreover `E[W]/q >= L(p)/p`, since each term `max(0,1-F(t)/p)` is nondecreasing
in p. The success floor and minimum-cost premises are mandatory; the calculation
does not infer a success probability or a uniform expected-work-per-success
claim when p is unspecified. A zero nonconstant polynomial with a constant cap
below p is rejected as inconsistent with eventual finite-work success of at
least p.

For the nonnegative polynomial envelope used here, the sum stops at the first
integer budget where F reaches p. The implementation finds that budget by
integer doubling/bisection and evaluates exact power sums via telescoping
identities. It does not enumerate a security-sized range of budgets. Tests
compare these sums with direct small-budget enumeration, check the birthday
counterexample, and evaluate a quadratic threshold at 2^128 exactly. The valid
expected-work lower bound is below the observed early-stopping work in that
control, while the fixed-budget value is above it.

This correction of scope does not establish the supplied whole-protocol success
CDF, success floor, charged-work mapping or native security. Historical frozen
worksheet numbers remain fixed-budget arithmetic evidence and must not be
reinterpreted as expected-runtime certificates. The original full adaptive
soundness/knowledge/work objective and matched native benchmark gate remain open.

### Native global first-query field-stop work charge

`native_first_query_field_stop_polynomial` now connects the syntactic first-input
field-stop argument to the native stopped-verifier work envelopes. If C is the
trusted flat coefficient ceiling, r the base-field rejection probability, and R
the analysis threshold, write `mu=min(1,C*r^R)`. Each eligible distinct input has
stop probability at most mu before its first answer. Its actor does not change
that statistical charge: adversarial prequeries, setup and earlier verifier
queries are included at their first input, rather than resampled when reused.

If total XOF requests in the same capped-work experiment obey
`Q_X <= (1+V_X)*T+h_X`, the eligible distinct input count is no greater, giving

`Pr[field analysis stop] <= min(1,mu*((1+V_X)*T+h_X))`.

This supplies an exact constant/linear polynomial. It deliberately overcounts
receipt producers, byte requests and repeated invocations through the total
query cap. Complete syntactic coverage, the flat count ceiling, ideal latent
whole-stream consistency and the global work/query mapping remain premises.
No maximum adversary query count is selected and no production loop is capped.

`native_first_query_field_work_report` adds this field-stop polynomial exactly
once to a mandatory remaining-failure polynomial, unions the joint hash/XOF
components, and reports fixed-budget and expected-work quantities separately.
The expected calculation requires an explicit positive success-probability
floor. The remaining polynomial must cover every other failure, including all
v4 column rejection, lookup retries, application/opening transitions and
source/stream/unclassified-path coverage. The old per-selected-submission
field-stop union is not additionally charged by this entrypoint. It does not
claim to solve the remaining first-entry or knowledge reduction.

Controls exercise all twenty typed descriptor combinations and the complete
report for both native fields. A synthetic supplied phase coefficient gives a
passing conditional fixed-budget target but a failing conditional expected-work
target, verifying that the reports cannot be interchanged. The coefficient is a
resource-measure control, not a proved native phase bound. Constant-one unknown
coverage gives trivial results in both measures and every security admission
flag remains false.

Native rejection fractions can have decimal numerators/denominators beyond
Python's default 4300-digit conversion limit. The first integration run exposed
that formatting failure. `exact_rational_text` and `exact_rational` now format
and parse exact integer/fraction text in small decimal chunks, preserving ordinary
strings and leaving the process-wide digit limit unchanged. Composition and
expected-work reporting use these helpers. Tests cover native-sized and
5000-digit values, round trips, unchanged global limits and full native report
serialization; the failed initial log is preserved. No rounding or float-based
security comparison is introduced.

### Pure v4 byte-family identity and first-family stop charge

The canonical byte-root scan is now separate from proposed sampler replay.
`canonical_column_root_request` identifies the maximal trailing alternating
8-byte request/response run from frame boundaries alone. The existing semantic
`canonical_column_run_proposal` still applies the original accepted-draw quota
and proposed-byte checks afterward. No source or stage admission rule is relaxed.

For pure stop accounting, `column_stop_family_root` checks the selected schedule-
four Brakedown profile/application header and uses that unconditional syntactic
root. It includes every framed descendant, even one proposing more accepted
values than an actual verifier call could consume. Such an early off-path query
must not be forgotten when deciding whether the whole family was previously
exposed. `column_stop_ledger` counts distinct members and roots, attributing a
root to its earliest queried member. A later verifier root query or replay does
not replace that actor. This is a syntactic superclass, not opening admission.

For a fixed root, all strings obtained by appending matching response/request
frames form a tree. Canonical maximal roots partition these strings into disjoint
families, and each actual next request strictly increases input length. Under the
ideal independent-input model, before the first query to any member the entire
family's output tree is fresh given the outside-family history. The root's
canonical rejection sampler therefore has the same latent geometric waiting
law even if the first queried node is a descendant that the eventual root walk
never reaches. Future selection based on that first output does not create a
new first-family trial.

For a fixed domain N, quota Q of ordered accepted draws, and analysis rejection
threshold R, use the exact production cutoff
`cutoff=(2^64-1)-((2^64-1) mod N)`, not 2^64. With
`r=(2^64-cutoff)/2^64`, the whole-family stop event has probability at most
`min(1,Q*r^R)` before first exposure. Duplicate indices still consume accepted
draws; later path-transport deduplication does not change this quota.
`column_stop_first_family_bound` multiplies that local bound by mandatory actor-
resolved expected first-family counts and caps the sum at one. No fixed adversary
query ceiling or production retry limit is introduced.

For native power-of-two domains, rejection regions are nested as domains grow:
the rejected top interval has length N. A maximum-domain, maximum-quota sampler
uses the same raw request/response walk and cannot finish before a smaller-domain,
smaller-quota call. Every R-rejection gap in the latter is also a rejection gap
in the former before its quota. This gives a conservative geometry envelope if
the trusted native domain/quota maxima and call-boundary separation are justified.
The envelope is not assumed valid for arbitrary unreviewed geometries.

Both field v4 controls query a descendant beyond the semantic quota first, then
its root and a verifier replay, retaining one adversary-origin family. A second
root is attributed to setup. The small-oracle control shows why selected-root
charging is invalid: a family selected after a favorable descendant answer has
conditional stop probability 3/8 although its unconditional first-family bound
is 1/4. Charging the expected two first-family trials covers that selection.
Other controls exhaust stream stop probabilities, nested geometry domination,
unknown-actor contributions and unbounded grinding. Complete native family
coverage, latent-tree consistency, expected-count/work caps and automatic native
column-stop composition remain separate obligations; admission stays false.

### Native joint first-opportunity sampler-stop composition

`native_first_query_sampler_stop_polynomial` now combines canonical field stops
and schedule-four Brakedown column rejection in one conditional native model.
For v4 Brakedown it reads the reviewed role domains, ordered-draw quotas and
common analysis retry threshold, rejects non-power-of-two or inconsistent shapes,
and selects the maximum domain/quota envelope. Other backends and schedule five
have zero column-rejection contribution: their trusted index samplers use a
power-of-two mask, and v5 Brakedown uses an atomic fixed-size byte block.

Let mu_F be the bounded field-input stop probability and mu_C the bounded whole
column-family stop probability. An eligible field input ends with a kind-four
field descriptor. A column-family member ends with a matching kind-two eight-byte
request. Full framing makes the two classes disjoint, and each canonical family
maps to its distinct earliest member. Consequently

`M_field_inputs + M_first_column_families <= Q_distinct_XOF_inputs`.

Together with the conditional first-query/first-family bounds this yields a
joint stop charge using `mu=max(mu_F,mu_C)`, not their sum:

`Pr[pure sampler stop] <= min(1,mu*((1+V_X)*T+h_X))`.

The bound still requires complete opportunity coverage, a fixed trusted native
profile, ideal latent stream/tree consistency, native role/call-boundary
justification and global query/work caps. The maximum-domain/quota construction
is a domination of the listed native geometries; the report does not thereby
certify that every runtime path obeys that list. No independence between bad
field/family events or adversarial query cutoff is assumed.

`native_first_query_sampler_work_report` unions this term with mandatory supplied
remaining failures and the joint oracle terms. Field-only reporting retains its
existing API and numeric behavior through a shared composition core. The joint
report exposes separate automatic field/column flags and leaves lookup stopping
explicitly outside this automatic term. Application/opening/source/coverage and
lookup failure bounds, knowledge extraction, the success floor for expected work
and native admission still require separate justification.

Controls exercise all twenty typed combinations and complete reports. Every
listed v4 role tail is dominated by the chosen envelope. V5 and non-Brakedown
cases exactly preserve the field-only coefficients. Invalid geometry, unequal
retry thresholds and unreviewed schedule/backend identifiers reject. Fixed-budget
and expected-work calculations retain their separate resource interpretations;
unknown remaining coverage gives trivial results and all certification flags
remain false. These are arithmetic controls, not native runtime benchmarks.

### Conditional hazards and expected work without a success floor

The separate `classical_hazard_work.py` interface requires a predictable
first-bad-event hazard `min(1,a+b*j)` before each charged unit step j, conditional
on the entire prior joint history. This is stronger than a uniform budget CDF.
It allows arbitrary stopping and retries, with one global charged index and no
uncharged initial bad event. Under this premise, a monotone dominating hazard
process gives a lower bound on expected work per success without a supplied
success floor. The potential/tail-sum proof and its computational relaxation
are recorded under “Expected work without a success floor under conditional
hazards” in [implementation-status.md](implementation-status.md). The existing
CDF-only expected-work interface retains its success-floor requirement.

`native_sampler_hazard` uses the local first-opportunity bounds above, rather
than differentiating the aggregate query polynomial. With at most B distinct
first XOF inputs per charged step, disjoint field and first-family opportunities
give conditional sampler hazard `B*max(mu_F,mu_C)`. The family event is assigned
before the earliest member's answer, including off-path descendants; later
root selection cannot create a fresh trial. The report can include this joint
term or a field-only term, and rejects simultaneous use of both. Remaining
lookup, application, opening, source/stream/coverage and knowledge hazards are
mandatory caller premises. All-actor pathwise batching and native coverage
remain unproved, and the report does not certify them or admit parameters.
