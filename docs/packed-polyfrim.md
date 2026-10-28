# Direct ordered-matrix PolyFRIM core

`pcs::packed_polyfrim` starts the direct packed construction, without the scalar
bridge's extra sumcheck. It implements the fold algebra and a separately named authenticated consistency
ladder. It is not an evaluation-binding PCS and is not selected by the complete
PBS backend.

For a packed Boolean table T, convert each lane to multilinear monomial
coefficients by the Boolean Möbius transform. Interleave the resulting lane
vectors as coefficients of a vector-valued univariate polynomial P(X), where bit
i of an exponent represents variable i. Write P(X)=E(X²)+X O(X²).
A Boolean matrix query (M0,M1) on the low variable becomes

```
P_next(Z) = (M0+M1) E(Z) + M1 O(Z).
```

Indeed its coefficient vectors are T0 and T1−T0, so the result is
M0*T0+M1*T1. Apply this step in increasing variable order. Matrix multiplication
order is preserved at every step; no suffix factor is moved through a fold.
There is no scalar projection or intermediate claim about individual lanes.

Given authenticated oracle vectors P(beta), P(-beta), the public consistency
calculation at the next-domain point beta² is

```
E(beta²) = (P(beta)+P(-beta))/2
O(beta²) = (P(beta)-P(-beta))/(2 beta).
```

The helper rejects beta=0, characteristic two and malformed lane/matrix shapes.
It computes the expected next vector; it cannot authenticate supplied symbols.
All coefficient conversions and folds use O(k*2^n) field storage, with dense
matrix folding O(k²*2^n) arithmetic across the ladder. This full-polynomial
construction does not yet have PipFRI's fragment-size commitment advantage.

Appending equally many private high coefficients adds a high variable. An
additional final query (I,0) discards them after all original matrix folds.
The module accepts padding from its caller; it neither generates randomness nor
enforces any mask lifetime or disclosure capacity. This identity is a necessary
algebraic property, not a zero-knowledge argument. Public folds can be singular,
and the rank/disclosure analysis must handle those cases.

The construction direction uses the public-point PolyFRIM ladder and high-variable
padding in local `refs/2025-1354.pdf`, sections 4.1–4.2. Replacing scalar folds by
ordered matrix maps is an adaptation requiring its own analysis. The initial
implementation tests direct matrix-weight expansion, antipodal consistency at
every layer and the padding terminal identity for both fields, dimensions 0–6
and widths 1/2/4/8. A concrete noncommuting example distinguishes reversed order.

Remaining implementation includes private random masking, bounded-reuse
disclosure analysis and complete-PBS statement binding. The same-root projected
rolling-proximity composition below now implements the next checking layer,
while its quantitative vector-proximity argument remains open. Concrete soundness, hiding and Fiat–Shamir
composition must precede security-matched complete-PBS promotion.

Validation: all four new tests pass (56 padded ladders and 896 antipodal
consistency checks), followed by all 31 PCS unit tests in release/locked mode.
Logs and validated sources are archived under
`target/performance/direct-packed-polyfrim-core/`; source SHA-256 is
`3b1885af9d7863631decc18c03dc5e0c349a3e630f926fc50f2e8f1e48921413`.

## Authenticated sampled consistency

`packed_polyfrim::authenticated` commits each vector-polynomial layer on its
squared coset. Each Merkle leaf contains all lanes at one antipodal pair. Leaf
hashes bind the full trusted degree/domain/width/query geometry, layer, index and
ordered values under a dedicated namespace. All layer roots are fixed before
query indices. The transcript also binds the expected original root, the complete
ordered matrix query and terminal lane claim. Sampling uses uniform low bits of
fresh transcript bytes for the trusted power-of-two domain; repeated samples are
retained. The verifier requires exact root, query, lane and path lengths.

The source state owns its polynomial and oracle privately. Honest proving checks
its parameter context and terminal claim before transcript mutation. Proofs carry
only intermediate roots and sampled authenticated pairs; the original root and
claim are verifier inputs. Every sampled transition checks the public matrix fold
against the appropriate next-layer lane vector, with the final step checking the
external claim. The oracle encoder is independently checked against Horner
polynomial evaluation at every domain point in the small fixtures.

This is a consistency component. A malicious initial word can satisfy sampled
local equations without being a sufficiently close low-degree codeword. No
proximity, evaluation-binding, knowledge, hiding or concrete security-bit claim
follows from accepting it. The existing rolling FRI protocol is not implicitly
composed merely because its FFT encoder is reused. The next composition must
bind low-degree checks to these exact packed roots, rather than to independently
committed copies of the purported lane polynomials.

All 35 release PCS unit tests pass. The four new authenticated tests cover 32
serialized/decoded honest ladders over both prime fields, widths 1/2/4/8 and
one through four variables. They check exact post-proof transcript agreement,
all oracle points against Horner evaluation, malformed paths/values/lengths,
false external claims and preflight transcript preservation. Four fresh
false-transition certificates use genuine roots and independently validated
paths under the false statement, then fail specifically at the matrix equation.
Logs and validated sources are in
`target/performance/direct-packed-polyfrim-authenticated/`, source SHA-256
`3db2825616ace2db13e1fe3b697848b5941ca2217141fee5f8e9e393f89160dc`.

## Same-root projected rolling proximity

`authenticated::proximity` composes matrix consistency with rolling FRI. After
all vector-oracle roots are fixed and the consistency transcript is processed,
it draws a lane-weight row for every layer from the caller's transcript. The scalar word for that
layer is the linear combination of its committed lanes. No scalar copy is
committed. A domain-separated identifier binds each packed root, layer, geometry
and projection row; the new rolling-FRI virtual-all mode binds all identifiers
before its folding challenges. Ordinary and virtual-first rolling modes retain
their existing domains and message schedules.

At every original-oracle query the verifier authenticates the entire packed
antipodal leaf against that exact layer root and reconstructs both projected
values. Virtual originals must have empty scalar Merkle paths. Derived scalar
oracles retain ordinary authenticated rolling-FRI roots and fold checks. The
terminal scalar is checked as in the rolling protocol. The combined certificate
contains both consistency and proximity packets plus the packed query paths;
there is no option for the verifier to omit either component.

This removes the independently committed-copy gap. It does not establish a
concrete vector-proximity bound: a reduction from random lane projections to a
common nearby vector polynomial, scalar FRI soundness, matrix-consistency error,
field/challenge distributions (including the caller-selected transcript sampler)
and adaptive Fiat–Shamir composition must still be
quantified and reviewed. In particular, the small-prime fixtures are correctness
tests, not 128-bit profiles. The construction remains non-hiding and is not
selected by complete PBS.

For exact code membership, a simple conditional projection lemma applies. Fix
all packed words before drawing a uniform row lambda in F^k. Interpolate each
lane on its N distinct domain points, giving coefficient polynomials of degree
<N. If some lane has degree >=m, the matrix of coefficients at degrees m,...,N−1
has a nonzero row h. A projected word has degree <m only if h*lambda=0. Fix all
lambda entries except one whose coefficient in h is nonzero: exactly one choice
of that entry satisfies the equation. Thus exact membership can cancel with
probability at most 1/|F|. Taking a union over L fixed layers gives L/|F| for
these exact-membership cancellation events.

This argument assumes genuinely uniform rows conditioned on the fixed words.
It is not a robust proximity lemma: rolling FRI allows distance from the code,
and nearby projected codewords can depend on lambda. Replacing the required
vector-proximity bound by this exact-membership bound would be unjustified.

Validation: all 58 selected release/locked tests pass: 39 PCS unit tests, four
masked adapters, eight ordinary adapters and seven encoder checks. The combined
construction serializes/decodes/verifies 32 honest packets over both fields and
all four widths. Four fresh foreign scalar projections pass independent scalar
FRI checks and actual packed-path checks, then fail at projection equality. Two
fresh over-degree words with genuine roots/paths pass zero-matrix consistency
and all nonterminal scalar recurrences, then fail the rolling terminal equation.
The relaxed terminal prover used to build those two certificates exists only
under `cfg(test)`; production proving and verification retain strict checks.
Logs, checked counts and validated sources are under
`target/performance/direct-packed-polyfrim-proximity/`, source SHA-256
`16503bab78953a3f4e4807b7a42a7d6bffd71b8c87dcbaaaee8930711f3f8eb0`.
