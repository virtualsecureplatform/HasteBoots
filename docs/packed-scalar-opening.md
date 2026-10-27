# Ordered matrix queries through a scalar PCS

`snarks::packed_scalar_opening` is an experimental sumcheck reduction to the
masked scalar PipFRI adapter. It provides a standalone verifier for a batch of
ordered matrix responses, with one original-source opening and no auxiliary
source-view or weight-table commitment. It is not direct packed PolyFRIM, is not
zero knowledge, and is not selected by the complete PBS backend.

## Statement and index convention

The trusted shape has n Boolean cell variables and k=2^a consecutive lanes per
cell. The scalar table has v=n+a variables: a low lane bits followed by n cell
bits, all little endian. Parameters, expected scalar root, every ordered query,
optional terminal matrix and every claimed lane vector are bound before fresh
extension-field projections. Neither query geometry nor sumcheck degree is
selected by the proof.

For a query q, write its two matrices at variable i as M[q,i,0/1], and its optional
terminal matrix as C[q] (identity when absent). The requested output is

```
y[q] = C[q] * sum_b M[q,n-1,b[n-1]] ... M[q,0,b[0]] * V[b].
```

Choose independent uniform rows rho[q] in E^k after fixing the whole statement.
For scalar Boolean index (j,b), define

```
K(j,b) = sum_q rho[q]^T C[q] M[q,n-1,b[n-1]] ... M[q,0,b[0]] e[j]
c      = sum_q rho[q]^T y[q].
```

The desired scalar identity is `sum_s K(s) T(s) = c`, with T the original
flattened source. A degree-two sumcheck reduces it to `tau = T(r) K(r)` at a fresh
point r. One scalar PCS opening authenticates T(r) against the expected root.
A zero-variable scalar source has no sumcheck messages and checks this terminal
identity directly, while still authenticating its scalar value.

The public kernel is evaluated without its Boolean table. For lane point z and
cell point x, let L(z) be the k-entry Boolean equality basis. Then

```
K(z,x) = sum_q rho[q]^T C[q]
         * product_{i=n-1 down to 0} ((1-x[i])*M[q,i,0] + x[i]*M[q,i,1])
         * L(z).
```

Each variable occurs in exactly one factor, so this is the multilinear extension
of the Boolean kernel, even when the matrices do not commute. This justifies
both the verifier's small matrix-product computation and the sumcheck degree.
The reference prover expands row products in descending variable order to build
the weight table. For Q queries it uses O(Q * 2^n * k^2 * [E:B]) base operations
for these matrix products, plus field interpolation/sumcheck/scalar-PCS work.
It materializes field tables and has not been tuned for native packed workloads.

## Why the scalar-fragment shortcut fails

Let A=[[1,1],[0,1]], B=[[1,0],[1,1]], and u=(1,0). Folding the low variable with A
and the high variable with B gives B*A*u=(1,1). Combining the high suffix first
and then folding with A instead gives A*B*u=(2,1). The test
`noncommuting_suffix_cannot_move_through_public_fold` pins this counterexample.
The additional sumcheck preserves the ordered product inside K; it does not
assume suffix matrices commute through a public fragment fold.

## Conditional interactive soundness

This argument assumes the scalar commitment defines one polynomial T over E
fixed before rho, and supplies committed-polynomial evaluation soundness for the
adaptive terminal point. Denote failure of that guarantee by epsilon_PCS. This
is a substantive assumption about the concrete PCS, not a certificate supplied
by this bridge or merely the assertion that two honest openings agree.

Condition on a fixed T. If any claimed response differs from the actual matrix
response over E, their concatenated difference delta is nonzero. Uniform rho has
`rho dot delta = 0` with probability exactly 1/|E|: condition on all coefficients
except one multiplying a nonzero delta entry. When this cancellation does not
occur, the sumcheck starts with a false scalar sum. A false degree-two sumcheck
can reach a valid terminal equation with probability at most 2v/|E|. The terminal
source value is authenticated and K(r) is independently public. A union bound
therefore gives

```
epsilon_bridge <= epsilon_PCS + (1 + 2v)/|E|.
```

There is no extra Q factor: all Q*k output differences use one independent
uniform coefficient each. For B adaptive bridge proofs using a single source,
assuming a fixed polynomial and a B-opening PCS guarantee, the corresponding
union bound is `epsilon_PCS,B + sum_i (1+2v_i)/|E|`. Each proof spends one mask
allowance, regardless of its number of matrix queries. Direct extension sampling
is used in tests. This interactive argument does not quantify Fiat–Shamir,
random-oracle queries, hash security or the concrete scalar PipFRI error.

## Base-coordinate projection contract

An adapter's “base table” tag does not by itself prove its committed extension
coefficients lie in B. For this particular interface, a fixed base projection
suffices for sound base-field responses. Let pi:E->B be the first polynomial-basis
coordinate, so pi embeds B identically and is B-linear. It commutes with every
base-field matrix and finite sum. Thus

```
pi(MW_E(T)) = MW_B(pi(T)).
```

If a claimed base vector y is false for the fixed base table pi(T), then
`MW_E(T)-embed(y)` is nonzero, and the same conditional bound detects it. Accepted
responses therefore authenticate this single fixed base table, without claiming
coefficient membership for the full extension table. Honest base commitments
have zero additional coordinates. A malicious non-base source can also be
accepted when those coordinates cancel, as the explicit committed-source test
shows; its base projection still gives the claimed response. A complete packed
composition must preserve this projection contract for all canonical source
uses, rather than treating arbitrary extension-valued scalar evaluations as
ordinary evaluations of pi(T).

## Exact scalar value and lazy encodings

The bridge uses `MaskedPipFRIPCS::try_open_at` to obtain both the proof and the
exact scalar value bound by its private source session. Recomputing an equal
value through a separate logical-table fold is insufficient for transcript
agreement: Goldilocks permits lazy representatives whose serialized bytes differ.
A boundary test reproduced an honest `scalar source opening` rejection before
this fix. The returned-value API preserves the PCS's actual representation
through proof serialization. Its extension-table counterpart is
`try_open_at_ef`; existing proof-only methods keep the same transcript and budget
semantics. Tests exercise field-equal, byte-distinct evaluations and constants,
zero/one/minus-one and a lazy zero representation, for base and extension tables.

## Hiding limitation and remaining integration

This bridge is not zero knowledge. With one lane, two cells and both matrices
one, the public claim is T(0)+T(1). The first sumcheck message reveals
rho*T(0) and rho*T(1). For nonzero rho these recover both entries, beyond the
claimed sum. `plain_sumcheck_reveals_more_than_the_claimed_sum` demonstrates this
with an accepted masked-PCS proof. The scalar terminal value is another public
observation; masking the PCS oracle alone cannot repair the bridge's algebraic
view. A hiding variant requires a separate construction and analysis.

Tests also cover independent full matrix-product/Boolean-MLE kernel references,
terminal maps, constants, 1/4/16-query batches, serde roundtrips, exact transcript
agreement, one-allowance batching, exhaustion and malformed/changed statements.
Fresh false-witness certificates use genuine sumcheck messages for the false
witness and genuine scalar openings against the original root. Independent
replay accepts all child checks, while the real verifier rejects the final
ordered-matrix terminal equation.

The current roots belong to the scalar PCS; they cannot open an existing
MW-Brakedown root. Full PBS adoption needs a versioned canonical-root integration,
all current key/endpoint/duplicate-view checks, source projection review, concrete
PCS/whole-proof/Fiat–Shamir budgets and matched performance/byte measurements.
The existing complete packed backend remains on MW-Brakedown. The direct packed
PipFRI consistency/proximity/hiding research gate remains open.

## Validation checkpoint

All 81 targeted regression tests pass: 25 PCS unit tests, four masked scalar
adapter tests, six ordinary scalar adapters, seven coordinate encoders, 31
SNARK unit tests (including ten bridge tests) and eight scalar LogUp integration
tests. The locked workspace check passes. Source, lock and test evidence are
archived under `target/performance/packed-scalar-bridge/`. No native bridge
performance result or complete-PBS backend is claimed by this checkpoint.

## Capacity comparison

The reference is now measured against MW-Brakedown on identical synthetic
2^21-scalar tables (18 cell variables, eight lanes), with independent dense
ordered queries and batches of 1/4/16. Both use 64 oracle queries and blowup two;
these are common experimental settings, not matched soundness or hiding. The
bridge uses quintic challenges and its existing masked scalar geometry (fragment
size 2^14, budget four). Two process orders are reversed per field. All 24
capacity-size and 12 toy certificates are serialized, decoded and verified
against retained roots. Fixture and query hashes match across backends, and each
bridge batch spends exactly one allowance.

The bridge is not competitive on latency. Single-query proving is 0.93–0.99 s
versus about 0.007 s over BabyBear, and 1.27–1.36 s versus 0.010–0.011 s over
Goldilocks. At 16 queries it takes 3.89–3.93 / 5.15–5.26 s, versus
0.062–0.064 / 0.084–0.085 s for MW-Brakedown. Commit costs are about
0.308/0.389 s versus 0.035/0.051 s. Bridge proof size stays near 1.05/1.46 MB
while the 16-query Brakedown proof grows to 6.25/11.23 MB. The size advantage does
not compensate for the roughly 62x proving cost in this implementation.

Keep the full PBS integration on MW-Brakedown. This result rejects the current
materialized-kernel/extra-sumcheck implementation as the next latency backend;
it does not establish a lower bound for specialized or direct packed protocols.
The source/binary/command/measurement archive is
`target/performance/packed-scalar-comparison/`. These are capacity-size synthetic
linear openings, not actual native FHE traces or complete PBS measurements.
