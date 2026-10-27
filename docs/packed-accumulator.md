# Packed accumulator arithmetic and continuity

`snarks::packed_accumulator` connects existing roots for seven coefficient tables
in this fixed order (named index constants are exported): input accumulator,
monomial-times-accumulator, external-product input, output accumulator,
Hadamard sum-product, duplicated-a decomposition input, duplicated-b decomposition
input. Each physical table is `a_rows || b_rows`, with consecutive N-coefficient
polynomials per row and zero padding to M power-of-two rows. Packing width k is
a power of two dividing N. The trusted shape fixes N and actual rounds L<=M.

It proves the following against the same canonical roots:

* `external_input = monomial_product - input_acc`;
* `output_acc = input_acc + sum_product`;
* both duplicated decomposition inputs are the corresponding external-input half;
* the first input row equals the expected initial a||b polynomial;
* the actual last output row, L-1, equals the expected final a||b polynomial;
* active accumulator rounds are continuous.

Initial/final polynomials are explicit expected verifier inputs, consumed in
field equations as well as bound to the transcript. The enclosing PBS protocol
must derive the initial polynomial from the public LUT/ciphertext and connect
the final polynomial to extraction/key switching. The separate linked `packed_monomial` component now proves monomial
multiplication and derives public NAND initialization when enabled with
`--with-monomial`; see `packed-monomial.md`. Key binding and a complete PBS
statement remain outstanding. The current native integration is a single PBS chain;
multiple independent chains still require batch endpoint/boundary handling.

## Query maps

All roots, row-code parameter digests, shape and expected endpoints are fixed
before one common packed matrix query Q. The verifier authenticates mapped
queries against original roots; it accepts no committed shifted/duplicated view.
The prover folds their common coefficient prefix once when evaluating claims.

A duplicated-half query replaces the final half matrix pair with `(S,0)` for a
or `(0,S)` for b, where `S=Q_half[0]+Q_half[1]`. A fixed-row query replaces the
row bits with identity/zero selectors and keeps coefficient and half matrices.
The expected endpoint values come from the public coefficient vectors.

For continuity let `S[t]=input[(t+1) mod M]`. Use the identity
`S-output = delta[M-1]*initial - delta[L-1]*final` and authenticate the endpoints
separately. For native zero padding this covers every actual adjacent round,
including L<M. When L=M the two corrections share the same last row. The module
does not separately require every padding cell to be zero; enclosing arithmetic
and public-key/monomial rules must constrain any padding they rely on.

To evaluate S without another root, partition source row r=t+1 into carry cases.
For r!=0 let j be its first set bit. Source low bits below j are zero, bit j is
one, while t has j low ones and bit j zero. Keep the ordered matrix
`C_j = Q_j[0] Q_(j-1)[1] ... Q_0[1]` at source bit j's one branch, select source
zero on lower bits, and leave higher bits unchanged. The r=0 wrap case uses the
ordered all-one product on an all-zero source selector. These log2(M)+1 mapped
claims sum to the shift value. Coefficient matrices stay to their right and the
half matrix stays to their left; no matrices commute. M=1 has one identity case.

A public row correction first evaluates each endpoint half at the coefficient
query, applies that row's ordered matrix weight, then mixes the halves. Applying
the row weight after half mixing would be wrong for noncommuting matrices.

At native sizes, all mapped points share the low coefficient prefix. With the
current PCS split each source therefore needs one structured response and one
random test, despite multiple query claims. Queries/claims are bound before
those tests; responses precede shared column sampling.

## Soundness inventory and tests

Every checked residual is a fixed linear function of original tables and public
endpoints. A false residual passes one common matrix query with error at most
`mu*((2k-1)/p)^k`; the budget conservatively unions all seven identities. Add the
PCS response proximity events and seven source random tests. The tool uses a
worst response count when the PCS prefix extends into row bits, rather than
assuming one sampled group's count suffices. This remains an experimental
interactive component budget, excluding whole-PBS and Fiat-Shamir analysis.

Dense noncommuting reference tests compare shift, duplicated-half and boundary
maps to explicit tables over BabyBear and Goldilocks. Round-trip tests include
one round, power-of-two rounds, partial padding, serialization, changed active
round counts, every source/query value, malformed proofs and endpoint changes.
The stronger forgery test constructs genuine PCS openings under the requested
endpoint transcript prefix, then verifies that a wrong endpoint or broken
internal chain is rejected by the equations themselves. Other arithmetic and
duplicated-half identities remain true in the broken-chain case.

```sh
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --with-accumulator
RAYON_NUM_THREADS=16 cargo run --release -p vfhe --example packed_pbs_hadamard -- --full --with-accumulator
python3 tools/packed_budget.py --accumulator-component target/performance/accumulator-linkage/full.log
```

The example reuses the exact decomposition input roots and Hadamard sum-product
coefficient root. Four newly committed tables supply the remaining accumulator
sources. Its endpoint values are taken from the native trace for this component
experiment; public LUT/input derivation and final extraction are still pending.

## Recorded native evidence

The toy and original-size, seed-42, 16-thread release examples verify the linked
component after NTT/Hadamard and canonical decomposition. At original BabyBear
sizes N=1024 and L=728, M=1024, the proof uses 22 query claims and 14 linear
responses/tests across the seven roots. It adds 25,190,926 bytes including four
new roots and both expected endpoint vectors, and takes 0.825 s for preparation,
commits, proving, verification and serialization in one smoke run.

The emitted-dimension conservative interactive component budget totals
1.6742e-42, below 2^-128; it excludes the rest of PBS and Fiat-Shamir compilation.
Logs, budget JSON and the saved executable/source archive are under
`target/performance/accumulator-linkage/`. The SNARK suite passes 32 tests,
including the new map, round-trip and genuine-opening forgery tests; eight
Python tool tests pass. Other crates are unchanged from the preceding full
120-test regression run. These results do not establish complete PBS or the
promotion gate.
