# Masked direct packed matrix adapter

`pcs::matrix_weighted::masked_polyfrim` adapts the experimental masked packed
construction to canonical base-field matrix queries. It retains the caller's
logical base table, one extension-field commitment and one private mask session.
The complete PBS implementation still uses concrete Brakedown parameters/states;
this adapter is the prerequisite for generalizing that backend boundary, not a
completed PBS backend or a security promotion.

Trusted setup specifies logical variables, lane width, physical variables,
blowup, sampling count and lifetime allowance. Extra high Boolean coordinates
repeat the original logical table. Opening appends (I,0) matrices for those dummy
coordinates, preserving the original ordered response. Physical capacity and
available base-field NTT roots are checked against the core's numerical masking
guard. The adapter embeds the base-domain root into the selected extension.
These choices do not change the logical FHE table geometry.

The complete canonical-source context includes backend namespace, both logical
and physical geometries, masking parameters, base characteristic, extension
degree and the basis multiplication table. Root aliases must match that entire
context. Equal physical roots with different logical dimensions are deliberately
different source contexts. No auxiliary source-view commitment is created.

`open_many` binds the complete ordered queries/claims/root/context and starting
mask index before deriving a child transcript. The child samples directly in the
extension field using the base characteristic and full basis binding. Its final
transcript digest is bound back into the base-field parent. Verification derives
every query and expected root from its caller; proofs carry only the child
packets and their bounded consecutive indices.

The private session is behind one mutex. The adapter checks all claim shapes,
parameter/root identity, source values and total remaining capacity before
publishing parent transcript data. One lock covers the entire call, so concurrent
calls cannot both spend the same allowance. Poisoned locks fail closed. No
opening recommits or resets exhausted masks. Stateless verification permits
independently verifying previously accepted packets; it does not enforce a
cross-call acceptance history.

These multi-query packets currently contain individual direct openings. They
spend one allowance per query, including repetitions. They do not implement
cross-query aggregation or share a new joint source LDT. Those are remaining
work before the direct backend can satisfy the full aggregation/performance plan.

## Base projection contract

Assume the core commitment fixes an extension-valued polynomial P with the
required shape and supplies its matrix-opening guarantee. Define pi as the first
polynomial-basis coordinate E->F. It is F-linear and fixes embedded base elements.
For every base-field ordered matrix query M,

```
pi(M(P)) = M(pi(P)).
```

Restricting dummy coordinates to zero therefore defines one fixed logical base
table. Requiring the full extension response to equal embed(y) authenticates the
base response y for that projection. The adapter does not assert that every
original committed extension coefficient belongs to F. A test commits two
nonbase values whose extra coordinates cancel under a base matrix query and
checks the accepted response against their actual fixed base projection. This
is the intended contract, not a coefficient-membership certificate.

The polynomial-fixing, proximity, masking and adaptive Fiat–Shamir assumptions
remain the core's open analysis obligations. The adapter neither supplies those
proofs nor makes the enclosing PBS algebra zero knowledge.

## Validation scope

All 74 selected release/locked tests pass: 51 PCS unit tests, four public packed
adapter tests, four masked scalar adapter tests, eight ordinary adapters and
seven encoder checks. BabyBear sextic and Goldilocks cubic schedules serialize,
decode and verify 1/4/16-query packets against one retained root, spending indices
0, 1..4 and 5..20. All 42 child openings verify; logical tables have three
variables/two lanes and physical capacity has thirteen variables. These are
synthetic packed matrix openings, not original-size FHE proofs.

Additional checks cover constant logical tables, false final claims rejected by
atomic preflight, unchanged failed-call counters/transcripts, exhausted budgets,
wrong roots, reordered claims/indices, concurrent spending, poisoned state,
complete-context aliases and the fixed base-projection example. Packet records
explicitly mark native FHE, joint aggregation and whole-security certification
false. No native latency or security-matched size result is claimed.

The six digest-linked packet records, checked opening/index schedules, full logs
and validated sources are archived under
`target/performance/masked-packed-matrix-adapter/`, source SHA-256
`6d7fe12bcb403d0f51d07709b0412faa901a39af945c614f32bacea6cad79bcf`.
