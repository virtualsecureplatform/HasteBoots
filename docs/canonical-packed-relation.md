# Canonical polynomial-relation authentication

`packed_relation::prove_canonical` and `verify_canonical` authenticate each
ZeroCheck terminal through the trusted `CanonicalPcs` implementation. The prover
borrows the original tables retained by each source state. It does not clone the
full witness or commit an intermediate source view.

The canonical transcript binds the relation, every parameter context and the
ordered expected roots before ZeroCheck. Sources may have different physical
padding capacities while sharing the logical dimensions. Masked public terminal
values are normalized on output and checked for canonical encoding on input.
The original typed Brakedown entry points retain their v1 framing and proof
encoding; backend selection is not controlled by proof metadata.

The sumcheck prover now accepts borrowed tables through the existing round
engine. Owned callers retain their API. Frozen pre-change relation code and
owned-versus-borrowed ZeroCheck controls compare serialized messages and final
transcript challenges over BabyBear and Goldilocks.

Masked component tests serialize, decode and verify partial-lane relations using
mixed physical capacities. Negative controls change terminal values, omit an
opening or replace an expected root. Fresh false-relation certificates use valid
ZeroCheck messages for a foreign satisfying relation, followed by genuine
openings of the actual committed factors. Independent replay verifies every
child against its requested root; the production verifier rejects the terminal
identity. Honest proving of the false relation fails before spending an opening.

This changes authentication only. ZeroCheck's public algebra remains non-hiding.
No masked complete-PBS format, robust vector-proximity theorem, adaptive hiding
proof, composed 128-bit security certificate or new native performance claim is
provided. Shared/batched relation authentication and key/setup ownership remain
to be generalized.

Validation passes all 96 selected release/locked tests: 82 SNARK components,
two borrowed-table wire controls and twelve complete v7/v8/v9 PBS tests. All
sixty fresh full binding cases retain their expected outcomes: six accepted
controls and fifty-four rejected attacks. The locked workspace check passes.
Logs and validated sources are archived under
`target/performance/canonical-packed-relation-boundary/`.
