# Canonical-source PBS batch authentication

The opt-in `packed_pbs::batch::canonical` protocol uses outer version 7 and
`merlin-direct-canonical-source-pbs-batch-v1`. It retains all version 6 member
constraints and discharges each member's Hadamard relation in the outer proof.
It preserves the original FHE parameters and output key. This experimental
protocol is non-hiding and has no whole-proof security certification.

`packed_relation::batch::canonical` shares ZeroCheck challenges across independent
equations. Each terminal identity is checked separately. Its PCS wrapper derives
aliases by exact root equality under one trusted, complete parameter context and
one common matrix query. It rejects conflicting alias values by field equality
before sampling any aggregation weights. The caller's full ordered root/value
registry and derived aliases are transcript-bound; neither source identifiers nor
alias decisions are supplied by the proof. Only first occurrences need private
states and joint PCS column authentication. Distinct roots remain separate even
when their claimed values agree.

For B statements and 2d public bootstrapping-key factors, the Hadamard registry
contains B(4d+1) slots but at most B(2d+1)+2d distinct roots. Further identical
roots can reduce this count. This removes redundant authentication; it does not
yet avoid repeated factor folding or share the much larger comparison proofs.
Member root inventories retain all original slots as a conservative bound.

The old relation and complete v6 protocols retain their domains and formats.
Their implementations and the canonical protocols share source bodies in tracked
`protocol.rs.inc` files, with explicit module-local authentication types, domains
and outer versions. A v7 member's version remains 6; it cannot be verified through
a public standalone member API. The outer verifier requires version 7 and always
checks the canonical Hadamard certificate.

Run either `packed_batch_pbs_babybear` or `packed_batch_pbs_goldilocks` with
`--canonical-sources --validation-batches`, optionally adding `--full` for the
original ring-1024/LWE-728 geometry. `--separate` is incompatible with
`--canonical-sources`. The log validator accepts `--mode canonical-sources` and
retains all original per-member interactive error terms. This bound is conditional
and excludes Fiat–Shamir, hash availability, knowledge and hiding.

## Validation

Both field profiles pass decoded public complete verification at sizes 1, 4, and
16, plus mutations of statements, keys, endpoints, proof fields, order and counts.
Four relation integration tests cover both formats and heterogeneous factor
counts. Four relation unit tests cover fresh opposite-equation certificates,
including the canonical path: actual residuals cannot cancel across equations.
Four PCS integration tests cover both paths, including deterministic rejection of
conflicting aliases, distinct roots with equal values, missing columns and wrong
private states. All 86 Python checks pass.

Two opposite-order toy sessions verify 24 packets and 168 member instances.
All twelve current version 6 packets match archived proof bytes/hashes exactly.
All repeated version 7 hashes match too. At sixteen statements, total proof bytes
fall from 97,699,161 to 94,496,509 for BabyBear (3.28%) and from 153,012,391 to
142,674,871 for Goldilocks (6.76%). All fresh statements, native keys, FHE
parameters and four PCS layouts match the archived standalone fixtures. These
are toy size/correctness results, not native latency evidence.

Frozen source and binaries, commands, logs and comparison scripts are under
`target/performance/canonical-pbs/`. Original-size native correctness is running serially under
`target/performance/canonical-pbs-native/`. Native comparative timing,
reconstructed full v7 malicious-child audits and comparative memory remain
separate validation gates. This change does not establish the full-plan promotion
criteria.
