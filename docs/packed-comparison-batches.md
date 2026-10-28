# Complete cross-statement comparison batches

`packed_pbs::batch::shared` is an opt-in version-9 outer certificate. Each member
keeps its independent NTT, reconstruction, endpoint, accumulator, monomial,
extraction and key-switch checks, including the original public output key.
The outer verifier additionally requires one canonical joint Hadamard proof,
ordered blind-rotation comparison packets, and ordered final key-switch packets.
There is no public standalone verifier for partial version-9 members.

Blind-rotation decompositions are ordered by member, then input half. Groups have
at most four decompositions; final key-switch groups have at most four members.
The verifier derives these groups, the comparison requests and every source slot
from trusted configuration and member commitments. It checks exact packet counts.
The outer transcript binds the complete four PCS contexts, trusted setup, ordered
statements, Hadamard roots, coefficient roots and borrow roots before challenges.
Distinct group-role/bound frames prevent packets from being moved between stages.

The prover moves committed coefficient and borrow states into private owners.
It borrows the original state tables for the joint Hadamard proof, then releases
evaluation states. It releases comparison states as each group completes. No
witness-state cloning or recommitment is needed. Unlike the streamed standalone
decomposition component, this initial complete composition retains all member
comparison states until after the joint Hadamard proof. Native peak memory still
needs measurement and may require a more tightly streamed schedule.

The integration fixture covers decoded complete batches of 1/4/5/16 native NAND
statements over BabyBear sextic and Goldilocks cubic. Five members exercise partial
final groups in both stages. It checks original-key decryption, public verification,
wrong keys/statements, missing or reordered groups, terminal source mutations,
changed roots, changed versions and omitted member obligations. Existing v7/v8
fixtures run alongside it to check retained ownership paths and public formats.
All ten selected release tests pass: two new v9 fixtures verify 52 decoded
member statements, and eight existing v7/v8 fixtures retain their expected
outcomes, including their reconstructed malicious/control certificates.
Source archives, the command and the terminal test log are under
`target/performance/comparison-batches/`.

## Root and conditional error accounting

`packed_root_inventory::comparison_batch_inventory` counts member declarations
and outer helper declarations separately, after public verification. At batch
size B the BabyBear profile has 60B member slots, 8B blind-rotation helpers and
7B key-switch helpers (75B total). Goldilocks has 102B, 16B and 13B respectively
(131B total). It does not report a partial member as a complete root inventory.
Trusted key roots and authentication siblings are excluded, as in earlier formats.
The Rust fixture checks these counts on all eight decoded 1/4/5/16 certificates.

The native example now selects this format with `--joint-comparisons`, mutually
exclusive with `--separate` and `--canonical-sources`. It emits the actual outer
helper counts and the trusted group schedule. `validate_joint_pbs_batches.py`
requires these fields and rejects changed or missing counts, contexts and groups.
For its conditional interactive budget it retains B complete v8 inventories.
There are exactly 2*(ceil(2B/4)+ceil(B/4)) lookup authentication cancellations,
at most the retained 6B full-extension cancellation terms. Every scalar and
packed relation equation remains independent. The old per-root fixed-word terms
are retained conservatively, under the same unreviewed availability/RS assumptions
as the component analysis; this is not a whole-proof security certificate.
All 89 Python checks and both updated root-inventory integration fixtures pass.

`tools/run_comparison_batch_validation.py` runs frozen binaries serially, checks
v6/v7 toy wire compatibility, validates fresh v9 1/4/16 certificates, and optionally
runs original-size certificates with exact archived statement/key/parameter/layout
matches. It writes commands, child PIDs, start ticks, immutable log hashes and a
terminal status. The current native session is under
`target/performance/comparison-batches-native/`, with build sources/binaries under
`target/performance/comparison-batch-native-build/`. Its six toy runs pass:
twelve v6/v7 controls (84 member instances) are wire-exact, and six v9 packets
verify 42 member instances. Original-size validation now completes all six
certificates, covering 42 fresh ring-1024/LWE-728 statements across both fields.
All archived native statements, keys, parameters and four PCS layouts match.
At sixteen members, BabyBear uses 4,707,873,888 bytes versus v7's 5,484,939,929
(14.17% lower); Goldilocks uses 5,833,344,537 versus 8,024,735,049 (27.31% lower).
Observed process peaks are 27,624,876 and 76,602,808 KiB respectively. These
correctness-run timings/resources are not paired performance evidence.
The conditional 42-member interactive union inventory is 129.32427 bits,
not a whole-proof security certificate. This native run uses the pre-pooling
build; the subsequent scalar-fold optimization has separate validation artifacts.

## Fresh helper-source binding audit

Ten complete reconstructed certificates pass their expected outcomes: two
controls are accepted and eight foreign-helper attacks are rejected. Each has
two complete members. Every NTT/reconstruction/accumulator/monomial/key-switch
child, outer Hadamard proof and lookup packet is generated afresh. Local replay
checks every member, the joint Hadamard relation, each scalar recurrence and
openings of the actual declared source/helper roots. The malicious helpers use
a different canonical digit/borrow string for the first or last member, in the
blind-rotation or key-switch stage. Public verification rejects its reciprocal
identity against the authenticated source values.

These fixtures use zero evaluation keys, identity rotations and an exact constant
accumulator at ring dimension 32/LWE dimension 21. They isolate helper binding;
they are not native secure-key fixtures or false-output/key-splice attacks. No
honest-proof transcript replay is used. Logs, validated source archives and the
ten digest-checked case records are under `target/performance/comparison-batch-audit/`.

## Fresh normal-key statement binding audit

The complete v9 suite now reconstructs twenty certificates using normally
generated VFHE evaluation keys and genuine traces over both fields at small
ring/LWE dimensions. Two controls verify; eighteen attacks reject: input mask,
output body, retained output mask coefficient, blind-rotation key, switching key,
initial/final accumulator endpoint, spliced chain and duplicated view. The tests
rebuild every member child, canonical joint Hadamard proof and both mandatory
comparison stages under the requested statement. Local reference verification
checks actual-root openings and the undisputed equations before public rejection.
Malicious members occupy first and last positions; key attacks use one member.
These are normal-key small fixtures, not original-size adversarial measurements.

All twelve selected v7/v8/v9 integration tests pass. Logs and twenty checked v9
case records are in `target/performance/comparison-native-key-audit/`; validated
source SHA-256 is
`0212e38252218bd60b5d7d7b7712da083869917b1ff5fd87e3995de68f974d1e`.
The separate zero-key helper-source audit remains relevant to reciprocal binding.

This is an experimental non-hiding format. Whole-proof Fiat–Shamir/hash and
knowledge security, direct packed hiding FRI, independent review and final
promotion remain open. Passing adversarial fixtures does not prove those claims.
