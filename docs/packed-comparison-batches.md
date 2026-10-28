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

This is an experimental non-hiding format. Fresh reconstructed whole-v9 malicious
certificates, original-size 1/4/16 runs, precise whole-v9 root/security accounting,
byte comparisons and paired complete timing remain to be done. Existing component
forgery results and v8 native evidence do not close these v9 gates. Whole-proof
Fiat–Shamir/hash security, direct packed hiding FRI and final promotion remain open.
