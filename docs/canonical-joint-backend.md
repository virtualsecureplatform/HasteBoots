# Canonical joint-source masked backend

`matrix_weighted::masked_polyfrim::joint::Parameters` is a distinct trusted
`CanonicalPcs` implementation. It uses the original masked table commitment and
retained private owner, with joint-source packets for both single and batched
canonical authentication. Its constructor validates the same physical geometry,
base/extension basis and per-query disclosure allowance. `from_independent`
selects it for an already validated parameter set; `independent_parameters`
returns a read-only view of that geometry.

The canonical context has a new fixed domain. All seven canonical relation and
registry domains also differ from the independent backend. The exact new context
is passed to the joint opening parent/child seed framing. Existing direct joint
calls keep their original context and bytes; independent calls keep their API
and format. Backend selection is a caller-chosen Rust parameter type, not a
proof field, deserialization flag or runtime fallback. Parameters remain trusted
and are intentionally not proof-deserializable.

The physical source state is shared with the existing adapter, so both APIs can
consume one original lifetime. Logical tables, native dimensions, root hashing,
randomness use and per-query allowance are unchanged. A root may be identical
under different trusted backend contexts; registry aliasing still requires both
root and context. Tests verify that otherwise valid direct-joint and canonical
packets cannot cross those contexts, even with the same root and proof type.

The generic canonical opening registry now groups queries into this backend's
one-source packets. Aliases share the original owner, unused roots spend no
allowance, and a later-root failure never refunds already published openings.
Normalization and rejection of noncanonical claims retain the existing masked
contract. Query-specific masked ladders and their FRIs remain separate.

## Complete PBS selection

The existing canonical version-10 and shared-comparison version-11 entry points
are generic over `CanonicalPcs`, so the trusted joint parameter type selects the
new packets throughout the original PBS stages. Parent versions retain their
algebraic meanings. The backend choice is bound by all trusted role contexts and
native-key descriptors before the prover's algebraic challenges; a new version
field is not used to negotiate the backend.

`vfhe/tests/packed_canonical_joint_pbs.rs` exercises both versions over BabyBear6
and Goldilocks3 using encrypted native NAND, N=32, LWE=21, BR radix eight and KS
radix five. It serializes/decodes complete proofs, invokes the public verifier,
checks retained key budgets, and retains shape/value/root/statement mutation
checks. A separately preprocessed independent owner with the same native keys,
geometry and randomness must have identical raw key roots. Both crossed trusted
setup/context combinations must reject, as must a joint complete proof under
the independent expected setup. The record includes the native-key-root digest.

The profile counts ordered response certificates separately from original-source
proximity certificates. The latter occur once per joint packet; response and
mask allowances are still charged per query. Declared root inventory slots keep
their original meaning and are not a complete oracle/security count.

This integrates source sharing, not full query/FRI aggregation. Robust vector
proximity, base-projection knowledge, whole-proof Fiat–Shamir/hash/knowledge
composition, adaptive hiding, original-size security-matched resource/timing
validation and independent review remain open. The small one-query fixtures and
public mask seeds are validation controls; all promotion flags remain false.

## Verified integration and byte comparison

All 74 selected component/registry tests and the locked workspace check pass:
58 PCS core, one canonical-context, four independent adapter, five joint adapter,
three independent registry and three joint registry tests. Frozen four-query
controls over both fields preserve every non-timing record in both existing APIs
(independent and direct joint), including complete proof and transcript hashes.

Two isolated complete-PBS processes each pass both field tests, producing four
publicly verified serialized/decoded proofs per process. All eight complete proof
hashes, native-key-root fingerprints, geometries and statements repeat exactly.
The tests execute 52 proof/statement mutation rejections, eight crossed-setup
validation rejections and four complete-proof wrong-setup rejections. Raw
independent native key roots equal the joint roots in each case. Key owners
spend one allowance in version 11 and a second in version 10, with no refresh.

The new profiles match the previous independent complete profiles' ciphertext
statement, FHE parameters, full trusted geometry and ordered response counts.
Their trusted setup hashes differ, as required by the new backend contexts.

| Field | Version | Independent bytes | Joint bytes | Reduction | Ordered responses | Joint source certificates |
| --- | --- | --- | --- | --- | --- | --- |
| BabyBear6 | 11 | 16,771,685 | 14,847,856 | 11.47% | 441 | 165 |
| BabyBear6 | 10 | 17,552,895 | 15,551,355 | 11.40% | 468 | 177 |
| Goldilocks3 | 11 | 11,444,568 | 10,392,079 | 9.20% | 499 | 291 |
| Goldilocks3 | 10 | 12,523,853 | 11,347,630 | 9.39% | 554 | 317 |

The independent source-certificate count equals its ordered response count.
Across both repetitions the joint profiles retain all 3,924 response ladders and
mask allowances, using 1,900 original-source certificates. Root inventory slots
remain 76 for BabyBear and 132 for Goldilocks; these declared slots exclude many
internal PCS commitments and are not a security budget.

| Field | Run | Version 11 prove (s) | Version 10 prove (s) | Process peak RSS (KiB) |
| --- | --- | --- | --- | --- |
| BabyBear6 | 0 | 176.656 | 177.970 | 1,746,908 |
| Goldilocks3 | 0 | 20.825 | 23.516 | 1,746,908 |
| BabyBear6 | 1 | 177.655 | 181.073 | 1,749,420 |
| Goldilocks3 | 1 | 20.043 | 21.337 | 1,749,420 |

Versions execute in order 11 then 10, using eight Rayon threads. Timings cover
full proving routines, with separate serialization/decode/verification values in
the raw JSON. Native key generation and NAND trace generation are outside those
clocks. Peak RSS covers the entire process, both retained proofs and negative
test clones, not an isolated prover. The previous independent timing runs were
not contemporaneous opposite-order controls, so no backend latency promotion is
claimed from this comparison. Parameters use one PCS query and one lookup
repetition at N=32/LWE=21 with public test seeds; original-size/security and all
original promotion gates remain open.

The frozen executable, executed/final source snapshots, exact source equivalence,
raw logs, per-run records and `independent-byte-comparison.json` are retained under
`target/performance/canonical-joint-backend/`. Full proof hashes are recorded in
the raw JSON and checked across repetitions by `tools/profile_complete_masked_pbs.py`.
