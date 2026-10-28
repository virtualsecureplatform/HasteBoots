# Complete PBS with shared-query comparisons

Opt-in complete protocol version 8 composes
`packed_decomposition::shared` and `packed_extension_lookup::shared` with the
existing aggregated Hadamard backend. It exposes `packed_pbs::SharedProof`,
`prove_shared`, `prove_shared_with_statistics` and `verify_shared`, with transcript
identifier `merlin-direct-shared-query-comparisons-v1` and a distinct v8 parent
domain. Existing versions and default entry points retain their formats.

Every comparison limb in one decomposition shares a scalar terminal point.
Its sum and reciprocal identity are checked independently using the same
helper value. One packet authenticates the canonical source registry and another
authenticates the coefficient helpers. Reconstruction, zero borrow endpoints,
NTT links, Hadamard products, accumulator continuity, public NAND/modulus-switch
endpoints and final key switching retain their full checks. Both blind-rotation
decompositions and the final key-switch decomposition use this backend.

The original FHE configuration and output key are preserved. The verifier takes
only trusted setup, requested ciphertexts and a decoded proof; it receives no
trace or private commitment states. This is a complete single-PBS protocol,
with sharing within each decomposition. Groups of 1/4/16 in its validation are
independent fresh certificates, not a cross-statement comparison proof. Composing
it with joint complete batches remains unfinished, as do hiding, full
Fiat–Shamir/hash/composition security and performance promotion.

## Counters and conservative inventory

The shared lookup API now exposes phase counters. Joint sum/identity algebra is
counted in `sumcheck`, while `zero_check` is reserved for a separate invocation.
Timed and untimed paths preserve proof bytes. Full-PBS stage timers include the
entire new comparison protocol.

`full_pbs_budget.py` recognizes only the explicit v8 transcript/backend pairing.
It retains every older per-limb conditional interactive term and adds six
full-extension cancellation terms: two PCS packets for each of three
decompositions. The Hadamard cancellation term remains present too. All four
PCS contexts must use unpadded equal-width block RS, with the aggregated path's
existing packing restrictions. Shared scalar challenges require no independence
between equations because their individual degree/field bounds are unioned.
This is a conservative fixed-word/interactive inventory, not a whole-security
certificate.

## Validation

Both selected fields pass complete decoded verification at fresh groups 1/4/16
at test dimensions, covering all NAND truth pairs and original output-key
semantics. All three decomposition stages reject missing/duplicate packets,
changed helper roots, terminal values, algebra ordering and source/helper
opening mutations. Versions, keys, endpoints, root order and public ciphertext
mutations reject too. Twenty fresh reconstructed full certificates pass their
expected outcomes: two controls accepted, eighteen deliberate attacks rejected.
Their local algebra and actual-root reference openings pass before the public
verifier rejects the intended relation.

The selected build passes 25 targeted Rust tests (21 lookup tests and four
complete-PBS tests), 88 Python checks, and both selected release example builds.
Frozen toy runs verify 84 decoded certificates, including 42 exact archived v5
wire controls and 42 new v8 proofs. Every statement, native key, FHE parameter
set and PCS layout matches the archived fixtures. Aggregate toy bytes across
21 statements fall 1.56% for BabyBear and 2.31% for Goldilocks versus v5. These
are correctness/size results, not native timing evidence.

Run `packed_extension_pbs_babybear6` with
`--aggregate-hadamard --shared-query-lookups --helper-left-extra 1`, or
`packed_extension_pbs_goldilocks3` with
`--aggregate-hadamard --shared-query-lookups --width 4`. Add
`--validation-batches` for fresh 1/4/16 groups and `--full` for the original
ring-1024/LWE-728 parameters. The deferred flag is mutually exclusive. Evidence
is under `target/performance/shared-pbs/`. Original-size correctness is running
serially under `target/performance/shared-pbs-native/`: all 21 BabyBear proofs
already pass, matching archived statements, keys, parameters, layouts and root
inventories; Goldilocks remains in progress. Native BabyBear total bytes across
those statements fall from 7,590,261,868 to 7,040,575,514 (7.24%) versus v5. No
comparative native timing claim follows from this correctness run.
