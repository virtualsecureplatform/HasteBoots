# Canonical decomposition with shared comparisons

`packed_decomposition::canonical::shared` combines the existing canonical radix
reconstruction and borrow-endpoint checks with one shared lookup group for every
limb transition. It is an additional proof type and transcript domain. The
per-limb canonical entry point and complete version-10 PBS keep their existing
proof format and framing.

Both entry points use the same borrow-chain construction from the retained
digit tables. Digits must be in the radix and their integer string must be below
p before any source opening is spent. Each borrow column is committed once with
private cryptographic randomness. The linear check still separately enforces
field reconstruction and zero initial/final borrows. The original digit roots
and the same borrow states then enter `canonical::shared` extension lookups;
no replacement digit or compressed source root is introduced.

The shared comparison proof retains every limb's trusted transition table,
source slot order, prefix mask and independent tuple-compression repetitions.
Every sum and reciprocal identity is checked separately. Their common scalar
terminal point pulls back to one query for each used digit or borrow root.
Initial and final borrow checks remain mandatory, including when the digits
reconstruct the source only modulo p.

The original source needs one opening. Each digit and each borrow needs two:
one for linear reconstruction/endpoints and one for shared comparison. Every
reciprocal helper needs one. These per-role counts do not grow with comparison
repetitions R; the number of independently committed reciprocal helpers remains
d*R. Aliasing roles adds their linear opening obligations to the same retained
session. Source/borrow/helper parameters remain caller-trusted. A later failure
does not refund earlier openings.

The new path uses public linear and sumcheck algebra. The masked PCS does not
make it a hiding proof, and per-root packets are not genuine joint aggregation.
Complete canonical key-switch/PBS integration, native-size measurements, robust
vector proximity, adaptive hiding, knowledge/Fiat-Shamir composition and the
original security/performance promotion gates remain open. Helper memory grows
with the number of limbs and repetitions; native callers must bound groups.

## Validation

Decoded masked comparisons use the same trusted parameters, original source
roots, radix, active length, digit tables and repetition counts for the shared
and per-limb paths. They include 0, 1, p-1, p-2, 17 and p/2, with partial-domain
padding and two repetitions. Tests check exact source/digit lifetime spending,
borrow opening indices, helper opening indices, exhaustion, missing borrow roots,
mutated linear/comparison terminals and swapped original digit roles. Ordinary
Brakedown proofs also verify after serialization and decoding.

Two fresh noncanonical certificates commit integer digits for p and source zero.
Every actual-root linear opening and shared extension lookup authenticates under
the requested prefix. Reference replay reports valid reconstruction and initial
zero borrow, but a false final zero borrow. Production rejects that identity.
Normal proving rejects the same noncanonical digits before spending any source
opening. No production proof flag bypasses the checks.

Before extracting the common borrow builder, two deterministic complete
per-limb proof hashes were frozen. The final build must reproduce their bytes
and final transcript agreement exactly over both fields. The baseline log and
pre-refactor sources are retained alongside final validation evidence under
`target/performance/canonical-shared-decomposition/`.

The matched-parameter component comparisons produce:

| Field | Per-limb children | Shared children | Per-limb bytes | Shared bytes |
| --- | ---: | ---: | ---: | ---: |
| BabyBear/sextic | 50 | 27 | 1,610,616 | 886,555 |
| Goldilocks/cubic | 98 | 51 | 2,092,130 | 1,106,611 |

These small one-proximity-query fixtures are not whole-security-matched or
original-size PBS measurements. They establish fewer authenticated queries and
smaller component proofs, not a complete latency or security promotion claim.
Both comparison pairs authenticate 226 child openings overall; the two fresh
noncanonical certificates authenticate another 78 before production rejects the
final borrow identity.

All 78 default release/locked SNARK unit tests and nine sumcheck tests pass
(87 tests); 30 expensive complete masked audits remain opt-in. The locked
workspace check passes. Frozen wire records, checked comparisons, test logs,
pre-refactor sources and the validated final source snapshot are archived in
the evidence directory above.
