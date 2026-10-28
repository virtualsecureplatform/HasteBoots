# Canonical packed linear identities

`packed_linear::prove_canonical` and `verify_canonical` authenticate trusted
linear identities through `CanonicalPcs`. They use the original retained tables,
expected roots and complete parameter contexts. Every source is authenticated;
there is no auxiliary witness-view commitment. The shared query is sampled only
after binding all contexts, roots and trusted coefficients.

The backend boundary now provides single-opening packets as well as ordered
multi-query packets. Brakedown dispatches to its original single-opening API;
the masked adapter uses one bounded direct opening. The existing linear
`prove`/`verify` entry points and `Proof<F,O>` spelling wrap the shared
implementation with Brakedown packet types. The old prover's caller-supplied
cached table references retain their behavior. A frozen direct-dispatch reference
from `e5e9cd1` checks complete proof bytes and final prover/verifier challenges
for BabyBear width eight and Goldilocks width four.

The masked path has a separate v2 linear domain. It canonicalizes trusted public
coefficient encodings and disclosed source responses, and rejects noncanonical
response fields in the serialized proof. Normalization preserves dimensions and
mathematical field values. Brakedown retains its original encoding behavior.
Each successful masked source opening spends its retained session's allowance;
checking a false linear identity fails before any child opening is attempted.

## Validation

The new masked tests verify four decoded identity certificates: constant and
nonconstant logical tables over BabyBear/sextic and Goldilocks/cubic challenges.
They check all three source openings, final transcript agreement, source counters,
changed trusted coefficients, response mutations and missing child packets.
A Goldilocks encoding test accepts an equivalent trusted coefficient encoding
and rejects an equal-value noncanonical proof response.

Two fresh false-identity certificates use committed constant source words one,
two and four. They reconstruct the requested transcript, generate genuine child
openings for all actual roots, and pass independent replay of all six child
checks. The production linear verifier rejects the false identity itself. This
exercises the algebraic check rather than relying on corrupted authentication
paths or replaying an honest transcript.

All 73 selected SNARK component tests and twelve complete v7/v8/v9 PBS integration
tests pass (85 total). The complete binding cases retain their expected outcomes.
These are component and small complete-PBS regressions, not new native performance
or whole-security measurements.

NTT authentication, polynomial relations, key/setup ownership and multi-root
Hadamard authentication still need their remaining backend generalization before
a masked complete-PBS format can be claimed. This component reveals its specified
linear responses; using a masked PCS does not make the enclosing algebra zero
knowledge. General hiding, composed soundness, adaptive Fiat–Shamir analysis and
security-matched promotion remain open.

The locked workspace check also passes. Logs, both exact-wire controls, four
masked identity packet records, two fresh false-identity records and validated
sources are under `target/performance/canonical-packed-linear-boundary/`, source
SHA-256 `78e6a5eb09ac7141b5a12e3374a537950a5cf082dfbd7fbfdcbe5c87ef9dc895`.
