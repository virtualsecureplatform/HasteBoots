# Complete PBS with deferred lookup source authentication

Experimental protocol version 5 combines version 4's aggregated Hadamard
authentication with shared source authentication across the limbs of each
canonical decomposition. It covers both blind-rotation halves and final
key-switch decomposition. This is within one PBS; different statements still
produce independent certificates. The existing versions and defaults remain.

## API and canonical linkage

`packed_pbs::{prove_deferred,prove_deferred_with_statistics,verify_deferred}` use
`DeferredProof<F,EF,O>`. The verifier takes trusted parameters/setup and the
input/output ciphertext statement, without a native trace or private PCS state.
It rejects a protocol version mismatch before verifying child proofs. The parent
domain is `HasteBoots complete binary NAND PBS deferred lookup sources v5` and
the transcript identifier is
`merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1`.

Each decomposition reconstructs its expected digit roots from the enclosing
canonical sources, commits its borrow columns, and retains the existing linear
reconstruction and zero borrow endpoint proof. Its comparison registry contains
digits followed by borrow roots. Limb i uses slots `[i,d+i,d+i+1]`, derived from
the trusted radix configuration. The registry binds parameter contexts and roots
before lookup algebra. Each lookup retains its independent extension challenges
and immediate reciprocal-helper authentication. Every original-source terminal
query/value is bound when derived, then authenticated in a final packet for each
used distinct `(context,root)` pair. The verifier reconstructs those obligations;
proofs cannot supply an alternative registry or unchecked claims.

There is one outer comparison packet per decomposition, containing exactly d
lookup proofs. Inner standalone source-opening arrays must be empty. Packet and
claim shape checks reject missing, additional or reordered data. The entire
source authentication, including the final packets, contributes to prover phase
statistics. See `packed-deferred-lookups.md` for the collector and component API.

All other linkage remains: private NTT views, trusted bootstrapping-key factors,
accumulator arithmetic and continuity, public NAND monomial initialization,
modulus switching, key switching and extraction into the original LWE key.
Key-switch product authentication retains its original backend. No new
commitments are introduced by deferral: verified root-slot inventories remain
75 for BabyBear degree 6/width 8 and 131 for Goldilocks degree 3/width 4.

## Explicit selection

The example requires both flags, so a partial flag combination cannot silently
select another variant:

```sh
cargo run -p vfhe --release --example packed_extension_pbs_babybear6 -- --full --helper-left-extra 1 --aggregate-hadamard --defer-lookup-sources
cargo run -p vfhe --release --example packed_extension_pbs_goldilocks3 -- --full --width 4 --aggregate-hadamard --defer-lookup-sources
```

Metadata identifies version 5, `hadamard_backend=multi-root` and
`lookup_backend=deferred-extension`. The batch validator also requires explicit
`--aggregate-hadamard --defer-lookup-sources`; batches 1/4/16 describe ordered
independent fresh proofs with shared preprocessing, not cross-statement
aggregation.

## Conditional inventory and limits

The algebraic lookup equations, extension challenge counts, and helper checks
are unchanged. Only original-source authentication is deferred. For d limbs and
r repetitions, the old per-limb opening inventory charges 3d random tests and
3d(r+1) response groups. The collector has at most 2d+1 distinct source packets
and 3dr structured claims. Since d>=1, both old counts upper-bound the deferred
counts. Duplicate queries/roots can further reduce packets, without removing
any expected equality. The existing fixed-word/shared-column argument is still
required; sharing does not introduce an independent cancellation challenge.

`tools/full_pbs_budget.py` conservatively retains every version-4 error term,
including Hadamard aggregation cancellation. It requires the explicit deferred
mode and native unpadded equal-width block-RS geometry for both source domains.
It does not claim improved security from smaller packets. The complete proof
remains experimental and non-hiding. Fiat–Shamir, hash-query budgeting,
composition, independent security review, security-matched comparisons and
promotion remain open; an interactive inventory is not a certificate for them.

## Validation and performance

The full verifier tests cover fresh 1/4/16 groups and all NAND input pairs in
test dimensions, decoded public verification, expected output decryption,
alternate keys, unsupported versions, changed canonical roots/endpoints and
swapped child proofs. Additional mutations target all three decompositions:
missing/additional comparison packets, missing limbs or source authentication,
changed source claims, injected standalone openings and reordered limbs.

The reconstructed-certificate audit also selects the version-5 decomposition and
Hadamard backends. It builds fresh local child proofs under the requested parent
context and authenticates actual roots before applying the production verifier.
Thus wrong input/output/key/endpoint/round/duplicate-view cases exercise the
intended public equations, beyond replaying honest proofs with altered metadata.

The four new tests pass. The eleven reconstructed-certificate audits across
versions 2/3/4/5 pass 110 cases: eleven controls accepted and 99 intended
rejections. Version 5 contributes twenty cases, with two controls/eighteen
rejections. Workspace/example checks, release builds and 83 Python tests pass.

Two serial native comparisons reverse field and method order, with sixteen
Rayon threads and two proofs per subprocess. Setup is reused; complete time
includes native trace generation, proving and serialization. The table uses the
second proof from each subprocess. Original ring-1024/LWE-728 dimensions,
output key, statement, four layouts and Q=544 are unchanged across methods.
These are conditional-profile comparisons, not whole-security-matched results.

| Field | v4 bytes | v5 bytes | Byte reduction | v4 complete, two orders | v5 complete, two orders |
|---|---:|---:|---:|---|---|
| BabyBear degree 6/width 8 | 378,478,271 | 361,453,722 | 4.50% | 18.131 / 18.174 s | 18.084 / 18.120 s |
| Goldilocks degree 3/width 4 | 559,825,723 | 525,215,658 | 6.18% | 32.005 / 31.798 s | 31.930 / 32.083 s |

BabyBear reused complete latency is 0.26%/0.30% lower. Goldilocks is 0.24%
lower / 0.90% higher. Verification is 2.071/2.142 s versus 2.138/1.887 s
(BabyBear), and 2.379/2.682 s versus 1.882/2.097 s (Goldilocks). This supports
an opt-in size optimization, not a robust complete-prover speedup or the 10%
promotion target. Defaults remain unchanged.

All 66 benchmark packets verify: sixteen native, eight legacy toy wire controls
and 42 fresh v5 toy cases. Native v4 retains exact archived wire bytes; both
methods bind identical original statements/keys/parameters/layouts. Version-5
proof hashes and sizes repeat exactly across ordering. Fresh toy statements and
native keys/parameters also match their archived v4 fixtures. Verified root
inventories stay at 75/131. The unchanged conditional 21-proof interactive
inventories are 130.50895/130.16056 bits; these are not Fiat–Shamir certificates.

Evidence is under `target/performance/deferred-pbs/`: raw logs/resources, exact
executables, commands/provenance, terminal process status, checked comparison,
test logs and 110 reconstructed binding cases. The build snapshot SHA-256 is
`2ffa89f720f303e3a14a39e6d4f2dd584dd15deb0b719fb3ab5d391b4db42a87`;
all 344 Rust/manifest/lock inputs matched before measurement. Executable hashes
are `de29020b81995c859fd606f236f81b25c931eb5919565a886b5074afed5affd3`
(BabyBear) and `fbff8921f8f0cf5a1f033e065083d86351d711b165db9eecba187e9235581b23`
(Goldilocks). No builds or tests ran during timing.

Original-size fresh 1/4/16 validation is complete under
`target/performance/deferred-pbs-native-fresh/`, reusing these exact executables.
All 42 fresh statements (21 per field) and all NAND pairs verify against archived
native statements/keys/parameters/layouts. Both processes exit successfully;
all 42 root-inventory records are digest-linked and retain counts 75/131.
The combined conditional interactive inventory is 129.32427 bits. The two
concurrent runs are correctness-only, with no performance claims. Their manifest
links the immutable build snapshot and exact executables above; subsequent
shared-challenge relation development does not change those frozen artifacts.
Version 6 adds an explicit joint-Hadamard batch composition; see
`packed-joint-pbs.md`. Its original-size validation and reconstructed binding audits now pass. Further
cross-statement stage sharing, hiding, independent whole-security review and
promotion remain open. The relation batching component is described
separately in `packed-batch-relations.md`.
