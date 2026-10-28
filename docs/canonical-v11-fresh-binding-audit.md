# Fresh complete version-11 binding certificates

The test-only complete-proof audit now constructs version-11 certificates with
shared canonical comparisons under the requested public statement, trusted key
roots and actual source commitments. It generates every child after binding
that request; the attacks do not mutate an honest proof after its challenges.
Every certificate is serialized, decoded and checked by both complete reference
replay and the production version-11 verifier.

The shared audit driver also retains the version-10 cases. Private static test
adapters choose the matching radix and final-key-switch proof types and domains.
No serialized flag selects relaxed production verification. New adapters and
comparison hooks compile only under `cfg(test)`; release APIs, parameters and
proof framing are unchanged.

## Cases and replay obligations

Each backend/field pair has an accepted control and fourteen rejected cases:

| Cases | Intended false reported obligation |
| --- | --- |
| `Initial`, `Final`, `Addition`, `Chain`, `DigitA`, `DigitB` | Accumulator endpoints/arithmetic/continuity/source-view linkage |
| `Rotation` | Caller-derived public monomial factor |
| `KeyProduct` | Bootstrapping-key product |
| `SwitchKeyProduct` | Final switching-key product |
| `ExtractionA`, `ExtractionB` | Requested output extraction target |
| `CanonicalA`, `CanonicalB`, `SwitchCanonical` | Final zero borrow for an integer digit string equal to p |

Reference replay separately records both key products, both blind-rotation
reconstructions and borrow endpoints, final-stage reconstruction/borrow
endpoints, accumulator linkage, public rotations and extraction. All other
reported obligations must hold in each attack. Accumulator linkage is one
reported obligation covering several coupled identities, not a claim that only
one internal scalar equation differs.

Every original-source NTT and actual-root PCS opening remains strict. Shared
lookup replay checks every independent sum and reciprocal equation, each
original source query and each coefficient-helper query. Noncanonical modulus
digit strings have valid field reconstruction, valid initial borrow and genuine
lookup transitions; only their final zero-borrow report is false. The final key
stage also authenticates its known negative-mask input and all native key roots.
Prover and reference replay must finish with equal transcript challenges.
Production accepts controls and rejects attacks at their intended stage.

## Scope

The fixtures are exact algebraic adversarial examples using zero native key
samples, plus radix-weighted key limbs and nonzero rotations for the two foreign
key-product cases. They are not secure encrypted-key or original-size native
profiles. Existing encrypted version-11 completeness fixtures are separate.

The audit does not replace fresh complete false-lookup certificates, an audit
using secure encrypted original-size fixtures, or independent adversarial
review. The one-proximity-query masked settings test completeness. General
hiding, robust vector proximity, knowledge/Fiat-Shamir composition, genuine
1/4/16 joint aggregation and the original security/performance promotion gates
remain open.

## Running and evidence

Two default version-11 tests generate thirty Brakedown certificates. Thirty
manual masked tests each generate one complete certificate; they are ignored
by default because of their CPU and memory requirements:

```sh
RAYON_NUM_THREADS=8 cargo test --release --locked -p snarks --lib \
  packed_pbs::canonical::audit::v11_masked_ \
  -- --ignored --nocapture --test-threads=2
```

Validation used thirty concurrent audit workers on the available 125-GiB host.
All sixty version-11 certificates pass reference replay: four controls accepted
and fifty-six attacks rejected by production. The default run also retains
thirty version-10 Brakedown certificates (two controls, twenty-eight rejections).
All eighty default SNARK unit tests, thirty manual version-11 audits and nine
sumcheck tests pass: 119 unique tests. Sixty expensive manual cases are now
opt-in across versions 10 and 11. The locked workspace check passes.

`target/performance/v11-fresh-binding-audit/executed-sources.tar.gz` captures the
source used by the manual run. While it ran, an obsolete unused version-10
`cfg(test)` binding wrapper was removed; every reachable audit routine stayed
unchanged. The final eighty-test default suite passes after that cleanup.
The archive checker confirms that this wrapper removal is the only source-code
difference between the manual execution snapshot and final sources. Final
sources, checked certificate records and logs are archived in the same directory.

## Joint backend follow-up

The canonical joint-source backend now has 60 additional opt-in fresh complete
cases across versions 10/11 and both fields. Its control/attack obligations reuse
this driver and strict reference replay. All backends now also compare a separate
32-byte end-of-proof challenge and record full proof hashes and rejection stages.
The original independent masked case names remain unchanged. There are 120
opt-in masked cases in total; see `canonical-joint-fresh-binding-audit.md` for
current joint results, record validation and remaining scope limitations.
