# Canonical final key switching with shared comparisons

`packed_key_switch::canonical::protocol::shared` proves the complete original-key
final stage using shared canonical radix comparisons. It retains the known-table
query for the negative accumulator mask, original coefficient/evaluation roots,
NTT links, native switching-key products and original output extraction. The
public accumulator and output mask/body determine the statement; verification
needs no private trace or retained prover state.

One internal protocol implementation is parameterized by a private, static
comparison strategy. The existing `protocol::Proof`, `prove` and `verify` select
per-limb decomposition. The new `shared` entry point selects shared decomposition
and binds a distinct domain before the known-input or child challenges. Neither
serialized proof flags nor prover-supplied metadata choose the strategy. The
old proof alias retains its serialized field order and has frozen whole-stage
byte controls over both selected fields.

The same retained coefficient states supply every NTT, reconstruction/comparison
and extraction query. Native key states belong to trusted preprocessing and
retain their mask counters across repeated final-stage proofs. The public input
root still authenticates its caller-derived table before canonical decomposition.
No source view, key column or output endpoint is taken from an untrusted trace.

With packed width k, each digit coefficient root needs k+2 openings: k for its
NTT, one for reconstruction and one shared comparison query. The sum coefficient
root needs k+1, each evaluation root k+1, each original key root one, and the
known input two. Each borrow root needs two, and each reciprocal helper one.
These per-role query counts are independent of comparison repetitions; helper
root count still grows with digit count times repetitions. Trusted callers must
provision the whole retained key lifetime, and failures do not refund openings.

This final-stage entry point is integrated into complete version-11 PBS. The old
complete version-10 PBS path remains available. Genuine 1/4/16 joint aggregation, original-size measurements, general
hiding, robust vector proximity, knowledge/Fiat-Shamir composition and the
original matched-security size/latency promotion gates remain open. Shared
comparisons retain public algebra and do not establish zero knowledge.

## Validation

The nonzero native-layout key fixture checks negacyclic NTT products against
independently assembled coefficient words and original extraction equations at
ring dimension 32 and output LWE dimension 21. The masked comparison uses the
original five-bit switching radix and two comparison repetitions. Both paths
use identical role parameters, native key roots, public accumulator/output and
coefficient words. Each proof commits its own private coefficient/evaluation
and known-input sessions. The same trusted key owner spends one ticket for the
shared proof and a second for the per-limb proof.

Both serialized forms are decoded and publicly verified, with prover/verifier
transcript agreement. Tests inspect exact NTT/product/decomposition/extraction
opening indices and reject changed input roots, missing known-input packets,
missing NTT children, mutated products, missing borrow roots, changed shared
helper terminals, changed extraction, wrong output mask/body and foreign trusted
key roots. Ordinary shared proofs cover both fields with the eight-bit fixture.

Two whole-stage per-limb proof hashes were captured before dispatch refactoring;
the final implementation must reproduce them exactly. The existing per-limb
integration fixtures also use the common native fixture generator. These are
small algebraic fixtures, not secure encrypted native profiles or original-size
PBS timing measurements. Their single proximity query is for completeness.

Sources before the dispatch refactor, frozen wire records, checked comparisons,
release/locked logs and validated final sources are archived under
`target/performance/canonical-shared-key-switch/`.

The five-bit, two-repetition component comparisons produce:

| Field | Per-limb children | Shared children | Per-limb bytes | Shared bytes |
| --- | ---: | ---: | ---: | ---: |
| BabyBear/sextic | 231 | 190 | 8,563,300 | 7,209,467 |
| Goldilocks/cubic | 299 | 222 | 6,950,896 | 5,215,297 |

All four masked certificates verify after decoding and authenticate 942 child
openings overall. These byte reductions are component results; they do not
certify complete-PBS latency or whole-proof security matching.

Validation passes 78 default release/locked SNARK unit tests, nine sumcheck
tests, four existing final-stage integration tests, two frozen wire controls and
four new shared-stage integration tests: 97 unique tests. The 30 expensive
complete masked audits remain opt-in. The locked workspace check passes.

Complete version-11 integration is now available through
`packed_pbs::canonical::shared`; see `canonical-shared-complete-pbs.md` for its
validation and remaining security/performance gates.
