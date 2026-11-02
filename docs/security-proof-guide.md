# Security proof guide

This is the starting point for a mathematical review of the experimental
classical complete-PBS protocol. The implementation has correctness and trace
controls, but no complete 128-bit security theorem. Keep the protocol definition,
assumptions, lemmas and experimental observations separate.

## Review checkpoint

The Git commit containing `security-proof-baseline.json` is the source checkpoint.
The manifest records repository file hashes and its parent commit. Verify it with:

```sh
python3 tools/proof_baseline.py --verify docs/security-proof-baseline.json
```

The manifest detects source/document changes; it does not certify security.
`Cargo.lock` pins the Rust dependency resolution. Large captures, frozen test
executables and historical audit JSON under `target/` are local evidence and
are not included in the source checkpoint. Reproduce observations from the
checked-in tests instead of treating a missing local artifact as a theorem.

The long [implementation ledger](implementation-status.md) and
[experimental notes](unmasked-polyfrim.md) retain historical investigations.
Use this guide for current scope and navigation. Historical statements that a
run was pending, or a bound was established, are not the current proof status.

## Identify the exact protocol

Three version numbers have different meanings:

| Identifier | Meaning | Defining source |
| --- | --- | --- |
| Complete protocol 12 | Profile-bound complete PBS proof and stage composition | `snarks/src/packed_pbs/canonical/classical.rs`, `canonical/stages.rs` |
| Profile schedule 4 | Atomic NTT/ZeroCheck phases with sequential Brakedown column draws | `pcs/src/classical_profile.rs`, `helper/src/transcript.rs` |
| Profile schedule 5 | Also draws Brakedown columns in one fixed-size byte phase | Same sources |
| PCS parameter context v2 | Field, matrix layout, quota, encoding and code-domain binding | `pcs/src/matrix_weighted.rs::context_digest` |

“V4” and “v5” in recent audit records mean profile schedules, not complete wire
versions. The legacy complete v11 experiment is a separate protocol path.

A useful first theorem target is schedule 5 with Brakedown: it avoids the
additional sequential-family argument required by schedule 4. Keep the latter
as an explicit extension. This is a proof-work recommendation, not a change to
the verifier's supported profiles. Treat the ordered query quota Q as a parameter
until the full bound justifies a choice. The original-size Q=1 runs are
correctness controls, not 128-bit parameter choices.

The eventual native specialization must preserve n=1024, LWE dimension 728,
the original public evaluation keys and output key. Existing representative
fields are BabyBear with degree-six extension/width eight and Goldilocks with
cubic extension/width four. The descriptor, not the field name alone, fixes the
extension basis, role geometry, hash suite and challenge schedule.

Field values and serialized representatives also differ: BabyBear's newtype
wire stores a Montgomery representative; Goldilocks uses its u64 representation.
Use the implementations in `algebra/src/baby_bear/mod.rs` and
`algebra/src/goldilocks/mod.rs` when proving normalization and injective encoding.
The context-root auditor decodes these representations; that check alone does
not establish canonical encoding at every protocol boundary.

## Statement, setup and witness

The public statement supplies the original input/output endpoints and is bound
to the retained public evaluation-key setup. The witness consists of the
computation trace and the committed tables used to establish the complete PBS
relation. Define the exact NAND/PBS relation from `Statement`, `Config`,
`public_inputs`, and the stage verifiers; do not replace it with independent
opening claims.

`classical::preprocess` constructs setup from caller-supplied parameters and
public evaluation keys. `classical::verify` checks the expected field/profile,
compares the setup/proof profile identifiers, creates the parent transcript and
calls the complete verifier. Trusted configuration and role parameters must be
fixed in the security experiment; proof metadata must not select them.

The public `verify` API consumes a typed `Proof`. Specify the external byte
decoder separately if the theorem concerns arbitrary wire messages, including
trailing bytes, canonical field representations and malformed allocations.
Instrumented decode controls do not silently define every production caller's
byte-acceptance policy.

| Role | Reused sources |
| --- | --- |
| 0 | Main coefficients, evaluations, key/input tables, borrows, accumulator and monomial sources |
| 1 | Main lookup helpers |
| 2 | Final key-switch sources, input, borrows and extraction |
| 3 | Final lookup helpers |

One root with one trusted context must have one common decoded source across
every opening. Choosing a different witness table for each opening would prove
a different relation. Equal roots with different trusted contexts must not be
silently identified. Specify decoding outside the proximity promise and prove
how that case contributes to the failure event.

The target here is non-hiding correctness/soundness and the required knowledge
property. Existing performance experiments do not impose a new trace-hiding
requirement. FHE confidentiality and proof security are separate claims.

## Transcript and oracle model

Start from the exact bytes in `helper/src/classical_transcript.rs` and the typed
adapter in `helper/src/transcript.rs`. A frame is:

```text
kind:u8 || label_length:u64_le || label || body_length:u64_le || body
```

| Kind | Purpose |
| --- | --- |
| 0 | Protocol/application/profile initialization |
| 1 | Appended public message |
| 2 / 3 | Requested byte length / returned challenge bytes |
| 4 / 5 | Field modulus/count descriptor / consumed-byte receipt |
| 6 / 7 | Child context / child completion binding |
| 8 | Parent checkpoint in the cloned state |

A field phase binds a 16-byte little-endian modulus and an eight-byte count,
then reads masked candidates until canonical values are obtained. The receipt
contains a 16-byte consumed length and a 64-byte SHAKE output over the consumed
bytes with its receipt domain separator. It is not merely the list of accepted
field values. Extension challenges additionally bind the basis representation.

Model one input-indexed ideal XOF with consistent whole output streams, shared
by all relevant transcript/receipt uses, and the declared ideal hash interface.
Repeated input strings return the same stream. Different method names or reader
instances do not establish independent trials. State whether the two oracle
interfaces are independent and cover every direct primitive call required by
the theorem; current interface counters explicitly exclude some direct calls.
Replacing the ideal model by concrete SHA-512/SHAKE256 requires stated
cryptographic assumptions, not the trace auditor's successful recomputation.

For v4 Brakedown, use the production cutoff
`(2^64-1)-((2^64-1) mod N)`. Every accepted draw, including duplicates, consumes
quota before transport deduplication. Attribute a family to its earliest queried
member, including an off-path descendant. For v5, bind the power-of-two domain,
draw `8*Q` bytes once, mask each u64 and deduplicate after the ordered draws.

Child seeds and completions bind the child to its parent continuation. Failed
verification transcripts are discarded. A proof must explain the adaptive
dependencies across these links, not assume fresh randomness at each stage.

## Mathematical target

Use classical adaptive adversaries with no arbitrary fixed query cutoff. Define
the experiment's setup distribution, allowed oracle access, verifier submissions,
stopping rule and charged work before stating a concrete security level.

A candidate expected-work target is

```text
E[W_A] >= 2^128 * Pr[A causes acceptance of a false PBS statement].
```

This is a target, not an established result. W_A must be a justified attacker
work measure. Explain how honest/setup/verifier activity is charged or offset,
including any initial bad event; do not condition it away for free. State a
separate extractor theorem, with its assumptions and cost/failure bounds, if a
knowledge claim is required. Soundness does not automatically imply knowledge.

The accounting interfaces have different premises:

| Interface | What its calculation can establish under supplied premises |
| --- | --- |
| `classical_work_cost.report` | Fixed maximum-budget/success ratio |
| `classical_work_cost.expected_work_bound` | Expected-work bound with an explicit success floor and uniform truncation CDF |
| `classical_hazard_work.affine_hazard_work_bound` | Expected-work/success bound without a success floor, under a full-history conditional hazard |
| `classical_window_work.WindowWork` | An abstract literal/concat/slice construction ledger; not a concrete machine-cost proof |

Do not obtain a conditional hazard by differentiating a budget polynomial.
Do not identify an observed counter maximum with a pathwise adversarial bound.
Rejection thresholds in the worksheets are analysis stops; production samplers
have no such retry cap. Charge every relevant first-query/first-family stop,
including prequeries and later selection. Lookup reciprocal retries remain a
separate obligation from pure field/column rejection.

## Proof obligations and dependency order

“Source argument” below means an implementation argument available for review.
“Control” means finite executable evidence. Neither label supplies a completed
cryptographic theorem.

| ID | Obligation | Present material | Remaining mathematical work |
| --- | --- | --- | --- |
| P1 | Exact PBS relation, trusted setup and role mapping | Complete stage code and correctness controls | Define relation and prove complete stage composition |
| P2 | Injective encodings and profile/context binding | Framing, factories, field/geometry checks | Prove parsing/normalization properties and substitution resistance |
| P3 | One common source per root/context | Frozen-history and authenticated-path controls | Prove availability/decoding/extraction lemma covering arbitrary prefixes |
| P4 | Block RS and matrix-weighted opening security | Root-order checks, distance argument, direct-evaluation tests | Prove proximity/random-test/structured-response bounds for this layout and shared columns |
| P5 | Algebraic stage soundness | Conditional parent and PCS worksheets | Establish every conditional local bound against the common sources |
| P6 | Adaptive Fiat–Shamir and child composition | Prefix classifiers, chronological reader/hash audits | Cover arbitrary queries, prequeries, aliases and unknown/unclassified paths |
| P7 | Resources and expected work across all trials | Per-call and parent-call source arguments; separate cost calculators | Prove full pathwise/query/construction caps and conditional hazards in the same experiment |
| P8 | Concrete parameter selection | Exact arithmetic tools and correctness profiles | Combine proved terms once, choose Q and derive 128-bit claim and extractor cost |

Work in order P1/P2, P3/P4, P5/P6, then P7/P8. If a step needs a new assumption,
record it explicitly instead of filling an unknown failure term with zero.
PolyFRIM/dictionary/fragmented variants need their own opening and virtual-source
lemmas; a Brakedown proof does not automatically cover them.

## Code and evidence map

| Area | Production definition | Review material |
| --- | --- | --- |
| Profile and setup | `pcs/src/classical_profile.rs`; `snarks/src/packed_pbs/canonical/classical.rs` | Profile/decoding tests; native validation example |
| Complete stage order | `snarks/src/packed_pbs/canonical.rs`, `canonical/stages.rs` | `docs/canonical-complete-pbs.md`; parent call controls |
| Encoding and PCS | `pcs/src/utils/code/block.rs`; `pcs/src/matrix_weighted.rs` | `docs/block-rs.md`; `pcs/tests/block_rs*.rs`, `classical_hash_resources.rs` |
| Source aliases and batching | `snarks/src/packed_opening_batch.rs`; shared lookup/decomposition code | Registry/prefix controls under `canonical/audit/` |
| Byte transcript | `helper/src/classical_transcript.rs`, `helper/src/transcript.rs` | Helper tests; `tools/audit_classical_*` readers |
| Fixed-word arithmetic | `tools/classical_candidate_terms.py`, `classical_parent_phases.py` | Conditional worksheets, not theorem certificates |
| Resources/work | `tools/classical_*resources.py`, `classical_work_cost.py`, `classical_hazard_work.py` | Source arguments in `canonical-opening-budget.md` and explicit required premises |

The large `canonical/audit/outer_prefix.rs` tree is test-only analysis machinery.
Its proposed states and first-bad-event fixtures are not a production adversary
API, a complete prefix grammar or an extractor. The finite native captures bind
actual returned bytes to counters; they do not quantify over adversaries.

## Supplied papers

The workspace's reference PDFs live separately under `../refs/` relative to the
repository and are not included in this source checkpoint:

- `2025-1354.pdf`: *HasteBoots: Proving TFHE Programmable Bootstrapping in Seconds*.
- `2025-719.pdf`: *SNARKs over Small Prime Fields without Extension Field Multiplication*.
- `2025-261(1).pdf`: *Shred-to-Shine Metamorphosis of (Distributed) Polynomial Commitments*.
- `2026-347.pdf`: *Relaxed Modular PCS from Arbitrary PCS and Applications to SNARKs for Integers*.

For each imported theorem, write down its exact hypotheses and map them to this
encoding, proximity metric, challenge sharing, source convention and oracle
model. A matching algorithm name or an asymptotic result is not the concrete
composition theorem required here.
