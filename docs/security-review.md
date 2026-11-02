# Security proof preparation review

This review consolidates the current experimental classical protocol for
mathematical work. It does not complete its security argument. The implementation
plan remains paused; verifier behavior and transcript bytes are unchanged by
this preparation pass.

## Findings and disposition

| Finding | Disposition |
| --- | --- |
| Complete wire version, profile schedule and PCS context version were easy to confuse | Defined separately in the proof guide; added a module-level clarification |
| Definitions, assumptions, source arguments and passing observations were interleaved with a long historical ledger | Added a current proof guide, source map and ordered obligation table; retained historical investigations |
| The submitted-call worksheet used `established=True` for a source-reviewed argument and finite controls | Added `source_reviewed=True`; left mathematical establishment false pending proof review, without changing numerical bounds |
| A fresh clone would lack the local trace/binary artifacts referenced by the ledger | Marked those as local historical evidence; the checkpoint contains source/tests rather than claiming to distribute captures |
| Dependency resolution and the source boundary were not pinned together | Track `Cargo.lock` and add a verifiable repository-file manifest |
| Fixed-budget, success-floor and conditional-hazard results have different premises | Documented the distinction and the required common adversarial experiment |

## Open issues for the proof author

1. **Choose and state the theorem instance.** Schedule-5 Brakedown is a useful
   first target, with schedule 4 and the other PCS backends treated separately.
   No query quota has yet been justified as a 128-bit profile.
2. **Fix a common source interpretation.** Local opening equations and passing
   path checks do not establish one decoded word/witness for every root/context
   under arbitrary adaptive prefixes. Extraction needs an explicit argument.
3. **Complete stream and prefix coverage.** Independent readers, repeated
   inputs, unread/partial outputs, child links and off-path v4 descendants must
   belong to one consistent oracle experiment. Unknown inputs cannot disappear
   from a union bound.
4. **Review malformed NTT processing in the cost model.** In
   `packed_ntt::verify_canonical`, field validation and row challenges precede
   appending folded polynomial vectors; `check_folded` checks their dimensions
   afterward. It rejects malformed dimensions before coefficient-compression
   queries, but the preceding traversal/serialization must be accounted for.
   This is a processing/resource-proof issue identified by source inspection,
   not an identified accepting forgery. No guard was moved in this cleanup.
5. **Define charged work and initial conditions.** Honest setup offsets, repeated
   submissions and shared-string construction require an explicit cost coupling.
   The stronger conditional-hazard premise is not implied by a cumulative CDF.
6. **Discharge code-level resource arguments.** Per-call and parent-call arguments
   are available for review. They do not establish every transcript/hash input,
   direct primitive call, intermediate construction or global conditional bound.
7. **Specify the byte boundary.** The public verifier accepts a typed proof.
   A theorem about arbitrary proof bytes must also fix the decoder and its
   treatment of trailing data, field representations and allocations.

## Validation and evidence scope

The local review reruns the Python analysis tests, helper transcript tests and
targeted Rust PCS/NTT controls. The source manifest verifies the checkpoint's contents; Git
preserves its parent history. Large historical jobs and their local results do
not become distributed proof evidence merely because this source is committed.

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -s tools -p 'test_*.py'` | 357 passed, including six checkpoint integrity controls |
| `cargo test --locked -p helper --features transcript-audit` | 47 passed; no failing doctests |
| `cargo test --locked -p pcs --features transcript-audit --test classical_hash_resources --test block_rs --test block_rs_lift` | 8 passed |
| `cargo test --locked -p snarks --test packed_ntt` | 2 passed, including legacy wire/transcript comparisons |
| `git diff --check` | Passed |

The review runs used Rust/Cargo 1.98.0 and Python 3.12.3 on the current Linux
workspace. The Cargo tests were initially run against the retained lockfile;
the commands above add `--locked` for reproduction. This is targeted validation,
not a new exhaustive run of every workspace test or a matched native benchmark.

The checkpoint integrity controls detect changed, added and removed files,
changed executable modes and symlink spellings, duplicate records, accidental
overwrite and attempted security-label promotion. Ignored build/trace products
are excluded, and verification remains valid after the checkpoint is committed.

Earlier native v4/v5 runs demonstrate original-size correctness. Their Q=1
configuration establishes neither the 128-bit proof-security target nor the
security-matched performance gate. The four-profile delegated-failure control
demonstrates error-path counting on synthetic n32/LWE21 keys. Each has the
finite scope described in the implementation ledger.

## How to continue

Verify `security-proof-baseline.json`, read the proof guide, and begin with P1/P2.
Give each lemma its hypotheses, probability space, proof and source mapping.
Use code changes only when a specific proof obligation requires them; a change
to protocol behavior requires a new baseline and an explanation of whether
accepted proof bytes or transcript order changed. Select security parameters
and run the final matched performance comparisons after the security bounds
have been justified.
