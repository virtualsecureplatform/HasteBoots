# Experimental masked scalar PipFRI

`pcs::pipfri::masked` implements a separate scalar reference based on Protocol 3
of the local PipFRI paper (`refs/2025-1354.pdf`, §4.2). It is not selected by the
ordinary scalar PCS adapter or either complete packed PBS backend.

Each size-m fragment receives m private random padding coefficients. An independent
size-2m random polynomial masks the public target. The proof sends its evaluation,
but no individual fragment-evaluation vector. The padded point appends zero, so
its target remains the original table evaluation. Both coefficient and Boolean
evaluation bases are supported.

The original-fragment/mask low-degree batch is a virtual oracle. Its queried pairs
are reconstructed from authenticated packed source pairs, without building or
committing another combined tree. The public-point fold ladder and rolling FRI
share exactly the same query locations. Ordinary rolling FRI keeps its existing
transcript namespace; the virtual variant has a separate namespace and requires
empty virtual Merkle paths plus an enclosing authentication callback.

Call `commit` with a fresh private cryptographic RNG, retain the resulting
`ProverSession`, and give its commitment plus trusted parameters to a
`VerifierSession`. Both sessions enforce a fixed opening budget and monotone
opening indices. The private session cannot be cloned or serialized. Incorrect
claims fail before spending the prover budget; successful verification advances
the verifier budget. A new verifier session does not reset the prover's private
mask lifetime. Publicly seeded RNGs in tests are reproducibility fixtures only.

Parameters conservatively require

```
m >= max_openings * (2 + queries * (2 + 4*log2(2m)))
```

This numerical allowance is an engineering guard, not a zero-knowledge theorem.
The nonzero mask/batch challenges, repeated openings, Fiat–Shamir transcript and
composition need their own analysis. Merkle hiding requires an explicit hash or
random-oracle argument; authentication alone does not establish it.

Tests cover serialization and transcript agreement, two-opening budgets, replay,
malformed/tampered source and virtual pairs, both bases, and prime/extension
arithmetic. Fresh false evaluation and false mask-evaluation certificates use
genuine source/fold commitments and paths; strict verification rejects their
terminal public-fold equation. Coordinate-wise and generic extension encoders
must produce identical commitments, proofs and transcript states.

The cumulative disclosure audit conditions on two actual openings' public coins
and query positions. An independent coefficient-space implementation reconstructs
every revealed field element and checks equality with the serialized proof view.
For observation matrix A and permitted evaluation matrix Y it tests

```
rank([A; Y 0]) == rank(A_random) + rank(Y)
```

A negative control additionally reveals an unmasked individual fragment evaluation
and must increase the rank. These are finite-field linear-view checks on selected
transcripts, not a general adaptive zero-knowledge proof. Hashes and challenge
dependence remain outside this numerical audit.

Remaining work includes a reviewed masking/soundness argument, concrete complete
proof parameters, standalone complete-PBS binding, native complete-PBS
measurements, and a security-matched comparison. The earlier
non-hiding coordinate-encoding timings do not measure this masked construction.

## Scalar PCS adapter

`pcs::multilinear::masked_pipfri::MaskedPipFRIPCS` is an opt-in implementation
of the existing scalar PCS trait. Its `Specification` explicitly fixes fragment
size, rate, query count and maximum openings per commitment. Setup rejects
insufficient mask capacity and unavailable/overflowing native domains. The
trait-required default parameters are an uninitialized sentinel rejected by
verification. The ordinary adapter and complete packed backends stay separate.

The adapter's private `State` owns one non-cloneable core prover session behind a
mutex. Every single or batch opening spends that same lifetime budget. A batch
locks the session across preflight and all its openings, so concurrent calls
cannot both spend an allowance. Wrong parameters, source kind, root, point
dimensions or insufficient capacity fail before transcript mutation or spending
any allowance. Poisoned locks fail closed. Checked `try_open`, `try_open_ef`,
`try_batch_open` and `try_batch_open_ef` return errors; the existing infallible
trait methods panic on those caller errors after the lock is released. No path
refreshes exhausted masks automatically. Each new commitment draws fresh private
randomness from the OS-seeded thread RNG.

Small logical tables repeat over additional high dummy coordinates until the
configured fragment size is reached. Logical points append zero in those dummy
coordinates. Logical dimension, complete trusted parameters and base/extension
source kind are bound in the adapter transcript; batches also bind all points
and the expected commitment. Verification checks exact vector lengths, proof
indices within the trusted budget, and consecutive indices within each batch.

Trait verification is stateless and deliberately permits independently verifying
a previously accepted proof. It does not enforce a global acceptance counter.
The honest private prover's lifetime bound still applies across calls, and the
core `VerifierSession` remains available for applications that require ordered
acceptance and replay detection. `masked::verify_opening` exposes the same
stateless cryptographic check for enclosing protocols.

Adapter tests cover constants, small tables and multiple fragments, base and
quintic tables, single and 1/4/16-point batches, serialization, transcript
agreement, parameter/kind/root/shape mismatches, malformed proofs, mask capacity
and concurrent spending. Existing scalar LogUp can select the adapter without
changing its relation. This is interface integration, not a complete-PBS
composition or a proof that the whole LogUp transcript hides its witness.

## Native four-stage experiment

`masked_pipfri_pbs_babybear` and `masked_pipfri_pbs_goldilocks` select the quintic
adapter for the existing native modulus-switch, blind-rotation, key-switch and
extraction wrappers. They preserve the original FHE parameter objects and output
key contract. The benchmark checks NAND(1,1) decryption and verifies all four
stages with direct quintic transcripts. It serializes the proof tuple for size
measurement, then verifies the original in-memory proofs. The legacy wrappers
retain witness-derived evaluation fields skipped by serialization; this is not a
standalone decoded-proof verifier or the fully bound complete packed-PBS API.

A cached blind-rotation key retains its private mask session across iterations.
The experiment checks that each PBS spends exactly one key opening, that its
proof index matches the spent allowance, and that the proof carries the expected
key root and parameters. JSON records include before/after budgets, proof index,
actual public fixture/FHE parameter/native key digests, and the retained masked
key root. An over-budget reused-key run is rejected before generating a key;
there is no automatic recommit to refresh masks. `--cold` explicitly requests a
fresh commitment for each iteration. The geometry must independently pass the
core disclosure-capacity guard.

The default experiment uses fragment size 2^14, blowup 2, 64 queries and a lifetime
budget of four openings. These remain experimental unbudgeted parameters, with
no claim that the complete SNARK is zero knowledge or has 128-bit security.

## Parallel implementation

Fragment encoding and packed-leaf hashing now use ordered parallel collection.
Private random padding is still generated in the original sequential order.
Target-coefficient and virtual-source linear combinations split disjoint output
blocks across workers; each output retains its original source/addition order.
This preserves raw field encodings, including permitted lazy representations,
rather than relying only on mathematical field equality. Parameters, roots,
transcript domains, proof structure and lifetime budgets are unchanged.

A pre-parallel sequential commit reference checks coefficient/codeword bytes and
commitment roots. Runs with 1, 2 and 4 workers compare full proof bytes, transcript
states and the next RNG output across both bases, both quintics and both
encoders. Linear combinations also compare raw serialized outputs against the
original sequential addition schedule. All 49 regression tests pass, including
the numerical disclosure audit, concurrent session spending and LogUp integration.

Two reversed-order scalar pairs and native first/reused experiments are archived
under `target/performance/masked-pipfri-parallel/`. This changes implementation
costs, not the remaining masking, soundness, Fiat–Shamir or standalone complete-PBS
requirements. See `performance-results.md` for measured scope and limitations.

For composing protocols, `MaskedPipFRIPCS::try_open_at` and `try_open_at_ef`
return the exact authenticated scalar value together with its proof. This matters
when lazy field encodings allow mathematically equal evaluations to have
different bytes. The ordered-matrix bridge uses this API after a reproduced
Goldilocks boundary failure caused by separately recomputing that value. The
existing proof-only methods share the same checked implementation and retain
their transcript and budget semantics. The regression explicitly exercises
byte-distinct equal values.
