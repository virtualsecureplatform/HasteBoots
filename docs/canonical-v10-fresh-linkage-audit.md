# Fresh complete version-10 linkage certificates

The test-only version-10 audit constructs fresh complete certificates under the
requested statement, trusted setup and actual source roots. It does not mutate
or replay an honest proof after Fiat-Shamir challenges have been sampled.

The fixtures use zero native evaluation-key samples, identity rotations and a
constant accumulator to isolate linkage obligations. These are exact algebraic
adversarial fixtures, not secure encrypted-key profiles or original-size native
runs. The existing encrypted version-10 completeness fixtures remain separate.

## Cases and strict replay

Each backend/field pair has an accepted control and six rejected cases:

- `Initial`: a different requested input body changes the public initial
  accumulator while the committed accumulator belongs to the original body.
- `Final`: a changed final accumulator/body is consistent with final key
  switching, but differs from the committed blind-rotation endpoint.
- `Addition`: the output accumulator word differs from input plus sum.
- `Chain`: one interior input/product/output entry changes together, preserving
  local arithmetic and monomial identities while breaking round continuity.
- `DigitA` and `DigitB`: independently valid decomposition source/digit words
  differ from the actual external-product half they must represent.

Every certificate is serialized and decoded. Independent complete replay uses
production Hadamard, NTT, decomposition, monomial and final key-switch verifiers.
The accumulator replay checks dimensions, canonical responses and every genuine
PCS opening against caller-derived roots/queries, then reports its arithmetic
result separately. The prover and replay finish with identical transcript
challenges. Production accepts the control and rejects each attack at
accumulator linkage. Other stage equations remain strict.

The two accumulator reference entry points and full certificate constructor are
compiled only under `cfg(test)`. The release prover/verifier APIs and proof
format are unchanged; no proof flag selects relaxed checks.

## Scope and remaining work

The audit covers complete certificates that are false at accumulator linkage.
It does not replace fresh complete attacks at key products, public rotations,
canonical comparison identities or final extraction, nor an audit using secure
encrypted original-size fixtures. Component attacks at those layers are already
separate evidence, not a substitute for complete composition checks.

The masked fixtures use one proximity query for completeness testing. General
hiding, robust vector proximity, knowledge/Fiat-Shamir composition, genuine joint
aggregation and the original matched-security performance gates remain open.

## Running and evidence

The two ordinary audit tests generate fourteen certificates. The fourteen
masked tests each generate one full certificate and are explicitly ignored by
default because they require substantial CPU and memory. Run them manually:

```sh
RAYON_NUM_THREADS=8 cargo test --release --locked -p snarks --lib \
  packed_pbs::canonical::audit::masked_ -- --ignored --nocapture --test-threads=2
```

The validation run used fourteen concurrent audit workers on the available
125-GiB host. All fourteen masked cases passed. Both backend/field pairs have
one accepted control and six rejected attacks, for twenty-eight fresh complete
certificates overall: four controls accepted, twenty-four attacks rejected.
All strict child replay and final transcript equality checks pass.

`target/performance/v10-fresh-linkage-audit/executed-sources.tar.gz` freezes the
source that produced the manual run. The final source differs only in test
selection metadata (the expensive cases are now opt-in) and documentation.
The ignored-test listing verifies that all fourteen cases remain runnable.
The final source snapshot, logs and checked records are archived alongside it.

Validation passes 62 default release/locked unit tests and all fourteen manual
masked audit tests, for 76 unique test cases. The locked workspace check passes.
The source snapshots, selection listing, checked certificate records and logs
are under `target/performance/v10-fresh-linkage-audit/`.
