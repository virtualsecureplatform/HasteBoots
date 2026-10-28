# Fresh complete version-10 linkage certificates

The test-only version-10 audit constructs fresh complete certificates under the
requested statement, trusted setup and actual source roots. It does not mutate
or replay an honest proof after Fiat-Shamir challenges have been sampled.

The fixtures use zero native evaluation-key samples, actual identity rotations and a
constant accumulator to isolate linkage obligations. These are exact algebraic
adversarial fixtures, not secure encrypted-key profiles or original-size native
runs. The existing encrypted version-10 completeness fixtures remain separate.

## Cases and strict replay

Each backend/field pair has an accepted control and nine rejected cases:

- `Initial`: a different requested input body changes the public initial
  accumulator while the committed accumulator belongs to the original body.
- `Final`: a changed final accumulator/body is consistent with final key
  switching, but differs from the committed blind-rotation endpoint.
- `Addition`: the output accumulator word differs from input plus sum.
- `Chain`: one interior input/product/output entry changes together, preserving
  local arithmetic and monomial identities while breaking round continuity.
- `DigitA` and `DigitB`: independently valid decomposition source/digit words
  differ from the actual external-product half they must represent.

- `Rotation`: the requested first-round rotation is one while genuine committed
  source words satisfy rotation zero.
- `ExtractionA` and `ExtractionB`: the requested output mask coefficient or body
  differs from the actual final key-switch extraction target.

Every certificate is serialized and decoded. Independent complete replay uses
production Hadamard, NTT and decomposition verification. Test-only accumulator,
monomial and final key-switch replay separately report the linkage, public-factor
and extraction identities while strictly authenticating every actual-root PCS
opening and checking all other stage equations. Each attack fails only its
intended identity. Prover and replay finish with identical transcript challenges.
Production accepts each control and rejects each attack at its intended stage.

The reference entry points and full certificate constructor are compiled only
under `cfg(test)`. Release prover/verifier APIs and the proof format are unchanged;
no proof flag selects relaxed checks.

## Scope and remaining work

The audit covers accumulator linkage, public rotations and final extraction.
It does not replace fresh complete attacks at key products or canonical
comparison identities, nor an audit using secure
encrypted original-size fixtures. Component attacks at those layers are already
separate evidence, not a substitute for complete composition checks.

The masked fixtures use one proximity query for completeness testing. General
hiding, robust vector proximity, knowledge/Fiat-Shamir composition, genuine joint
aggregation and the original matched-security performance gates remain open.

## Running and evidence

The two ordinary audit tests generate twenty certificates. The twenty masked
tests each generate one full certificate and are explicitly ignored by default
because they require substantial CPU and memory. Run them manually:

```sh
RAYON_NUM_THREADS=8 cargo test --release --locked -p snarks --lib \
  packed_pbs::canonical::audit::masked_ -- --ignored --nocapture --test-threads=2
```

The validation run used twenty concurrent audit workers on the available
125-GiB host. Both backends and fields have one accepted control and nine
rejected attacks, for forty fresh complete certificates overall: four controls
accepted and thirty-six attacks rejected. All strict child replay and final
transcript equality checks pass.

Validation passes 62 default release/locked unit tests and all twenty manual
masked audit tests, for 82 unique test cases. The locked workspace check passes.
The validated source snapshot, checked certificate records and logs are under
`target/performance/v10-fresh-stage-audit/`. The earlier accumulator-only run
remains archived under `target/performance/v10-fresh-linkage-audit/`.
