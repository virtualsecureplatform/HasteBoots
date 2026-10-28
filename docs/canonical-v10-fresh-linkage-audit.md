# Fresh complete version-10 linkage certificates

The test-only version-10 audit constructs fresh complete certificates under the
requested statement, trusted setup and actual source roots. It does not mutate
or replay an honest proof after Fiat-Shamir challenges have been sampled.

The linkage fixtures use zero native evaluation-key samples and a constant
accumulator. The key-product fixture uses radix-weighted trusted body-key limbs
and a nonzero rotation, with the actual trace computed for the zero key. These
are exact algebraic
adversarial fixtures, not secure encrypted-key profiles or original-size native
runs. The existing encrypted version-10 completeness fixtures remain separate.

## Cases and strict replay

Each backend/field pair has an accepted control and fourteen rejected cases:

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

- `KeyProduct`: canonical digits encode the genuine rotated external input,
  but its zero sum product belongs to a foreign zero bootstrapping key. The
  requested trusted key has radix-weighted body-key limbs; its actual source
  terminals and all downstream children authenticate successfully.

- `SwitchKeyProduct`: a genuine trusted blind-rotation product creates a nonzero
  accumulator mask. The known negative-mask source and canonical digits are
  correct, but the final zero sum product belongs to a foreign zero switching
  key. All final-stage openings authenticate the requested radix-weighted
  switching key; extraction remains valid for the zero product.

- `CanonicalA`, `CanonicalB` and `SwitchCanonical`: the committed digits encode
  integer p for a source equal to field zero in either blind-rotation half or
  final key switching. Reconstruction in the field and the initial zero borrow
  hold. Every genuine digit/borrow lookup transition holds, while the final
  borrow is one and must be rejected. All other PBS stage equations hold.

Every certificate is serialized and decoded. Independent complete replay uses
production NTT and lookup verification. Test-only decomposition, key-product,
accumulator, monomial and final key-switch replay separately report both key products, linkage,
public-factor and extraction identities, plus each decomposition's reconstruction
and initial/final zero-borrow identities, while strictly authenticating every
actual-root PCS opening and checking all other stage equations. Each attack fails only its
intended identity. Prover and replay finish with identical transcript challenges.
Production accepts each control and rejects each attack at its intended stage.

The reference entry points and full certificate constructor are compiled only
under `cfg(test)`. Release prover/verifier APIs and the proof format are unchanged;
no proof flag selects relaxed checks.

## Scope and remaining work

The audit covers foreign bootstrapping-key and switching-key products, accumulator
linkage, public rotations, final extraction and noncanonical modulus digit strings.
It does not replace fresh complete false-lookup certificates or an audit using
secure encrypted original-size fixtures. Component attacks at those layers are
already separate evidence, not a substitute for complete composition checks.

The masked fixtures use one proximity query for completeness testing. General
hiding, robust vector proximity, knowledge/Fiat-Shamir composition, genuine joint
aggregation and the original matched-security performance gates remain open.

## Running and evidence

The two ordinary audit tests generate thirty certificates. The thirty
masked tests each generate one full certificate and are explicitly ignored by
default because they require substantial CPU and memory. Run them manually:

```sh
RAYON_NUM_THREADS=8 cargo test --release --locked -p snarks --lib \
  packed_pbs::canonical::audit::masked_ -- --ignored --nocapture --test-threads=2
```

The validation run used thirty concurrent audit workers on the available
125-GiB host. Both backends and fields have one accepted control and fourteen
rejected attacks, for sixty fresh complete certificates overall: four controls
accepted and fifty-six attacks rejected. All strict child replay and final
transcript equality checks pass.

Validation passes 62 default release/locked unit tests and all thirty manual
masked audit tests, for 92 unique test cases. The locked workspace check passes.
The validated source snapshot, checked certificate records and logs are under
`target/performance/v10-fresh-canonicity-audit/`. The earlier accumulator-only run
remains archived under `target/performance/v10-fresh-linkage-audit/`.
