# Native key ownership for canonical backends

`packed_bootstrap_key::canonical` and `packed_key_switch::canonical` commit
trusted native evaluation-key tables through `CanonicalPcs`. The owners retain
only each backend's original state and the expected public key descriptor. They
do not clone or serialize source sessions, create duplicate source commitments,
or accept execution-trace key columns as trusted setup.

The bootstrapping key uses the existing native a/b half and digit ordering,
including padding of the input-mask dimension. The switching key shares its
layout and validation helper with legacy preprocessing: a followed by b for
each digit, checked native polynomial size, radix and digit count. The original
ring/output dimension restriction is preserved.

`packed_pbs::canonical_setup` composes both owners under the existing trusted
PBS configuration. It validates all four logical source/helper geometries and
key parameter contexts. Physical masking capacity cannot change a logical FHE
operation. The public result is the existing `VerifierSetup`, containing only
trusted configuration and key roots. Public key descriptors are serializable
for transport but remain intentionally non-deserializable from proof bytes.

Every call to `br_oracles` or `ks_oracles` borrows the same original states.
Retrieving a fresh oracle vector or cloning the public verifier setup does not
refresh private masks. The caller must provision lifetime budgets across all
future proofs, including repeated factors and decomposition uses. Replacing
trusted setup with newly randomized roots is a new setup operation, not an
implicit refresh of a retained owner.

This module remains a setup boundary. Backend-general complete PBS composition
is integrated separately in versions 10/11; see `canonical-joint-backend.md`.
There is no complete-PBS proof format or verifier in this setup module.
The new setup does not hide public ZeroCheck/NTT messages, prove
robust vector proximity, complete adaptive hiding or certify whole-proof
128-bit security. No native performance result follows from these component
checks.

## Validation

Both selected field pairs use nonconstant N=32 native key fixtures with 21 input
and output LWE coefficients. Every retained table is checked against the native
key's a/b halves, digit ordering and zero padding. Eighteen masked key roots in
total support two serialized/decoded opening rounds, giving 36 verified child
openings. Fresh oracle vectors retain the same counters; a third opening fails.
Different physical contexts, swapped logical geometries, missing switching keys
and incorrect bootstrapping-key round counts are rejected. Independently
randomized setup roots differ even for the same native keys.

Over both base fields, ordinary Brakedown canonical preprocessing produces
exactly the legacy public setup bytes. Existing key-layout, foreign-key binding
and complete key-switch tests remain required, along with the full v7/v8/v9 PBS
regression suites. These fixtures test native data layout, not original-size
native PBS performance.

All 116 selected release/locked tests pass: 95 SNARK components, nine sumcheck
tests and twelve complete v7/v8/v9 PBS integration tests. Sixty fresh full
binding cases preserve six accepted controls and fifty-four rejected attacks.
The locked workspace check passes. Logs, checked records and validated sources
are under `target/performance/canonical-native-key-setup-boundary/`.

## Original-size masked resource validation

Actual original native key owners are now measured with 128 sampling queries
under both retained and transient cache policies. All 88 owner instantiations
and eight decoded opening packets pass, with exact parameter/table/root/proof
and transcript fingerprints across policies. See
`native-masked-key-setup-profile.md` for the measured multi-owner memory
reductions, added opening cost and the remaining complete-PBS/security gates.
