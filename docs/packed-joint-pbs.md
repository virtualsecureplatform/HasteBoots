# Complete joint-Hadamard PBS batches

Experimental version 6 composes one ordered complete NAND PBS certificate for
multiple statements. It replaces the members' Hadamard certificates with one
shared-challenge relation proof and joint PCS authentication. Every other PBS
constraint remains individually checked, including canonical decomposition,
NTT linkage, accumulator arithmetic/continuity, public NAND initialization,
modulus switching, key switching and extraction into the original output key.
This shares authentication across statements; it does not yet share lookup
algebra or authentication across members. Versions 2–5 remain unchanged.

## API and witness ownership

`packed_pbs::batch::{prove,verify}` use a separate `batch::Proof<F,EF,O>` with
checked outer version 6, ordered member constraints, and one mandatory joint
Hadamard certificate. The public verifier takes only trusted parameters/setup
and the expected input/output ciphertext statements. It takes no trace, private
state, independently declared key, or prover-supplied root registry.

Members have a distinct version-6 domain and no standalone Hadamard packet. The
backend omitting that packet is private; no public standalone verifier selects
it. A member object alone is not a complete certificate. The outer verifier
checks every member and always discharges all missing Hadamard obligations.

The prover moves each member's original evaluation tables and PCS states into a
private batch owner after its other constraints succeed. It does not recompute
or recommit those evaluation sources. Public-key states come from the shared
trusted preprocessing. Factor buffers are cloned for the existing algebra API,
so holding multiple traces, retained states and partial certificates increases
peak memory; native memory validation is still in progress.

For each member, expected Hadamard roots are reconstructed from its canonical
evaluation roots and the trusted bootstrapping-key roots, in the original
interleaved order. The outer domain binds version, extension degree, setup,
four parameter contexts, ordered ciphertext statements and ordered root groups
before shared ZeroCheck challenges. Each inner transcript independently binds
its own full statement/setup/canonical sources. The outer binding uses the
canonical roots, rather than hashing entire large member-proof buffers.

The relation frontend checks each equation separately at a common ordered base
matrix query, then authenticates every individual claim using full-extension
aggregation weights. There is no base-field equation-sum compression. No new
source commitments are introduced; conservative root inventories are 75/131
per member in the selected BabyBear/Goldilocks profiles, with trusted key roots
excluded. Repeated public-key roots currently remain repeated PCS sources.

## Examples and conditional inventory

```sh
cargo run -p vfhe --release --example packed_batch_pbs_babybear -- --validation-batches
cargo run -p vfhe --release --example packed_batch_pbs_goldilocks -- --full --validation-batches
```

`--batch-size N` selects a single fresh batch; `--validation-batches` selects
ordered sizes 1/4/16 with one shared key/setup and all NAND input pairs.
`--separate` produces a collection of complete standalone v5 certificates for
the same requested statements. Joint mode reports outer version 6 and transcript
`merlin-direct-joint-hadamard-pbs-batch-v1`; separate mode retains version 5.
Each serialized packet is decoded and publicly verified before reporting.

`tools/validate_joint_pbs_batches.py` requires the exact group schedule, native
dimensions/profile, distinct fresh statements, truth-table results, digest-linked
root counts, verification scope and explicit mode/version. It can compare all
21 statements, keys, parameters and four layouts with the archived standalone
native fixture. It rejects unsupported or mixed metadata.

Its conditional interactive inventory conservatively keeps B times every
standalone-v5 error term for a group of B members. Individual ZeroCheck equations
remain separate, so shared challenges require a union bound, not independence.
The old per-factor source terms dominate the proposed joint concatenated-word
term/tail under the checked native unpadded geometry. B extension cancellation
terms also upper-bound the one new joint cancellation term. This does not
establish Fiat–Shamir, hash-query, knowledge, hiding or whole-proof security.
Independent review of the underlying PCS adaptation and composition remains open.

## Current validation and limits

Both complete batch Rust tests pass fresh sizes 1/4/16, decoded public
verification and decryption of all NAND pairs at ring-32/LWE-21 test dimensions.
They reject wrong versions/counts, omitted joint data, reordered members,
reordered statements even when members follow that reordering, alternate keys,
changed canonical roots/endpoints/decomposition/extraction, and false root
claims preserving the local terminal Hadamard equation. A requested wrong
output cannot be proved with the original trace. The tests cover the last
member, not only the first. Stronger fresh reconstructed-child v6 binding
audits remain pending; mutation tests are not a substitute for them.

Workspace/examples and release builds pass; all 86 Python tests pass. Fifty
decoded standalone v3/v4/v5 packets retain exact archived bytes and bindings.
Two-order toy runs verify all 24 batch/collection packets, covering 168 member
instances. Proof hashes/sizes repeat across order, and both methods bind the
same archived statements/keys/parameters/layouts. At sixteen members, toy bytes
fall only 0.563% (BabyBear) / 0.093% (Goldilocks). These toy numbers do not support
a native performance or promotion claim.

Evidence is under `target/performance/joint-pbs/`: raw logs/resources, exact
executables, commands, checked comparisons, test logs and source provenance.
Build snapshot SHA-256:
`bfcdcc2eedeff63e50990d81958de69ae317ac644ea51525cec60ea47e77b355`;
all 400 files outside `docs/` matched before the toy comparison. Executable
hashes are `88fdf79fe75b67b9f9c77b398b80ff84bc81906c884e3d9820dbc2a61fd43400`
(BabyBear) and `bfd322349602f0680331d22a268c69b347033cd1153080b2aec6ed2c3ababd5f`
(Goldilocks).

Original ring-1024/LWE-728 validation is running serially by field under
`target/performance/joint-pbs-native/`, using these frozen executables. It will
verify three joint certificates per field covering 21 fresh statements and
compare every native fixture. These are correctness-only runs. Completion,
native performance/memory comparisons, further cross-statement stage sharing,
hiding, whole-security review and promotion remain pending.
