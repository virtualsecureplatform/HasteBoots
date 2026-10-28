# Fresh full-PBS false-lookup certificates

The complete binding audit now constructs invalid lookup witnesses in either
blind-rotation decomposition (`LookupA`, `LookupB`) and final key switching
(`SwitchLookup`). Both versions 10 and 11 are checked over BabyBear6 and
Goldilocks3 through Brakedown, independent masked and joint-source masked PCS.
These are fresh complete certificates, not mutations of an honest transcript.

## Construction and strict replay

Start with the existing algebraic control and compute its honest radix digits
and borrow columns. Before committing the borrow roots or sampling lookup
challenges, replace intermediate borrow column one by the constant field value
two. Reconstruction involves the original source and digits; endpoint checks
involve only the first and last borrow columns. They therefore remain true.
The committed intermediate value is not a Boolean borrow, so the adjacent
transition tuples lie outside the caller-derived public lookup table.

Construct reciprocal helpers and sumcheck algebra using the separate honest
borrow columns. This valid reference witness supplies multiplicities and
reciprocals, while all source claims and PCS openings use the actual committed
columns, including the bad value two. The certificate does not authenticate a
substituted source root or change public tables, challenges or parameters.
The terminal reciprocal equation must detect the difference between the actual
source and the algebra's foreign witness.

Private test-only lookup constructors reuse the existing foreign-witness path.
The reference verifier retains public-table sum claims, helper/sum equality,
sumcheck verification, canonical encodings, helper authentication and every
actual-source opening. Only the specifically identified terminal reciprocal
identity is reported as false; all other errors still abort replay. It continues
through later lookups and all remaining PBS stages, then compares both the field
challenge and the 32-byte transcript fingerprint with construction. Production
must reject at `terminal reciprocal identity`.

The decomposition audit separately reports its three linear checks and lookup
validity; final key switching propagates both reports. All products, linkage,
rotations, extraction and every unrelated comparison must remain valid. One
lookup-validity report covers adjacent invalid transitions, not exactly one
internal scalar equation. The public PBS statement may remain unchanged: these
cases test rejection of an invalid auxiliary witness, not a claim that each
public NAND output is false.

## Validation

All 80 default SNARK tests and 24 manual masked false-lookup tests pass, as does
the locked workspace check. The default run checks 72 fresh Brakedown complete
certificates, including the twelve new false lookups. Manual cases check twelve
independent masked and twelve joint masked certificates. All 36 new false
lookups reject at the intended terminal identity, with all other reported
obligations valid. Across the 96 checked complete records, four controls accept
and 92 attacks reject.

| Backend | Version 10 | Version 11 |
| --- | --- | --- |
| Brakedown | 6 rejected / 2 fields | 6 rejected / 2 fields |
| Independent masked | 6 rejected / 2 fields | 6 rejected / 2 fields |
| Joint-source masked | 6 rejected / 2 fields | 6 rejected / 2 fields |

All sixty earlier Brakedown binding certificates retain their exact serialized
proof hashes, byte sizes, 32-byte fingerprints and production errors across
this audit refactor. Four deliberately altered lookup-report exercises reject:
hidden lookup failure, extra linear failure, wrong rejection stage and accepted
invalid lookup.

The 24 manual cases completed in 242.47 seconds with eight Rayon threads and
24 test workers. This is audit throughput, not a latency benchmark. Existing
masked binding cases were not rerun in this extension. Their original fixtures
and names remain available; there are now 144 opt-in masked tests including the
new lookup cases.

Release code is unchanged. New lookup reference modules have `cfg(test)` guards;
all changed comparison methods and complete-audit hooks are test-only. The
source checker removes these guarded items while preserving other nonblank
source lines and string contents, then compares with the baseline. Executed
and final code/lock snapshots agree exactly. Raw logs, coverage-checked records,
source comparisons, hashes and the frozen executable are retained under
`target/performance/full-false-lookup-audit/`.

## Reproducing and scope

```sh
RAYON_NUM_THREADS=8 cargo test --release --locked -p snarks --lib \
  false_lookup -- --ignored --nocapture --test-threads=8 > manual.log 2>&1
python3 tools/check_complete_binding_audit.py --log manual.log \
  --backend masked-joint --scope false-lookups --output checked-joint.json
```

The checker distinguishes original `binding`, `false-lookups`, and combined
`all` coverage. New scopes require explicit lookup-validity reports. It checks
reports and Rust completion, not proof bytes independently.

These cases use zero-key algebraic controls and public mask seeds at N=32,
LWE=21, one PCS query and one lookup repetition. They add one concrete family
of full lookup-composition forgeries. Broader lookup attacks, secure encrypted
original-size adversarial profiles, robust vector proximity, base-projection
knowledge, whole-proof Fiat–Shamir/hash/knowledge composition, adaptive hiding,
full query/FRI aggregation, independent review and original promotion gates
remain open. This audit is not a security theorem or a performance promotion.
