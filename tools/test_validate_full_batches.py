import copy
import unittest

from test_compare_extension_profiles import fixture, encode
from validate_full_batches import validate, match_native_reference


def batch_fixture(field):
    gold = field == "goldilocks"
    layouts, reference = fixture("d3-w4" if gold else "d5-w8")
    row = reference[0]
    if not gold:
        row.update(field=field, prime=2013265921, private_coefficient_roots=9, ntt_links=9)
        for layout in layouts:
            layout["prime"] = row["prime"]
    rows = []
    for size in (1, 4, 16):
        for index in range(size):
            i = len(rows)
            left, right = index & 1, (index >> 1) & 1
            rows.append(dict(row, iteration=i, validation_mode="independent-fresh-inputs",
                validation_group_size=size, validation_group_index=index,
                left_plaintext=left, right_plaintext=right, decrypted_plaintext=1-left*right,
                statement_sha256=f"{i:064x}", proof_sha256=f"{i+100:064x}"))
    return layouts, rows


class AggregateValidationTests(unittest.TestCase):
    def test_version_four_is_explicit_and_not_cross_statement_aggregation(self):
        layouts,rows=batch_fixture("goldilocks")
        for row in rows:
            row.update(protocol_version=4,transcript="merlin-direct-extension-comparisons-aggregated-hadamard-v1",hadamard_backend="multi-root")
        result=validate(encode(layouts,rows),"goldilocks",aggregate_hadamard=True)
        self.assertEqual(result["proofs"],21)
        self.assertTrue(result["aggregate_hadamard"])
        self.assertIn("within-proof Hadamard aggregation",result["scope"])
        self.assertIn("no cross-statement aggregation",result["scope"])
        with self.assertRaises(ValueError):validate(encode(layouts,rows),"goldilocks")
        rows[0]["hadamard_backend"]="independent"
        with self.assertRaises(ValueError):validate(encode(layouts,rows),"goldilocks",aggregate_hadamard=True)

    def test_version_five_requires_explicit_deferred_mode(self):
        layouts,rows=batch_fixture("goldilocks")
        for row in rows:
            row.update(protocol_version=5,transcript="merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1",
                       hadamard_backend="multi-root",lookup_backend="deferred-extension")
        result=validate(encode(layouts,rows),"goldilocks",aggregate_hadamard=True,defer_lookup_sources=True)
        self.assertEqual(result["proofs"],21)
        self.assertTrue(result["defer_lookup_sources"])
        self.assertIn("per-decomposition deferred",result["scope"])
        self.assertIn("no cross-statement aggregation",result["scope"])
        for options in [{},{"aggregate_hadamard":True},{"defer_lookup_sources":True},
                        {"aggregate_hadamard":True,"defer_lookup_sources":1}]:
            with self.assertRaises(ValueError):validate(encode(layouts,rows),"goldilocks",**options)
        rows[0]["lookup_backend"]="extension"
        with self.assertRaises(ValueError):validate(encode(layouts,rows),"goldilocks",aggregate_hadamard=True,defer_lookup_sources=True)


class BatchValidationTests(unittest.TestCase):
    def test_shifted_lane_baseline_joint_bound_and_protocol(self):
        layouts, rows = batch_fixture("babybear")
        for layout, left in zip(layouts, (3, 6, 1, 5)):
            layout["left_vars"] = left
            layout["row_message_scalars"] = 1 << (layout["variables"]-left)
            layout["row_message_blocks"] = layout["row_message_scalars"] // 8
            layout["row_encoded_blocks"] = max(32, 2*layout["row_message_blocks"])
        for row in rows:
            row.update(lookup_field_degree=1, lookup_backend="lanes", lookup_repetitions=16,
                       protocol_version=2, transcript="merlin-direct-canonical-rejection-v1",
                       helper_left_extra=1)
        result = validate(encode(layouts, rows), "babybear", profile="babybear-lanes-helper1")
        self.assertAlmostEqual(result["all_21_interactive_union_bits"], 130.2644925753674)
        for change in (dict(protocol_version=3), dict(lookup_backend="extension"),
                       dict(lookup_field_degree=6), dict(lookup_repetitions=15),
                       dict(transcript="legacy-aes128-seed"), dict(helper_left_extra=0)):
            rr = copy.deepcopy(rows)
            rr[0].update(change)
            with self.assertRaises(ValueError):
                validate(encode(layouts, rr), "babybear", profile="babybear-lanes-helper1")
        with self.assertRaises(ValueError):
            validate(encode(layouts, rows), "babybear", profile="babybear6-helper1")
        with self.assertRaises(ValueError):
            validate(encode(layouts, rows), "goldilocks", profile="babybear-lanes-helper1")

    def test_degree_six_joint_bound_and_profile_separation(self):
        layouts, rows = batch_fixture("babybear")
        for layout, left in zip(layouts, (3, 6, 1, 5)):
            layout["left_vars"] = left
            layout["row_message_scalars"] = 1 << (layout["variables"]-left)
            layout["row_message_blocks"] = layout["row_message_scalars"] // 8
            layout["row_encoded_blocks"] = max(32, 2*layout["row_message_blocks"])
        for row in rows:
            row.update(lookup_field_degree=6, helper_left_extra=1)
        result = validate(encode(layouts, rows), "babybear", profile="babybear6-helper1")
        self.assertAlmostEqual(result["all_21_interactive_union_bits"], 130.50894876851953)
        with self.assertRaises(ValueError):
            validate(encode(layouts, rows), "babybear", profile="babybear8-helper1")
        with self.assertRaises(ValueError):
            validate(encode(layouts, rows), "goldilocks", profile="babybear6-helper1")

    def test_degree_eight_actual_native_layout_and_joint_bound(self):
        layouts, rows = batch_fixture("babybear")
        for layout, left in zip(layouts, (3, 6, 1, 5)):
            layout["left_vars"] = left
            layout["row_message_scalars"] = 1 << (layout["variables"]-left)
            layout["row_message_blocks"] = layout["row_message_scalars"] // 8
            layout["row_encoded_blocks"] = max(32, 2*layout["row_message_blocks"])
        for row in rows:
            row.update(lookup_field_degree=8, helper_left_extra=1)
        result = validate(encode(layouts, rows), "babybear", profile="babybear8-helper1")
        self.assertAlmostEqual(result["all_21_interactive_union_bits"], 130.50894878333006)
        for mode in ("standard", "unshifted", "wrong-degree", "wrong-extra", "weak-queries"):
            ll, rr = copy.deepcopy(layouts), copy.deepcopy(rows)
            if mode == "unshifted": ll[1]["left_vars"] -= 1
            elif mode == "wrong-degree": rr[0]["lookup_field_degree"] = 5
            elif mode == "wrong-extra": rr[0]["helper_left_extra"] = True
            elif mode == "weak-queries": ll[0]["queries"] = 32
            with self.assertRaises(ValueError):
                validate(encode(ll, rr), "babybear", profile="standard" if mode == "standard" else "babybear8-helper1")
        with self.assertRaises(ValueError):
            validate(encode(layouts, rows), "goldilocks", profile="babybear8-helper1")

    def test_reference_checks_keys_but_allows_fresh_statements(self):
        layouts, rows = batch_fixture("goldilocks")
        result = validate(encode(layouts, rows), "goldilocks")
        reference = dict(rows[0], statement_sha256="f"*64, lookup_field_degree=5, width=8)
        match_native_reference(result, encode(layouts, [reference]))
        for change in (dict(native_keys_sha256="e"*64), dict(fhe_parameters_sha256="e"*64),
                       dict(full_parameters=1), dict(verified=False), dict(polynomial_size=32)):
            with self.assertRaises(ValueError):
                match_native_reference(result, encode(layouts, [dict(reference, **change)]))
        with self.assertRaises(ValueError): match_native_reference(result, "")

    def test_both_fields_and_union(self):
        for field in ("babybear", "goldilocks"):
            result = validate(encode(*batch_fixture(field)), field)
            self.assertEqual(result["proofs"], 21)
            self.assertGreater(result["per_proof_interactive_bits"], 128)
            self.assertAlmostEqual(result["per_proof_interactive_bits"] - result["all_21_interactive_union_bits"], 4.392317422778761)
        self.assertLess(validate(encode(*batch_fixture("babybear")), "babybear")["all_21_interactive_union_bits"], 128)

    def test_incomplete_and_duplicate_groups(self):
        for mode in ("missing", "duplicate", "wrong-index", "wrong-order"):
            layouts, rows = batch_fixture("goldilocks")
            if mode == "missing": rows.pop()
            elif mode == "duplicate": rows[-1] = rows[-2]
            elif mode == "wrong-index": rows[-1]["validation_group_index"] = 14
            else: rows[1], rows[2] = rows[2], rows[1]
            with self.assertRaises(ValueError): validate(encode(layouts, rows), "goldilocks")

    def test_truth_table_dimensions_and_scope(self):
        for change in [dict(left_plaintext=1), dict(decrypted_plaintext=0), dict(input_dimension=32),
                       dict(batch_size=16), dict(verified=1), dict(full_parameters=1),
                       dict(validation_mode="repeated-statement"), dict(lookup_field_degree=5),
                       dict(verification_scope="legacy-four-stage-wrapper-in-memory")]:
            layouts, rows = batch_fixture("goldilocks")
            rows[0].update(change)
            with self.assertRaises(ValueError): validate(encode(layouts, rows), "goldilocks")

    def test_freshness_and_setup_reuse(self):
        for key in ("statement_sha256", "proof_sha256", "native_keys_sha256", "fhe_parameters_sha256", "setup_ns"):
            layouts, rows = batch_fixture("babybear")
            rows[1][key] = rows[0][key] if key in ("statement_sha256", "proof_sha256") else ("f"*64 if key.endswith("sha256") else 6)
            with self.assertRaises(ValueError): validate(encode(layouts, rows), "babybear")

    def test_weak_or_duplicate_layout_and_invalid_costs(self):
        for mode in ("weak", "duplicate", "negative", "complete", "empty-proof"):
            layouts, rows = batch_fixture("goldilocks")
            if mode == "weak": layouts[0]["queries"] = 32
            elif mode == "duplicate": layouts.append(copy.deepcopy(layouts[0]))
            elif mode == "negative": rows[0]["verify_ns"] = -1
            elif mode == "complete": rows[0]["complete_ns"] = 1
            else: rows[0]["proof_bytes"] = 0
            with self.assertRaises(ValueError): validate(encode(layouts, rows), "goldilocks")


if __name__ == "__main__": unittest.main()
