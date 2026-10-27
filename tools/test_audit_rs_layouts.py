import copy
import unittest

from audit_rs_layouts import audit_layout, audit_packet
from test_compare_joint_target_profiles import fixture
from test_compare_extension_profiles import fixture as extension_fixture


class LayoutAuditTests(unittest.TestCase):
    def test_packet_rejects_legacy_seed_expansion(self):
        layouts, rows = fixture("extension")
        by_role = {layout["role"]: layout for layout in layouts}
        result = audit_packet(rows[0], by_role)
        self.assertEqual(result["lookup_degree"], 6)
        legacy = dict(rows[0], protocol_version=1, transcript="legacy-aes128-seed")
        with self.assertRaises(ValueError): audit_packet(legacy, by_role)

    def test_native_symbol_field_is_separate_from_lookup_field(self):
        for layout in fixture("extension")[0]:
            result = audit_layout(layout)
            self.assertEqual(result["symbol_degree"], 8)
            self.assertTrue(result["current_random_term_dominates"])
            self.assertTrue(result["current_tail_dominates_both"])
        for layout in extension_fixture("d3-w4")[0]:
            result = audit_layout(layout)
            self.assertEqual(result["symbol_degree"], 4)
            self.assertTrue(result["current_random_term_dominates"])

    def test_padding_wrong_alphabet_and_bad_ntt_domain_reject(self):
        base = fixture("extension")[0][0]
        for change in (dict(row_message_scalars=base["row_message_scalars"]-1),
                       dict(block_width=4), dict(row_encoded_blocks=33),
                       dict(prime=101), dict(queries=True), dict(row_code="scalar-rs")):
            with self.assertRaises(ValueError): audit_layout(dict(base, **change))

    def test_small_width_is_not_silently_covered_by_existing_term(self):
        layout = copy.deepcopy(fixture("extension")[0][-1])
        layout.update(width=2, block_width=2, row_message_scalars=32,
                      row_message_blocks=16, row_encoded_blocks=32)
        result = audit_layout(layout)
        self.assertFalse(result["current_random_term_dominates"])
        self.assertTrue(result["current_tail_dominates_both"])


if __name__ == "__main__": unittest.main()
