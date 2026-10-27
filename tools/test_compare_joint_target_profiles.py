import copy
import unittest

from compare_joint_target_profiles import controls, compare, PROFILES
from test_validate_full_batches import batch_fixture
from test_compare_extension_profiles import encode


def fixture(profile):
    layouts, fresh = batch_fixture("babybear")
    for layout, left in zip(layouts, (3, 6, 1, 5)):
        layout["left_vars"] = left
        layout["row_message_scalars"] = 1 << (layout["variables"]-left)
        layout["row_message_blocks"] = layout["row_message_scalars"] // 8
        layout["row_encoded_blocks"] = max(32, 2*layout["row_message_blocks"])
    degree, reps, version, transcript = PROFILES[profile]
    rows = [dict(fresh[0], iteration=i, helper_left_extra=1, lookup_backend=profile,
        lookup_field_degree=degree, lookup_repetitions=reps, protocol_version=version,
        transcript=transcript, validation_mode="repeated-statement", validation_group_size=1,
        validation_group_index=0, left_plaintext=1, right_plaintext=1, decrypted_plaintext=0,
        proof_sha256=("e" if profile == "lanes" else "f")*64,
        complete_ns=100 if profile == "lanes" else 70,
        proof_bytes=100 if profile == "lanes" else 90) for i in (0, 1)]
    return layouts, rows


def packets():
    return {(s, p): controls(encode(*fixture(p)), p) for s in (0, 1) for p in PROFILES}


class JointTargetTests(unittest.TestCase):
    def test_common_target_and_engineering_gates(self):
        result = compare(packets())
        self.assertTrue(result["latency_engineering_gate"])
        self.assertTrue(result["bytes_engineering_gate"])
        for row in result["comparisons"]:
            self.assertAlmostEqual(row["lane_joint_21_bits"], 130.2644925753674)
            self.assertAlmostEqual(row["extension_joint_21_bits"], 130.50894876851953)
        self.assertIn("no FS", result["scope"])

    def test_protocol_scope_and_weak_geometry(self):
        for change in (dict(lookup_repetitions=1), dict(lookup_field_degree=6),
                       dict(protocol_version=3), dict(verified=1), dict(output_dimension=1024),
                       dict(helper_left_extra=0), dict(verification_scope="legacy-four-stage-wrapper-in-memory")):
            layouts, rows = fixture("lanes"); rows[0].update(change)
            with self.assertRaises(ValueError): controls(encode(layouts, rows), "lanes")
        for mode in ("duplicate", "missing", "unshifted", "weak"):
            layouts, rows = fixture("extension")
            if mode == "duplicate": layouts.append(copy.deepcopy(layouts[0]))
            elif mode == "missing": rows.pop()
            elif mode == "unshifted": layouts[1]["left_vars"] -= 1
            else: layouts[0]["queries"] = 64
            with self.assertRaises(ValueError): controls(encode(layouts, rows), "extension")

    def test_reused_fixture_and_wire_are_fixed(self):
        for key in ("statement_sha256", "proof_sha256", "native_keys_sha256", "proof_bytes", "setup_ns"):
            layouts, rows = fixture("lanes")
            rows[1][key] = "d"*64 if key.endswith("sha256") else 101
            with self.assertRaises(ValueError): controls(encode(layouts, rows), "lanes")

    def test_cross_profile_and_cross_process_integrity(self):
        original = packets()
        for key in ("statement_sha256", "native_keys_sha256", "proof_sha256", "pcs_layouts"):
            changed = copy.deepcopy(original)
            if key == "pcs_layouts": changed[(1, "extension")][0][key]["helper"]["left_vars"] -= 1
            else: changed[(1, "extension")][0][key] = "d"*64
            with self.assertRaises(ValueError): compare(changed)
        original.pop((1, "lanes"))
        with self.assertRaises(ValueError): compare(original)

    def test_cost_failures_do_not_become_promotion_claims(self):
        changed = packets()
        for session in (0, 1):
            for row in changed[(session, "extension")]:
                row["complete_ns"] = 95
                row["proof_bytes"] = 250
        result = compare(changed)
        self.assertFalse(result["latency_engineering_gate"])
        self.assertFalse(result["bytes_engineering_gate"])
        self.assertIn("no FS/security-matched promotion", result["scope"])


if __name__ == "__main__": unittest.main()
