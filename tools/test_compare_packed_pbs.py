import unittest
import copy
from compare_packed_pbs import PROFILE,compare

class PackedComparisonTests(unittest.TestCase):
    def fixture(self):
        return dict({k:1 for k in PROFILE},complete_ns=100,proof_bytes=100)
    def test_size_and_latency_thresholds_are_independent(self):
        old=self.fixture();result=compare(old,dict(old,complete_ns=80,proof_bytes=250))
        self.assertTrue(result["latency_below_90_percent"])
        self.assertFalse(result["bytes_within_2x"])
        self.assertIn("no security-matched promotion",result["security"])
        result=compare(old,dict(old,complete_ns=91,proof_bytes=100))
        self.assertFalse(result["latency_below_90_percent"])
        self.assertTrue(result["bytes_within_2x"])
    def test_transcript_version_changes_are_not_paired_as_one_protocol(self):
        old=dict(self.fixture(),protocol_version=1,transcript="legacy-aes128-seed")
        new=dict(old,protocol_version=2,transcript="merlin-direct-canonical-rejection-v1")
        with self.assertRaises(ValueError):compare(old,new)

    def test_final_stage_layout_changes_are_also_rejected(self):
        old=self.fixture()
        old["pcs_layouts"]={role:{"queries":32} for role in ["source","helper","final_source","final_helper"]}
        for role in ["final_source","final_helper"]:
            new=copy.deepcopy(old);new["pcs_layouts"][role]["queries"]=33
            with self.assertRaises(ValueError):compare(old,new)

    def test_changed_parameter_inventory_and_missing_metrics_fail(self):
        old=self.fixture()
        for key in ["prime","source_queries","ntt_links","output_dimension","seed","helper_left_vars"]:
            with self.assertRaises(ValueError):compare(old,dict(old,**{key:2}))
        for change in [dict(complete_ns=0),dict(proof_bytes=None),dict(complete_ns=2.5)]:
            with self.assertRaises(ValueError):compare(old,dict(old,**change))

    def test_extension_degree_is_part_of_the_protocol_profile(self):
        old=dict(self.fixture(),protocol_version=3,lookup_backend="extension",lookup_field_degree=5)
        compare(old,dict(old))
        for change in [dict(lookup_field_degree=8),dict(lookup_backend="lanes")]:
            with self.assertRaises(ValueError):compare(old,dict(old,**change))
