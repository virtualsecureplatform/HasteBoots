import copy
import json
import unittest
from compare_extension_pbs import read_rows,compare

class ExtensionComparisonTests(unittest.TestCase):
    def fixture(self,backend):
        from test_full_pbs_budget import FullInventoryTests
        row,layouts=FullInventoryTests().fixture()
        ext=backend=="extension"
        row.update(field="babybear",lookup_backend=backend,protocol_version=3 if ext else 2,
            transcript="merlin-direct-prime-parent-extension-child-v1" if ext else "merlin-direct-canonical-rejection-v1",
            lookup_field_degree=5 if ext else 1,lookup_repetitions=1 if ext else 16,
            full_parameters=True,seed=42,batch_size=1,verified=True,security="experimental-unbudgeted",
            verification_scope="complete-serialized-public-verifier",statement_sha256="1"*64,
            fhe_parameters_sha256="2"*64,native_keys_sha256="3"*64,proof_sha256=("4" if ext else "5")*64,
            complete_ns=70 if ext else 100,prove_ns=60,serialization_ns=5,verify_ns=10,proof_bytes=80 if ext else 100)
        rows=[dict(row,iteration=i) for i in range(2)]
        return rows,layouts
    def text(self,rows,layouts):
        return "\n".join([*("HB_FULL_PCS "+json.dumps(v) for v in layouts.values()),
                           *("HB_FULL_PBS "+json.dumps(r) for r in rows)])
    def read(self,backend,rows=None,layouts=None):
        fixture_rows,fixture_layouts=self.fixture(backend)
        return read_rows(self.text(fixture_rows if rows is None else rows,
                                   fixture_layouts if layouts is None else layouts),"babybear",backend,2,True)
    def test_complete_cross_protocol_comparison_is_explicit(self):
        result=compare(self.read("lanes"),self.read("extension"))
        self.assertAlmostEqual(result["reused_latency_reduction"],0.3)
        self.assertAlmostEqual(result["proof_bytes_ratio"],0.8)
        self.assertIn("different experimental protocols",result["security"])
    def test_false_verification_truncation_and_inconsistent_profiles_fail(self):
        for change in [dict(verified=False),dict(verified=1),dict(protocol_version=2),
                       dict(lookup_repetitions=16),dict(lookup_field_degree=4),dict(input_dimension=32),
                       dict(proof_bytes=0),dict(iteration=3)]:
            rows,layouts=self.fixture("extension");rows[1].update(change)
            with self.assertRaises(ValueError):self.read("extension",rows,layouts)
        rows,layouts=self.fixture("extension")
        with self.assertRaises(ValueError):self.read("extension",rows[:1],layouts)
        layouts.pop("final_helper")
        with self.assertRaises(ValueError):self.read("extension",rows,layouts)
    def test_duplicate_layouts_or_changed_deterministic_proofs_fail(self):
        rows,layouts=self.fixture("extension")
        text=self.text(rows,layouts)+"\nHB_FULL_PCS "+json.dumps(layouts["source"])
        with self.assertRaises(ValueError):read_rows(text,"babybear","extension",2,True)
        rows[1]["proof_sha256"]="6"*64
        with self.assertRaises(ValueError):self.read("extension",rows,layouts)
    def test_public_keys_ciphertexts_and_all_layouts_must_match(self):
        for key in ["native_keys_sha256","statement_sha256","fhe_parameters_sha256"]:
            new=self.read("extension")
            for row in new:row[key]="6"*64
            with self.assertRaises(ValueError):compare(self.read("lanes"),new)
        new=copy.deepcopy(self.read("extension"))
        new[0]["pcs_layouts"]["final_helper"]["queries"]+=1
        with self.assertRaises(ValueError):compare(self.read("lanes"),new)
