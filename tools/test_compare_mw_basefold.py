import json
import unittest
from compare_mw_basefold import read_rows,compare
class MWComparisonTests(unittest.TestCase):
    def fixture(self,backend):
        row=dict(field="babybear",backend=backend,verified=True,full_parameters=True,verification_scope="native-hadamard-only",
            security="experimental-unbudgeted",seed=42,variables=18,width=8,factors=17,queries=544,blowup=2,
            fixture_sha256="1"*64,fhe_parameters_sha256="2"*64,proof_sha256="3"*64,
            commit_ns=10,prove_ns=100 if backend=="mw-brakedown" else 80,serialization_ns=5,verify_ns=10,proof_bytes=100)
        return [dict(row,iteration=i) for i in range(2)]
    def read(self,backend,rows=None):
        rows=self.fixture(backend) if rows is None else rows
        return read_rows("\n".join("HB_MW_COMPARISON "+json.dumps(r) for r in rows),"babybear",backend,2,True,544)
    def test_component_scope_is_explicit(self):
        r=compare(self.read("mw-brakedown"),self.read("structured-mw-basefold"))
        self.assertAlmostEqual(r["reused_prover_reduction"],.2)
        self.assertIn("not complete PBS",r["scope"])
    def test_wrong_verification_or_profile_and_truncation_fail(self):
        for change in [dict(verified=False),dict(verified=1),dict(verification_scope="complete-pbs"),dict(queries=32),dict(factors=33),dict(proof_bytes=0),dict(iteration=3)]:
            rows=self.fixture("structured-mw-basefold");rows[1].update(change)
            with self.assertRaises(ValueError):self.read("structured-mw-basefold",rows)
        with self.assertRaises(ValueError):self.read("structured-mw-basefold",self.fixture("structured-mw-basefold")[:1])
    def test_changed_factors_and_parameters_cannot_be_paired(self):
        for name in ["fixture_sha256","fhe_parameters_sha256","variables","width","queries"]:
            a=self.read("mw-brakedown");b=self.read("structured-mw-basefold")
            for row in b:row[name]="4"*64 if name.endswith("sha256") else 123
            with self.assertRaises(ValueError):compare(a,b)
