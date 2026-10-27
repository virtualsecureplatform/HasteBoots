import copy
import json
from pathlib import Path
import tempfile
import unittest
import hashlib
from compare_pipfri_pbs import checked_binary, compare, read_rows


def fixture():
    common = dict(field="babybear", backend="ordinary-pipfri-reference-v1", security="experimental-unbudgeted",
                  transcript="merlin-direct-extension-canonical-rejection-v1", verification_scope="legacy-four-stage-wrapper-in-memory",
                  threads=16, seed=42, verified=True, warmup=False, cold=False, fragment_vars_max=14, blowup=2, queries=64,
                  fhe_parameters_sha256="a"*64, statement_sha256="b"*64, trusted_bsk_root="c"*64,
                  proof_bytes=1000, pcs_bytes=800, piop_bytes=100, complete_ns=10000)
    return [dict(common, iteration=i, new_key_commitment=(i == 0)) for i in range(2)]


def parse(rows):
    text="Binary Blind Rotation with Trace\n"+"\n".join("HB_PIPFRI_BENCH "+json.dumps(r) for r in rows)
    return read_rows(text,"babybear",2,16,42)


class NativePipFRIComparisonTests(unittest.TestCase):
    def test_rejects_truncated_unverified_and_changed_reuse_records(self):
        rows=fixture();self.assertEqual(parse(rows),rows)
        with self.assertRaises(ValueError):parse(rows[:1])
        for key,value in [("verified",False),("verified",1),("new_key_commitment",True),("cold",True),("iteration",0),("statement_sha256","d"*64),("proof_bytes",0),("complete_ns",True)]:
            bad=copy.deepcopy(rows);bad[1][key]=value
            with self.assertRaises(ValueError,msg=key):parse(bad)
    def test_actual_public_hashes_geometry_and_sizes_must_match_between_binaries(self):
        old=parse(fixture());new=copy.deepcopy(old);new[1]["complete_ns"]=8000
        self.assertAlmostEqual(compare(old,new)["reused_latency_reduction"],0.2)
        for key,value in [("statement_sha256","d"*64),("trusted_bsk_root","d"*64),("fhe_parameters_sha256","d"*64),("queries",65),("transcript","different"),("proof_bytes",1001)]:
            bad=copy.deepcopy(new)
            for row in bad:row[key]=value
            with self.assertRaises(ValueError,msg=key):compare(old,bad)
    def test_modified_saved_executable_is_rejected_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/"pipfri_pbs_babybear";binary.write_bytes(b"recorded executable")
            (root/"manifest.json").write_text(json.dumps(dict(security="experimental-unbudgeted",binary_sha256={binary.name:hashlib.sha256(binary.read_bytes()).hexdigest()})))
            self.assertEqual(checked_binary(root,"babybear")[0],binary)
            binary.write_bytes(b"modified executable")
            with self.assertRaises(ValueError):checked_binary(root,"babybear")


if __name__=="__main__":unittest.main()
