import copy
import json
from pathlib import Path
import tempfile
import unittest

from audit_classical_final_key_controls import audit


def fixture():
    identity=dict(prime='2013265921',degree=6,version=5,backend='Polyfrim',
                  full_pbs_trace=False,security_qualified=False)
    return [dict(identity,bound_openings=63,nested_claim_counts_preflighted=True),
        dict(identity,verifier_child_queries=602,unique_child_seeds=64,initial_identity_queries=64,
             all_input_windows_registered=True,availability_hits=0,output_collisions=0),
        dict(identity,n=32,lwe=21,proof_bytes=3725515,verifier_hash_queries=31042,
             verifier_xof_queries=1298,nonzero_key=True,frozen_input_and_extraction_match=True,
             ntt_source_claims=128,product_source_claims=15,decomposition_source_claims=16,
             lookup_source_claims=15,lookup_helper_claims=7)]


def encoded(rows):
    return ''.join(prefix+json.dumps(row)+'\n' for prefix,row in zip(
        ['HB_FINAL_KEY_CHILD_CLAIMS ','HB_FINAL_KEY_TEMPORAL_ORIGINS ','HB_FINAL_KEY_EVENT_TRACE '],rows))


class FinalKeyControlAuditTests(unittest.TestCase):
    def check(self,text,**kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'run.log';path.write_text(text)
            return audit(path,**kwargs)

    def test_complete_control_is_not_suite_or_security_admission(self):
        result=self.check(encoded(fixture()),require_claims=True)
        self.assertEqual(result['completed_controls'],1)
        self.assertFalse(result['suite_completion_verified'])
        self.assertFalse(result['security_qualified'])

    def test_identity_source_counts_and_temporal_coverage_fail_closed(self):
        for index,key,value in [(0,'degree',3),(0,'bound_openings',10),
                (0,'nested_claim_counts_preflighted',False),(1,'initial_identity_queries',63),
                (1,'availability_hits',1),(1,'output_collisions',1),
                (1,'all_input_windows_registered',False),(2,'ntt_source_claims',127),
                (2,'proof_bytes',True),(2,'n',32.0),(2,'nonzero_key',False),(2,'security_qualified',True)]:
            rows=copy.deepcopy(fixture());rows[index][key]=value
            with self.assertRaises(ValueError):self.check(encoded(rows),require_claims=True)

    def test_duplicates_reordering_and_missing_bindings_rejected(self):
        text=encoded(fixture());lines=text.splitlines(keepends=True)
        for bad in (text+text,lines[1]+lines[0]+lines[2],lines[2],lines[1]+lines[2]):
            with self.assertRaises(ValueError):self.check(bad,require_claims=True)
        result=self.check(lines[1]+lines[2])
        self.assertEqual(result['completed_controls'],1)

    def test_live_partial_record_is_not_a_completed_control(self):
        text=encoded(fixture())+'HB_FINAL_KEY_CHILD_CLAIMS {"prime":'
        result=self.check(text,require_claims=True)
        self.assertEqual(result['completed_controls'],1)
        self.assertTrue(result['incomplete_trailing_control'])


if __name__=='__main__':unittest.main()
