import copy
import json
from pathlib import Path
import tempfile
import unittest

from compare_canonical_polyfrim import read_records, read_lookup_profiles, read_opening_inventory, compare


def records(backend):
    result=[]
    for i in range(2):
        r=dict(backend=backend,prime=2013265921,extension_degree=6,protocol_version=11,ring_dimension=1024,lwe_dimension=728,
               output_dimension=728,width=8,queries=128,lookup_repetitions=1,group_size=1,group_index=i,ordinal=i,warmup=i==0,cold=False,
               left=0,right=i,output=1,verified=True,altered_output_rejected=True,complete_pbs=True,original_size=True,
               whole_security_matched=False,hiding_certified=False,performance_gate=False,proof_bytes=100,root_slots=72,
               setup_s=1.,trace_s=1.,prove_s=8.,serialization_s=1.,complete_s=10.,decode_s=1.,verify_s=1.,phase_s=[1.]*7)
        r.update({key:'a'*64 for key in ('fhe_parameters_sha256','native_keys_sha256','parameters_sha256','trusted_setup_sha256','proof_sha256')})
        r['statement_sha256']=str(i)*64
        result.append(r)
    return result


class RecordsTest(unittest.TestCase):
    def test_opening_inventory_policy_must_be_explicit(self):
        rows = records('polyfrim')
        for row in rows: row['opening_inventory'] = True
        with self.assertRaises(ValueError): self.read(rows)

    def test_opening_inventory_scope_geometry_and_counts(self):
        rows = records('polyfrim')
        contexts = [c*64 for c in 'abcd']
        for row in rows: row.update(opening_inventory=True, contexts_sha256=contexts)
        profiles = [dict(backend='polyfrim', ordinal=i, scope='successful-complete-verification',
                         includes_altered_output_replay=False,
                         events=[dict(role=role, kind='batch', num_vars=n, width=8, queries=role+1,
                                      context_sha256=contexts[role], root_hex=f'{role:064x}')
                                 for role,n in enumerate((18,21,8,11))]) for i in range(2)]
        def read(selected):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'run.log'
                path.write_text('\n'.join('HB_CANONICAL_PBS '+json.dumps(r) for r in rows)
                                +'\n'+'\n'.join('HB_CANONICAL_OPENING_INVENTORY '+json.dumps(r) for r in selected))
                checked = read_records(path, 'babybear', 'polyfrim', True, False, 1, 1, opening_inventory=True)
                return read_opening_inventory(path, checked)
        self.assertEqual(read(profiles), profiles)
        with self.assertRaises(ValueError): read(profiles[:1])
        for key,value in [('scope','prover'), ('includes_altered_output_replay',True), ('ordinal',False)]:
            bad=copy.deepcopy(profiles);bad[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):read(bad)
        for key,value in [('role',True), ('role',4), ('num_vars',17), ('width',6),
                          ('queries',True), ('queries',0), ('kind','unknown'),
                          ('context_sha256','f'*64), ('root_hex','a'*63)]:
            bad=copy.deepcopy(profiles);bad[0]['events'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):read(bad)
        bad=copy.deepcopy(profiles);bad[0]['events'][1]['kind']='single'
        with self.assertRaises(ValueError):read(bad)
        bad=copy.deepcopy(profiles);bad[0]['events'].pop()
        with self.assertRaises(ValueError):read(bad)
        # Repeated calls to one root must remain separate observations.
        repeated=copy.deepcopy(profiles)
        repeated[0]['events'].append(copy.deepcopy(repeated[0]['events'][0]))
        self.assertEqual(len(read(repeated)[0]['events']),5)

    def test_v9_fixture_requires_explicit_policy_and_constant_inputs(self):
        rows = records('brakedown')
        for row in rows:
            row.update(queries=544, v9_fixture=True, left=0, right=0, output=1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'run.log'
            def read(selected, enabled):
                path.write_text('\n'.join('HB_CANONICAL_PBS '+json.dumps(r) for r in selected))
                return read_records(path, 'babybear', 'brakedown', True, False, 1, 1,
                                    v9_fixture=enabled)
            self.assertEqual(read(rows, True), rows)
            with self.assertRaises(ValueError): read(rows, False)
            bad = copy.deepcopy(rows); bad[1]['right'] = 1
            with self.assertRaises(ValueError): read(bad, True)
            bad = copy.deepcopy(rows); del bad[1]['v9_fixture']
            with self.assertRaises(ValueError): read(bad, True)
            bad = copy.deepcopy(rows); bad[1]['v9_fixture'] = 1
            with self.assertRaises(ValueError): read(bad, True)

    def test_v9_toy_fixture_has_legacy_dimensions(self):
        rows = records('brakedown')
        for row in rows:
            row.update(queries=544, v9_fixture=True, left=0, right=0, output=1,
                       original_size=False, ring_dimension=32, lwe_dimension=32,
                       output_dimension=32)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'run.log'
            def read(selected):
                path.write_text('\n'.join('HB_CANONICAL_PBS '+json.dumps(r) for r in selected))
                return read_records(path, 'babybear', 'brakedown', False, False, 1, 1,
                                    v9_fixture=True)
            self.assertEqual(read(rows), rows)
            bad = copy.deepcopy(rows)
            for row in bad:
                row.update(lwe_dimension=21, output_dimension=21)
            with self.assertRaises(ValueError): read(bad)

    def read(self, rows, backend="polyfrim", parallel=False):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'run.log'
            path.write_text('\n'.join('HB_CANONICAL_PBS '+json.dumps(r) for r in rows))
            return read_records(path,'babybear',backend,True,False,1,1,parallel_oracles=parallel)

    def test_lookup_profile_scope_schedule_and_numeric_types(self):
        rows = records('polyfrim')
        profiles = [dict(backend='polyfrim', ordinal=i, scope='main-decomposition-lookups',
                         includes_final_key_switch=False, preparation_s=.1, commitment_s=.1,
                         sumcheck_s=.1, zero_check_s=0, terminal_evaluation_s=.1, openings_s=.1)
                    for i in range(2)]
        def read(profiles):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'profiles.log'
                path.write_text('\n'.join('HB_CANONICAL_LOOKUP_PROFILE '+json.dumps(p) for p in profiles))
                return read_lookup_profiles(path, rows)
        self.assertEqual(read(profiles), profiles)
        with self.assertRaises(ValueError): read(profiles[:1])
        for key, value in [('ordinal', True), ('backend', 'brakedown'), ('scope', 'all-lookups'),
                           ('includes_final_key_switch', 0), ('sumcheck_s', -1), ('sumcheck_s', True),
                           ('sumcheck_s', float('nan')), ('sumcheck_s', 2), ('sumcheck_s', '0.1')]:
            changed = copy.deepcopy(profiles); changed[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): read(changed)

    def test_complete_records_and_unmatched_comparison(self):
        rows=self.read(records('polyfrim'))
        before=records('brakedown')
        summary=compare(before,rows)
        self.assertEqual(summary['latency_reduction'],0)
        self.assertFalse(summary['performance_gate'])
        self.assertFalse(summary['whole_security_matched'])

    def test_compact_profile_and_unknown_backend(self):
        self.read(records('polyfrim-compact'),'polyfrim-compact')
        with self.assertRaises(ValueError):
            self.read(records('unknown'),'unknown')

    def test_explicit_parallel_policy(self):
        rows=records('polyfrim')
        for r in rows:r['parallel_oracles']=True
        self.read(rows,parallel=True)
        with self.assertRaises(ValueError):self.read(rows)
        with self.assertRaises(ValueError):self.read(records('polyfrim'),parallel=True)

    def test_reject_bad_coverage_flags_geometry_and_timing(self):
        for key,value in [('verified',False),('verified',1),('whole_security_matched',True),('output',0),('output_dimension',1024),
                          ('phase_s',[8.]*7),('complete_s',1.),('verify_s',float('nan')),('proof_bytes',True),('queries',0),
                          ('statement_sha256','z'*64),('ordinal',5),('warmup',True),('parameters_sha256','b'*64)]:
            with self.subTest(key=key):
                bad=records('polyfrim');bad[1][key]=value
                with self.assertRaises(ValueError):self.read(bad)
        with self.assertRaises(ValueError):self.read(records('polyfrim')[:1])
        bad=records('polyfrim');bad[1]['statement_sha256']=bad[0]['statement_sha256']
        with self.assertRaises(ValueError):self.read(bad)

    def test_reject_different_workloads(self):
        for key,value in [('native_keys_sha256','b'*64),('statement_sha256','b'*64),('width',4),('root_slots',73),('cold',True)]:
            bad=copy.deepcopy(records('polyfrim'));bad[1][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):compare(records('brakedown'),bad)


if __name__=='__main__':unittest.main()
