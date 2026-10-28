import copy
import unittest
from joint_pbs_timing import validate_run, validate_repeated_wire
from test_batch_phase_statistics import fixture as phase_fixture
from test_validate_joint_pbs_batches import fixture,encode


def timing_fixture():
    layouts,packets,members,inventories,_=fixture('joint-comparisons')
    packets=[copy.deepcopy(packets[0]) for _ in range(2)]
    members=[copy.deepcopy(members[0]) for _ in range(2)]
    inventories=[copy.deepcopy(inventories[0]) for _ in range(2)]
    phases=[]
    for i in range(2):
        digest=f'{i+100:064x}'
        packets[i].update(proof_sha256=digest,prove_ns=100,complete_ns=200,timing_iteration=i)
        members[i].update(proof_sha256=digest,statement_sha256=f'{i+200:064x}')
        inventories[i]['proof_sha256']=digest
        _,row=phase_fixture();row.update(proof_sha256=digest)
        phases.append(row)
    return layouts,packets,members,inventories,phases


def text(data):
    import json
    return encode(*data[:4])+'\n'+'\n'.join('HB_BATCH_PHASES '+json.dumps(r) for r in data[4])


class TimingTests(unittest.TestCase):
    def test_two_fresh_complete_proofs_and_linked_phases(self):
        data=timing_fixture()
        result=validate_run(text(data),'goldilocks','joint-comparisons')
        self.assertEqual(result['batch_sizes'],[1,1])
        validate_run(text(data),'goldilocks','joint-comparisons',reference=result)
    def test_iteration_phase_counts_and_links_reject(self):
        data=timing_fixture()
        for group,index,key,value in [(1,1,'timing_iteration',0),(1,0,'timing_iteration',False),
                                      (4,0,'proof_sha256','f'*64),(4,0,'prove_ns',101)]:
            bad=copy.deepcopy(data);bad[group][index][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate_run(text(bad),'goldilocks','joint-comparisons')
        bad=copy.deepcopy(data);bad[4].pop()
        with self.assertRaises(ValueError):validate_run(text(bad),'goldilocks','joint-comparisons')
    def test_archived_native_fixture_must_match(self):
        data=timing_fixture();result=validate_run(text(data),'goldilocks','joint-comparisons')
        result['layouts']['source']['queries']+=1
        with self.assertRaises(ValueError):validate_run(text(data),'goldilocks','joint-comparisons',reference=result)
        result=validate_run(text(data),'goldilocks','joint-comparisons');result['members'][0]['statement_sha256']='f'*64
        with self.assertRaises(ValueError):validate_run(text(data),'goldilocks','joint-comparisons',reference=result)

    def test_reversed_order_requires_identical_certificates(self):
        first=validate_run(text(timing_fixture()),'goldilocks','joint-comparisons')
        second=copy.deepcopy(first)
        second['packets'][0]['complete_ns']+=10
        second['phases'][0]['prove_ns']+=10
        self.assertEqual(validate_repeated_wire(first,second),dict(proofs=2,exact_wire=True))
        for group,key,value in [('packets','proof_sha256','f'*64),
                                ('packets','proof_bytes',1),
                                ('packets','native_keys_sha256','f'*64),
                                ('packets','statements_sha256','f'*64),
                                ('members','statement_sha256','f'*64)]:
            changed=copy.deepcopy(second);changed[group][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                validate_repeated_wire(first,changed)
        changed=copy.deepcopy(second);changed['members'].reverse()
        with self.assertRaises(ValueError):validate_repeated_wire(first,changed)
