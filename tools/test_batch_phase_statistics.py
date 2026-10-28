import copy
import unittest
from batch_phase_statistics import validate, OUTER, MEMBERS, LOOKUP


def fixture(version=9):
    packet=dict(protocol_version=version,proof_sha256="a"*64,batch_size=1,prove_ns=100)
    row=dict(scope="complete-prover-wall-clock-phases",**packet,
             outer={k:0 for k in OUTER},members={k:1 for k in MEMBERS},
             blind_rotation={k:0 for k in LOOKUP},key_switch={k:0 for k in LOOKUP})
    if version==9:
        row["outer"].update(members_total_ns=20,hadamard_ns=10,blind_rotation_total_ns=30,key_switch_total_ns=20)
        for role in ("blind_rotation","key_switch"):
            row[role].update(sumcheck_ns=5,openings_ns=6)
    else:
        row["outer"]["members_total_ns"]=100
    return packet,row


class PhaseTests(unittest.TestCase):
    def test_both_complete_protocols_and_unattributed_work(self):
        for version in (5,9):
            packet,row=fixture(version)
            result=validate(packet,row)
            self.assertEqual(result["unattributed_prover_ns"],20 if version==9 else 0)
    def test_digest_scope_types_and_parent_budgets(self):
        packet,row=fixture()
        for path,value in [(('proof_sha256',),'b'*64),(('batch_size',),4),(('protocol_version',),5),
                           (('prove_ns',),99),(('scope',),'unknown'),(('outer','hadamard_ns'),True),
                           (('outer','binding_ns'),101),(('members','ntt_ns'),21),
                           (('blind_rotation','sumcheck_ns'),0),(('key_switch','openings_ns'),0),
                           (('blind_rotation','zero_check_ns'),1),(('key_switch','preparation_ns'),30)]:
            bad=copy.deepcopy(row);target=bad
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):validate(packet,bad)
        for key,value in [('proof_sha256',None),('batch_size',True)]:
            bad_packet=dict(packet);bad_packet[key]=value
            bad_row=dict(row);bad_row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate(bad_packet,bad_row)
        bad=copy.deepcopy(row);del bad['outer']['binding_ns']
        with self.assertRaises(ValueError):validate(packet,bad)
    def test_standalone_does_not_invent_joint_phases(self):
        packet,row=fixture(5)
        row['blind_rotation']['preparation_ns']=1
        with self.assertRaises(ValueError):validate(packet,row)
