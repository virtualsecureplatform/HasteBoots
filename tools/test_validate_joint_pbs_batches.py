import copy,json,unittest
from fractions import Fraction
from test_validate_full_batches import batch_fixture
from validate_joint_pbs_batches import validate,conservative_errors,MODES
from full_pbs_budget import full_bounds

def fixture(mode='joint-hadamard'):
    layouts,old=batch_fixture('goldilocks')
    packets=[];members=[];inventories=[];offset=0
    for count in [1,4,16]:
        row=dict(old[offset],kind='complete-binary-nand-pbs-batch',mode=mode,batch_size=count,
            protocol_version=MODES[mode][0],transcript=MODES[mode][1],verification_scope=MODES[mode][2],
            whole_proof_security_certified=False,helper_left_extra=0,proof_sha256=f'{count+999:064x}',statements_sha256=f'{count+1999:064x}',deserialize_ns=1)
        if mode=='joint-comparisons':
            row.update(comparison_group_size=4,blind_rotation_groups=(2*count+3)//4,key_switch_groups=(count+3)//4)
        packets.append(row)
        for index,ref in enumerate(old[offset:offset+count]):
            members.append({k:ref[k] for k in ['left_plaintext','right_plaintext','decrypted_plaintext','statement_sha256']})
            members[-1].update(batch_size=count,index=index,proof_sha256=row['proof_sha256'],verified=True)
        inventories.append(dict(scope='verified-proof-root-slots',batch_size=count,total=count*131,
            per_member=[131]*count,proof_sha256=row['proof_sha256'],trusted_key_roots_included=False,whole_proof_security_certified=False))
        if mode=='joint-comparisons':
            inventories[-1].update(per_member=[102]*count,blind_rotation_reciprocals=16*count,key_switch_reciprocals=13*count)
        offset+=count
    return layouts,packets,members,inventories,old

def encode(layouts,packets,members,inventories):
    return '\n'.join(prefix+' '+json.dumps(row) for prefix,rows in [('HB_FULL_PCS',layouts),('HB_FULL_BATCH_PBS',packets),('HB_BATCH_MEMBER',members),('HB_BATCH_ROOTS',inventories)] for row in rows)

class JointBatchTests(unittest.TestCase):
    def test_joint_and_separate_modes_preserve_conservative_single_bounds(self):
        for mode in MODES:
            layouts,packets,members,inventories,old=fixture(mode)
            result=validate(encode(layouts,packets,members,inventories),'goldilocks',mode=mode,
                reference_text='\n'.join(['HB_FULL_PCS '+json.dumps(r) for r in layouts]+['HB_FULL_PBS '+json.dumps(r) for r in old]))
            self.assertEqual(result['batch_sizes'],[1,4,16]);self.assertFalse(result['whole_proof_security_certified'])
            if mode=='separate-v5':self.assertEqual(result['scope'],'independent standalone v5 PBS proofs')
            elif mode=='joint-comparisons':
                self.assertIn('comparison authentication',result['scope'])
            else:
                self.assertIn('complete cross-statement Hadamard authentication',result['scope'])
                self.assertEqual('canonical source deduplication' in result['scope'],mode=='canonical-sources')
            layout={p['role']:p for p in layouts}
            native=dict(old[0],protocol_version=5,transcript=MODES['separate-v5'][1],lookup_backend='deferred-extension',hadamard_backend='multi-root')
            if mode=='joint-comparisons':
                native.update(protocol_version=8,transcript='merlin-direct-shared-query-comparisons-v1',lookup_backend='shared-extension')
            single=full_bounds(native,layout)
            self.assertEqual(conservative_errors(packets[2],layout),{k:16*v for k,v in single.items()})
            self.assertGreater(result['conditional_21_member_interactive_bits'],128)
    def test_strict_protocol_count_truth_table_and_root_binding(self):
        data=fixture()[:4]
        changes=[(1,0,'protocol_version',5),(1,0,'mode','separate-v5'),(1,0,'transcript','wrong'),
                 (1,0,'whole_proof_security_certified',True),(1,0,'verified',1),(1,0,'batch_size',4),
                 (1,0,'output_dimension',1024),(1,1,'native_keys_sha256','a'*64),
                 (2,1,'index',4),(2,0,'left_plaintext',1),(2,0,'decrypted_plaintext',0),
                 (2,0,'proof_sha256','a'*64),(2,0,'statement_sha256','bad'),
                 (3,0,'total',132),(3,0,'proof_sha256','b'*64),(3,0,'per_member',[132])]
        for group,index,key,value in changes:
            bad=copy.deepcopy(data);bad[group][index][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate(encode(*bad),'goldilocks')
        for group in [0,1,2,3]:
            bad=copy.deepcopy(data);bad[group].pop()
            with self.subTest(group=group),self.assertRaises(ValueError):validate(encode(*bad),'goldilocks')
        bad=copy.deepcopy(data);bad[2][1]['statement_sha256']=bad[2][0]['statement_sha256']
        with self.assertRaises(ValueError):validate(encode(*bad),'goldilocks')
    def test_reference_and_geometry_are_not_inferred_from_proof(self):
        layouts,packets,members,inventories,old=fixture()
        old[0]['statement_sha256']='c'*64
        with self.assertRaises(ValueError):validate(encode(layouts,packets,members,inventories),'goldilocks',reference_text='\n'.join('HB_FULL_PBS '+json.dumps(r) for r in old))
        layouts[0]['width']=8
        with self.assertRaises(ValueError):validate(encode(layouts,packets,members,inventories),'goldilocks')

    def test_comparison_outer_helpers_and_grouping_are_mandatory(self):
        data=fixture('joint-comparisons')[:4]
        changes=[(1,0,'comparison_group_size',8),(1,0,'blind_rotation_groups',2),
                 (1,2,'key_switch_groups',5),(3,0,'blind_rotation_reciprocals',15),
                 (3,0,'key_switch_reciprocals',12),(3,0,'per_member',[131]),
                 (3,0,'total',102)]
        for group,index,key,value in changes:
            bad=copy.deepcopy(data);bad[group][index][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                validate(encode(*bad),'goldilocks',mode='joint-comparisons')
        bad=copy.deepcopy(data);del bad[3][0]['key_switch_reciprocals']
        with self.assertRaises(ValueError):validate(encode(*bad),'goldilocks',mode='joint-comparisons')
        # All four contexts must be unpadded for the conditional joint PCS bound.
        bad=copy.deepcopy(data);bad[0][1]['block_width']=8
        with self.assertRaises(ValueError):validate(encode(*bad),'goldilocks',mode='joint-comparisons')
