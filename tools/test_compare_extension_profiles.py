import copy
import json
import unittest
from compare_extension_profiles import read_rows,compare_packets,PROFILES


def fixture(profile):
    degree,k=PROFILES[profile];p=2**64-2**32+1
    layouts=[]
    for role,n,left in [("source",18 if k==8 else 19,3 if k==8 else 4),("helper",21,5 if k==8 else 6),("final_source",8 if k==8 else 9,2 if k==8 else 3),("final_helper",11,5)]:
        scalars=1<<(n-left);blocks=scalars//k
        layouts.append(dict(role=role,row_code="block-rs",prime=p,width=k,variables=n,left_vars=left,row_message_scalars=scalars,row_message_blocks=blocks,row_encoded_blocks=2*blocks,block_width=k,queries=544))
    row=dict(kind="complete-binary-nand-pbs",field="goldilocks",prime=p,width=k,lookup_field_degree=degree,lookup_backend="extension",lookup_repetitions=1,
        protocol_version=3,transcript="merlin-direct-prime-parent-extension-child-v1",verification_scope="complete-serialized-public-verifier",security="experimental-unbudgeted",full_parameters=True,seed=42,batch_size=1,verified=True,polynomial_size=1024,input_dimension=728,output_dimension=728,basis_bits=8,key_switch_basis_bits=5,private_coefficient_roots=17,ntt_links=17,
        statement_sha256="a"*64,fhe_parameters_sha256="b"*64,native_keys_sha256="c"*64,proof_sha256=("d" if degree==5 else "e")*64,setup_ns=5,trace_ns=1,prove_ns=50,serialization_ns=1,complete_ns=53,verify_ns=1,proof_bytes=100)
    return layouts,[dict(row,iteration=i) for i in range(2)]


def encode(layouts,rows):
    return "\n".join([*("HB_FULL_PCS "+json.dumps(x) for x in layouts),*("HB_FULL_PBS "+json.dumps(x) for x in rows)])

class ProfileTests(unittest.TestCase):
    def test_all_profiles_and_reuse(self):
        packets={(s,p):read_rows(encode(*fixture(p)),p,True) for s in range(2) for p in PROFILES}
        self.assertEqual(len(compare_packets(packets)),6)
    def test_protocol_scope_types_and_inventory(self):
        for change in [dict(lookup_field_degree=5),dict(width=8),dict(verified=1),dict(output_dimension=1024),dict(verification_scope="legacy-four-stage-wrapper-in-memory"),dict(protocol_version=2),dict(lookup_repetitions=2),dict(proof_bytes=0)]:
            layouts,rows=fixture("d3-w4");rows[0].update(change)
            with self.assertRaises(ValueError):read_rows(encode(layouts,rows),"d3-w4",True)
    def test_missing_duplicate_or_weak_layouts(self):
        for mode in range(3):
            layouts,rows=fixture("d3-w4")
            if mode==0:layouts.pop()
            elif mode==1:layouts.append(layouts[0])
            else:layouts[0]["queries"]=32
            with self.assertRaises(ValueError):read_rows(encode(layouts,rows),"d3-w4",True)
    def test_cross_profile_fixture_and_within_profile_wire(self):
        packets={(s,p):read_rows(encode(*fixture(p)),p,True) for s in range(2) for p in PROFILES}
        for key in ["native_keys_sha256","statement_sha256","proof_sha256","pcs_layouts"]:
            altered=copy.deepcopy(packets)
            if key=="pcs_layouts":altered[(1,"d3-w4")][0][key]["source"]["left_vars"]+=1
            else:altered[(1,"d3-w4")][0][key]="f"*64
            with self.assertRaises(ValueError):compare_packets(altered)

if __name__=="__main__":unittest.main()
