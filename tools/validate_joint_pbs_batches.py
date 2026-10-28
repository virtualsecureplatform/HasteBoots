#!/usr/bin/env python3
"""Audit complete 1/4/16 PBS batch logs and a conservative interactive inventory.

Not a hash, Fiat-Shamir, knowledge, hiding, or whole-security certificate.
The joint fixed-word PCS adaptation still requires independent review.
"""
import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re
from full_pbs_budget import full_bounds,ROLES

MODES={
    'joint-hadamard':(6,'merlin-direct-joint-hadamard-pbs-batch-v1','complete-serialized-public-batch-verifier'),
    'separate-v5':(5,'merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1','complete-serialized-independent-public-verifiers'),
}
def conservative_errors(record,layouts):
    """Retain batch_size times every checked native standalone-v5 error term.

    Individual ZeroCheck equations remain separate under shared fresh matrices.
    The old per-root PCS counts dominate the joint concatenated-word term/tail;
    retaining B extension cancellation terms also dominates the single joint
    cancellation term. No independence between members is assumed.
    """
    mode=record.get('mode');count=record.get('batch_size')
    if mode not in MODES or type(count) is not int or count<1:
        raise ValueError('unsupported batch mode/count')
    version,transcript,scope=MODES[mode]
    expected=dict(kind='complete-binary-nand-pbs-batch',protocol_version=version,
                  transcript=transcript,verification_scope=scope,verified=True,
                  whole_proof_security_certified=False)
    if any(type(record.get(k)) is not type(v) or record[k]!=v for k,v in expected.items()):
        raise ValueError('batch protocol, verification or security metadata mismatch')
    p=record.get('prime');bits=record.get('basis_bits')
    if type(p) is not int or p<2 or type(bits) is not int or bits<1:
        raise ValueError('missing batch field/radix')
    digits=((p-1).bit_length()+bits-1)//bits
    standalone=dict(record,kind='complete-binary-nand-pbs',protocol_version=5,
        transcript=MODES['separate-v5'][1],lookup_backend='deferred-extension',
        hadamard_backend='multi-root',private_coefficient_roots=2*digits+1,ntt_links=2*digits+1)
    return {name:count*error for name,error in full_bounds(standalone,layouts).items()}

def validate(text,field,full=True,mode='joint-hadamard',reference_text=None):
    if field not in ('babybear','goldilocks') or mode not in MODES or type(full) is not bool:
        raise ValueError('unsupported field/mode/geometry selection')
    layouts={};packets=[];members=[];inventories=[]
    for line in text.splitlines():
        if line.startswith('HB_FULL_PCS '):
            row=json.loads(line.split(' ',1)[1]);role=row.get('role')
            if role not in ROLES or role in layouts:raise ValueError('duplicate/unknown layout role')
            layouts[role]=row
        elif line.startswith('HB_FULL_BATCH_PBS '):packets.append(json.loads(line.split(' ',1)[1]))
        elif line.startswith('HB_BATCH_MEMBER '):members.append(json.loads(line.split(' ',1)[1]))
        elif line.startswith('HB_BATCH_ROOTS '):inventories.append(json.loads(line.split(' ',1)[1]))
    if len(packets)!=3 or [p.get('batch_size') for p in packets]!=[1,4,16] or len(members)!=21 or len(inventories)!=3:
        raise ValueError('complete ordered 1/4/16 batch schedule required')
    gold=field=='goldilocks';p,k,degree,extra=(2**64-2**32+1,4,3,0) if gold else (2013265921,8,6,1)
    ndigits=((p-1).bit_length()+7)//8;sdigits=((p-1).bit_length()+4)//5
    roots_per_member=8*ndigits+4*sdigits+15
    seen_proofs=set();seen_statements=set();errors=[];offset=0
    for packet,inventory,count in zip(packets,inventories,[1,4,16]):
        expected=dict(field=field,mode=mode,prime=p,width=k,lookup_field_degree=degree,
            helper_left_extra=extra,full_parameters=full,seed=42,polynomial_size=1024 if full else 32,
            input_dimension=728 if full else 32,output_dimension=728 if full else 32,
            basis_bits=8,key_switch_basis_bits=5,lookup_repetitions=1)
        if any(type(packet.get(key)) is not type(value) or packet[key]!=value for key,value in expected.items()):
            raise ValueError('native FHE/profile mismatch')
        for key in ['proof_sha256','statements_sha256','native_keys_sha256','fhe_parameters_sha256']:
            if not isinstance(packet.get(key),str) or not re.fullmatch('[a-f0-9]{64}',packet[key]):raise ValueError('missing batch digest')
        if packet['proof_sha256'] in seen_proofs:raise ValueError('repeated batch proof')
        seen_proofs.add(packet['proof_sha256'])
        for key in ['setup_ns','native_keys_sha256','fhe_parameters_sha256']:
            if packet.get(key)!=packets[0].get(key):raise ValueError('setup/native keys changed across groups')
        for key in ['setup_ns','trace_ns','prove_ns','serialization_ns','complete_ns','deserialize_ns','verify_ns','proof_bytes']:
            if type(packet.get(key)) is not int or packet[key]<0:raise ValueError('invalid timing/byte metadata')
        if packet['proof_bytes']==0 or packet['complete_ns']<sum(packet[key] for key in ['trace_ns','prove_ns','serialization_ns']):
            raise ValueError('inconsistent complete batch cost')
        expected_inventory=dict(scope='verified-proof-root-slots',batch_size=count,
            proof_sha256=packet['proof_sha256'],total=count*roots_per_member,
            per_member=[roots_per_member]*count,trusted_key_roots_included=False,whole_proof_security_certified=False)
        if any(type(inventory.get(k)) is not type(v) for k,v in expected_inventory.items()) or any(type(v) is not int for v in inventory.get('per_member',[])) or inventory!=expected_inventory:raise ValueError('unlinked or incorrect batch root inventory')
        for index,member in enumerate(members[offset:offset+count]):
            left,right=index&1,(index>>1)&1
            expected_member=dict(batch_size=count,index=index,left_plaintext=left,right_plaintext=right,
                decrypted_plaintext=1-left*right,proof_sha256=packet['proof_sha256'],verified=True)
            if any(type(member.get(key)) is not type(value) or member[key]!=value for key,value in expected_member.items()):
                raise ValueError('batch member truth table/order/verification mismatch')
            digest=member.get('statement_sha256')
            if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest) or digest in seen_statements:
                raise ValueError('missing/repeated member statement')
            seen_statements.add(digest)
        offset+=count
        errors.append(sum(conservative_errors(packet,layouts).values(),Fraction()))
    union=sum(errors,Fraction())
    if union>Fraction(1,2**128):raise ValueError('conditional 21-member interactive inventory misses threshold')
    result=dict(field=field,mode=mode,full_parameters=full,batch_sizes=[1,4,16],packets=packets,
        members=members,layouts=layouts,inventories=inventories,
        conditional_21_member_interactive_bits=-math.log2(float(union)),
        scope=('complete cross-statement Hadamard authentication with per-member remaining PBS constraints' if mode=='joint-hadamard' else 'independent standalone v5 PBS proofs'),
        whole_proof_security_certified=False)
    if reference_text is not None:
        refs=[json.loads(s.split(' ',1)[1]) for s in reference_text.splitlines() if s.startswith('HB_FULL_PBS ')]
        if len(refs)!=21:raise ValueError('21 native reference statements required')
        ref_layout_rows=[json.loads(s.split(' ',1)[1]) for s in reference_text.splitlines() if s.startswith('HB_FULL_PCS ')]
        ref_layouts={r.get('role'):r for r in ref_layout_rows}
        if len(ref_layout_rows)!=4 or ref_layouts!=layouts:
            raise ValueError('native PCS layout fixture changed')
        if any(r.get('kind')!='complete-binary-nand-pbs' or r.get('verified') is not True
               or r.get('verification_scope')!='complete-serialized-public-verifier'
               or r.get('full_parameters') is not full for r in refs):
            raise ValueError('invalid native reference verification scope')

        for member,reference in zip(members,refs):
            for key in ['statement_sha256','left_plaintext','right_plaintext','decrypted_plaintext']:
                if member[key]!=reference.get(key):raise ValueError('native statement fixture changed')
        for packet in packets:
            for key in ['native_keys_sha256','fhe_parameters_sha256','polynomial_size','input_dimension','output_dimension','prime','width']:
                if any(packet[key]!=r.get(key) for r in refs):raise ValueError('native key/parameter fixture changed')
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('log',type=Path)
    parser.add_argument('--field',choices=['babybear','goldilocks'],required=True)
    parser.add_argument('--mode',choices=list(MODES),default='joint-hadamard');parser.add_argument('--toy',action='store_true')
    parser.add_argument('--reference-log',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=validate(args.log.read_text(),args.field,not args.toy,args.mode,
        args.reference_log.read_text() if args.reference_log else None)
    result['log_sha256']=hashlib.sha256(args.log.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['packets','members','layouts','inventories']},indent=2))
if __name__=='__main__':main()
