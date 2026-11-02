"""Audit final-key control records; never certify their cryptographic claims."""
import argparse
import hashlib
import json
from pathlib import Path

from audit_artifacts import write_json_new
from classical_profile_descriptor import BACKENDS

PREFIXES = {'HB_FINAL_KEY_CHILD_CLAIMS ': 'claims',
            'HB_FINAL_KEY_TEMPORAL_ORIGINS ': 'origins',
            'HB_FINAL_KEY_EVENT_TRACE ': 'control'}
IDENTITY = ('prime', 'degree', 'version', 'backend')


def integer(row, key, minimum=0):
    value = row.get(key)
    if type(value) is not int or value < minimum:
        raise ValueError('invalid integer: '+key)
    return value


def validate(group, require_claims):
    control, origins = group['control'], group['origins']
    identity = tuple(control.get(k) for k in IDENTITY)
    prime, degree, version, backend = identity
    if ((prime, degree) not in [('2013265921',6), ('18446744069414584321',3)]
            or type(degree) is not int or type(version) is not int
            or version not in (4,5) or backend not in BACKENDS):
        raise ValueError('unsupported control identity')
    if any(tuple(row.get(k) for k in IDENTITY) != identity for row in group.values()):
        raise ValueError('control record identity mismatch')
    for row in group.values():
        if row.get('security_qualified') is not False or row.get('full_pbs_trace') is not False:
            raise ValueError('unexpected admission or coverage flag')
    if integer(control,'n') != 32 or integer(control,'lwe') != 21:
        raise ValueError('unsupported synthetic geometry')
    if (control.get('nonzero_key') is not True
            or control.get('frozen_input_and_extraction_match') is not True):
        raise ValueError('missing accepted source-word controls')
    digits = (int(prime).bit_length()+4)//5
    for key, expected in [('ntt_source_claims',16*(digits+1)),
            ('product_source_claims',2*digits+1), ('decomposition_source_claims',2*digits+2),
            ('lookup_source_claims',2*digits+1), ('lookup_helper_claims',digits)]:
        if integer(control,key) != expected:
            raise ValueError('source-word count mismatch: '+key)
    for key in ('proof_bytes','verifier_hash_queries','verifier_xof_queries'):
        integer(control,key,1)
    seeds = integer(origins,'unique_child_seeds',1)
    if (backend == 'Brakedown' and seeds != 1) or (
            backend != 'Brakedown' and not 7*digits+9 <= seeds <= 9*digits+9):
        raise ValueError('child seed count outside native stage schedule')
    if integer(origins,'initial_identity_queries',1) != seeds:
        raise ValueError('initial identity/seed count mismatch')
    if integer(origins,'verifier_child_queries',1) < seeds:
        raise ValueError('missing post-identity requests')
    if (origins.get('all_input_windows_registered') is not True
            or integer(origins,'availability_hits') != 0
            or integer(origins,'output_collisions') != 0):
        raise ValueError('unexpected target/collision observation')
    claims = group.get('claims')
    if require_claims and claims is None:
        raise ValueError('missing child claim bindings')
    if claims is not None:
        bound = integer(claims,'bound_openings')
        if (claims.get('nested_claim_counts_preflighted') is not True
                or seeds != bound+1):
            raise ValueError('claim/seed coverage mismatch')
        if (backend == 'Brakedown' and bound != 0) or (
                backend != 'Brakedown' and not 7*digits+8 <= bound <= 9*digits+8):
            raise ValueError('child binding count outside native stage schedule')
    return identity


def audit(log, *, require_claims=False):
    data = Path(log).read_bytes()
    pending, controls, identities = {}, [], set()
    partial = False
    for line in data.decode().splitlines(keepends=True):
        prefix = next((p for p in PREFIXES if line.startswith(p)), None)
        if prefix is None:
            continue
        if not line.endswith('\n'):
            partial = True
            break
        kind = PREFIXES[prefix]
        if kind in pending or (kind == 'claims' and pending) or (
                kind == 'origins' and require_claims and 'claims' not in pending):
            raise ValueError('duplicate or reordered final-key records')
        pending[kind] = json.loads(line[len(prefix):])
        if kind == 'control':
            if 'origins' not in pending:
                raise ValueError('missing temporal origin record')
            identity = validate(pending,require_claims)
            if identity in identities:
                raise ValueError('duplicate final-key control identity')
            identities.add(identity)
            controls.append(pending)
            pending = {}
    if not controls:
        raise ValueError('no complete final-key controls')
    return dict(log=str(Path(log).resolve()), read_snapshot_sha256=hashlib.sha256(data).hexdigest(),
        completed_controls=len(controls), controls=controls,
        incomplete_trailing_control=bool(pending) or partial,
        suite_completion_verified=False, cryptographic_assertions_independently_proved=False,
        security_qualified=False, performance_gate=False)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--require-claims',action='store_true')
    args=parser.parse_args()
    write_json_new(args.output,audit(args.log,require_claims=args.require_claims))
