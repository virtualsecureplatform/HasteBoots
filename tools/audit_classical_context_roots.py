"""Check negacyclic root orders in previously joined caller context evidence.

This consumes the context-preimage audit as evidence; it does not repeat its
trace scan or establish stage binding, transform correctness, or security.
"""
import argparse
import hashlib
import json
from pathlib import Path

from audit_artifacts import write_json_new
from audit_classical_native_oracle_counts import audit as audit_counts
from audit_classical_role_contexts import DOMAIN, PARAMETERS, PREFIX, role_geometry


def uint(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('native unsigned integer required')
    if value < 251:
        return bytes([value])
    for tag, size in ((251, 2), (252, 4), (253, 8)):
        if value < 1 << (8*size):
            return bytes([tag])+value.to_bytes(size, 'little')


def context_preimage(profile, role, wire):
    """Rebuild the exact standard-bincode Brakedown parameter preimage."""
    geometry = role_geometry(profile, role)
    prime = profile['prime'].encode('ascii')
    string = uint(len(prime))+prime
    leading = ('num_vars', 'width', 'left_vars', 'ordered_quota',
               'block_width', 'codeword_blocks')
    code = ('message_len', 'block_width', 'message_blocks', 'codeword_blocks')
    return (PARAMETERS+string+b''.join(uint(geometry[key]) for key in leading)
            +uint(len(DOMAIN))+DOMAIN
            +b''.join(uint(geometry[key]) for key in code)+string+uint(wire))


def check_context(profile, role, row, declared_digest):
    if not isinstance(row, dict) or type(row.get('role')) is not int or row['role'] != role:
        raise ValueError('ordered unique roles required')
    geometry = row.get('geometry')
    if not isinstance(geometry, dict):
        raise ValueError('context geometry required')
    for key, expected in role_geometry(profile, role).items():
        if type(geometry.get(key)) is not int or geometry[key] != expected:
            raise ValueError('context evidence differs from caller geometry')
    wire = geometry.get('ntt_root_wire_repr')
    algebra = check_root(profile['prime'], geometry['codeword_blocks'], wire)
    digest = hashlib.sha512(context_preimage(profile, role, wire)).hexdigest()
    if row.get('context_sha512') != digest or declared_digest != digest:
        raise ValueError('reconstructed root preimage differs from caller context digest')
    return dict(role=role, context_sha512=digest,
                context_preimage_reconstructed_and_hashed=True, **algebra)


def check_root(prime, domain, wire):
    """Prove order 2N by r**N == -1 for a power-of-two N in either field."""
    if prime not in ('2013265921', '18446744069414584321'):
        raise ValueError('reviewed base field required')
    p = int(prime)
    if type(domain) is not int or domain < 32 or domain >= 2**64 or domain & (domain-1):
        raise ValueError('native power-of-two block domain required')
    if (p-1) % (2*domain):
        raise ValueError('negacyclic domain exceeds field two-adicity')
    bits = 32 if prime == '2013265921' else 64
    if type(wire) is not int or not 0 <= wire < 2**bits:
        raise ValueError('root wire integer outside field storage width')
    if bits == 32:
        if wire >= p:
            raise ValueError('noncanonical BabyBear Montgomery representative')
        root = wire * pow(2**32, -1, p) % p
    else:
        # Goldilocks serde stores its u64 directly; arithmetic canonicalizes
        # a lazy representative with one subtraction, unlike BabyBear serde.
        root = wire % p
    if pow(root, domain, p) != p-1:
        raise ValueError('root does not have exact negacyclic order 2N')
    return dict(root_canonical=root, root_order=2*domain,
                ntt_root_algebra_checked=True)


def audit(log, contexts, *, toy=False):
    counts = audit_counts(log, toy=toy, require_rejections=True,
        require_lookup_retry_counts=True, require_field_sampling_counts=True,
        require_honest_activity=True, require_xof_output_counts=True,
        require_column_sampling_counts=True, require_sampler_phase_maxima=True)
    context_bytes = Path(contexts).read_bytes()
    evidence = json.loads(context_bytes)
    for key in ('log_sha256',):
        if evidence.get(key) != counts[key]:
            raise ValueError('context evidence/log mismatch')
    profile = counts['profile']
    if (evidence.get('profile_id_sha512') != profile['profile_id_sha512']
            or evidence.get('native') is not (not toy)
            or evidence.get('all_declared_context_preimages_observed') is not True):
        raise ValueError('joined caller context evidence required')
    rows = evidence.get('roles')
    if not isinstance(rows, list) or len(rows) != 4:
        raise ValueError('four joined role contexts required')
    diagnostics = [json.loads(line[len(PREFIX):]) for line in Path(log).read_text().splitlines()
                   if line.startswith(PREFIX)]
    if len(diagnostics) != 1:
        raise ValueError('one caller role-context diagnostic required')
    diagnostic = diagnostics[0]
    expected = dict(profile_id_sha512=profile['profile_id_sha512'],
        caller_factory_contexts=True, native=not toy,
        ring_dimension=32 if toy else 1024, lwe_dimension=21 if toy else 728,
        security_qualified=False, performance_gate=False)
    if any(type(diagnostic.get(k)) is not type(v) or diagnostic[k] != v
           for k, v in expected.items()):
        raise ValueError('caller context diagnostic/proof mismatch')
    declared = diagnostic.get('role_contexts_sha512')
    if not isinstance(declared, list) or len(declared) != 4:
        raise ValueError('four caller context digests required')
    checked = [check_context(profile, role, row, declared[role])
               for role, row in enumerate(rows)]
    return dict(log_sha256=counts['log_sha256'],
        profile_id_sha512=profile['profile_id_sha512'], native=not toy,
        context_evidence=str(Path(contexts).resolve()),
        context_evidence_sha256=hashlib.sha256(context_bytes).hexdigest(),
        context_preimage_join_consumed_as_evidence=True,
        context_preimages_independently_rescanned=False, roles=checked,
        ntt_root_algebra_checked=True, transform_correctness_established=False,
        semantic_stage_binding_established=False,
        arbitrary_query_coverage_established=False,
        security_qualified=False, performance_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--contexts', required=True)
    parser.add_argument('--toy', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit(args.log, args.contexts, toy=args.toy))
