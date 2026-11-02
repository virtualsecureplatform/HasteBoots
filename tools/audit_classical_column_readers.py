"""Reconstruct observed v4 column runs; never infer an adversarial work bound."""
import argparse
from collections import defaultdict
import json
from pathlib import Path

from audit_artifacts import write_json_new
from audit_classical_reader_event_stream import audit, PHASES
from audit_classical_request_boundaries import PREFIX, frame, inspect_input
from audit_classical_role_contexts import role_geometry
from audit_classical_native_oracle_counts import audit as audit_counts
from audit_classical_native_reader_events import audit as audit_bindings

LABEL = b'mw unbiased column'
COLUMN_METRICS = ('column_sampling_phases', 'column_values_sampled',
                  'column_candidate_draws', 'max_column_candidates_per_value',
                  'max_column_values_per_phase')
MAXIMUM = 2**64-1


def replay_samples(domain, quota, samples):
    """Exact production MAX-cutoff rule, preserving ordered repeated indices."""
    if (type(domain) is not int or not 0 < domain < 2**64
            or type(quota) is not int or not 0 < quota < 2**64):
        raise ValueError('positive native domain and quota required')
    cutoff = MAXIMUM-MAXIMUM % domain
    ordered, attempts, maximum, candidates, trailing = [], 0, 0, 0, 0
    for sample in samples:
        if type(sample) is not int or not 0 <= sample <= MAXIMUM:
            raise ValueError('u64 sample required')
        if len(ordered) == quota:
            trailing += 1
            continue
        candidates += 1
        attempts += 1
        if sample < cutoff:
            ordered.append(sample % domain)
            maximum = max(maximum, attempts)
            attempts = 0
    return dict(ordered_indices=ordered, distinct_indices=sorted(set(ordered)),
        candidate_draws=candidates, max_candidates_per_value=maximum,
        pending_attempts=attempts, completed=len(ordered) == quota,
        trailing_candidates=trailing)


def column_request(data, prime, expected_profile):
    parsed = inspect_input(data, prime)
    if parsed is None or parsed[1] != 2:
        return None
    pos, context, root, root_context, awaiting, prior = len(PREFIX), None, None, None, False, []
    last_label = None
    while pos < len(data):
        kind, label, body, pos = frame(data, pos)
        last_label = label
        if kind == 1 and label == b'mw brakedown row-code v2':
            if len(body) != 64:
                raise ValueError('invalid single-opening context')
            context = bytes(body).hex()
        elif kind == 1 and label == b'mw batched row-code v1':
            if len(body) < 64:
                raise ValueError('invalid batch-opening context')
            context = bytes(body[:64]).hex()
        if kind == 2 and label == LABEL and body == (8).to_bytes(8, 'little'):
            if not awaiting:
                root, root_context, prior = pos, context, []
            awaiting = False
        elif kind == 3 and label == LABEL and len(body) == 8 and root is not None and not awaiting:
            prior.append(bytes(body))
            awaiting = True
        else:
            root, awaiting, prior = None, False, []
    if last_label != LABEL:
        return None
    if parsed[3] != expected_profile or parsed[2] != 8 or root is None or awaiting:
        raise ValueError('invalid/foreign sequential column endpoint')
    return dict(root=bytes(data[:root]), context=root_context, prior=tuple(prior))


def audit_columns(path, fingerprint, profile, context_evidence):
    if profile['descriptor_version'] != 4 or profile['backend'] != 'Brakedown':
        raise ValueError('reviewed v4 Brakedown profile required')
    profile_id = context_evidence['profile_id_sha512']
    if context_evidence.get('all_declared_context_preimages_observed') is not True:
        raise ValueError('verified caller-context evidence required')
    contexts = {}
    roles = context_evidence['roles']
    if len(roles) != 4 or {row['role'] for row in roles} != set(range(4)):
        raise ValueError('four caller roles required')
    for row in roles:
        expected = role_geometry(profile, row['role'])
        if any(type(row['geometry'].get(key)) is not int or row['geometry'][key] != value
               for key, value in expected.items()):
            raise ValueError('caller context geometry mismatch')
        shape = (expected['codeword_blocks'], expected['ordered_quota'])
        key = row['context_sha512']
        if not isinstance(key, str) or len(key) != 128 or any(c not in '0123456789abcdef' for c in key):
            raise ValueError('canonical caller context digest required')
        if key in contexts and contexts[key]['shape'] != shape:
            raise ValueError('ambiguous caller context geometry')
        contexts.setdefault(key, dict(shape=shape, roles=[]))['roles'].append(row['role'])
    families, readers, unresolved, clock = {}, {}, [], 0

    def started(phase, reader, data):
        nonlocal clock
        clock += 1
        try:
            request = column_request(data, int(profile['prime']), profile_id)
        except ValueError as error:
            unresolved.append(dict(reader=reader, reason=str(error)))
            return
        if request is None:
            return
        context = contexts.get(request['context'])
        if context is None:
            unresolved.append(dict(reader=reader, reason='unrecognized caller context'))
            return
        key = (phase, request['root'])
        family = families.setdefault(key, dict(index=len(families), phase=phase,
            context=context, positions=defaultdict(list)))
        info = dict(reader=reader, started=clock, completed=None,
                    prior=request['prior'], raw=bytearray(), cross_phase=False)
        family['positions'][len(request['prior'])].append(info)
        readers[reader] = (family, info)

    def returned(phase, reader, offset, data):
        nonlocal clock
        clock += 1
        if reader not in readers:
            return
        family, info = readers[reader]
        if offset != len(info['raw']):
            raise ValueError('column output offset mismatch')
        info['raw'].extend(data)
        info['cross_phase'] |= phase != family['phase']
        if info['completed'] is None and len(info['raw']) == 8:
            info['completed'] = clock

    streamed = audit(path, fingerprint, on_reader_start=started, on_output_chunk=returned)
    totals = [{key: 0 for key in COLUMN_METRICS} for _ in PHASES]
    outcomes = []
    for family in families.values():
        positions = family['positions']
        first = min((info for rows in positions.values() for info in rows), key=lambda info: info['started'])
        multiplicity = len(positions.get(0, []))
        failures, raw_prefix, earliest_previous = [], [], None
        domain, quota = family['context']['shape']
        replay = replay_samples(domain, quota, [])
        for position in range(max(positions)+1):
            rows = positions.get(position, [])
            valid = []
            for info in rows:
                if len(info['raw']) != 8 or info['cross_phase']:
                    failures.append(dict(reader=info['reader'], reason='incomplete/cross-phase draw'))
                elif info['prior'] != tuple(raw_prefix):
                    failures.append(dict(reader=info['reader'], reason='inline bytes differ from observed predecessors'))
                elif position and (earliest_previous is None or earliest_previous >= info['started']):
                    failures.append(dict(reader=info['reader'], reason='predecessor unavailable at input query'))
                else:
                    valid.append(info)
            if not valid:
                failures.append(dict(position=position, reason='missing consistent draw'))
                break
            if not multiplicity or len(valid) != multiplicity:
                failures.append(dict(position=position, reason='inconsistent repeated-run multiplicity'))
            raw = bytes(valid[0]['raw'])
            if any(bytes(info['raw']) != raw for info in valid):
                raise ValueError('inconsistent outputs for same canonical draw input')
            raw_prefix.append(raw)
            earliest_previous = min(info['completed'] for info in valid)
            replay = replay_samples(domain, quota, [int.from_bytes(raw, 'little') for raw in raw_prefix])
            if replay['completed']:
                if max(positions) > position:
                    failures.append(dict(reason='queried after ordered quota completed'))
                break
        if not replay['completed']:
            failures.append(dict(reason='ordered quota incomplete'))
        closed = not failures
        if closed:
            total = totals[family['phase']]
            total['column_sampling_phases'] += multiplicity
            total['column_values_sampled'] += quota*multiplicity
            total['column_candidate_draws'] += replay['candidate_draws']*multiplicity
            total['max_column_candidates_per_value'] = max(total['max_column_candidates_per_value'], replay['max_candidates_per_value'])
            total['max_column_values_per_phase'] = max(total['max_column_values_per_phase'], quota)
        outcomes.append(dict(family=family['index'], phase=PHASES[family['phase']],
            roles=family['context']['roles'], domain=domain, ordered_quota=quota,
            first_reader=first['reader'], first_position=len(first['prior']),
            root_reader_instances=multiplicity, closed=closed, failures=failures, replay=replay))
        outcomes[-1]['observed_positions'] = {str(position): [info['reader'] for info in rows]
                                             for position, rows in sorted(positions.items())}
    streamed.update(column_inventory=dict(zip(PHASES, totals)), families=outcomes,
        unresolved_readers=unresolved, closed_observed_column_inventory=not unresolved and all(row['closed'] for row in outcomes),
        root_family_count=len(families), column_reader_instances=len(readers),
        roots_grouped_by_exact_bytes=True, repeated_roots_are_not_distinct_trials=True,
        semantic_stage_binding_established=False, arbitrary_query_coverage_established=False,
        native_verifier_caps_established=False)
    return streamed


def compare_column_counts(result, counts, *, phase='verify'):
    if not result['closed_observed_column_inventory']:
        raise ValueError('column inventory has unresolved paths')
    for key in COLUMN_METRICS:
        if result['column_inventory'][phase][key] != counts[key]:
            raise ValueError('column reader/counter mismatch: '+key)
    return dict(observed_column_counts_equal=True, compared_fields=list(COLUMN_METRICS),
                security_qualified=False, performance_qualified=False)


def audit_log(log, context_path, *, toy=False):
    contexts = json.loads(Path(context_path).read_text())
    counts = audit_counts(log, toy=toy, require_rejections=True, require_lookup_retry_counts=True,
        require_field_sampling_counts=True, require_honest_activity=True, require_xof_output_counts=True,
        require_column_sampling_counts=True, require_sampler_phase_maxima=True)
    if (contexts['log_sha256'] != counts['log_sha256']
            or contexts['profile_id_sha512'] != counts['profile']['profile_id_sha512']):
        raise ValueError('context evidence is for a different validation log/profile')
    bound = audit_bindings(log, toy=toy)
    if contexts['accepted_trace_sha512'] != bound['traces'][0]['trace_sha512']:
        raise ValueError('context evidence is for a different accepted capture')
    captures = []
    for trace, measurement in zip(bound['traces'],
            (counts['measurements'][0], counts['rejected_measurements'][0])):
        result = audit_columns(trace['path'], trace['trace_sha512'], counts['profile'], contexts)
        comparison = compare_column_counts(result, measurement)
        captures.append(dict(kind=trace['kind'], inventory=result, comparison=comparison))
    return dict(log=counts['log'], log_sha256=counts['log_sha256'],
        context_evidence=str(Path(context_path).resolve()), native=not toy,
        captures=captures, scope='First accepted/rejected captured v4 verifier pair only',
        semantic_stage_binding_established=False, arbitrary_query_coverage_established=False,
        security_qualified=False, performance_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--contexts', required=True)
    parser.add_argument('--toy', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit_log(args.log, args.contexts, toy=args.toy))
