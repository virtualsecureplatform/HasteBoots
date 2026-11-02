"""Observed descriptor completion and causal raw-byte receipt matching.

Syntactic request classes are not authenticated stage interpretations. Unknown,
foreign and incomplete readers remain explicit; no adversarial bound is proved.
"""
import argparse
from collections import defaultdict, deque

from audit_artifacts import write_json_new
from audit_classical_reader_event_stream import audit, PHASES
from audit_classical_request_boundaries import inspect_input, RECEIPT

FIELD_METRICS = ('field_sampling_phases', 'field_values_sampled', 'field_candidate_draws',
                 'max_field_candidates_per_value', 'field_output_bytes',
                 'max_field_phase_output_bytes', 'max_field_values_per_phase')


def audit_inventory(path, expected_sha512, prime, *, expected_profile=None):
    if type(prime) is not int or prime not in (2013265921, 18446744069414584321):
        raise ValueError('supported trusted prime required')
    if (not isinstance(expected_sha512, str) or len(expected_sha512) != 128
            or any(c not in '0123456789abcdef' for c in expected_sha512)):
        raise ValueError('expected trace fingerprint required')
    if expected_profile is not None and (not isinstance(expected_profile, str)
            or len(expected_profile) != 128 or any(c not in '0123456789abcdef' for c in expected_profile)):
        raise ValueError('invalid expected profile')
    width = ((prime-1).bit_length()+7)//8
    mask = (1 << (prime-1).bit_length())-1
    readers, profiles, clock = {}, set(), 0

    def complete(info):
        if info['kind'] == 'field':
            return (info['values'] == info['declared'] and not info['pending']
                    and info['attempts'] == 0)
        return info['kind'] in ('bytes', 'checkpoint', 'receipt') and info['bytes'] == info['declared']

    def started(phase, reader, data):
        nonlocal clock
        clock += 1
        info = dict(phase=phase, started=clock, completed=None, kind='unknown',
                    declared=None, bytes=0, cross_phase=False, reason='unframed input')
        try:
            parsed = inspect_input(data, prime)
        except ValueError as exception:
            parsed = None
            info['reason'] = 'malformed framed input: '+str(exception)
        if parsed is not None:
            _, endpoint, count, profile = parsed
            profiles.add(profile)
            if expected_profile is not None and profile != expected_profile:
                info['reason'] = 'foreign profile'
            else:
                info.update(kind={2: 'bytes', 4: 'field', 8: 'checkpoint'}[endpoint], declared=count)
        elif data[:len(RECEIPT)] == RECEIPT:
            info.update(kind='receipt', declared=64, receipt_raw=bytes(data[len(RECEIPT):]))
        if info['kind'] == 'field':
            info.update(raw=bytearray(), pending=bytearray(), values=0,
                        candidates=0, attempts=0, maximum=0)
            if complete(info):
                info['completed'] = clock
        readers[reader] = info

    def returned(phase, reader, offset, data):
        nonlocal clock
        clock += 1
        info = readers[reader]
        if offset != info['bytes']:
            raise ValueError('inventory output offset mismatch')
        info['bytes'] += len(data)
        info['cross_phase'] |= phase != info['phase']
        if info['kind'] == 'field':
            info['raw'].extend(data)
            info['pending'].extend(data)
            end = len(info['pending'])//width*width
            for pos in range(0, end, width):
                value = int.from_bytes(info['pending'][pos:pos+width], 'little') & mask
                info['candidates'] += 1
                info['attempts'] += 1
                if value < prime:
                    info['values'] += 1
                    info['maximum'] = max(info['maximum'], info['attempts'])
                    info['attempts'] = 0
            del info['pending'][:end]
            if info['completed'] is None and complete(info):
                info['completed'] = clock

    result = audit(path, expected_sha512, on_reader_start=started, on_output_chunk=returned)
    rows = [dict(reader_queries=0, unknown_readers=0, incomplete_readers=0,
                 observed_output_bytes=0, byte_request_bytes=0, checkpoint_bytes=0,
                 receipt_queries=0, receipt_output_bytes=0,
                 **{key: 0 for key in FIELD_METRICS}) for _ in PHASES]
    unknown, incomplete, cross_phase, matching_events = [], [], [], []
    for reader, info in readers.items():
        row = rows[info['phase']]
        row['reader_queries'] += 1
        row['observed_output_bytes'] += info['bytes']
        if info['cross_phase']:
            cross_phase.append(reader)
        if info['kind'] == 'unknown':
            row['unknown_readers'] += 1
            unknown.append(dict(reader=reader, reason=info['reason']))
        if not complete(info):
            row['incomplete_readers'] += 1
            incomplete.append(reader)
            continue
        if info['kind'] == 'field':
            row['field_sampling_phases'] += 1
            row['field_values_sampled'] += info['values']
            row['field_candidate_draws'] += info['candidates']
            row['field_output_bytes'] += info['bytes']
            row['max_field_candidates_per_value'] = max(row['max_field_candidates_per_value'], info['maximum'])
            row['max_field_phase_output_bytes'] = max(row['max_field_phase_output_bytes'], info['bytes'])
            row['max_field_values_per_phase'] = max(row['max_field_values_per_phase'], info['declared'])
            matching_events.append((info['completed'], 0, reader, info['phase'], bytes(info['raw'])))
        elif info['kind'] == 'receipt':
            row['receipt_queries'] += 1
            row['receipt_output_bytes'] += info['bytes']
            matching_events.append((info['started'], 1, reader, info['phase'], info['receipt_raw']))
        elif info['kind'] == 'bytes':
            row['byte_request_bytes'] += info['bytes']
        else:
            row['checkpoint_bytes'] += info['bytes']
    available, pairs, unmatched_receipts = defaultdict(deque), [], []
    for tick, kind, reader, phase, raw in sorted(matching_events):
        if kind == 0:
            available[(phase, raw)].append((reader, tick))
        elif available.get((phase, raw)):
            field, completed_at = available[(phase, raw)].popleft()
            if completed_at >= tick:
                raise ValueError('receipt predecessor is not strictly earlier')
            pairs.append(dict(field_reader=field, receipt_reader=reader,
                              field_completed_at=completed_at, receipt_started_at=tick, phase=PHASES[phase]))
        else:
            unmatched_receipts.append(reader)
    unmatched_fields = sorted(reader for values in available.values() for reader, _ in values)
    for phase, row in zip(PHASES, rows):
        if row['reader_queries'] != result['phases'][phase]['xof_queries']:
            raise ValueError('reader classification count mismatch')
        if not cross_phase and row['observed_output_bytes'] != result['phases'][phase]['output_bytes']:
            raise ValueError('reader inventory byte mismatch')
    result.update(prime=str(prime), profile_ids=sorted(profiles),
        reader_inventory=dict(zip(PHASES, rows)), matched_field_receipts=pairs,
        unmatched_field_readers=unmatched_fields, unmatched_receipt_readers=unmatched_receipts,
        unknown_readers=unknown, incomplete_readers=incomplete, cross_phase_readers=cross_phase,
        closed_observed_inventory=not (unknown or incomplete or cross_phase or unmatched_fields or unmatched_receipts),
        receipt_matching_uses_exact_raw_bytes=True, late_receipts_not_repaired=True,
        semantic_field_receipt_stage_binding_established=False,
        arbitrary_query_coverage_established=False, native_verifier_caps_established=False)
    return result


def compare_field_counts(result, counts, *, phase='verify'):
    """Compare independently decoded complete reader phases to audited counters."""
    if not result['closed_observed_inventory']:
        raise ValueError('reader inventory has unresolved coverage or completion')
    for key in FIELD_METRICS:
        if result['reader_inventory'][phase][key] != counts[key]:
            raise ValueError('reader field/counter mismatch: '+key)
    return dict(compared_fields=list(FIELD_METRICS), phase=phase,
                observed_field_counts_equal=True, native_verifier_caps_established=False,
                security_qualified=False, performance_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace')
    parser.add_argument('--expected-sha512', required=True)
    parser.add_argument('--prime', type=int, required=True)
    parser.add_argument('--expected-profile')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit_inventory(args.trace, args.expected_sha512,
        args.prime, expected_profile=args.expected_profile))
