#!/usr/bin/env python3
"""Audit streamed oracle-interface events, never security/performance admission."""
import argparse
import hashlib
import json
from pathlib import Path

HEADER = b"HB_ORACLE_EVENT_STREAM_V1\n"
PHASES = ("setup", "prove", "verify")
CONTROL_PREFIX = "HB_COMPLETE_PBS_EVENT_TRACE "


def audit(path, expected_sha512=None, *, on_xof_input=None):
    digest = hashlib.sha512()
    phases = [dict(hash_queries=0, xof_queries=0, hash_input_bytes=0,
                   xof_input_bytes=0, max_hash_input=0, max_xof_input=0)
              for _ in PHASES]
    events = 0
    previous_phase = 0
    with Path(path).open("rb") as source:
        header = source.read(len(HEADER))
        if header != HEADER:
            raise ValueError("unsupported oracle-event stream header")
        digest.update(header)
        while True:
            frame = source.read(10)
            if not frame:
                break
            if len(frame) != 10:
                raise ValueError("truncated event header")
            kind, phase = frame[:2]
            if kind not in (1, 2) or phase not in range(3) or phase < previous_phase:
                raise ValueError("invalid event kind or phase order")
            previous_phase = phase
            digest.update(frame)
            length = int.from_bytes(frame[2:], "little")
            remaining = length
            preimage = hashlib.sha512() if kind == 1 else None
            captured = bytearray() if kind == 2 and on_xof_input is not None else None
            while remaining:
                # This is an IO buffer size, not a query-length/adversary limit.
                chunk = source.read(min(remaining, 1 << 20))
                if not chunk:
                    raise ValueError("truncated event input")
                digest.update(chunk)
                if preimage is not None:
                    preimage.update(chunk)
                if captured is not None:
                    captured.extend(chunk)
                remaining -= len(chunk)
            if preimage is not None:
                output = source.read(64)
                if len(output) != 64:
                    raise ValueError("truncated SHA-512 output")
                digest.update(output)
                if output != preimage.digest():
                    raise ValueError("SHA-512 preimage/output mismatch")
            if captured is not None:
                on_xof_input(phase, memoryview(captured))
            key = "hash" if kind == 1 else "xof"
            row = phases[phase]
            row[key + "_queries"] += 1
            row[key + "_input_bytes"] += length
            row["max_" + key + "_input"] = max(row["max_" + key + "_input"], length)
            events += 1
    fingerprint = digest.hexdigest()
    if expected_sha512 is not None and fingerprint != expected_sha512.lower():
        raise ValueError("oracle-event stream fingerprint mismatch")
    return dict(path=str(Path(path).resolve()), trace_sha512=fingerprint,
                events=events, phases=dict(zip(PHASES, phases)),
                sha512_preimages_verified=True, xof_outputs_recorded=False,
                security_qualified=False, performance_qualified=False)


def audit_controls(log):
    """Recompute completed control rows; a live log never proves suite completion."""
    controls = []
    identities = set()
    with Path(log).open() as source:
        for line in source:
            if not line.startswith(CONTROL_PREFIX):
                continue
            # A writer may currently be emitting its last row. Only complete
            # newline-terminated records are observations, never partial JSON.
            if not line.endswith('\n'):
                break
            row = json.loads(line[len(CONTROL_PREFIX):])
            fingerprint = row['trace_sha512']
            if (not isinstance(fingerprint, str) or len(fingerprint) != 128
                    or any(c not in '0123456789abcdefABCDEF' for c in fingerprint)):
                raise ValueError('invalid control trace SHA-512 fingerprint')
            identity = tuple(row[key] for key in ('prime', 'degree', 'version', 'backend'))
            if identity in identities:
                raise ValueError('duplicate complete-PBS control identity')
            identities.add(identity)
            result = audit(row['trace_path'], fingerprint)
            for key, observed in result['phases']['verify'].items():
                reported = row['verifier_' + key]
                if type(reported) is not int or reported != observed:
                    raise ValueError('verifier counter mismatch: ' + key)
            controls.append(dict(control=row, audit=result))
    if not controls:
        raise ValueError('no completed complete-PBS controls')
    return dict(log=str(Path(log).resolve()), completed_controls=len(controls),
                controls=controls, suite_completion_verified=False,
                security_qualified=False, performance_qualified=False)


SOURCE_PREFIXES = ("HB_COMPLETE_FINAL_OBLIGATIONS ",
                   "HB_COMPLETE_PRIMARY_SOURCE_WORDS ",
                   "HB_COMPLETE_FINAL_SOURCE_WORDS ")
IDENTITY_KEYS = ('prime', 'degree', 'version', 'backend')
TEMPORAL_PREFIX = "HB_COMPLETE_TEMPORAL_ORIGINS "


def validate_temporal_control(row, control):
    """Validate captured generic-phase records, never an adaptive ROM theorem."""
    if tuple(row.get(k) for k in IDENTITY_KEYS) != tuple(control.get(k) for k in IDENTITY_KEYS):
        raise ValueError('temporal/control identity mismatch')
    for key in ('all_captured_input_windows_checked', 'same_prover_verifier_seed_sets',
                'generic_completed_phase_streams_checked'):
        if row.get(key) is not True:
            raise ValueError('missing captured temporal check: ' + key)
    for key in ('all_input_windows_registered', 'availability_filter_checked', 'security_qualified'):
        if row.get(key) is not False:
            raise ValueError('unexpected general temporal admission: ' + key)
    def vector(key, length):
        values = row.get(key)
        if (type(values) is not list or len(values) != length
                or any(type(v) is not int or v < 0 for v in values)):
            raise ValueError('invalid temporal vector: ' + key)
        return values
    identities = vector('initial_identity_requests', 3)
    later = vector('later_child_requests', 3)
    seeds = vector('unique_child_seeds', 3)
    if (any(v[0] != 0 or v[1] != v[2] for v in (identities, later, seeds))
            or seeds[2] < 3 or identities[2] < seeds[2] or later[2] < seeds[2]):
        raise ValueError('incomplete temporal phase coverage')
    if vector('captured_availability_hits', 2) != [0, 0]:
        raise ValueError('captured availability hit')
    for key, minimum in [('xof_output_collisions', 0), ('replayed_receipt_frames', 1)]:
        value = row.get(key)
        if type(value) is not int or value < minimum or (key == 'xof_output_collisions' and value != 0):
            raise ValueError('invalid temporal counter: ' + key)


def audit_source_controls(log, *, require_temporal=False):
    """Audit the n32/LWE21, width8, radix8/5, repetition1 control fixture.

    Source claims remain Rust-verifier evidence, not an independent security
    proof. Here we check its complete ordered records and independently audit
    every trace event, fingerprint and verifier resource counter.
    """
    groups = []
    pending = []
    prefixes = SOURCE_PREFIXES + (CONTROL_PREFIX,)
    if require_temporal:
        prefixes = (SOURCE_PREFIXES[0], TEMPORAL_PREFIX) + prefixes[1:]
    with Path(log).open() as source:
        for line in source:
            if not line.endswith('\n'):
                break
            prefix = next((p for p in prefixes
                           if line.startswith(p)), None)
            if prefix is None:
                continue
            expected = prefixes[len(pending)]
            if prefix != expected:
                raise ValueError('incomplete or reordered source-word records')
            pending.append(json.loads(line[len(prefix):]))
            if len(pending) == len(prefixes):
                groups.append(pending)
                pending = []
    result = audit_controls(log)
    if len(groups) != result['completed_controls']:
        raise ValueError('source-word/control count mismatch')
    for group, entry in zip(groups, result['controls']):
        temporal = group[1] if require_temporal else None
        if require_temporal:
            group = group[:1] + group[2:]
        obligations, primary, final, control = group
        if control != entry['control']:
            raise ValueError('source-word/control ordering mismatch')
        identity = tuple(control[k] for k in IDENTITY_KEYS)
        if any(tuple(row[k] for k in IDENTITY_KEYS) != identity
               for row in (obligations, final)):
            raise ValueError('source-word identity mismatch')
        if any(type(control.get(k)) is not int or control[k] != value
               for k, value in [('n', 32), ('lwe', 21), ('queries', 8)]):
            raise ValueError('unsupported source-word fixture geometry')
        if (obligations.get('complete_transcript_match') is not True
                or primary.get('monomial_checked') is not True
                or final.get('all_pbs_stages_coupled') is not True):
            raise ValueError('incomplete source-word stage coverage')
        bits = int(control['prime']).bit_length()
        main_digits, final_digits = (bits + 7) // 8, (bits + 4) // 5
        counts = [(obligations, 'ntt_components', final_digits + 1),
                  (obligations, 'linear_sources', 2 * final_digits + 2),
                  (primary, 'claims', 46 * main_digits + 74),
                  (final, 'ntt_source_claims', 16 * (final_digits + 1)),
                  (final, 'product_source_claims', 2 * final_digits + 1),
                  (final, 'decomposition_source_claims', 2 * final_digits + 2),
                  (final, 'lookup_source_claims', 2 * final_digits + 1),
                  (final, 'lookup_helper_claims', final_digits),
                  (final, 'events_replayed', entry['audit']['events'])]
        for row, key, expected in counts:
            if type(row.get(key)) is not int or row[key] != expected:
                raise ValueError('source-word count mismatch: ' + key)
        entry['source_word_records'] = dict(obligations=obligations,
                                            primary=primary, final=final)
        if require_temporal:
            validate_temporal_control(temporal, control)
            if (any(row.get('security_qualified') is not False for row in group)
                    or control.get('encrypted_native') is not False):
                raise ValueError('unexpected source control admission/geometry flag')
            entry['temporal_origins'] = temporal
    result['all_stage_source_control_records_verified'] = True
    result['captured_generic_phase_control_records_verified'] = require_temporal
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", nargs='?')
    parser.add_argument("--control-log", help="audit completed control rows and verifier counters")
    parser.add_argument("--require-source-words", action="store_true",
                        help="require complete ordered all-stage source-word control records")
    parser.add_argument("--require-temporal", action="store_true",
                        help="also require captured generic receipt/link and availability records")
    parser.add_argument("--expected-sha512")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if bool(args.trace) == bool(args.control_log):
        parser.error('provide either a trace or --control-log')
    if args.control_log and args.expected_sha512:
        parser.error('--expected-sha512 applies to a single trace only')
    if args.require_source_words and not args.control_log:
        parser.error('--require-source-words requires --control-log')
    if args.require_temporal and not args.require_source_words:
        parser.error('--require-temporal requires --require-source-words')
    result = (audit_source_controls(args.control_log, require_temporal=args.require_temporal) if args.require_source_words
              else audit_controls(args.control_log)) if args.control_log else audit(args.trace, args.expected_sha512)
    with Path(args.output).open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
