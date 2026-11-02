"""Conditional window construction accounting with shared strings and slices.

This is an explicit ideal-oracle cost model, not a claim about SHA512/SHAKE
implementation work or an established whole-protocol attacker-work reduction.
"""
from dataclasses import dataclass
from fractions import Fraction
from classical_work_cost import exact_rational, exact_rational_text


@dataclass(frozen=True)
class StringRef:
    owner: object
    length: int


class WindowWork:
    """Length-only accounting; never materializes or recharges shared prefixes.

    Every literal byte costs one unit, a concatenation/slice costs one unit,
    and each oracle submission costs one unit. All submitted input strings
    must be built through this interface in the same execution. References
    are trusted model handles, not proof-supplied certificates.
    """
    def __init__(self, window_bytes=64):
        if type(window_bytes) is not int or window_bytes < 1:
            raise ValueError('positive exact window size required')
        self.window_bytes = window_bytes
        self._owner = object()
        self.work = self.created_window_bound = self.xof_submissions = 0
        self.hash_submissions = 0

    def _check(self, value):
        if not isinstance(value, StringRef) or value.owner is not self._owner:
            raise ValueError('string from this construction ledger required')

    def _windows(self, length):
        return max(0, length-self.window_bytes+1)

    def literal(self, length):
        if type(length) is not int or length < 0:
            raise ValueError('nonnegative exact literal length required')
        self.work += length
        self.created_window_bound += self._windows(length)
        return StringRef(self._owner, length)

    def concat(self, left, right):
        self._check(left)
        self._check(right)
        self.work += 1
        self.created_window_bound += (self._windows(left.length+right.length)
                                     - self._windows(left.length)
                                     - self._windows(right.length))
        return StringRef(self._owner, left.length+right.length)

    def slice(self, value, start, end):
        self._check(value)
        if any(type(v) is not int for v in (start, end)) or not 0 <= start <= end <= value.length:
            raise ValueError('valid exact slice bounds required')
        self.work += 1
        # Every window of the slice already occurred in the parent string.
        return StringRef(self._owner, end-start)

    def submit(self, value, *, xof):
        self._check(value)
        if type(xof) is not bool:
            raise ValueError('explicit oracle kind required')
        self.work += 1
        self.xof_submissions += int(xof)
        self.hash_submissions += int(not xof)


def shared_window_xof_polynomial(*, output_bits=512, window_bytes=64,
                                 query_per_work, query_offset,
                                 construction_per_work, window_offset):
    """Substitute caller-proved affine work caps into the prefix exposure bound.

    Q <= query_per_work*T+query_offset; newly constructed windows are bounded
    by max(1,window_bytes-1)*construction_per_work*T, plus window_offset. Q
    includes all relevant fresh prefix answers, even at oversized inputs.
    Target pairs <= Q*W; collision pairs <= Q^2/2 (a safe relaxation of choose
    Q 2). All query/construction costs and verifier/honest offsets need proof.
    """
    dimensions = (output_bits, window_bytes)
    bounds = (query_per_work, query_offset, construction_per_work, window_offset)
    if (any(type(v) is not int or v < 1 for v in dimensions)
            or output_bits != 8*window_bytes
            or any(type(v) not in (int, Fraction) or v < 0 for v in bounds)):
        raise ValueError('positive dimensions and nonnegative exact affine caps required')
    a, h, b, w = map(Fraction, bounds)
    b *= max(1, window_bytes-1)
    denominator = 1 << output_bits
    return dict(constant=(h*w+h*h/2)/denominator,
                linear=(a*w+h*b+a*h)/denominator,
                quadratic=(a*b+a*a/2)/denominator,
                window_creation_per_work=max(1, window_bytes-1),
                required_premises=[
                    'All relevant input strings use literal/concat/slice construction with charged operations',
                    'Shared string references and prefix states are reused without new windows',
                    'Affine caps cover all adversary, verifier, setup and factory activity in one experiment',
                    'Fresh prefix outputs are conditionally uniform and all constructed input windows are registered'],
                input_bounds_verified=False, attacker_work_coupling_established=False,
                whole_proof_security_certified=False)


def joint_shared_window_oracle_polynomial(*, output_bits=512, window_bytes=64,
                                         hash_queries_per_work, hash_query_offset,
                                         xof_queries_per_work, xof_query_offset,
                                         construction_per_work, window_offset):
    """Joint conditional hash/XOF coefficients under one shared construction cap.

    All affine caps and offsets are mandatory and must cover the same complete
    experiment. Within-oracle collision terms are separate; both oracle types
    see the same constructed target-window set. No phase component is supplied.
    """
    components = {}
    for name, rate, offset in (
            ('merkle', hash_queries_per_work, hash_query_offset),
            ('xof', xof_queries_per_work, xof_query_offset)):
        term = shared_window_xof_polynomial(
            output_bits=output_bits, window_bytes=window_bytes,
            query_per_work=rate, query_offset=offset,
            construction_per_work=construction_per_work, window_offset=window_offset)
        components[name] = {key: term[key] for key in ('constant', 'linear', 'quadratic')}
    totals = {key: sum(component[key] for component in components.values())
              for key in ('constant', 'linear', 'quadratic')}
    return dict(**totals, components=components, output_bits=output_bits,
        window_creation_per_work=max(1, window_bytes-1),
        required_premises=[
            'All oracle inputs use the same charged literal/concat/slice construction history',
            'Separate hash/XOF affine caps include every adversary/verifier/setup/factory request',
            'Window offset covers all uncharged initial input windows',
            'Fresh outputs are conditionally uniform given the complete joint ideal-oracle history',
            'Every relevant input window is registered before the relevant answer'],
        scope='First-answer window hits and within-oracle collisions only',
        phase_component_supplied=False, input_bounds_verified=False,
        attacker_work_coupling_established=False, whole_proof_security_certified=False)


def native_stopped_joint_window_work(candidate, *, honest_hash_outputs,
                                    honest_xof_outputs, honest_window_values):
    """Use existing typed stopped-verifier caps as a conditional construction cap.

    Materializing each submitted input as a literal is an upper bound on a
    possible string representation, without requiring prefix reuse. This is
    not a lower bound on concrete machine work or a proof of verifier caps.
    """
    hashes = candidate['verifier_hash_outputs_upper_bound']
    xofs = candidate['verifier_xof_resource_envelope']['totals']['xof_queries']
    hash_bytes = candidate['verifier_hash_input_envelope']['maximum_hash_query_input_bytes']
    xof_bytes = candidate['verifier_frame_resource_envelope']['maximum_xof_query_input_bytes']
    quantities = (hashes, xofs, hash_bytes, xof_bytes,
                  honest_hash_outputs, honest_xof_outputs, honest_window_values)
    if any(type(value) is not int or value < 0 for value in quantities):
        raise ValueError('nonnegative exact native caps and explicit honest offsets required')
    construction = hashes*hash_bytes+xofs*xof_bytes
    result = joint_shared_window_oracle_polynomial(
        hash_queries_per_work=1+hashes, hash_query_offset=honest_hash_outputs,
        xof_queries_per_work=1+xofs, xof_query_offset=honest_xof_outputs,
        construction_per_work=1+construction, window_offset=honest_window_values)
    result.update(profile_id_sha512=candidate['profile_id_sha512'],
        verifier_hash_queries=hashes, verifier_xof_queries=xofs,
        verifier_hash_input_bytes_per_query=hash_bytes,
        verifier_xof_input_bytes_per_query=xof_bytes,
        verifier_literal_construction_bytes=construction,
        honest_offsets=dict(hash_outputs=honest_hash_outputs, xof_outputs=honest_xof_outputs,
                            window_values=honest_window_values),
        stopping_conditions=list(candidate['verifier_xof_resource_envelope']['stopping_conditions'])+[
            'Canonical field candidate ceiling '+str(candidate['sampler_resource_envelope']['candidate_limit_per_coefficient'])],
        additional_sampler_stop_union=candidate['verifier_xof_output_envelope']['additional_sampler_stop_union'],
        sampler_stop_union_scope='Per verifier invocation; all-submission phase composition remains required',
        production_loops_unchanged=True, analysis_only_stops=True,
        native_verifier_caps_established=False, global_resource_coupling_established=False,
        scope='Conditional stopped typed-verifier joint oracle polynomial; sampler stop errors and phase terms remain separate',
        security_qualified=False, performance_qualified=False)
    result['required_premises'] += [
        'One adversarial query, construction unit and verifier submission each cost at least one charged unit',
        'Typed verifier query/input ceilings hold on every stopped early-reject path',
        'All sampler stopping errors and complete phase coverage are added separately',
        'Honest offsets include all setup/factory and other uncharged initial activity']
    return result


def native_stopped_joint_work_report(candidate, *, honest_hash_outputs,
                                    honest_xof_outputs, honest_window_values,
                                    other_failure_polynomial, target_bits=128):
    """Compose joint oracle terms and per-submission sampler stops before work.

    The mandatory other polynomial must bound ALL remaining failures in charged
    work, including adversarial sampler stops, lookup stops, unclassified paths,
    source/stream coverage and every algebraic/opening transition. It excludes
    only the verifier's additional field/column sampler stops added here. Its
    validity is not established by this arithmetic entrypoint.
    """
    from classical_work_cost import exact_coefficients, composed_report
    if not isinstance(other_failure_polynomial, dict) or set(other_failure_polynomial) != {
            'constant', 'linear', 'quadratic'}:
        raise ValueError('explicit constant/linear/quadratic remaining-failure polynomial required')
    keys = ('constant', 'linear', 'quadratic')
    other = dict(zip(keys, exact_coefficients([other_failure_polynomial[k] for k in keys])))
    oracle = native_stopped_joint_window_work(candidate,
        honest_hash_outputs=honest_hash_outputs, honest_xof_outputs=honest_xof_outputs,
        honest_window_values=honest_window_values)
    encoded_stop = oracle['additional_sampler_stop_union']['exact']
    stop = Fraction(int(encoded_stop['numerator_hex'], 16),
                    int(encoded_stop['denominator_hex'], 16))
    if not 0 <= stop <= 1:
        raise ValueError('per-verifier sampler-stop probability required')
    phase = dict(other)
    # At most T charged submissions. Under the fresh-versus-prequeried
    # split premise, fresh verifier phases contribute beta*T; known-stream
    # stops must already be included in the supplied other-failure bound.
    phase['linear'] += stop
    result = composed_report(dict(oracle['components'], phase=phase), target_bits=target_bits)
    result.update(profile_id_sha512=oracle['profile_id_sha512'],
        other_failure_polynomial={k: exact_rational_text(v) for k, v in other.items()},
        additional_verifier_sampler_stop_per_submission=exact_rational_text(stop),
        additional_verifier_sampler_stop_linear_coefficient=exact_rational_text(stop),
        verifier_sampler_stop_scope='Fresh sampler phases first exposed by the verifier; prequeried stops belong to the supplied other bound',
        fresh_vs_prequeried_sampler_split_established=False,
        stopping_conditions=oracle['stopping_conditions'],
        honest_offsets=oracle['honest_offsets'],
        scope='Conditional full supplied-failure plus stopped-verifier oracle arithmetic; premises unverified',
        other_failure_bound_verified=False, native_verifier_caps_established=False,
        production_loops_unchanged=True, analysis_only_stops=True)
    result['missing'] += [
        'Uniform supplied other-failure polynomial including every unclassified accepting path',
        'Proved fresh-versus-prequeried sampler split for the automatic verifier-stop charge',
        'Adversarial sampler-stop and lookup-stop coverage not supplied by this automatic verifier charge',
        'Complete shared-string construction and native input-cap justification']
    return result


def native_first_query_field_stop_polynomial(candidate, *, honest_xof_outputs):
    """Conditional global canonical-field stop charge at distinct first inputs.

    At count ceiling C, each eligible first input contributes <=min(1,C*r^R).
    All eligible inputs, regardless of actor, are bounded by total XOF requests
    <=(1+V_X)*T+h_X. This is not a fresh-per-selected-submission estimate.
    """
    from classical_sampler_resources import field_stop_first_query_bound
    sampler = candidate['sampler_resource_envelope']
    count = sampler['coefficient_count_ceiling']
    queries = candidate['verifier_xof_resource_envelope']['totals']['xof_queries']
    if (type(count) is not int or not 0 <= count < 2**64
            or any(type(value) is not int or value < 0 for value in (queries, honest_xof_outputs))):
        raise ValueError('representable coefficient ceiling and exact query cap/offset required')
    # A deterministic C bound for one input, independent of its actor. The
    # unknown slot here is bookkeeping, not an assumed experiment actor count.
    local = field_stop_first_query_bound(int(candidate['profile']['prime']),
        sampler['candidate_limit_per_coefficient'], expected_coefficients=dict(
            adversary=0, verifier=0, setup=0, unknown=count))
    encoded = local['total']['exact']
    per_input = Fraction(int(encoded['numerator_hex'], 16), int(encoded['denominator_hex'], 16))
    return dict(constant=per_input*honest_xof_outputs,
        linear=per_input*(1+queries), quadratic=Fraction(),
        per_eligible_first_input=per_input, coefficient_ceiling=count,
        rejected_candidate_limit=sampler['candidate_limit_per_coefficient'],
        verifier_xof_queries=queries, honest_xof_outputs=honest_xof_outputs,
        scope='Canonical field rejection only; all eligible distinct first inputs, including prequeries',
        required_premises=[
            'Every bounded actual field request lies in the selected profile/modulus syntactic superclass',
            'The coefficient ceiling is fixed and valid for every relevant trusted verifier call',
            'Independent ideal whole-stream completion at first input agrees with later uses',
            'Total XOF query cap includes every adversarial, verifier and honest initial exposure'],
        complete_request_coverage_established=False, whole_stream_model_established=False,
        global_query_cap_established=False, production_loops_unchanged=True,
        whole_proof_security_certified=False)


def _native_first_query_work_core(candidate, *, honest_hash_outputs,
                                  honest_xof_outputs, honest_window_values,
                                  other_failure_polynomial, stop_polynomial,
                                  success_probability_lower_bound, target_bits):
    from classical_work_cost import exact_coefficients, composed_report, expected_work_bound
    keys = ('constant', 'linear', 'quadratic')
    if not isinstance(other_failure_polynomial, dict) or set(other_failure_polynomial) != set(keys):
        raise ValueError('explicit exact remaining-failure polynomial required')
    other = dict(zip(keys, exact_coefficients([other_failure_polynomial[k] for k in keys])))
    oracle = native_stopped_joint_window_work(candidate,
        honest_hash_outputs=honest_hash_outputs, honest_xof_outputs=honest_xof_outputs,
        honest_window_values=honest_window_values)
    phase = {key: other[key]+stop_polynomial[key] for key in keys}
    result = composed_report(dict(oracle['components'], phase=phase), target_bits=target_bits)
    totals = {key: sum(exact_rational(c[key]) for c in result['components'].values()) for key in keys}
    expected = expected_work_bound([totals['linear'], totals['quadratic']],
        constant=totals['constant'], success_probability_lower_bound=success_probability_lower_bound)
    result.update(profile_id_sha512=oracle['profile_id_sha512'],
        other_failure_polynomial={key: exact_rational_text(other[key]) for key in keys},
        stopping_conditions=oracle['stopping_conditions'], honest_offsets=oracle['honest_offsets'],
        conditional_fixed_budget_target_met=result['conditional_work_target_met'],
        expected_work=expected,
        conditional_expected_work_target_met=exact_rational(expected['expected_work_per_success_bound']) >= 2**target_bits,
        whole_stream_model_established=False, other_failure_bound_verified=False,
        native_verifier_caps_established=False, production_loops_unchanged=True,
        analysis_only_stops=True)
    result['missing'] += [
        'Proved success-probability floor for the separate expected-work report',
        'Global query/construction caps and complete remaining-failure polynomial']
    return result


def native_first_query_field_work_report(candidate, *, honest_hash_outputs,
                                        honest_xof_outputs, honest_window_values,
                                        other_failure_polynomial,
                                        success_probability_lower_bound, target_bits=128):
    """Conditional field-only stop composition; columns/lookup remain supplied."""
    field = native_first_query_field_stop_polynomial(candidate, honest_xof_outputs=honest_xof_outputs)
    result = _native_first_query_work_core(candidate,
        honest_hash_outputs=honest_hash_outputs, honest_xof_outputs=honest_xof_outputs,
        honest_window_values=honest_window_values, other_failure_polynomial=other_failure_polynomial,
        stop_polynomial=field, success_probability_lower_bound=success_probability_lower_bound,
        target_bits=target_bits)
    result.update(first_query_field_stop_polynomial={key: exact_rational_text(field[key])
                                                   for key in ('constant', 'linear', 'quadratic')},
        field_stop_coefficient_ceiling=field['coefficient_ceiling'], field_stop_scope=field['scope'],
        complete_field_request_coverage_established=False,
        scope='Conditional first-query field-stop plus supplied remaining-failure and joint-oracle composition',
        automatic_column_or_lookup_stop_charge=False)
    result['missing'] += [
        'Complete field-request superclass coverage and virtual whole-stream consistency',
        'All v4 column-rejection and lookup-stop events in supplied remaining failures']
    return result


def native_first_query_sampler_stop_polynomial(candidate, *, honest_xof_outputs):
    """Joint field/column stop envelope using disjoint first opportunities.

    Fields and column members have different terminal frame kinds. Their
    first-input/first-family opportunities therefore inject jointly into XOF
    inputs. Native v4 Brakedown column geometry uses the power-of-two maximum
    domain and maximum ordered-draw quota; other schedules/backends add no
    column-rejection loop. Coverage and output-tree assumptions remain unproved.
    """
    from classical_sampler_resources import column_stop_first_family_bound
    profile = candidate['profile']
    if profile['descriptor_version'] not in (4, 5) or profile['backend'] not in (
            'Brakedown', 'Polyfrim', 'PolyfrimDictionary', 'FragmentedPipfri', 'FragmentedPipfriVirtual'):
        raise ValueError('audited native schedule/backend required')
    field = native_first_query_field_stop_polynomial(candidate, honest_xof_outputs=honest_xof_outputs)
    column = Fraction()
    geometry = None
    if profile['descriptor_version'] == 4 and profile['backend'] == 'Brakedown':
        domains = [role['per_opening']['encoded_blocks'] for role in candidate['roles']]
        quotas = profile['role_queries']
        limits = [role['column_sampler_resource_envelope']['per_call']['candidate_limit_per_draw']
                  for role in candidate['roles']]
        if (not domains or len(domains) != len(quotas) or len(limits) != len(domains)
                or any(type(n) is not int or not 0 < n < 2**64 or n & (n-1) for n in domains)
                or any(type(q) is not int or not 0 < q < 2**64 for q in quotas)
                or any(type(r) is not int or r < 1 for r in limits) or len(set(limits)) != 1):
            raise ValueError('matching power-of-two native domains, quotas and common retry stop required')
        geometry = dict(domain=max(domains), ordered_draws=max(quotas),
                        rejected_candidate_limit=limits[0], role_domains=domains, role_quotas=list(quotas))
        local = column_stop_first_family_bound(geometry['domain'], geometry['ordered_draws'],
            geometry['rejected_candidate_limit'], expected_families=dict(
                adversary=0, verifier=0, setup=0, unknown=1))
        encoded = local['total']['exact']
        column = Fraction(int(encoded['numerator_hex'], 16), int(encoded['denominator_hex'], 16))
    per_opportunity = max(field['per_eligible_first_input'], column)
    return dict(constant=per_opportunity*honest_xof_outputs,
        linear=per_opportunity*(1+field['verifier_xof_queries']), quadratic=Fraction(),
        field_local_bound=field['per_eligible_first_input'], column_local_bound=column,
        joint_local_bound=per_opportunity, column_geometry=geometry,
        counting_method='Disjoint field inputs and first byte-family members bounded jointly by XOF requests',
        native_geometry_domination_established=False, complete_opportunity_coverage_established=False,
        output_tree_model_established=False, production_loops_unchanged=True,
        whole_proof_security_certified=False)


def native_first_query_sampler_work_report(candidate, *, honest_hash_outputs,
                                          honest_xof_outputs, honest_window_values,
                                          other_failure_polynomial,
                                          success_probability_lower_bound, target_bits=128):
    """Joint pure-sampler stop composition; lookup/source/application bounds required."""
    stop = native_first_query_sampler_stop_polynomial(candidate, honest_xof_outputs=honest_xof_outputs)
    result = _native_first_query_work_core(candidate,
        honest_hash_outputs=honest_hash_outputs, honest_xof_outputs=honest_xof_outputs,
        honest_window_values=honest_window_values, other_failure_polynomial=other_failure_polynomial,
        stop_polynomial=stop, success_probability_lower_bound=success_probability_lower_bound,
        target_bits=target_bits)
    result.update(first_query_sampler_stop_polynomial={key: exact_rational_text(stop[key])
                                                     for key in ('constant', 'linear', 'quadratic')},
        sampler_local_bounds={key: exact_rational_text(stop[key]) for key in (
            'field_local_bound', 'column_local_bound', 'joint_local_bound')},
        column_geometry=stop['column_geometry'],
        automatic_field_stop_charge=True,
        automatic_column_stop_charge=stop['column_geometry'] is not None,
        automatic_lookup_stop_charge=False,
        complete_sampler_coverage_established=False, native_geometry_domination_established=False,
        scope='Conditional joint first-query field/column stops plus supplied remaining failures and oracle terms')
    result['missing'] += [
        'Joint disjoint-opportunity coverage and native maximum-domain/quota domination',
        'Fresh independent whole-family output-tree model and actual stream consistency',
        'All lookup-stop, application/opening/source/knowledge coverage in supplied bounds']
    return result
