"""Conditional expected-work ratios from a predictable affine success hazard.

Unlike a success-by-budget CDF alone, this requires a bound conditional on
every full pre-step history. It supplies arithmetic, not a protocol reduction.
"""
from fractions import Fraction

from classical_work_cost import exact_rational, exact_rational_text, expected_work_bound


def field_sampler_hazard(*, prime, coefficient_ceiling, rejected_candidate_limit,
                         fresh_xof_inputs_per_step):
    """First-input hazard for bounded canonical-field requests in ideal streams.

    The bad event is defined by the latent whole-stream completion at its first
    query. A later reused input is not a new trial, regardless of when the
    verifier finally consumes its bytes. Column families are a separate model.
    """
    from classical_sampler_resources import field_stop_first_query_bound
    if (type(prime) is not int or prime not in (2013265921, 18446744069414584321)
            or type(coefficient_ceiling) is not int or not 0 <= coefficient_ceiling < 2**64
            or type(rejected_candidate_limit) is not int or rejected_candidate_limit < 1
            or type(fresh_xof_inputs_per_step) is not int or fresh_xof_inputs_per_step < 0):
        raise ValueError('reviewed field, native coefficient count and exact positive retry limit required')
    local = field_stop_first_query_bound(prime, rejected_candidate_limit,
        expected_coefficients=dict(adversary=0, verifier=0, setup=0, unknown=coefficient_ceiling))
    encoded = local['total']['exact']
    per_input = Fraction(int(encoded['numerator_hex'], 16), int(encoded['denominator_hex'], 16))
    return dict(constant=exact_rational_text(per_input*fresh_xof_inputs_per_step), slope='0',
        per_eligible_first_input=exact_rational_text(per_input),
        fresh_xof_inputs_per_step=fresh_xof_inputs_per_step,
        coefficient_ceiling=coefficient_ceiling, rejected_candidate_limit=rejected_candidate_limit,
        required_premises=[
            'Each eligible first input fixes its canonical-field descriptor and count at most the coefficient ceiling',
            'Distinct first inputs have independent ideal whole-stream completions conditional on the entire previously exposed history',
            'Every later use consumes that same completion; prequeried inputs are charged at their first query only',
            'The fresh-input batch cap covers all actors and all requests within each charged step',
            'Every relevant field-stop event lies in this descriptor superclass'],
        automatic_column_stop_charge=False, automatic_lookup_stop_charge=False,
        complete_request_coverage_established=False, whole_stream_model_established=False,
        conditional_hazard_established=False, production_loops_unchanged=True,
        security_qualified=False)


def native_sampler_hazard(candidate, *, fresh_xof_inputs_per_step):
    """Pure field/v4-column stop hazard at disjoint first opportunities.

    Only the local probability/geometry calculation is reused from the native
    worksheet; its aggregate query polynomial is not differentiated or used
    as a conditional-hazard proof.
    """
    from classical_window_work import native_first_query_sampler_stop_polynomial
    if type(fresh_xof_inputs_per_step) is not int or fresh_xof_inputs_per_step < 0:
        raise ValueError('nonnegative exact all-actor fresh-input batch ceiling required')
    local = native_first_query_sampler_stop_polynomial(candidate, honest_xof_outputs=0)
    mu = local['joint_local_bound']
    return dict(profile_id_sha512=candidate['profile_id_sha512'],
        constant=exact_rational_text(mu*fresh_xof_inputs_per_step), slope='0',
        fresh_xof_inputs_per_step=fresh_xof_inputs_per_step,
        field_local_bound=exact_rational_text(local['field_local_bound']),
        column_local_bound=exact_rational_text(local['column_local_bound']),
        joint_local_bound=exact_rational_text(mu), column_geometry=local['column_geometry'],
        automatic_column_stop_charge=local['column_geometry'] is not None,
        automatic_lookup_stop_charge=False,
        required_premises=[
            'The trusted profile is fixed and every relevant field request obeys its count ceiling',
            'Canonical maximal byte-run roots partition all relevant v4 column inputs, including off-path descendants',
            'Field descriptors and earliest column-family members are disjoint first-input opportunities',
            'Before its earliest member, each whole family tree is fresh conditional on outside-family history',
            'Each field input has a fresh consistent ideal whole-stream completion at its first query',
            'Actual column runs obey the reviewed power-of-two domain/quota domination and call boundaries',
            'The all-actor batch ceiling covers every distinct first XOF input in the charged step'],
        complete_opportunity_coverage_established=False,
        native_geometry_domination_established=False, output_tree_model_established=False,
        conditional_hazard_established=False, production_loops_unchanged=True,
        security_qualified=False)


def joint_oracle_hazard(*, hash_answers_per_step, xof_answers_per_step,
                       hash_prior_answers_per_work, hash_prior_answer_offset,
                       xof_prior_answers_per_work, xof_prior_answer_offset,
                       target_windows_per_work, target_window_offset):
    """Affine first-bad-event hazard for bounded fresh ideal-answer batches.

    Prior-answer caps apply BEFORE each charged step j; predictable target
    windows must be bounded throughout it. Per-step limits cover all activity,
    including any verifier work performed by one adversary submission. These
    are not derivatives of a success-by-budget polynomial.
    """
    values = (hash_answers_per_step, xof_answers_per_step,
              hash_prior_answers_per_work, hash_prior_answer_offset,
              xof_prior_answers_per_work, xof_prior_answer_offset,
              target_windows_per_work, target_window_offset)
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError('nonnegative exact pathwise resource ceilings required')
    rh, rx, qh, hh, qx, hx, w, w0 = values
    denominator = 2**512
    # Each fresh answer hits <=W predictable targets or its own oracle's
    # previous answers. Unordered pairs inside the batch are charged once.
    # Repeated queries supply no fresh-answer collision opportunity.
    target_constant = Fraction((rh+rx)*w0, denominator)
    collision_constant = Fraction(rh*hh+rx*hx+rh*(rh-1)//2+rx*(rx-1)//2, denominator)
    constant = target_constant+collision_constant
    slope = Fraction((rh+rx)*w+rh*qh+rx*qx, denominator)
    return dict(constant=exact_rational_text(constant), slope=exact_rational_text(slope),
        components=dict(predictable_targets=dict(
            constant=exact_rational_text(target_constant),
            slope=exact_rational_text(Fraction((rh+rx)*w, denominator))),
            within_oracle_collisions=dict(
            constant=exact_rational_text(collision_constant),
            slope=exact_rational_text(Fraction(rh*qh+rx*qx, denominator)))),
        required_premises=[
            'Fresh 512-bit answers are uniform conditional on the complete joint pre-answer history',
            'Pathwise prior-answer ceilings hold before every charged step and target ceilings throughout it',
            'Fresh-answer batch limits cover adversary, verifier, setup and factory work within each charged step',
            'All relevant targets are registered before the answer; later declarations cannot create earlier hits',
            'No uncharged initial bad event is omitted from the experiment'],
        scope='First predictable-target hit or within-oracle prefix collision only',
        pathwise_caps_established=False, conditional_hazard_established=False,
        complete_stream_consistency_established=False, security_qualified=False)


def joint_hazard_work_report(*, oracle_hazard, remaining_constant, remaining_slope,
                            field_hazard=None, sampler_hazard=None):
    """Union oracle and ALL remaining conditional hazards before expected work.

    The remaining term is mandatory, including algebraic, sampler, stream,
    coverage and knowledge failures, except field stops supplied explicitly
    through field_hazard or the joint native sampler_hazard (mutually exclusive).
    An unconditional failure polynomial is
    not an admissible substitute for a predictable conditional hazard.
    """
    values = [oracle_hazard[key] for key in ('constant', 'slope')]
    values += [remaining_constant, remaining_slope]
    if field_hazard is not None and sampler_hazard is not None:
        raise ValueError('field-only and joint sampler hazards must not be double charged')
    supplied_sampler = sampler_hazard if sampler_hazard is not None else field_hazard
    if supplied_sampler is not None:
        values += [supplied_sampler[key] for key in ('constant', 'slope')]
    else:
        values += [0, 0]
    if any(type(value) not in (int, str, Fraction) for value in values):
        raise ValueError('exact conditional hazard coefficients required')
    oa, ob, ra, rb, fa, fb = map(exact_rational, values)
    if any(value < 0 for value in (oa, ob, ra, rb, fa, fb)):
        raise ValueError('nonnegative conditional hazards required')
    result = affine_hazard_work_bound(constant=oa+ra+fa, slope=ob+rb+fb)
    result.update(oracle_hazard=oracle_hazard,
        remaining_conditional_hazard=dict(constant=exact_rational_text(ra),
                                         slope=exact_rational_text(rb)),
        remaining_conditional_hazard_established=False,
        field_hazard=field_hazard, sampler_hazard=sampler_hazard,
        automatic_field_stop_charge=supplied_sampler is not None,
        automatic_column_stop_charge=(sampler_hazard is not None
            and sampler_hazard['automatic_column_stop_charge']),
        automatic_lookup_stop_charge=False,
        composition='Union conditional first-bad-event hazards before expected-work conversion')
    result['required_premises'] += oracle_hazard['required_premises']+[
        'Remaining coefficients bound every other first failure conditional on every complete pre-step history',
        'Every successful false proof or knowledge failure entails one of the covered first bad events']
    if supplied_sampler is not None:
        result['required_premises'] += supplied_sampler['required_premises']
    return result


def affine_hazard_work_bound(*, constant, slope):
    """Bound E[charged steps]/Pr(success), without a supplied success floor.

    Premise: first success occurs only on a charged unit step j>=1, whose
    conditional probability is <=min(1, constant+slope*j) given its entire
    pre-step history. Stopping and retries may be arbitrary and adaptive.
    Global j never resets. There is no maximum adversary query budget.
    """
    if any(type(value) not in (int, str, Fraction) for value in (constant, slope)):
        raise ValueError('exact nonnegative hazard coefficients required')
    a, b = map(exact_rational, (constant, slope))
    if a < 0 or b < 0 or not a+b:
        raise ValueError('nonzero nonnegative affine hazard required')
    if b == 0:
        bound = 1/min(Fraction(1), a)
        method = 'constant conditional hazard summed over executed steps'
    else:
        # Sum_{j=1}^t (a+b*j) is a CDF union bound for the dominating
        # first-success process. Its tail-sum lower-bounds that process's
        # mean. Monotone conditional hazards transfer the mean to E[W]/p;
        # the probability-one call here is for that *dominating process*,
        # not a success-floor premise about the actual adversary.
        tail = expected_work_bound([a+b/2, b/2], success_probability_lower_bound=1)
        bound = exact_rational(tail['minimum_expected_work_bound'])
        method = 'monotone dominating hazard process with exact CDF tail-sum relaxation'
    return dict(hazard_constant=exact_rational_text(a), hazard_slope=exact_rational_text(b),
        expected_work_per_success_bound=exact_rational_text(bound),
        success_probability_lower_bound_required=False,
        fixed_adversary_query_cutoff_required=False,
        work_measure='expected_charged_unit_steps_per_success', method=method,
        required_premises=[
            'No success occurs before a charged step',
            'Before each executed unit step j, conditional first-success probability is at most min(1,a+b*j)',
            'The conditioning includes the entire adaptive joint history, hidden branches, retries and verifier submissions',
            'The global charged-step index does not reset across retries or submissions',
            'All successful transitions and all relevant adversary, honest and verifier activity are covered by the hazard model'],
        conditional_hazard_established=False, protocol_bound_established=False,
        unrestricted_expected_work_certified=False, security_qualified=False)
