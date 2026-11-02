#!/usr/bin/env python3
"""Conditional classical work-cost arithmetic; does not supply protocol bounds.

Input a uniform all-trials success bound min(1, c + sum a[k]*T**k), k>=1,
where T is a fixed maximum charged-work budget. All coefficients must be nonnegative.
The optimized budget/success ratio is not an unrestricted expected-runtime bound.
The bound must hold conditional on prior attack history to justify retries.
"""
import argparse
from fractions import Fraction
import json


def all_trials_envelope(adversarial_phase_error, verifier_phases,
                        verifier_resources, honest_offsets):
    """Compose caller-proved caps when queries and submissions each cost >=1.

    T bounds adversarial oracle requests, resource declarations and verifier
    submissions separately; declarations must be charged or separately capped.
    Each verifier phase is (maximum occurrences per submission, conditional
    bad-transition probability). Resource values bound total oracle requests
    or declarations per submission, including rejected paths. No independence
    between trials, phases, or verifier invocations is assumed.
    """
    adversarial = exact_coefficients([adversarial_phase_error])[0]
    if adversarial > 1 or not isinstance(verifier_phases, (list, tuple)):
        raise ValueError('probability and explicit verifier phase list required')
    verifier_error = Fraction()
    for phase in verifier_phases:
        if not isinstance(phase, (list, tuple)) or len(phase) != 2:
            raise ValueError('each phase requires a count and conditional error')
        count, probability = phase
        if type(count) is not int or count < 0:
            raise ValueError('phase count must be a nonnegative integer')
        probability = exact_coefficients([probability])[0]
        if probability > 1:
            raise ValueError('phase error must be a probability')
        verifier_error += count * probability
    if not isinstance(verifier_resources, dict) or not isinstance(honest_offsets, dict):
        raise ValueError('explicit matching resource maps required')
    if set(verifier_resources) != set(honest_offsets):
        raise ValueError('resource and offset names must match')
    resources = {}
    for name, count in verifier_resources.items():
        offset = honest_offsets[name]
        if not isinstance(name, str) or not name or any(
                type(x) is not int or x < 0 for x in (count, offset)):
            raise ValueError('named nonnegative integer resource caps required')
        # One adversarial request/declaration per charged work unit, plus
        # at most count requests for each of the at most T submissions.
        resources[name] = dict(per_work=1 + count, offset=offset)
    return dict(linear_phase_error=adversarial + verifier_error,
                verifier_error_per_submission=verifier_error,
                resources=resources, protocol_bound_established=False)


def exact_rational(value):
    """Parse exact native-sized rationals without changing Python digit limits."""
    if type(value) not in (int, str, Fraction):
        raise ValueError('exact integer, rational string or Fraction required')
    try:
        return Fraction(value)
    except ValueError:
        if not isinstance(value, str):
            raise
        def integer_text(part):
            part = part.strip()
            sign = -1 if part.startswith('-') else 1
            if part[:1] in ('-', '+'):
                part = part[1:]
            if not part or any(c not in '0123456789' for c in part):
                raise ValueError('exact integer/fraction text required')
            number = 0
            for start in range(0, len(part), 9):
                chunk = part[start:start+9]
                number = number*10**len(chunk)+int(chunk)
            return sign*number
        parts = value.split('/')
        if len(parts) not in (1, 2):
            raise ValueError('exact integer/fraction text required')
        return Fraction(integer_text(parts[0]), integer_text(parts[1]) if len(parts) == 2 else 1)


def exact_rational_text(value):
    """Canonical decimal text, including fractions beyond 4300 digits."""
    value = exact_rational(value)
    def integer_text(number):
        sign = '-' if number < 0 else ''
        number = abs(number)
        chunks = []
        while number >= 10**9:
            number, remainder = divmod(number, 10**9)
            chunks.append(remainder)
        return sign+str(number)+''.join(f'{chunk:09d}' for chunk in reversed(chunks))
    numerator = integer_text(value.numerator)
    return numerator if value.denominator == 1 else numerator+'/'+integer_text(value.denominator)


def exact_coefficients(coefficients):
    if not isinstance(coefficients, (list, tuple)):
        raise ValueError('coefficients must be a list or tuple of exact rationals')
    if any(type(value) not in (int, str, Fraction) for value in coefficients):
        raise ValueError('floating-point and boolean coefficients are not exact rational inputs')
    coefficients = tuple(exact_rational(value) for value in coefficients)
    if not coefficients or any(value < 0 for value in coefficients):
        raise ValueError('nonempty nonnegative coefficients required')
    return coefficients


def minimum_work(coefficients, constant=0, minimum_budget=1):
    """Minimum maximum-budget/success ratio; not an expected-runtime bound."""
    coefficients = exact_coefficients(coefficients)
    if type(constant) not in (int, str, Fraction):
        raise ValueError('constant must be an exact rational')
    constant = exact_rational(constant)
    if constant < 0 or type(minimum_budget) is not int or minimum_budget < 1:
        raise ValueError('nonnegative constant and positive integer minimum budget required')
    if not any(coefficients):
        if not constant:
            raise ValueError('zero polynomial supplies no finite work threshold')
        if constant >= 1:
            return Fraction(minimum_budget), (minimum_budget, minimum_budget)
        return Fraction(minimum_budget) / min(Fraction(1), constant), None

    def error(work):
        return constant + sum((a * work ** k for k, a in enumerate(coefficients, 1)), Fraction())

    def cost(work):
        return Fraction(work) / min(Fraction(1), error(work))

    if error(minimum_budget) >= 1:
        return Fraction(minimum_budget), (minimum_budget, minimum_budget)
    low, high = minimum_budget, 2 * minimum_budget
    while error(high) < 1:
        low, high = high, 2 * high
    while low + 1 < high:
        middle = (low + high) // 2
        if error(middle) < 1:
            low = middle
        else:
            high = middle
    return min(cost(minimum_budget), cost(low), cost(high)), (low, high)


def report(coefficients, target_bits, constant=0, minimum_budget=1):
    if type(target_bits) is not int or target_bits < 1:
        raise ValueError('positive integer target bits required')
    coefficients = exact_coefficients(coefficients)
    result, bracket = minimum_work(coefficients, constant, minimum_budget)
    return dict(coefficients=[exact_rational_text(a) for a in coefficients],
                coefficient_order='linear, quadratic, cubic, ...', constant=exact_rational_text(constant),
                work_domain='integers at least minimum_attack_budget',
                minimum_attack_budget=minimum_budget,
                minimum_work_per_success_bound=exact_rational_text(result),
                minimum_budget_per_success_bound=exact_rational_text(result),
                work_measure="fixed_maximum_budget",
                unrestricted_expected_work_certified=False,
                saturation_bracket=None if bracket is None else list(bracket), target_bits=target_bits,
                conditional_work_target_met=result >= 2 ** target_bits,
                required_premise='Uniform all-trials conditional success bound in attacker work; justified minimum budget and honest/verifier offsets',
                protocol_bound_established=False, security_qualified=False,
                performance_gate=False)


def expected_work_bound(coefficients, *, success_probability_lower_bound,
                        constant=0, minimum_budget=1):
    """Tail-sum lower bound from a uniform capped-work success CDF.

    F(t)=constant+sum a[k]*t^k bounds success by charged work t. Every success
    costs >=minimum_budget. If actual success probability q>=p>0, then
    E[W]>=sum_t max(0,p-F(t)), using p for t<minimum_budget, and
    E[W]/q is at least that sum divided by p. This requires the supplied
    success floor and uniform CDF premise, not a retry/independence heuristic.
    """
    from math import comb
    coefficients = exact_coefficients(coefficients)
    if (type(success_probability_lower_bound) not in (int, str, Fraction)
            or type(constant) not in (int, str, Fraction)
            or type(minimum_budget) is not int or minimum_budget < 1):
        raise ValueError('exact probability/constant and positive integer minimum budget required')
    probability, constant = exact_rational(success_probability_lower_bound), exact_rational(constant)
    if not 0 < probability <= 1 or constant < 0:
        raise ValueError('positive success probability at most one and nonnegative constant required')
    def error(work):
        return constant+sum((a*work**k for k, a in enumerate(coefficients, 1)), Fraction())
    if error(minimum_budget) >= probability:
        stop = minimum_budget
    else:
        if not any(coefficients):
            raise ValueError('success floor exceeds the uniform constant success cap')
        low, high = minimum_budget, 2*minimum_budget
        while error(high) < probability:
            low, high = high, 2*high
        while low+1 < high:
            middle = (low+high)//2
            if error(middle) < probability:
                low = middle
            else:
                high = middle
        stop = high
    def power_sums(end):
        # Exact sum of t^k for 0<=t<end, via telescoping (t+1)^(k+1).
        sums = [end]
        for degree in range(1, len(coefficients)+1):
            numerator = end**(degree+1)-sum(comb(degree+1, j)*sums[j] for j in range(degree))
            value, remainder = divmod(numerator, degree+1)
            assert remainder == 0
            sums.append(value)
        return sums
    upper, lower = power_sums(stop), power_sums(minimum_budget)
    total = minimum_budget*probability+(stop-minimum_budget)*(probability-constant)
    total -= sum((a*(upper[k]-lower[k]) for k, a in enumerate(coefficients, 1)), Fraction())
    return dict(success_probability_lower_bound=exact_rational_text(probability),
        minimum_expected_work_bound=exact_rational_text(total),
        expected_work_per_success_bound=exact_rational_text(total/probability),
        first_budget_reaching_success_floor=stop,
        minimum_attack_budget=minimum_budget,
        work_measure='expected_charged_work_with_supplied_success_floor',
        required_premises=[
            'Uniform success-by-budget bound applies to every truncation of this complete experiment',
            'Actual success probability is at least the supplied positive floor',
            'Every successful run costs at least the justified minimum budget'],
        input_bounds_verified=False, protocol_bound_established=False,
        unrestricted_expected_work_certified=False, security_qualified=False)


def composed_report(components, target_bits=128, minimum_budget=1):
    """Union caller-proved all-trials polynomials before optimizing work.

    Required names prevent accidentally dropping an entire oracle family.
    The phase component must include all algebraic, opening, retry and
    verifier-submission terms. This function cannot establish that coverage.
    """
    if not isinstance(components, dict) or set(components) != {'phase', 'merkle', 'xof'}:
        raise ValueError('explicit phase, merkle and xof components required')
    totals = [Fraction(), Fraction(), Fraction()]
    normalized = {}
    for name, component in components.items():
        if not isinstance(component, dict) or set(component) != {'constant', 'linear', 'quadratic'}:
            raise ValueError('each component requires constant, linear and quadratic terms')
        values = exact_coefficients([component[key] for key in ('constant', 'linear', 'quadratic')])
        normalized[name] = dict(zip(('constant', 'linear', 'quadratic'), map(exact_rational_text, values)))
        totals = [a+b for a, b in zip(totals, values)]
    result = report(totals[1:], target_bits, totals[0], minimum_budget)
    result.update(components=normalized,
                  composition='Union all-trials terms before minimizing work per success',
                  missing=['Complete phase coverage and conditional bad-state reduction',
                           'Proved global resource caps including all verifier submissions',
                           'Knowledge/extraction argument'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--coefficients',
                        help='JSON list of exact rational strings, starting with the linear coefficient')
    source.add_argument('--components',
                        help='JSON object with explicit phase/merkle/xof constant/linear/quadratic terms')
    parser.add_argument('--target-bits', type=int, default=128)
    parser.add_argument('--constant', default='0', help='Exact nonnegative constant term')
    parser.add_argument('--minimum-budget', type=int, default=1,
                        help='Proved minimum work for any potentially successful attack')
    args = parser.parse_args()
    if args.components is not None:
        if Fraction(args.constant) != 0:
            parser.error('--constant belongs inside each --components entry')
        print(json.dumps(composed_report(json.loads(args.components), args.target_bits,
                                         args.minimum_budget), indent=2))
        return
    print(json.dumps(report(json.loads(args.coefficients), args.target_bits,
                           args.constant, args.minimum_budget), indent=2))


if __name__ == '__main__':
    main()
