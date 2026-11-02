"""Conditional available-word block-RS opening terms, including padded rows."""
from fractions import Fraction


def opening_terms(variables, width, left_vars, block_width, blowup, queries, prime):
    values = (variables, width, left_vars, block_width, blowup, queries, prime)
    if any(type(v) is not int for v in values) or not (
            0 <= left_vars <= variables <= 32 and 1 <= width <= block_width
            and blowup in (2, 4, 8) and queries >= 1 and prime >= 3):
        raise ValueError('supported block-RS geometry with test rows <= symbol width required')
    scalars = 1 << (variables-left_vars)
    blocks = (scalars+block_width-1)//block_width
    message = 1 << (blocks-1).bit_length()
    encoded = max(32, message*blowup)  # Exact Rust constructor floor.
    if (prime-1) % (2*encoded) or encoded*block_width >= 2**64:
        raise ValueError('unsupported native NTT domain or symbol storage size')
    distance = encoded-message+1
    radius = (distance-1)//3
    random = min(Fraction(1), Fraction(encoded*(encoded+1), prime**width))
    sampling = Fraction(encoded-radius-1, encoded)**queries
    return dict(message_scalars=scalars, message_blocks=message, encoded_blocks=encoded,
        block_width=block_width, independent_test_rows=width,
        coefficient_padding=message*block_width-scalars,
        decoding_radius=radius, minimum_rejecting_columns=radius+1,
        random_test=random, column_sampling=sampling,
        total=min(Fraction(1), random+sampling),
        column_draws=queries, transported_columns_upper_bound=min(queries, encoded),
        authentication_hash_outputs_upper_bound=min(queries, encoded)*encoded.bit_length())


def first_query_terms(variables, width, left_vars, block_width, blowup, queries, prime,
                      *, expected_false_row_queries, expected_bad_column_families,
                      oracle_exception_bound, coverage_failure_bound):
    """Conditional first-component union bound from supplied expectation bounds.

    Terminal observed counts are not expectation bounds. All four supplied
    bounds require independent justification for the same experiment, including
    verifier queries. No adversarial query cutoff or security admission follows.
    """
    bounds = (expected_false_row_queries, expected_bad_column_families,
              oracle_exception_bound, coverage_failure_bound)
    if any(type(value) not in (int, Fraction) or value < 0 for value in bounds):
        raise ValueError('nonnegative exact finite expectation/probability bounds required')
    rows, families, exceptions, coverage = map(Fraction, bounds)
    if exceptions > 1 or coverage > 1:
        raise ValueError('exception and coverage probabilities must be at most one')
    local = opening_terms(variables, width, left_vars, block_width, blowup, queries, prime)
    row_term = rows*local['random_test']
    column_term = families*local['column_sampling']
    return dict(local=local, expected_false_row_queries=rows,
        expected_bad_column_families=families, row_contribution=row_term,
        column_contribution=column_term, oracle_exception_bound=exceptions,
        coverage_failure_bound=coverage,
        total=min(Fraction(1), exceptions+coverage+row_term+column_term),
        required_premises=[
            'Supplied bounds apply to the same complete adversary/verifier experiment',
            'Counts are expectations or upper bounds, not realized trace counts',
            'Predictable first-row states and disjoint first-entry sampling families',
            'Uniform fixed-word row and independent whole-family transition bounds',
            'Coverage bound includes unclassified accepting entries and source/stream mismatches',
            'Oracle exception bound covers all relevant availability and collision events'],
        input_bounds_verified=False, attacker_work_coupling_established=False,
        whole_proof_security_certified=False)
