"""Single-call Brakedown resource bounds from trusted shape guards.

Counts include the PCS binding hash, field raw/receipt readers and columns.
They exclude caller contexts, input-string construction and parent call counts.
"""
from classical_brakedown_geometry import role_geometry


def call_envelope(profile, role, *, field_candidate_limit=512, column_candidate_limit=8):
    if (profile['backend'] != 'Brakedown' or profile['descriptor_version'] not in (4, 5)
            or type(role) is not int or not 0 <= role < 4
            or any(type(limit) is not int or limit < 1
                   for limit in (field_candidate_limit, column_candidate_limit))):
        raise ValueError('reviewed Brakedown role/schedule and positive analysis limits required')
    prime = int(profile['prime'])
    if prime not in (2013265921, 18446744069414584321):
        raise ValueError('reviewed native base field required')
    v, w, left, block, q = (profile[key][role] for key in (
        'role_variables', 'role_widths', 'role_left_vars', 'role_block_widths', 'role_queries'))
    atomic = profile['descriptor_version'] == 5
    if type(q) is not int or not 1 <= q < 2**64:
        raise ValueError('native ordered quota required')
    if atomic and q > (2**63-1)//8:
        raise ValueError('native atomic column byte count required')
    # Resource counts need geometry, not a soundness polynomial with enormous
    # powers of Q or width. This parser performs only native shape arithmetic.
    geometry = role_geometry(profile, role)
    blocks = geometry['codeword_blocks']
    if (prime-1) % (2*blocks) or blocks*block >= 2**64:
        raise ValueError('supported native NTT domain and symbol storage required')
    transported = min(q, blocks)
    coefficients = w*w*(1 << left)
    if coefficients >= 2**64:
        raise ValueError('native field descriptor coefficient count required')
    field_bytes = ((prime-1).bit_length()+7)//8
    raw = coefficients*field_candidate_limit*field_bytes
    column_queries = 1 if atomic else q*column_candidate_limit
    column_bytes = 8*q if atomic else 8*column_queries
    return dict(role=role, codeword_blocks=blocks, ordered_draws=q,
        transported_columns_upper_bound=transported,
        hash_outputs_upper_bound=1+transported*blocks.bit_length(),
        field_phases_upper_bound=1, field_coefficients_upper_bound=coefficients,
        field_raw_output_bytes_upper_bound=raw, field_receipt_bytes_upper_bound=64,
        field_xof_queries_upper_bound=2, column_xof_queries_upper_bound=column_queries,
        column_output_bytes_upper_bound=column_bytes,
        xof_queries_upper_bound=2+column_queries,
        xof_output_bytes_upper_bound=raw+64+column_bytes,
        hash_bound_requires_sampler_stops=False,
        field_output_bound_requires_analysis_stop=True,
        column_bound_requires_analysis_stop=not atomic,
        field_candidate_limit=field_candidate_limit,
        column_candidate_limit=None if atomic else column_candidate_limit,
        production_loops_unchanged=True,
        scope='One single/batch PCS call, including rejected paths; trusted fixed geometry',
        parent_invocation_bounds_established=False, input_construction_bound_established=False,
        whole_native_resource_bound_established=False, security_qualified=False)
