"""Pure trusted-role geometry shared by context and resource auditors."""


def role_geometry(profile, role):
    if profile['backend'] != 'Brakedown' or type(role) is not int or not 0 <= role < 4:
        raise ValueError('trusted Brakedown role required')
    variables, width, left, quota, block = (profile[key][role] for key in (
        'role_variables', 'role_widths', 'role_left_vars', 'role_queries', 'role_block_widths'))
    if (type(variables) is not int or type(left) is not int or not 0 <= left <= variables < 64
            or any(type(value) is not int or value < 1 for value in (width, quota, block))):
        raise ValueError('valid native role geometry required')
    blowup = profile['blowup']
    if type(blowup) is not int or blowup < 2 or blowup & (blowup-1):
        raise ValueError('power-of-two native blowup required')
    message = 1 << (variables-left)
    blocks = 1 << (((message+block-1)//block)-1).bit_length()
    domain = max(32, blocks*blowup)
    if domain >= 2**64:
        raise ValueError('native domain overflow')
    return dict(num_vars=variables, width=width, left_vars=left, ordered_quota=quota,
                block_width=block, codeword_blocks=domain,
                message_len=message, message_blocks=blocks)
