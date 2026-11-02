"""Decode the diagnostic bincode descriptor; never load a verifier profile.

This validates the current trusted native harness types and encoding format.
Rust verifiers still obtain immutable profiles exclusively from their caller.
"""


BACKENDS = ['Brakedown', 'Polyfrim', 'FragmentedPipfri',
            'PolyfrimDictionary', 'FragmentedPipfriVirtual']

FIELD_NONRESIDUES = {
    ('2013265921', 4): 11, ('2013265921', 5): 2,
    ('2013265921', 6): 31, ('2013265921', 8): 11,
    ('18446744069414584321', 2): 7, ('18446744069414584321', 3): 7,
    ('18446744069414584321', 4): 7, ('18446744069414584321', 5): 3,
}


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, count):
        if count < 0 or self.at + count > len(self.data):
            raise ValueError('truncated profile descriptor')
        result = self.data[self.at:self.at+count]
        self.at += count
        return result

    def unsigned(self, bits=64):
        tag = self.take(1)[0]
        if tag < 251:
            value = tag
        elif tag <= 254:
            size, minimum = {251: (2, 251), 252: (4, 2**16),
                             253: (8, 2**32), 254: (16, 2**64)}[tag]
            value = int.from_bytes(self.take(size), 'little')
            if value < minimum:
                raise ValueError('noncanonical profile integer')
        else:
            raise ValueError('invalid profile integer tag')
        if value >= 1 << bits:
            raise ValueError('profile integer overflow')
        return value

    def optional(self):
        tag = self.take(1)[0]
        if tag not in (0, 1):
            raise ValueError('invalid profile option tag')
        return self.unsigned() if tag else None

    def string(self):
        return self.take(self.unsigned()).decode('utf-8')


def decode_descriptor(data):
    reader = Reader(data)
    version = reader.unsigned(32)
    if version not in (1, 2, 3, 4, 5):
        raise ValueError('unsupported profile descriptor version')
    backend = reader.unsigned(32)
    if backend >= len(BACKENDS):
        raise ValueError('unsupported profile backend')
    roles = [dict(num_vars=reader.unsigned(), width=reader.unsigned(),
                  queries=reader.unsigned(), left_vars=reader.optional(),
                  block_width=reader.optional()) for _ in range(4)]
    if version == 5 and any(r['queries'] > (2**63-1)//8 for r in roles):
        raise ValueError('atomic column byte count overflow on native 64-bit runtime')
    blowup, fragment_vars = reader.unsigned(), reader.optional()
    prime, degree = reader.string(), reader.unsigned()
    nonresidue = FIELD_NONRESIDUES.get((prime, degree))
    if nonresidue is None:
        raise ValueError('unsupported native profile field representation')
    if reader.unsigned() != degree**3:
        raise ValueError('incorrect profile basis-table length')
    for i in range(degree):
        for j in range(degree):
            for k in range(degree):
                expected = (nonresidue if i+j >= degree else 1) if k == (i+j) % degree else 0
                if reader.unsigned(128) != expected:
                    raise ValueError('incorrect native field basis table')
    merkle, transcript = reader.string(), reader.string()
    expected_transcript = {
        1: 'framed-shake256-canonical-rejection-v1',
        2: 'framed-shake256-canonical-rejection-atomic-ntt-v2',
        3: 'framed-shake256-canonical-rejection-atomic-phases-v3',
        4: 'framed-shake256-canonical-rejection-atomic-zerocheck-v4',
        5: 'framed-shake256-canonical-rejection-atomic-columns-v5',
    }[version]
    if reader.at != len(data) or merkle != 'sha512-v1' or transcript != expected_transcript:
        raise ValueError('profile suite or descriptor suffix mismatch')
    return dict(descriptor_version=version, backend=BACKENDS[backend], prime=prime,
                extension_degree=degree, blowup=blowup, fragment_vars=fragment_vars,
                role_variables=[r['num_vars'] for r in roles],
                role_widths=[r['width'] for r in roles],
                role_queries=[r['queries'] for r in roles],
                role_left_vars=[r['left_vars'] for r in roles],
                role_block_widths=[r['block_width'] for r in roles])
