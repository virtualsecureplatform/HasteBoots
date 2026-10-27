"""Query-log model for fixed-depth Merkle availability; not a SHA security proof.

Leaves use fixed-length opaque payloads, not Rust/bincode field decoding.
Programmed outputs allow tests to exhibit the exact excluded hash events.
"""
import hashlib

TAG = b"HasteBoots/mw-column/v1"


class Oracle:
    def __init__(self):
        self.queries = {}

    def query(self, data, programmed=None):
        if data in self.queries:
            if programmed is not None and programmed != self.queries[data]:
                raise ValueError("inconsistent oracle programming")
            return self.queries[data]
        output = hashlib.sha256(data).digest() if programmed is None else programmed
        if len(output) != 32:
            raise ValueError("digest length")
        self.queries[data] = output
        return output


class FrozenWord:
    def __init__(self, oracle, root, depth, payload_size):
        if depth < 0 or payload_size < 1 or len(root) != 32:
            raise ValueError("invalid shape")
        self.history = dict(oracle.queries)
        self.targets = {root}
        self.inverse = {}
        for data, output in self.history.items():
            if output in self.inverse and self.inverse[output] != data:
                raise ValueError("pre-freeze collision")
            self.inverse[output] = data
            if len(data) == 64:
                self.targets.update((data[:32], data[32:]))
        self.root, self.depth, self.payload_size = root, depth, payload_size

    def column(self, index):
        if not 0 <= index < 1 << self.depth:
            raise ValueError("column index")
        digest = self.root
        for level in range(self.depth, 0, -1):
            data = self.inverse.get(digest)
            if data is None or len(data) != 64:
                return bytes(self.payload_size)
            side = (index >> (level - 1)) & 1
            digest = data[32 * side:32 * (side + 1)]
        data = self.inverse.get(digest, b"")
        if not data.startswith(TAG) or len(data) != len(TAG) + self.payload_size:
            return bytes(self.payload_size)
        return data[len(TAG):]

    def bad_events(self, oracle):
        events, inverse = [], {}
        for data, output in oracle.queries.items():
            if output in inverse and inverse[output] != data:
                events.append("collision")
            inverse[output] = data
            if data not in self.history and output in self.targets:
                events.append("late target hit")
        return set(events)

    def authenticate(self, oracle, index, payload, path):
        if not 0 <= index < 1 << self.depth:
            return False
        if len(payload) != self.payload_size or len(path) != self.depth + 1:
            return False
        digest = oracle.query(TAG + payload)
        if digest != path[0]:
            return False
        for level, sibling in enumerate(path[1:]):
            data = sibling + digest if (index >> level) & 1 else digest + sibling
            digest = oracle.query(data)
        return digest == self.root
