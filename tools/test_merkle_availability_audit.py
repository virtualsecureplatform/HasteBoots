import unittest

from merkle_availability_audit import FrozenWord, Oracle, TAG


class AvailabilityTests(unittest.TestCase):
    def test_complete_tree_all_columns(self):
        oracle = Oracle()
        values = [bytes([i + 1]) for i in range(8)]
        layers = [[oracle.query(TAG + value) for value in values]]
        while len(layers[-1]) > 1:
            layer = layers[-1]
            layers.append([oracle.query(layer[i] + layer[i + 1])
                           for i in range(0, len(layer), 2)])
        word = FrozenWord(oracle, layers[-1][0], 3, 1)
        for i, value in enumerate(values):
            path = [layers[0][i]] + [layers[j][(i >> j) ^ 1] for j in range(3)]
            self.assertEqual(word.column(i), value)
            self.assertTrue(word.authenticate(oracle, i, value, path))
        self.assertFalse(word.bad_events(oracle))

    def test_partial_tree_defaults_and_late_preimage(self):
        oracle = Oracle()
        left = oracle.query(TAG + b"a")
        unknown = bytes([99]) * 32
        root = oracle.query(left + unknown)
        word = FrozenWord(oracle, root, 1, 1)
        self.assertEqual([word.column(i) for i in range(2)], [b"a", b"\0"])
        self.assertTrue(word.authenticate(oracle, 0, b"a", [left, unknown]))
        oracle.query(TAG + b"b", programmed=unknown)
        self.assertTrue(word.authenticate(oracle, 1, b"b", [unknown, left]))
        self.assertEqual(word.column(1), b"\0")
        self.assertEqual(word.bad_events(oracle), {"late target hit"})

    def test_guessed_root(self):
        oracle = Oracle()
        root = bytes([7]) * 32
        word = FrozenWord(oracle, root, 0, 1)
        oracle.query(TAG + b"x", programmed=root)
        self.assertTrue(word.authenticate(oracle, 0, b"x", [root]))
        self.assertIn("late target hit", word.bad_events(oracle))

    def test_collision_and_pre_freeze_collision(self):
        oracle = Oracle()
        root = oracle.query(TAG + b"a")
        word = FrozenWord(oracle, root, 0, 1)
        oracle.query(TAG + b"b", programmed=root)
        self.assertTrue(word.authenticate(oracle, 0, b"b", [root]))
        self.assertIn("collision", word.bad_events(oracle))
        with self.assertRaisesRegex(ValueError, "collision"):
            FrozenWord(oracle, root, 0, 1)

    def test_shape_and_index_rejection(self):
        oracle = Oracle()
        root = oracle.query(b"malformed leaf")
        word = FrozenWord(oracle, root, 0, 1)
        self.assertEqual(word.column(0), b"\0")
        self.assertFalse(word.authenticate(oracle, 1, b"a", [root]))
        self.assertFalse(word.authenticate(oracle, 0, b"a", []))
        self.assertFalse(word.authenticate(oracle, 0, b"aa", [root]))
        with self.assertRaises(ValueError):
            word.column(-1)

    def test_shared_subtrees_and_depth_bounded_cycles(self):
        oracle = Oracle()
        leaf = oracle.query(TAG + b"a")
        branch = oracle.query(leaf + leaf)
        root = oracle.query(branch + branch)
        word = FrozenWord(oracle, root, 2, 1)
        for i in range(4):
            self.assertEqual(word.column(i), b"a")
            self.assertTrue(word.authenticate(oracle, i, b"a", [leaf, leaf, branch]))
        self.assertFalse(word.bad_events(oracle))
        # A programmed pre-freeze fixed point tests traversal termination,
        # not feasibility of finding a SHA fixed point.
        cyclic = Oracle()
        root = bytes([17]) * 32
        cyclic.query(root + root, programmed=root)
        word = FrozenWord(cyclic, root, 12, 1)
        self.assertEqual(word.column(123), b"\0")
        malformed = Oracle()
        root = malformed.query(b"not an internal node")
        word = FrozenWord(malformed, root, 12, 1)
        self.assertEqual(word.column(123), b"\0")


if __name__ == "__main__":
    unittest.main()
