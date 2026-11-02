import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from audit_artifacts import write_json_new


class AuditArtifactTests(unittest.TestCase):
    def test_partial_serialization_is_never_published(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'done.json'
            partial, release = threading.Event(), threading.Event()
            value = {'status': 'passed', 'controls': list(range(20))}
            errors = []

            def slow_dump(value, output, **kwargs):
                encoded = json.dumps(value, **kwargs)
                middle = len(encoded) // 2
                output.write(encoded[:middle]); output.flush()
                partial.set()
                if not release.wait(5):
                    raise RuntimeError('test writer not released')
                output.write(encoded[middle:])

            def writer():
                try:
                    write_json_new(path, value)
                except Exception as error:
                    errors.append(error)

            with patch('audit_artifacts.json.dump', slow_dump):
                thread = threading.Thread(target=writer)
                thread.start()
                try:
                    self.assertTrue(partial.wait(5))
                    self.assertFalse(path.exists())
                finally:
                    release.set(); thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(json.loads(path.read_text()), value)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_existing_artifact_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'done.json'
            write_json_new(path, {'original': True})
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_json_new(path, {'replacement': True})
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_failed_encoding_leaves_no_completion_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'done.json'
            with self.assertRaises(TypeError):
                write_json_new(path, {'invalid': object()})
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
