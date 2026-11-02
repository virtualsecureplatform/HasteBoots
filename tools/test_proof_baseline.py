import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from proof_baseline import create, verify


class ProofBaselineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        subprocess.run(['git', 'init', '-q'], cwd=self.root, check=True)
        (self.root/'source.rs').write_text('initial source\n')
        (self.root/'.gitignore').write_text('target/\n')
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'fixture'], cwd=self.root, check=True)
        self.manifest = self.root/'baseline.json'

    def test_snapshot_survives_commit_and_excludes_ignored_artifacts(self):
        (self.root/'new.py').write_text('new source\n')
        (self.root/'target').mkdir()
        (self.root/'target'/'trace').write_bytes(b'local evidence')
        value = create(self.root, self.manifest)
        self.assertEqual({row['path'] for row in value['files']}, {'.gitignore', 'source.rs', 'new.py'})
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'checkpoint'], cwd=self.root, check=True)
        self.assertEqual(verify(self.root, self.manifest), dict(files=3, added=[], removed=[], changed=[]))

    def test_changed_added_and_removed_files_are_all_reported(self):
        (self.root/'second.rs').write_text('second\n')
        create(self.root, self.manifest)
        (self.root/'source.rs').write_text('modified\n')
        (self.root/'second.rs').unlink()
        (self.root/'extra.rs').write_text('extra\n')
        result = verify(self.root, self.manifest)
        self.assertEqual(result['changed'], ['source.rs'])
        self.assertEqual(result['removed'], ['second.rs'])
        self.assertEqual(result['added'], ['extra.rs'])

    def test_symlink_target_spelling_is_frozen(self):
        (self.root/'link').symlink_to('source.rs')
        create(self.root, self.manifest)
        (self.root/'link').unlink()
        (self.root/'link').symlink_to('missing.rs')
        self.assertEqual(verify(self.root, self.manifest)['changed'], ['link'])

    def test_executable_mode_change_invalidates_the_checkpoint(self):
        source = self.root/'source.rs'
        source.chmod(0o644)
        create(self.root, self.manifest)
        source.chmod(0o755)
        self.assertEqual(verify(self.root, self.manifest)['changed'], ['source.rs'])

    def test_cannot_overwrite_evidence_or_promote_security(self):
        create(self.root, self.manifest)
        with self.assertRaises(FileExistsError):
            create(self.root, self.manifest)
        value = json.loads(self.manifest.read_text())
        value['security_qualified'] = True
        self.manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            verify(self.root, self.manifest)

    def test_duplicate_file_records_are_rejected(self):
        value = create(self.root, self.manifest)
        value['files'].append(value['files'][0])
        self.manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            verify(self.root, self.manifest)


if __name__ == '__main__':
    unittest.main()
