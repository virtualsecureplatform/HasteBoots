import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from archive_sources import snapshot_sources

class SourceArchiveTests(unittest.TestCase):
    def test_ignored_lock_and_untracked_sources_are_captured(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            subprocess.run(["git","init","-q"],cwd=root,check=True)
            (root/".gitignore").write_text("Cargo.lock\ntarget/\n__pycache__/\n")
            (root/"tracked.rs").write_text("// tracked source\n")
            subprocess.run(["git","add",".gitignore","tracked.rs"],cwd=root,check=True)
            (root/"new.rs").write_text("// untracked source\n")
            pinned=b'version = 4\n# exact dependency snapshot\n'
            (root/"Cargo.lock").write_bytes(pinned)
            (root/"target").mkdir();(root/"target"/"ignored.bin").write_bytes(b"not source")
            output=root/"target"/"source.tar.gz"
            self.assertEqual(snapshot_sources(root,output),pinned)
            with tarfile.open(output,"r:gz") as archive:
                self.assertEqual(set(archive.getnames()),{".gitignore","tracked.rs","new.rs","Cargo.lock"})
                self.assertEqual(archive.extractfile("Cargo.lock").read(),pinned)
                self.assertEqual(archive.extractfile("new.rs").read(),b"// untracked source\n")
            before=output.read_bytes()
            with self.assertRaises(FileExistsError):snapshot_sources(root,output)
            self.assertEqual(before,output.read_bytes())
    def test_missing_lock_does_not_create_an_incomplete_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/"source.tar.gz"
            with self.assertRaises(FileNotFoundError):snapshot_sources(root,output)
            self.assertFalse(output.exists())
