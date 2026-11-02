"""Publish complete immutable audit JSON without exposing partial files."""
import json
import os
from pathlib import Path
import tempfile


def write_json_new(path, value):
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=path.parent, prefix='.' + path.name + '.',
                                         delete=False) as output:
            temporary = Path(output.name)
            json.dump(value, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        # Link only after close; unlike replace(), this cannot overwrite an
        # existing evidence artifact. Temporary and destination share a device.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
