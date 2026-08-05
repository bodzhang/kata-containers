import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "write_provenance.py"
SPEC = importlib.util.spec_from_file_location("write_provenance", SCRIPT)
write_provenance = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(write_provenance)


class WriteProvenanceTests(unittest.TestCase):
    def test_records_raw_create_requests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw_dir = root / "raw"
            tagged_dir = root / "tagged"
            raw_dir.mkdir()
            tagged_dir.mkdir()
            request = raw_dir / "0001-container.json"
            request.write_text('{"container_id":"container"}\n', encoding="utf-8")
            workload = root / "workload.yaml"
            workload.write_text("kind: Pod\n", encoding="utf-8")
            profile = root / "profile.env"
            profile.write_text("PROFILE_NAME=test\n", encoding="utf-8")
            tags = root / "dynamic-tags.json"
            tags.write_text("{}\n", encoding="utf-8")
            output = root / "provenance.json"

            arguments = [
                "write_provenance.py",
                "--profile", str(profile),
                "--input", str(workload),
                "--tag-manifest", str(tags),
                "--raw-dir", str(raw_dir),
                "--tagged-dir", str(tagged_dir),
                "--output", str(output),
            ]
            with mock.patch.object(sys, "argv", arguments):
                write_provenance.main()

            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["schema_version"], 2)
            self.assertEqual(
                result["outputs"]["raw_create_requests"],
                {
                    request.name: hashlib.sha256(request.read_bytes()).hexdigest()
                },
            )


if __name__ == "__main__":
    unittest.main()