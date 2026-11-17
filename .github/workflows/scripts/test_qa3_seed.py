import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile
from types import SimpleNamespace
from unittest import mock
import qa3_hosted as hosted

from qa3_hosted import verify_seed_archive

ROOT = Path(__file__).resolve().parents[2]


class SeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "seed.zip"
        self.lock = json.loads((ROOT / "qa/hosted-consumer-python.lock.json").read_text())
        with zipfile.ZipFile(ROOT / "qa/hosted-consumer-seed.zip") as z:
            self.data = {n: z.read(n) for n in z.namelist()}

    def write(self, rebind=True, extra=None, mode=stat.S_IFREG | 0o644):
        if rebind:
            manifest = json.loads(self.data["manifest.json"])
            manifest["payloads"] = [{"path": n, "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()} for n, b in sorted(self.data.items()) if n != "manifest.json"]
            self.data["manifest.json"] = json.dumps(manifest).encode()
        with zipfile.ZipFile(self.path, "w") as z:
            for n, b in self.data.items():
                info = zipfile.ZipInfo(n)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                z.writestr(info, b)
            if extra:
                info = zipfile.ZipInfo(extra)
                info.external_attr = mode << 16
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    z.writestr(info, b"x")
        self.lock["seedSha256"] = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def mutate_inputs(self, change):
        value = json.loads(self.data["inputs.json"])
        change(value)
        self.data["inputs.json"] = json.dumps(value).encode()
        self.write()
        with self.assertRaises(ValueError):
            verify_seed_archive(self.path, self.lock)

    def test_actual_seed(self):
        self.assertEqual(verify_seed_archive(ROOT / "qa/hosted-consumer-seed.zip", self.lock)["sourceWheels"], 25)

    def test_stale_manifest(self):
        self.data["profiles/consumer/requirements.lock"] += b"\n"
        self.write(rebind=False)
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)

    def test_missing_payload(self):
        del self.data["inputs.json"]
        self.write(rebind=False)
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)

    def test_stale_requirements(self):
        self.mutate_inputs(lambda x: x["profiles"][-1].update(requirementsSha256="0" * 64))

    def test_stale_runtime(self):
        self.mutate_inputs(lambda x: x.update(runtimeBaseline="0" * 40))

    def test_stale_count(self):
        self.mutate_inputs(lambda x: x["sourceWheels"].update(count=24))

    def test_stale_size(self):
        self.mutate_inputs(lambda x: x["sourceWheels"].update(bytes=0))

    def test_case_changed_wheel(self):
        self.mutate_inputs(lambda x: next(w for w in x["profiles"][-1]["wheels"] if w["filename"].startswith("mozInstall")).update(filename="mozinstall-2.1.0-py2.py3-none-any.whl"))

    def test_duplicate_json_key(self):
        self.data["inputs.json"] = b'{"schema": 1, "schema": 2}'
        self.write()
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)

    def test_case_alias_entry(self):
        self.write(extra="INPUTS.JSON")
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)

    def test_prebuild_rejects_before_process(self):
        self.data["profiles/consumer/requirements.lock"] += b"\n"
        self.write(rebind=False)
        source = Path(self.tmp.name) / "source"
        seed_dir = source / ".github/qa"
        seed_dir.mkdir(parents=True)
        (seed_dir / "hosted-consumer-seed.zip").write_bytes(self.path.read_bytes())
        (seed_dir / "hosted-consumer-python.lock.json").write_text(json.dumps(self.lock))
        with mock.patch.object(hosted, "context_from_environment") as context:
            with self.assertRaisesRegex(ValueError, "seed payload digest"):
                hosted.packaging_preflight(SimpleNamespace(source=source))
            context.assert_not_called()

    def test_duplicate_entry(self):
        self.write(extra="inputs.json")
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)

    def test_symlink(self):
        self.write(extra="link", mode=stat.S_IFLNK | 0o777)
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)

    def test_directory(self):
        self.write(extra="dir/", mode=stat.S_IFDIR | 0o755)
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)

    def test_escape(self):
        self.write(extra="../escape")
        with self.assertRaises(ValueError): verify_seed_archive(self.path, self.lock)


if __name__ == "__main__":
    unittest.main()
