# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import record_runtime_source as recorder


def sha(data):
    return hashlib.sha256(data).hexdigest()


class NativePatchProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.previous = Path.cwd()
        self.temp = tempfile.TemporaryDirectory()
        os.chdir(self.temp.name)
        self.addCleanup(self.restore)
        self.git("init", "--quiet")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Fixture")
        self.write(recorder.NATIVE_SOURCE, b"before\n")
        self.write(".github/old.patch", b"old patch\n")
        self.write("old-source", b"old source\n")
        self.pin = {"upstream": {"version": "158.0.2"}, "floorp_patch": {
            "runtime_path": ".github/old.patch", "sha256": sha(b"old patch\n"),
            "patched_files": {"old-source": sha(b"old source\n")}}}
        self.write(".github/runtime-upstream.json", json.dumps(self.pin).encode())
        for name in ("browser/config/version.txt", "browser/config/version_display.txt", "config/milestone.txt"):
            self.write(name, b"158.0.2\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture base")
        self.head = self.git("rev-parse", "HEAD").decode().strip()
        self.patch = ("--- a/" + recorder.NATIVE_SOURCE + "\n+++ b/" + recorder.NATIVE_SOURCE + "\n@@ -1 +1 @@\n-before\n+after\n").encode()
        self.manifest = {"schema_version": 1, "scope": "windows-graphics-native-rebuild-diagnostic",
            "base_runtime_commit": self.head, "patches": [{"runtime_path": recorder.NATIVE_PATCH,
            "sha256": sha(self.patch), "origin": {"repository": "Floorp-Projects/Floorp",
            "commit": "1" * 40, "path": ".github/patches/floorp-runtime/native-rebuild/windows-sandbox-extended-path.patch"},
            "source_files": {recorder.NATIVE_SOURCE: {"base_sha256": sha(b"before\n"), "patched_sha256": sha(b"after\n")}}}]}

    def restore(self):
        os.chdir(self.previous)
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.PIPE)

    def write(self, name, data):
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def install(self):
        self.write(recorder.NATIVE_PATCH, self.patch)
        self.write(recorder.NATIVE_MANIFEST, json.dumps(self.manifest).encode())
        self.write(recorder.NATIVE_SOURCE, b"after\n")

    def test_legacy_bytes_unchanged(self):
        output = Path("out/runtime-source-provenance.json")
        recorder.record_source(output)
        expected = {"schema_version": 1, "runtime_commit": self.head,
                    "upstream": self.pin["upstream"], "floorp_patch": self.pin["floorp_patch"]}
        self.assertEqual(output.read_text(encoding="utf-8"), json.dumps(expected, indent=2) + "\n")
        self.assertFalse(output.with_name("runtime-native-patch-provenance.json").exists())
        legacy = output.read_bytes()
        self.install()
        recorder.record_source(output)
        self.assertEqual(output.read_bytes(), legacy)
        native = json.loads(output.with_name("runtime-native-patch-provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(native["runtime_commit"], self.head)
        self.assertEqual(native["manifest"], self.manifest)
        self.assertEqual(native["manifest_sha256"], sha(recorder.NATIVE_MANIFEST.read_bytes()))
        self.assertEqual(native["actual_patched_sha256"], {recorder.NATIVE_SOURCE: sha(b"after\n")})
        self.assertEqual(native["recorder_sha256"], sha(Path(recorder.__file__).read_bytes()))

    def test_existing_source_validation_is_not_weakened(self):
        self.install()
        self.write("old-source", b"modified legacy source\n")
        with self.assertRaisesRegex(ValueError, "Compiled Runtime source"):
            recorder.record_source(Path("out/runtime-source-provenance.json"))
        self.assertFalse(Path("out").exists())

    def test_missing_native_source(self):
        self.install()
        Path(recorder.NATIVE_SOURCE).unlink()
        with self.assertRaises(FileNotFoundError):
            recorder.validate_native_patches(self.head)

    def test_missing_manifest(self):
        self.write(recorder.NATIVE_PATCH, self.patch)
        with self.assertRaises(ValueError):
            recorder.validate_native_patches(self.head)

    def test_modified_patch(self):
        self.install()
        self.write(recorder.NATIVE_PATCH, self.patch + b"extra")
        with self.assertRaises(ValueError):
            recorder.validate_native_patches(self.head)

    def test_missing_patch(self):
        self.install()
        Path(recorder.NATIVE_PATCH).unlink()
        with self.assertRaises(FileNotFoundError):
            recorder.validate_native_patches(self.head)

    def test_wrong_postimage_has_no_output(self):
        self.install()
        self.write(recorder.NATIVE_SOURCE, b"wrong\n")
        output = Path("out/runtime-source-provenance.json")
        with self.assertRaises(ValueError):
            recorder.record_source(output)
        self.assertFalse(output.exists())

    def test_head_preimage_cannot_be_replaced(self):
        self.install()
        self.git("add", recorder.NATIVE_SOURCE)
        self.git("commit", "--quiet", "-m", "changed preimage")
        head = self.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(ValueError, "preimage"):
            recorder.validate_native_patches(head)

    def test_non_ancestor_base(self):
        self.git("checkout", "--orphan", "unrelated")
        self.git("commit", "--quiet", "-m", "unrelated root")
        unrelated = self.git("rev-parse", "HEAD").decode().strip()
        self.install()
        with self.assertRaisesRegex(ValueError, "ancestor"):
            recorder.validate_native_patches(unrelated)

    def test_strict_schema_and_paths(self):
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m.update(schema_version=True),
            lambda m: m.update(extra=True),
            lambda m: m.update(scope="production"),
            lambda m: m.update(base_runtime_commit="HEAD"),
            lambda m: m["patches"].append(copy.deepcopy(m["patches"][0])),
            lambda m: m["patches"][0].update(runtime_path="../escape.patch"),
            lambda m: m["patches"][0].update(sha256="A" * 64),
            lambda m: m["patches"][0]["origin"].update(path="../escape.patch"),
            lambda m: m["patches"][0]["source_files"].update({"extra.cpp": {"base_sha256": "0" * 64, "patched_sha256": "1" * 64}}),
            lambda m: m["patches"][0]["source_files"][recorder.NATIVE_SOURCE].update(base_sha256="0" * 64),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.manifest = copy.deepcopy(original)
                mutate(self.manifest)
                self.install()
                with self.assertRaises(ValueError):
                    recorder.validate_native_patches(self.head)

    def test_extra_patch_target_even_with_matching_hash(self):
        self.patch += b"--- a/extra.cpp\n+++ b/extra.cpp\n@@ -1 +1 @@\n-a\n+b\n"
        self.manifest["patches"][0]["sha256"] = sha(self.patch)
        self.install()
        with self.assertRaisesRegex(ValueError, "unexpected paths"):
            recorder.validate_native_patches(self.head)

    def test_duplicate_json_key(self):
        self.install()
        self.write(recorder.NATIVE_MANIFEST, b'{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            recorder.validate_native_patches(self.head)


if __name__ == "__main__":
    unittest.main()
