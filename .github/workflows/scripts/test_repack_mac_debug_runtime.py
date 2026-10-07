# SPDX-License-Identifier: MPL-2.0

import json
import os
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml
from repack_mac_debug_runtime import SOURCE_ROOT, repack


class MacRepackTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.app = Path(self.work.name) / "Floorp Debug.app"
        self.resources = self.app / "Contents/Resources"
        (self.resources / "modules").mkdir(parents=True)
        (self.app / "Contents/MacOS").mkdir()
        self.binary = self.app / "Contents/MacOS/floorp"
        self.binary_bytes = struct.pack(">II", 0xFEEDFACF, 0) + b"native fixture"
        self.binary.write_bytes(self.binary_bytes)
        (self.resources / "chrome.manifest").write_text("resource gre .\n")
        (self.resources / "modules/Fixture.sys.mjs").write_bytes(b"export const n=157;\n")
        (self.resources / "application.ini").write_text(
            "[App]\nVersion=157.0.1\nBuildID=20261006190514\n"
        )
        (self.resources / "platform.ini").write_text("[Build]\nBuildID=20261006190514\n")
        self.evidence = Path(self.work.name) / "proof.json"

    def test_flat_package_becomes_real_omnijar_without_changing_code_or_resources(self):
        repack(self.app, "20261006190514", self.evidence, "fixture-source")
        with zipfile.ZipFile(self.resources / "omni.ja") as jar:
            self.assertEqual(jar.read("modules/Fixture.sys.mjs"), b"export const n=157;\n")
            self.assertIn("chrome.manifest", jar.namelist())
        self.assertEqual(self.binary.read_bytes(), self.binary_bytes)
        self.assertIn(
            'remove "Contents/Resources/omni.ja"',
            (self.resources / "precomplete").read_text(),
        )
        first = json.loads(self.evidence.read_text())
        self.assertEqual(first["original_resource_format"], "flat")
        repack(self.app, "20261006190514", self.evidence, "fixture-source")
        repeated = json.loads(self.evidence.read_text())
        self.assertEqual(repeated["original_resource_format"], "omni")
        self.assertEqual(repeated["native_binaries_sha256"], first["native_binaries_sha256"])
        self.assertEqual(self.binary.read_bytes(), self.binary_bytes)

    def test_wrong_build_id_leaves_the_original_package_unchanged(self):
        with self.assertRaisesRegex(ValueError, "BuildID"):
            repack(self.app, "20261006185710", self.evidence, "fixture-source")
        self.assertFalse((self.resources / "omni.ja").exists())
        self.assertTrue((self.resources / "chrome.manifest").is_file())
        self.assertEqual(self.binary.read_bytes(), self.binary_bytes)

    def test_release_and_pgo_packages_preserve_their_identity_and_native_code(self):
        for mode, build_id in (
            ("Release", "20261006154310"),
            ("PGO", "20261006185710"),
        ):
            with self.subTest(mode=mode):
                app = Path(self.work.name) / mode / "Floorp.app"
                resources = app / "Contents/Resources"
                (resources / "modules").mkdir(parents=True)
                (app / "Contents/MacOS").mkdir()
                binary = app / "Contents/MacOS/floorp"
                binary.write_bytes(self.binary_bytes)
                (resources / "chrome.manifest").write_text("resource gre .\n")
                module = b"export const mode=" + mode.encode() + b";\n"
                (resources / "modules/Fixture.sys.mjs").write_bytes(module)
                identity = f"[App]\nVersion=157.0.1\nBuildID={build_id}\n"
                (resources / "application.ini").write_text(identity)
                (resources / "platform.ini").write_text(f"[Build]\nBuildID={build_id}\n")
                proof = app.parent / "proof.json"
                repack(app, build_id, proof, f"{mode}-source")
                with zipfile.ZipFile(resources / "omni.ja") as jar:
                    self.assertEqual(jar.read("modules/Fixture.sys.mjs"), module)
                self.assertEqual(binary.read_bytes(), self.binary_bytes)
                self.assertEqual((resources / "application.ini").read_text(), identity)
                evidence = json.loads(proof.read_text())
                self.assertEqual(evidence["build_id"], build_id)
                self.assertEqual(evidence["compiled_source_commit"], f"{mode}-source")
                self.assertTrue(evidence["native_binaries_unchanged"])
                self.assertEqual(evidence["original_resource_format"], "flat")
                self.assertEqual(evidence["resource_format"], "omni")


class UniversalPackagingWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        package = self.root / "obj-x86_64-apple-darwin/dist/floorp"
        resources = package / "Floorp.app/Contents/Resources"
        resources.mkdir(parents=True)
        (resources / "application.ini").write_text("[App]\nBuildID=20261006185710\n")
        (package.parent / "floorp.update_framework_artifacts.zip").write_bytes(b"fixture")
        self.calls = self.root / "calls.jsonl"
        mach = self.root / "mach"
        mach.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['CALLS'], 'a') as output:\n"
            "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if len(sys.argv) > 2 and sys.argv[2].endswith('repack_mac_debug_runtime.py'):\n"
            "    sys.exit(int(os.environ.get('REPACK_EXIT', '0')))\n"
        )
        mach.chmod(0o755)
        workflow = yaml.safe_load(
            (SOURCE_ROOT / ".github/workflows/mac_integration.yml").read_text()
        )
        self.command = next(
            step["run"]
            for step in workflow["jobs"]["Integration"]["steps"]
            if step.get("name", "").startswith("Create DMG")
        )

    def run_packaging(self, debug, repack_exit=0):
        self.calls.unlink(missing_ok=True)
        environment = {
            **os.environ,
            "GHA_DEBUG": str(debug).lower(),
            "MOZ_BUILD_DATE": "20261006185710",
            "CALLS": str(self.calls),
            "REPACK_EXIT": str(repack_exit),
        }
        result = subprocess.run(
            ["bash", "-c", self.command],
            cwd=self.root,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return result, calls

    def test_normal_and_debug_workflow_repack_before_creating_the_dmg(self):
        for debug in (False, True):
            with self.subTest(debug=debug):
                result, calls = self.run_packaging(debug)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 2)
                self.assertIn("repack_mac_debug_runtime.py", calls[0][1])
                self.assertIn("20261006185710", calls[0])
                self.assertEqual(calls[1][:3], ["python", "-m", "mozbuild.action.make_dmg"])

    def test_failed_repack_prevents_dmg_creation(self):
        result, calls = self.run_packaging(False, repack_exit=17)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
