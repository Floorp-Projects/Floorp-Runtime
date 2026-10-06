# SPDX-License-Identifier: MPL-2.0

import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from repack_mac_debug_runtime import repack


class MacDebugRepackTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
