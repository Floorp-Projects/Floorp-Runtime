import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import qa3_hosted as hosted

SOURCE = Path(__file__).resolve().parents[3]


class PatchPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        qa = self.root / ".github/qa"
        qa.mkdir(parents=True)
        for name in ("source-policy.json", "hosted-consumer-seed.zip", "hosted-consumer-python.lock.json"):
            (qa / name).write_bytes((SOURCE / ".github/qa" / name).read_bytes())
        for name in ("upstream", "debug"):
            shutil.copytree(SOURCE / ".github/patches" / name, self.root / ".github/patches" / name)
        self.policy = json.loads((qa / "source-policy.json").read_text())
        self.first = self.root / self.policy["commonPatches"][0]["path"]

    def save(self):
        (self.root / ".github/qa/source-policy.json").write_text(json.dumps(self.policy))

    def test_actual_exact_inventory(self):
        result = hosted.verify_source_patch_policy(SOURCE)
        self.assertEqual(len(result["commonPatches"]), 31)
        self.assertEqual(len(result["debugPatches"]), 3)
        entry = next(e for e in result["commonPatches"] if e["path"].endswith("fdh-windows-private-profile-token.patch"))
        self.assertEqual(entry["sha256"], "121cd0eb12896e6365043369c58c37d53dcde3f129bbfa745e87639c5309a0f0")

    def test_unknown_rejected(self):
        (self.first.parent / "unknown.patch").write_text("unknown")
        with self.assertRaises(ValueError): hosted.verify_source_patch_policy(self.root)

    def test_missing_rejected(self):
        self.first.unlink()
        with self.assertRaises(ValueError): hosted.verify_source_patch_policy(self.root)

    def test_mutated_rejected(self):
        self.first.write_bytes(self.first.read_bytes() + b"\n")
        with self.assertRaises(ValueError): hosted.verify_source_patch_policy(self.root)

    def test_reordered_rejected(self):
        self.policy["commonPatches"].reverse()
        self.save()
        with self.assertRaises(ValueError): hosted.verify_source_patch_policy(self.root)

    def test_duplicate_rejected(self):
        self.policy["commonPatches"].append(self.policy["commonPatches"][0])
        self.save()
        with self.assertRaises(ValueError): hosted.verify_source_patch_policy(self.root)

    def test_old_policy_rejected(self):
        self.policy["commonPatches"] = [e for e in self.policy["commonPatches"] if not e["path"].endswith("fdh-windows-private-profile-token.patch")]
        self.save()
        with self.assertRaises(ValueError): hosted.verify_source_patch_policy(self.root)

    def test_debug_inventory_not_ignored(self):
        (self.root / self.policy["debugPatches"][0]["path"]).unlink()
        with self.assertRaises(ValueError): hosted.verify_source_patch_policy(self.root)

    def test_preflight_stops_before_build_context(self):
        (self.first.parent / "unknown.patch").write_text("unknown")
        with mock.patch.object(hosted, "context_from_environment") as context:
            with self.assertRaisesRegex(ValueError, "extra, missing"):
                hosted.packaging_preflight(SimpleNamespace(source=self.root))
            context.assert_not_called()

    def test_preflight_scoped_to_test_route(self):
        text = (SOURCE / ".github/workflows/common-build.yml").read_text()
        step = text.split("      - name: Check scoped Debug packaging Python before build\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("        if: inputs.qa3-debug-tests\n", step)
        self.assertIn("qa3_hosted.py preflight", step)
        import inspect
        self.assertIn("verify_source_patch_policy(args.source)", inspect.getsource(hosted.produce))


if __name__ == "__main__":
    unittest.main()
