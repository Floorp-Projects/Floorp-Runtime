# SPDX-License-Identifier: MPL-2.0

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from qa3_source_cohort import capture_tree, file_digest
from qa3_source_prepare import (
    OLD_URL,
    git,
    prepare_source,
    verify_checkout,
    verify_plan,
)


def save(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def commit(root):
    git(root, "add", ".")
    git(
        root,
        "-c",
        "user.name=QA fixture",
        "-c",
        "user.email=qa@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "fixture",
    )
    return git(root, "rev-parse", "HEAD").stdout.decode().strip()


def fixture(root):
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for i in range(27):
        save(root, f"c{i}.txt", "0\n")
    save(root, "build/application.ini.in", OLD_URL + "\n")
    save(root, ".gitignore", "ignored*\n")
    save(root, "browser/branding/base", "old\n")
    selections = []
    materials = []
    for suite, name, manifest in (
        ("browser-chrome", "browser/test.js", "browser/browser.toml"),
        ("xpcshell", "xpcom/test.js", "xpcom/xpcshell.toml"),
    ):
        for path, text in ((name, "assertion\n"), (manifest, '["test.js"]\n')):
            materials.append({
                "path": path,
                "sha256": file_digest(save(root, path, text)),
            })
        selections.append({
            "suite": suite,
            "id": name,
            "manifest": manifest,
            "archivePath": (
                "mochitest/browser/" if suite == "browser-chrome" else "xpcshell/tests/"
            )
            + name,
            "minimumAssertions": 1,
            "declaredConditions": {},
            "requiredNoSkip": True,
        })
    for path in (
        "testing/mochitest/runtests.py",
        "testing/mochitest/mochitest_options.py",
        "testing/xpcshell/runxpcshelltests.py",
        "testing/xpcshell/xpcshellcommandline.py",
        ".github/qa/canaries/browser_qa3_assertion.js",
        ".github/qa/canaries/test_qa3_assertion.js",
    ):
        materials.append({
            "path": path,
            "sha256": file_digest(
                save(root, path, "# fixture only, never native executed\n")
            ),
        })
    upstream = commit(root)
    common = []
    debug = []
    for directory, count, before, after, entries in (
        ("upstream", 27, "0", "1", common),
        ("debug", 3, "1", "2", debug),
    ):
        for i in range(count):
            path = save(
                root,
                f".github/patches/{directory}/{i:02}.patch",
                f"--- a/c{i}.txt\n+++ b/c{i}.txt\n@@ -1 +1 @@\n-{before}\n+{after}\n",
            )
            entries.append({
                "path": path.relative_to(root).as_posix(),
                "sha256": file_digest(path),
            })
    save(
        root,
        ".github/qa/source-policy.json",
        json.dumps({
            "schemaVersion": 1,
            "comparisonPolicy": "common-baseline-with-diagnostics",
            "commonPatches": common,
            "debugPatches": debug,
        }),
    )
    save(
        root,
        ".github/runtime-upstream.json",
        json.dumps({
            "upstream": {"repository": "mozilla-firefox/firefox", "commit": upstream}
        }),
    )
    save(root, ".github/assets/branding/base", "new\n")
    save(root, ".github/assets/branding/nested/extra", "added\n")
    save(
        root,
        ".github/workflows/mozconfigs/linux-x86_64.mozconfig",
        "ac_add_options --target=x86_64-pc-linux-gnu\nac_add_options --disable-tests\n",
    )
    save(
        root,
        ".github/qa/linux-proof-plan.json",
        json.dumps({
            "schemaVersion": 1,
            "id": "linux-x64-runtime-l1-proof-v1",
            "role": "canonical-debug",
            "target": "x86_64-pc-linux-gnu",
            "sourceMaterials": materials,
            "selection": selections,
            "nativeExecution": "UNVERIFIED",
            "coldHarnessCLI": "UNVERIFIED",
            "coldRequirements": "UNVERIFIED",
            "publicationAuthorized": False,
        }),
    )
    return upstream, commit(root)


class SourcePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.TemporaryDirectory()
        cls.upstream, cls.runtime = fixture(Path(cls.base.name) / "base")

    @classmethod
    def tearDownClass(cls):
        cls.base.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--shared",
                str(Path(self.base.name) / "base"),
                str(self.source),
            ],
            check=True,
        )
        self.output = self.root / "receipt"
        self.output.mkdir()
        self.runtime = type(self).runtime

    def prepare(self):
        return prepare_source(self.source, self.runtime, self.root / "obj", self.output)

    def change_json(self, name, callback):
        path = self.source / name
        data = json.loads(path.read_text())
        callback(data)
        path.write_text(json.dumps(data))
        self.runtime = commit(self.source)

    def shipped_canary_plan(self):
        """Bind the fixture plan's two canaries to the shipped files and pins."""
        checkout = Path(__file__).resolve().parents[3]
        shipped = json.loads(
            (checkout / ".github/qa/linux-proof-plan.json").read_text()
        )
        plan_path = self.source / ".github/qa/linux-proof-plan.json"
        plan = json.loads(plan_path.read_text())
        fixture_materials = {item["path"]: item for item in plan["sourceMaterials"]}
        for relative in (
            ".github/qa/canaries/browser_qa3_assertion.js",
            ".github/qa/canaries/test_qa3_assertion.js",
        ):
            pinned = [
                item for item in shipped["sourceMaterials"] if item["path"] == relative
            ]
            self.assertEqual(len(pinned), 1)
            (self.source / relative).write_bytes((checkout / relative).read_bytes())
            fixture_materials[relative]["sha256"] = pinned[0]["sha256"]
        plan_path.write_text(json.dumps(plan))
        return plan_path

    def test_shipped_canaries_match_frozen_plan(self):
        verify_plan(self.source, self.shipped_canary_plan())

    def test_stale_shipped_canary_digest_is_rejected(self):
        plan_path = self.shipped_canary_plan()
        original = plan_path.read_text()
        verify_plan(self.source, plan_path)
        for relative, stale in (
            (
                ".github/qa/canaries/browser_qa3_assertion.js",
                "869990c5be7fc3292b4c2a54c47b08114dc6ca7398bf8deec4b1df61d61330d8",
            ),
            (
                ".github/qa/canaries/test_qa3_assertion.js",
                "336ec5930031c36886fb2d1ab982d30165db951701ce1ea2b3cb47b04bdf20c9",
            ),
        ):
            plan = json.loads(original)
            for item in plan["sourceMaterials"]:
                if item["path"] == relative:
                    item["sha256"] = stale
            plan_path.write_text(json.dumps(plan))
            with self.subTest(path=relative), self.assertRaisesRegex(
                ValueError, "pinned harness or selected test source differs"
            ):
                verify_plan(self.source, plan_path)

    def test_changed_shipped_canary_bytes_are_rejected(self):
        plan_path = self.shipped_canary_plan()
        verify_plan(self.source, plan_path)
        for relative in (
            ".github/qa/canaries/browser_qa3_assertion.js",
            ".github/qa/canaries/test_qa3_assertion.js",
        ):
            path = self.source / relative
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.subTest(path=relative), self.assertRaisesRegex(
                ValueError, "pinned harness or selected test source differs"
            ):
                verify_plan(self.source, plan_path)
            path.write_bytes(original)

    def test_actual_git_p_c_b_d_f_and_generated_config(self):
        record, final, _ = self.prepare()
        self.assertEqual(record["executionKind"], "actual-source-preparation")
        self.assertEqual(record["ingestion"]["relation"], "verified-ancestor")
        self.assertNotEqual(record["common"]["B"], record["finalTree"])
        self.assertEqual(capture_tree(self.source), final)
        self.assertEqual(len(record["operations"]), 32)
        self.assertEqual((self.source / "c0.txt").read_text(), "2\n")
        self.assertEqual((self.source / "c26.txt").read_text(), "1\n")
        self.assertEqual(
            (self.source / "browser/branding/nested/extra").read_text(), "added\n"
        )
        self.assertIn("--enable-tests", (self.source / "mozconfig").read_text())
        self.assertIs(record["publicationAuthorized"], False)
        self.assertEqual(record["nativeQualification"], "UNVERIFIED")

    def test_wrong_runtime_or_missing_upstream(self):
        for runtime, upstream in (("0" * 40, self.upstream), (self.runtime, "0" * 40)):
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                verify_checkout(self.source, runtime, upstream)

    def test_shallow_checkout(self):
        (self.source / ".git/shallow").write_text(self.upstream + "\n")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_sparse_checkout(self):
        git(self.source, "config", "core.sparseCheckout", "true")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_skip_worktree_and_assume_unchanged(self):
        for flag in ("--skip-worktree", "--assume-unchanged"):
            git(self.source, "update-index", flag, "c0.txt")
            (self.source / "c0.txt").write_text("rogue\n")
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                self.prepare()
            (self.source / "c0.txt").write_text("0\n")
            git(
                self.source,
                "update-index",
                "--no-skip-worktree",
                "--no-assume-unchanged",
                "c0.txt",
            )

    def test_untracked_and_ignored_source(self):
        for name in ("untracked", "ignored-input"):
            path = self.source / name
            path.write_text("rogue\n")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.prepare()
            path.unlink()

    def test_local_filemode_false_cannot_hide_executable_change(self):
        git(self.source, "config", "core.fileMode", "false")
        (self.source / "c0.txt").chmod(0o755)
        self.assertEqual(git(self.source, "status", "--porcelain").stdout, b"")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_clean_filter_cannot_hide_raw_changed_bytes(self):
        save(self.source, ".gitattributes", "c0.txt filter=mask\n")
        self.runtime = commit(self.source)
        git(self.source, "config", "filter.mask.clean", "sed s/rogue/0/")
        (self.source / "c0.txt").write_text("rogue\n")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_reordered_or_reduced_common_policy(self):
        self.change_json(
            ".github/qa/source-policy.json", lambda x: x["commonPatches"].reverse()
        )
        with self.assertRaises(ValueError):
            self.prepare()

    def test_reduced_diagnostic_policy(self):
        self.change_json(
            ".github/qa/source-policy.json", lambda x: x["debugPatches"].pop()
        )
        with self.assertRaises(ValueError):
            self.prepare()

    def test_double_common_patch(self):
        git(self.source, "apply", ".github/patches/upstream/00.patch")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_ambiguous_update_url(self):
        save(self.source, "build/application.ini.in", OLD_URL + "\n" + OLD_URL + "\n")
        self.runtime = commit(self.source)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_url_write_extra_bytes_not_adopted_as_expected(self):
        original = Path.write_bytes

        def altered(path, data):
            if path == self.source / "build/application.ini.in":
                data += b"rogue\n"
            return original(path, data)

        with mock.patch.object(Path, "write_bytes", altered), self.assertRaises(
            ValueError
        ):
            self.prepare()

    def test_external_state_and_preexisting_mozconfig(self):
        with self.assertRaises(ValueError):
            prepare_source(self.source, self.runtime, self.source / "obj", self.output)
        save(self.source, "mozconfig", "unapproved\n")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_walk_error_cannot_produce_partial_pass(self):
        def fail_walk(*args, **kwargs):
            kwargs["onerror"](PermissionError("fixture"))
            return iter(())

        with mock.patch("qa3_source_cohort.os.walk", fail_walk), self.assertRaises(
            PermissionError
        ):
            capture_tree(self.source)

    def test_selected_source_digest_change(self):
        save(self.source, "browser/test.js", "unapproved\n")
        self.runtime = commit(self.source)
        with self.assertRaises(ValueError):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
