# SPDX-License-Identifier: MPL-2.0

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from qa3_source_cohort import (
    SCOPE,
    capture_tree,
    diagnostic_expectation,
    digest,
    file_digest,
    preflight,
    same_cohort,
    verify_build_subject,
    verify_final_source,
    verify_inventory,
    verify_patches,
    verify_profile,
    verify_subject,
    verify_upstream_ancestor,
)


class SourceCohortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.cpp"
        self.source.write_text("enforce\n")
        self.patch_dir = self.root / ".github/patches/debug"
        self.patch_dir.mkdir(parents=True)
        patch = self.patch_dir / "diagnostic.patch"
        patch.write_text(
            "--- a/source.cpp\n+++ b/source.cpp\n@@ -1 +1 @@\n-enforce\n+diagnostic\n"
        )
        self.patches = [
            {
                "path": patch.relative_to(self.root).as_posix(),
                "sha256": file_digest(patch),
            }
        ]
        self.inventory = capture_tree(self.root)
        self.common = {
            "schemaVersion": 1,
            "scope": SCOPE,
            "U": {
                "vcs": "git",
                "repository": "https://github.com/mozilla-firefox/firefox",
                "fullRevision": "a" * 40,
            },
            "R": "b" * 40,
            "P": [{"path": "common.patch", "sha256": "c" * 64}],
            "transforms": [{"path": "branding", "sha256": "d" * 64}],
            "B": self.inventory["sha256"],
        }
        self.subject = {
            "schemaVersion": 1,
            "common": self.common,
            "role": "production-opt",
            "target": "x86_64-pc-linux-gnu",
            "delta": [],
            "finalTree": self.inventory["sha256"],
            "configSha256": "e" * 64,
            "toolchainSha256": "f" * 64,
            "artifactSha256": "1" * 64,
            "run": 123,
            "attempt": 1,
        }

    def test_cohort_rejects_upstream_runtime_patch_order_transform_and_tree_changes(
        self,
    ):
        self.assertEqual(
            same_cohort(self.common, copy.deepcopy(self.common)), digest(self.common)
        )
        variants = []
        for key, value in (
            ("R", "0" * 40),
            ("B", "0" * 64),
            ("P", []),
            ("transforms", []),
        ):
            changed = copy.deepcopy(self.common)
            changed[key] = value
            variants.append(changed)
        changed = copy.deepcopy(self.common)
        changed["U"]["vcs"] = "hg"
        variants.append(changed)
        changed = copy.deepcopy(self.common)
        changed["P"] = [
            self.common["P"][0],
            {"path": "extra.patch", "sha256": "0" * 64},
        ]
        variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                same_cohort(changed, self.common)
        ordered = copy.deepcopy(changed)
        reversed_plan = copy.deepcopy(ordered)
        reversed_plan["P"].reverse()
        with self.assertRaises(ValueError):
            same_cohort(ordered, reversed_plan)

    def test_baseline_is_required_and_inventory_cannot_be_forged(self):
        for key in self.common:
            changed = copy.deepcopy(self.common)
            del changed[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                same_cohort(changed, self.common)
        changed = copy.deepcopy(self.inventory)
        changed["entries"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            verify_inventory(changed)
        changed = copy.deepcopy(self.inventory)
        changed["entries"] *= 2
        changed["sha256"] = digest(changed["entries"])
        with self.assertRaises(ValueError):
            verify_inventory(changed)

    def test_only_exact_applied_diagnostic_delta_is_accepted(self):
        expected = diagnostic_expectation(self.root, self.inventory, self.patches)
        self.source.write_text("diagnostic\n")
        verify_final_source(self.root, expected)
        with self.assertRaises(ValueError):
            verify_final_source(self.root, self.inventory)
        (self.root / "unreported.cpp").write_text("hidden delta\n")
        with self.assertRaises(ValueError):
            verify_final_source(self.root, expected)

    def test_untracked_ignored_files_and_modes_are_not_silently_excluded(self):
        (self.root / ".gitignore").write_text("ignored.cpp\n")
        expected = capture_tree(self.root)
        (self.root / "ignored.cpp").write_text("consumed input\n")
        with self.assertRaises(ValueError):
            verify_final_source(self.root, expected)
        (self.root / "ignored.cpp").unlink()
        self.source.chmod(0o755)
        with self.assertRaises(ValueError):
            verify_final_source(self.root, expected)

    def test_symlink_target_changes_are_detected(self):
        link = self.root / "link"
        link.symlink_to("source.cpp")
        expected = capture_tree(self.root)
        link.unlink()
        link.symlink_to("elsewhere.cpp")
        with self.assertRaises(ValueError):
            verify_final_source(self.root, expected)

    def test_external_dangling_and_excluded_source_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as external:
            outside = Path(external) / "outside.cpp"
            outside.write_text("not inventoried\n")
            (self.root / "mozconfig").write_text("separate configuration\n")
            (self.root / ".git").mkdir()
            (self.root / ".git/private").write_text("excluded\n")
            link = self.root / "link"
            for target in (str(outside), "absent.cpp", "mozconfig", ".git/private"):
                with self.subTest(target=target):
                    link.symlink_to(target)
                    with self.assertRaises(ValueError):
                        capture_tree(self.root)
                    link.unlink()

    def test_empty_diagnostic_delta_cannot_accept_a_different_final_baseline(self):
        for role in (
            "production-opt",
            "canonical-debug",
            "profile-generate",
            "profile-use",
        ):
            with self.subTest(role=role), self.assertRaises(ValueError):
                verify_subject({**self.subject, "role": role, "finalTree": "0" * 64})
        value, producer, consumer, profdata, jarlog = self.pgo_fixture()
        producer = {**producer, "finalTree": "0" * 64}
        consumer = {**consumer, "finalTree": "0" * 64}
        value["producerSubjectSha256"] = digest(producer)
        with self.assertRaises(ValueError):
            verify_profile(value, producer, consumer, profdata, jarlog, "3" * 64)

    def test_preflight_rejects_untracked_and_ignored_runtime_recipe_inputs(self):
        common = []
        directory = self.root / ".github/patches/upstream"
        directory.mkdir()
        for number in range(27):
            path = directory / f"{number:02}.patch"
            path.write_text(f"common fixture {number}\n")
            common.append({
                "path": path.relative_to(self.root).as_posix(),
                "sha256": file_digest(path),
            })
        debug = list(self.patches)
        for number in range(2):
            path = self.patch_dir / f"extra-{number}.patch"
            path.write_text(f"diagnostic fixture {number}\n")
            debug.append({
                "path": path.relative_to(self.root).as_posix(),
                "sha256": file_digest(path),
            })
        debug.sort(key=lambda entry: entry["path"].encode())
        policy = self.root / ".github/qa/source-policy.json"
        policy.parent.mkdir()
        policy.write_text(
            json.dumps({
                "schemaVersion": 1,
                "comparisonPolicy": "common-baseline-with-diagnostics",
                "commonPatches": common,
                "debugPatches": debug,
            })
        )
        (self.root / ".github/runtime-upstream.json").write_text(
            json.dumps({
                "upstream": {
                    "commit": "a" * 40,
                    "repository": "mozilla-firefox/firefox",
                }
            })
        )
        script = self.root / ".github/workflows/scripts/setup-floorp.sh"
        script.parent.mkdir(parents=True)
        script.write_text("fixture setup\n")
        (self.root / ".gitignore").write_text(".github/ignored-*\n")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=QA fixture",
                "-c",
                "user.email=qa@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        head = subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True
        ).strip()
        self.assertIs(preflight(self.root, head)["publicationAuthorized"], False)
        for name in ("untracked-input", "ignored-input"):
            path = self.root / ".github" / name
            path.write_text("undeclared recipe\n")
            with self.assertRaises(ValueError):
                preflight(self.root, head)
            path.unlink()

    def test_patch_inventory_rejects_missing_extra_changed_and_duplicate_material(self):
        verify_patches(self.root, self.patches, ".github/patches/debug")
        for entries in (
            [],
            self.patches * 2,
            [{**self.patches[0], "sha256": "0" * 64}],
        ):
            with self.assertRaises(ValueError):
                verify_patches(self.root, entries, ".github/patches/debug")
        (self.patch_dir / "extra.patch").write_text("extra")
        with self.assertRaises(ValueError):
            verify_patches(self.root, self.patches, ".github/patches/debug")

    def test_actual_git_ingestion_and_runtime_head_are_verified(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "QA fixture",
            "GIT_AUTHOR_EMAIL": "qa@example.invalid",
            "GIT_COMMITTER_NAME": "QA fixture",
            "GIT_COMMITTER_EMAIL": "qa@example.invalid",
        }
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "fixture"],
            env=env,
            check=True,
        )
        head = subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True
        ).strip()
        verify_upstream_ancestor(self.root, head, head)
        for upstream, runtime in (("0" * 40, head), (head, "0" * 40)):
            with self.assertRaises(ValueError):
                verify_upstream_ancestor(self.root, upstream, runtime)

    def test_exact_subject_rejects_wrong_config_target_attempt_and_final_bytes(self):
        verify_build_subject(self.subject, self.subject, self.root, self.inventory)
        for key, value in (
            ("configSha256", "0" * 64),
            ("target", "x86_64-pc-windows-msvc"),
            ("attempt", 2),
            ("artifactSha256", "0" * 64),
        ):
            changed = copy.deepcopy(self.subject)
            changed[key] = value
            with self.assertRaises(ValueError):
                verify_build_subject(changed, self.subject, self.root, self.inventory)
        self.source.write_text("unexpected\n")
        with self.assertRaises(ValueError):
            verify_build_subject(self.subject, self.subject, self.root, self.inventory)

    def test_linux_arm_and_legacy_debug_pgo_are_not_invented_canonical_profiles(self):
        for role, target in (
            ("legacy-debug-profile-use", "x86_64-pc-linux-gnu"),
            ("profile-use", "aarch64-unknown-linux-gnu"),
        ):
            subject = {**self.subject, "role": role, "target": target}
            with self.assertRaises(ValueError):
                verify_subject(subject)

    def pgo_fixture(self):
        producer = {**self.subject, "role": "profile-generate"}
        consumer = {**self.subject, "role": "profile-use", "configSha256": "2" * 64}
        profdata = self.root / "merged.profdata"
        jarlog = self.root / "en-US.log"
        profdata.write_bytes(b"profile bytes")
        jarlog.write_bytes(b"jarlog bytes")
        value = {
            "producerSubjectSha256": digest(producer),
            "producerArtifactSha256": producer["artifactSha256"],
            "producerRun": producer["run"],
            "producerAttempt": producer["attempt"],
            "workloadSha256": "3" * 64,
            "profdataSha256": file_digest(profdata),
            "jarlogSha256": file_digest(jarlog),
        }
        return value, producer, consumer, profdata, jarlog

    def test_pgo_profile_binds_actual_bytes_workload_binary_run_and_attempt(self):
        value, producer, consumer, profdata, jarlog = self.pgo_fixture()
        verify_profile(value, producer, consumer, profdata, jarlog, "3" * 64)
        for key, new in (
            ("producerAttempt", 2),
            ("producerRun", 124),
            ("producerArtifactSha256", "0" * 64),
            ("producerSubjectSha256", "0" * 64),
            ("workloadSha256", "0" * 64),
            ("profdataSha256", "0" * 64),
            ("jarlogSha256", "0" * 64),
        ):
            changed = {**value, key: new}
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_profile(changed, producer, consumer, profdata, jarlog, "3" * 64)
        profdata.write_bytes(b"same name; different bytes")
        with self.assertRaises(ValueError):
            verify_profile(value, producer, consumer, profdata, jarlog, "3" * 64)

    def test_pgo_profile_rejects_other_cohort_target_toolchain_and_missing_fields(self):
        value, producer, consumer, profdata, jarlog = self.pgo_fixture()
        for key, new in (
            ("target", "x86_64-pc-windows-msvc"),
            ("toolchainSha256", "0" * 64),
            ("finalTree", "0" * 64),
        ):
            changed = {**consumer, key: new}
            with self.assertRaises(ValueError):
                verify_profile(value, producer, changed, profdata, jarlog, "3" * 64)
        changed = copy.deepcopy(consumer)
        changed["common"]["R"] = "0" * 40
        with self.assertRaises(ValueError):
            verify_profile(value, producer, changed, profdata, jarlog, "3" * 64)
        for key in value:
            changed = dict(value)
            del changed[key]
            with self.assertRaises(ValueError):
                verify_profile(changed, producer, consumer, profdata, jarlog, "3" * 64)


if __name__ == "__main__":
    unittest.main()
