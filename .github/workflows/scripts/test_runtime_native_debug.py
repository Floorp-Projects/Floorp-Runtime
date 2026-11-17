# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import os
import re
import tempfile
import shutil
from pathlib import Path
import unittest
from unittest import mock

import qa3_hosted as hosted
import runtime_native_debug as native

ROOT = Path(__file__).resolve().parents[3]


class NativeDebugContracts(unittest.TestCase):
    def env(self):
        return {"RUNTIME_NATIVE_DEBUG_ARTIFACTS": "true", "GITHUB_REPOSITORY": native.REPOSITORY,
                "GITHUB_REF": "refs/heads/nora-0.2.0", "GITHUB_SHA": "a" * 40,
                "GITHUB_WORKFLOW_SHA": "a" * 40, "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_WORKFLOW_REF": native.REPOSITORY + "/.github/workflows/wrapper-build-linux.yml@refs/heads/nora-0.2.0",
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}

    def test_dispatch_and_retry_context(self):
        with mock.patch.dict(os.environ, self.env(), clear=True):
            value = hosted.context_from_environment("20261117180000")
        self.assertEqual(hosted.validate_context(value), value)
        self.assertEqual(value["attempt"], 2)
        self.assertEqual(value["profile"], native.PROFILE)

    def test_schedule_daily_only(self):
        env = self.env(); env["GITHUB_EVENT_NAME"] = "schedule"
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(ValueError):
            hosted.context_from_environment("20261117180000")
        env["GITHUB_WORKFLOW_REF"] = env["GITHUB_WORKFLOW_REF"].replace("wrapper-build-linux", "daily-build")
        with mock.patch.dict(os.environ, env, clear=True):
            hosted.context_from_environment("20261117180000")

    def test_validation_manual_candidate_has_distinct_identity(self):
        env = self.env(); env["RUNTIME_NATIVE_DEBUG_VALIDATION"] = "true"
        env["GITHUB_REF"] = "refs/heads/" + native.VALIDATION_BRANCH
        env["GITHUB_WORKFLOW_REF"] = env["GITHUB_WORKFLOW_REF"].replace("nora-0.2.0", native.VALIDATION_BRANCH)
        with mock.patch.dict(os.environ, env, clear=True):
            value = hosted.context_from_environment("20261117180000")
            self.assertEqual(value["profile"], native.VALIDATION_PROFILE)
            self.assertNotEqual(value["profile"], native.PROFILE)
            hosted.validate_context(value)
        for key, bad in (("GITHUB_EVENT_NAME", "schedule"), ("GITHUB_EVENT_NAME", "pull_request"),
                         ("GITHUB_REF", "refs/heads/nora-0.2.0"), ("RUNTIME_NATIVE_DEBUG_VALIDATION", "false"),
                         ("GITHUB_WORKFLOW_REF", env["GITHUB_WORKFLOW_REF"].replace("wrapper-build-linux", "daily-build"))):
            altered = dict(env); altered[key] = bad
            with self.subTest(key=key, bad=bad), mock.patch.dict(os.environ, altered, clear=True), self.assertRaises(ValueError):
                hosted.context_from_environment("20261117180000")

        old = dict(env)
        old["GITHUB_REF"] = "refs/heads/codex/debug-native-artifacts"
        old["GITHUB_WORKFLOW_REF"] = old["GITHUB_WORKFLOW_REF"].replace(native.VALIDATION_BRANCH, "codex/debug-native-artifacts")
        with mock.patch.dict(os.environ, old, clear=True), self.assertRaises(ValueError):
            hosted.context_from_environment("20261117180000")

    def test_foreign_contexts_rejected(self):
        for key, bad in {"GITHUB_REPOSITORY": "fork/runtime", "GITHUB_REF": "refs/heads/main",
                         "GITHUB_EVENT_NAME": "pull_request", "GITHUB_WORKFLOW_SHA": "b" * 40,
                         "GITHUB_WORKFLOW_REF": "foreign", "GITHUB_RUN_ID": "0", "GITHUB_RUN_ATTEMPT": "0"}.items():
            env = self.env(); env[key] = bad
            with self.subTest(key=key), mock.patch.dict(os.environ, env, clear=True), self.assertRaises(ValueError):
                hosted.context_from_environment("20261117180000")

    def test_invalid_context_values(self):
        with mock.patch.dict(os.environ, self.env(), clear=True):
            base = native.context_from_environment("20261117180000")
        for key, bad in (("attempt", True), ("run", -1), ("buildID", "today"),
                         ("publicationAuthorized", True), ("runtimeRecipe", "main"), ("profile", "unknown")):
            value = copy.deepcopy(base); value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError): native.validate_context(value)
        base["extra"] = 1
        with self.assertRaises(ValueError): native.validate_context(base)

    def test_old_proof_not_widened_by_absent_normal_flag(self):
        env = self.env(); del env["RUNTIME_NATIVE_DEBUG_ARTIFACTS"]
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(ValueError):
            hosted.context_from_environment("20261117180000")

    def test_exact_excluded_debug_patches_and_no_extra_allowance(self):
        for name, digest in native.EXCLUDED_DEBUG_PATCHES.items():
            self.assertEqual(hashlib.sha256((ROOT / ".github/patches/debug" / name).read_bytes()).hexdigest(), digest)
        self.assertFalse((ROOT / ".github/patches/native-debug/noraneko-chrome-csp-allowlist.patch").exists())
        self.assertEqual(native.PRODUCT_PROFILE["additionalPatches"], [])
        self.assertFalse(native.PRODUCT_PROFILE["productTestsExecuted"])

    def test_security_source_bytes_and_unknown_patch_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            shutil.copytree(ROOT / ".github/patches/debug", source / ".github/patches/debug")
            for relative in native.ASSERTION_SOURCE_FILES:
                path = source / relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"original assertion and enforcement bytes")
            with mock.patch.object(hosted, "raw_git", return_value=b"original assertion and enforcement bytes"):
                self.assertEqual(native.verify_product_profile(source), native.PRODUCT_PROFILE)
                changed = source / native.ASSERTION_SOURCE_FILES[0]
                changed.write_bytes(b"return NS_OK; assertion bypass")
                with self.assertRaises(ValueError): native.verify_product_profile(source)
                changed.write_bytes(b"original assertion and enforcement bytes")
                (source / ".github/patches/debug/unknown.patch").write_text("unknown patch")
                with self.assertRaises(ValueError): native.verify_product_profile(source)

    def test_strict_setup_is_validation_only_and_mode_bounded(self):
        env = self.env(); env.update(RUNTIME_NATIVE_DEBUG_VALIDATION="true", MOZ_BUILD_DATE="20261117180000")
        env["GITHUB_REF"] = "refs/heads/" + native.VALIDATION_BRANCH
        env["GITHUB_WORKFLOW_REF"] = env["GITHUB_WORKFLOW_REF"].replace("nora-0.2.0", native.VALIDATION_BRANCH)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(hosted, "raw_git", return_value=("a" * 40).encode()), mock.patch.object(native, "verify_product_profile") as verify:
            native.strict_setup(ROOT, "linux", "x86_64", "true", "false", "")
            verify.assert_called_once_with(ROOT)
            for mode in (("linux", "x86_64", "false", "false", ""), ("linux", "x86_64", "true", "true", "use"), ("windows", "x86_64", "true", "false", ""), ("mac", "x86_64", "true", "false", "")):
                with self.assertRaises(ValueError): native.strict_setup(ROOT, *mode)
        env["RUNTIME_NATIVE_DEBUG_VALIDATION"] = "false"
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(ValueError):
            native.strict_setup(ROOT, "linux", "x86_64", "true", "false", "")

    def test_precompile_config_must_keep_debug_tests_and_no_pgo(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            config = "ac_add_options --target=x86_64-pc-linux-gnu\nac_add_options --enable-debug\nac_add_options --enable-tests\n"
            with mock.patch.object(native, "strict_setup"):
                (source / "mozconfig").write_text(config); native.prepare(source)
                for changed in (config.replace("--enable-debug", "--disable-debug"), config.replace("--enable-tests", "--disable-tests"), config + "ac_add_options --enable-profile-use=cross\n"):
                    (source / "mozconfig").write_text(changed)
                    with self.assertRaises(ValueError): native.prepare(source)

    def test_recipe_verification_binds_assertion_source_hashes(self):
        value = {"context": {"profile": native.VALIDATION_PROFILE}, "assertionSourceSha256": {p: "a" * 64 for p in native.ASSERTION_SOURCE_FILES}}
        with mock.patch.object(native, "assertion_source_identity", return_value={p: "b" * 64 for p in native.ASSERTION_SOURCE_FILES}), self.assertRaisesRegex(ValueError, "assertion source differs"):
            hosted.verify_recipe_metadata(ROOT, value)

    def test_producer_requires_exact_product_profile(self):
        from test_qa3_hosted import producer, HOST
        for profile in (native.PROFILE, native.VALIDATION_PROFILE):
            value = producer(); value["context"]["profile"] = profile
            value["productProfile"] = copy.deepcopy(native.PRODUCT_PROFILE)
            value["assertionSourceSha256"] = {p: "b" * 64 for p in native.ASSERTION_SOURCE_FILES}
            with mock.patch.object(hosted, "host_identity", return_value=HOST), mock.patch.object(hosted, "worker_boot_identity", return_value="d" * 64):
                self.assertEqual(hosted.validate_producer(value, value["context"])["consumerVerdict"], "UNVERIFIED")
                for bad in (None, {}, {**native.PRODUCT_PROFILE, "productTestsExecuted": True}):
                    value["productProfile"] = bad
                    with self.subTest(profile=profile, bad=bad), self.assertRaises(ValueError):
                        hosted.validate_producer(value, value["context"])

    def test_wrapper_scope_preserves_other_branch_debug_and_release(self):
        import yaml
        wrapper = yaml.safe_load((ROOT / ".github/workflows/wrapper-build-linux.yml").read_text())
        expression = wrapper["jobs"]["build-normal"]["with"]["native-debug-artifacts"][3:-2].strip()
        for branch, debug, pgo, arch, validation, expected in (
            ("nora-0.2.0", True, False, "x86_64", False, False),
            ("other-branch", True, False, "x86_64", False, False),
            ("other-branch", False, False, "x86_64", False, False),
            ("nora-0.2.0", False, False, "x86_64", False, False),
            ("nora-0.2.0", True, True, "x86_64", False, False),
            ("nora-0.2.0", True, False, "aarch64", False, False),
            (native.VALIDATION_BRANCH, True, False, "x86_64", True, True),
            (native.VALIDATION_BRANCH, True, True, "x86_64", True, False),
        ):
            text = expression
            values = {"inputs.debug": debug, "inputs.pgo": pgo, "inputs.arch": arch,
                      "inputs.native_validation_only": validation, "github.ref": "refs/heads/" + branch}
            for key, value in values.items(): text = text.replace(key, repr(value))
            text = re.sub(r"!(?!=)", "not ", text).replace("&&", " and ").replace("||", " or ")
            with self.subTest(branch=branch, debug=debug, pgo=pgo, arch=arch, validation=validation):
                self.assertEqual(eval(text, {"__builtins__": {}}, {}), expected)

    def test_validation_retention_matches_proof_and_legacy_default(self):
        import yaml
        common = yaml.safe_load((ROOT / ".github/workflows/common-build.yml").read_text())
        steps = {step.get("name"): step for step in common["jobs"]["build"]["steps"]}
        for name in ("Upload build artifact", "Upload dist/host for MAR", "Upload application.ini for MAR"):
            expression = steps[name]["with"]["retention-days"][3:-2].strip()
            for qa3, native_artifact, validation, expected in ((False, False, False, 0), (True, False, False, 1), (True, True, False, 0), (True, True, True, 1)):
                text = expression
                for key, value in {"inputs.qa3-debug-tests": qa3, "inputs.native-debug-artifacts": native_artifact, "inputs.native-debug-validation": validation}.items():
                    text = text.replace(key, repr(value))
                text = re.sub(r"!(?!=)", "not ", text).replace("&&", " and ").replace("||", " or ")
                with self.subTest(name=name, qa3=qa3, native=native_artifact, validation=validation):
                    self.assertEqual(eval(text, {"__builtins__": {}}, {}), expected)

    def test_normal_workflow_scope_and_retention(self):
        import yaml
        common = yaml.safe_load((ROOT / ".github/workflows/common-build.yml").read_text())
        wrapper = yaml.safe_load((ROOT / ".github/workflows/wrapper-build-linux.yml").read_text())
        normal = wrapper["jobs"]["build-normal"]["with"]
        self.assertEqual(normal["native-debug-artifacts"], normal["qa3-debug-tests"])
        self.assertIn("inputs.debug && !inputs.pgo", normal["native-debug-artifacts"])
        self.assertIn("inputs.arch == 'x86_64'", normal["native-debug-artifacts"])
        for name in ("build-pgo-stage1", "build-pgo-final"):
            self.assertNotIn("native-debug-artifacts", wrapper["jobs"][name]["with"])
        self.assertEqual(common["jobs"]["qa3-consumer"]["if"], "inputs.qa3-debug-tests && !inputs.native-debug-artifacts")
        self.assertEqual(normal["native-debug-validation"], "${{ inputs.native_validation_only || false }}")
        for name in ("build-pgo-stage1", "build-pgo-final", "collect-profiles"):
            self.assertIn("!inputs.native_validation_only", wrapper["jobs"][name]["if"])
        self.assertIn("inputs.native_validation_only ||", wrapper["jobs"]["build-normal"]["if"])
        steps = {step.get("name"): step for step in common["jobs"]["build"]["steps"]}
        upload = steps["Upload same-run Debug support"]["with"]
        self.assertIn("native-debug-validation", upload["name"])
        self.assertIn("-linux-x86_64-v2-", upload["name"])
        self.assertIn("90", upload["retention-days"])
        self.assertNotIn("overwrite", upload)
        self.assertEqual(steps["Verify strict native Debug source policy"]["if"], "inputs.qa3-debug-tests && inputs.native-debug-artifacts")


if __name__ == "__main__": unittest.main()