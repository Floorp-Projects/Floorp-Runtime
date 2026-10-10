# SPDX-License-Identifier: MPL-2.0

import argparse
import copy
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from qa3_native_build import (
    install_canaries,
    merge_materials,
    verify_effective_config,
    verify_python_environment,
)
from qa3_native_consume import (
    canary_case,
    harness_argv,
    verify_inputs,
    verify_source_receipt,
)
from qa3_native_io import (
    IOBudget,
    capture_material_tree,
    pack_tree,
    read_json,
    write_json,
)
from qa3_source_cohort import capture_tree, digest, file_digest
from qa3_source_prepare import check_raw_index, git, prepare_source, tree_index_entries
from qa3_xpcshell_entry import run as run_xpcshell_once
from test_qa3_native_io import elf
from test_qa3_native_transport import context
from test_qa3_source_prepare import fixture

ROOT = Path(__file__).resolve().parents[3]


class NativeContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_effective_config_must_enable_tests_debug_and_exact_compiler(self):
        compiler = self.root / "compiler"
        compiler.write_bytes(b"fixture executable identity")
        toolchain = {
            "tools": [
                {"name": name, "path": str(compiler), "sha256": file_digest(compiler)}
                for name in ("clang", "clang++", "rustc", "cargo")
            ]
        }
        substs = {
            "ENABLE_TESTS": "1",
            "MOZ_DEBUG": "1",
            "TARGET_CPU": "x86_64",
            "OS_TARGET": "Linux",
            **{field: str(compiler) for field in ("CC", "CXX", "RUSTC", "CARGO")},
        }
        config = {
            "schemaVersion": 1,
            "source": str(self.root),
            "objdir": str(self.root / "obj"),
            "substs": substs,
        }
        verify_effective_config(config, self.root, self.root / "obj", toolchain)
        for field, value in (
            ("ENABLE_TESTS", False),
            ("MOZ_DEBUG", 1.0),
            ("TARGET_CPU", "aarch64"),
            ("OS_TARGET", "WINNT"),
            ("MOZ_ARTIFACT_BUILDS", True),
            ("MOZ_PROFILE_GENERATE", "1"),
            ("MOZ_PROFILE_USE", "1"),
            ("CC", "/unbound/compiler"),
        ):
            with self.subTest(field=field), self.assertRaises((OSError, ValueError)):
                verify_effective_config(
                    {**config, "substs": {**substs, field: value}},
                    self.root,
                    self.root / "obj",
                    toolchain,
                )

    def environment(self):
        env = self.root / "python-inputs"
        env.mkdir()
        (env / "wheelhouse").mkdir()
        wheel = env / "wheelhouse/fixture-1-py3-none-any.whl"
        wheel.write_bytes(b"fixture wheel input, never installed")
        (env / "requirements.lock").write_text(
            "fixture==1 --hash=sha256:" + file_digest(wheel) + "\n"
        )
        return env

    def test_offline_python_inputs_require_exact_wheels_and_hashes(self):
        env = self.environment()
        snapshot = capture_tree(env)
        self.assertEqual(verify_python_environment(env, snapshot["sha256"]), snapshot)
        (env / "wheelhouse/unlisted-1-py3-none-any.whl").write_bytes(b"extra")
        with self.assertRaises(ValueError):
            verify_python_environment(env, capture_tree(env)["sha256"])

    def test_offline_python_rejects_unpinned_url_sdist_option_and_wrong_hash(self):
        env = self.environment()
        for line in (
            "fixture>=1",
            "fixture @ https://example.invalid/pkg",
            "--index-url https://example.invalid",
            "fixture==1 --hash=sha256:" + "0" * 64,
        ):
            (env / "requirements.lock").write_text(line + "\n")
            with self.subTest(line=line), self.assertRaises(ValueError):
                verify_python_environment(env, capture_tree(env)["sha256"])
        (env / "wheelhouse/fixture.tar.gz").write_bytes(b"sdist")
        with self.assertRaises(ValueError):
            verify_python_environment(env, capture_tree(env)["sha256"])

    def test_offline_python_rejects_source_only_excluded_inputs(self):
        env = self.environment()
        pin = capture_tree(env)["sha256"]
        for name in ("mozconfig", ".git", ".hg"):
            marker = env / name
            marker.write_bytes(b"undeclared material")
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify_python_environment(env, pin)
            marker.unlink()
            marker.mkdir()
            with self.subTest(name=name + "/"), self.assertRaises(ValueError):
                verify_python_environment(env, pin)
            marker.rmdir()

    def test_primary_and_support_inventory_rejects_excluded_input_changes(self):
        for kind in ("primary", "support"):
            material = self.root / kind
            material.mkdir()
            (material / "input").write_bytes(b"immutable fixture")
            before = capture_material_tree(material)
            self.assertEqual(before, capture_tree(material))
            for name in ("mozconfig", ".git", ".hg"):
                marker = material / name
                marker.symlink_to("missing-input")
                with self.subTest(kind=kind, name=name), self.assertRaises(ValueError):
                    capture_material_tree(material)
                marker.unlink()
                marker.mkdir()
                (marker / "input").write_bytes(b"undeclared material")
                with self.subTest(kind=kind, name=name + "/"), self.assertRaises(
                    ValueError
                ):
                    capture_material_tree(material)
                shutil.rmtree(marker)
            self.assertEqual(before, capture_material_tree(material))

    def test_merge_accepts_identical_duplicate_only_and_counts_peak(self):
        source = self.root / "source"
        destination = self.root / "destination"
        source.mkdir()
        destination.mkdir()
        (source / "helper").write_bytes(b"bytes")
        budget = IOBudget(self.root, 20)
        merge_materials(source, destination, budget)
        merge_materials(source, destination, budget)
        self.assertEqual(budget.used, 5)
        (source / "helper").write_bytes(b"rogue")
        with self.assertRaises(ValueError):
            merge_materials(source, destination, budget)
        (source / "helper").write_bytes(b"bytes")
        (source / "helper").chmod(0o755)
        with self.assertRaises(ValueError):
            merge_materials(source, destination, budget)

    def test_direct_harness_uses_explicit_primary_helpers_and_fixed_case(self):
        for case in read_json(ROOT / ".github/qa/linux-proof-plan.json")["selection"]:
            argv = harness_argv(
                "/venv/python",
                self.root / "support",
                self.root / "primary/floorp",
                case,
                self.root / "profile",
            )
            self.assertIn("--log-raw", argv)
            self.assertEqual(argv[-1], str(self.root / "support" / case["archivePath"]))
            self.assertIn("--manifest", argv)
            self.assertIn(str(self.root / "support/bin"), argv)
            self.assertIn(str(self.root / "primary/floorp"), argv)
            if case["suite"] == "browser-chrome":
                self.assertIn("--certificate-path", argv)
                self.assertIn(str(self.root / "primary/floorp/floorp"), argv)
            else:
                self.assertIn(str(self.root / "support/bin/xpcshell"), argv)

    def test_source_receipt_roundtrip_rejects_cross_recipe_or_undeclared_delta(self):
        source = self.root / "source"
        _, runtime = fixture(source)
        output = self.root / "output"
        output.mkdir()
        preparation, final, _ = prepare_source(
            source, runtime, self.root / "obj", output
        )
        baseline = read_json(output / "baseline.json")
        proof = {"preparation": preparation}
        verify_source_receipt(source, proof, baseline, final, runtime)
        with self.assertRaises(ValueError):
            verify_source_receipt(source, proof, baseline, final, "0" * 40)
        for variant in ("unapplied", "wrong-postimage", "wrong-mode", "wrong-type"):
            changed = copy.deepcopy(final if variant != "unapplied" else baseline)
            if variant != "unapplied":
                entry = next(x for x in changed["entries"] if x["path"] == "c0.txt")
                if variant == "wrong-postimage":
                    entry["sha256"] = "0" * 64
                elif variant == "wrong-mode":
                    entry["executable"] = True
                else:
                    entry.clear()
                    entry.update(path="c0.txt", type="symlink", target="c1.txt")
                changed["sha256"] = digest(changed["entries"])
            changed_proof = copy.deepcopy(proof)
            changed_proof["preparation"]["finalTree"] = changed["sha256"]
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                verify_source_receipt(source, changed_proof, baseline, changed, runtime)
        preparation["delta"] = []
        with self.assertRaises(ValueError):
            verify_source_receipt(source, proof, baseline, final, runtime)

    def test_producer_bundle_consumer_binding_fixture_and_corruption(self):
        source = self.root / "fixture-source"
        _, runtime = fixture(source)
        receipt = self.root / "source-receipt"
        receipt.mkdir()
        preparation, final, plan = prepare_source(
            source, runtime, self.root / "fixture-obj", receipt
        )
        ctx = {**context(), "runtimeRecipe": runtime}
        inputs = self.root / "inputs"
        (inputs / "primary").mkdir(parents=True)
        (inputs / "support").mkdir()
        app = self.root / "app/floorp"
        app.mkdir(parents=True)
        identities = {
            name: __import__("qa3_native_io").elf_identity(elf(app / name))
            for name in ("floorp", "libxul.so")
        }
        for name, section in (("application.ini", "App"), ("platform.ini", "Build")):
            (app / name).write_text(
                f"[{section}]\nBuildID={ctx['buildID']}\nSourceStamp={runtime}\n"
            )
        pack_tree(app.parent, inputs / "primary/runtime.tar.xz")
        support = self.root / "bundle"
        support.mkdir()
        for case in plan["selection"]:
            target = support / case["archivePath"]
            target.parent.mkdir(parents=True)
            shutil.copy2(source / case["id"], target)
            shutil.copy2(
                source / case["manifest"], target.parent / Path(case["manifest"]).name
            )
        for path, source_path in (
            ("mochitest/runtests.py", "testing/mochitest/runtests.py"),
            (
                "mochitest/mochitest_options.py",
                "testing/mochitest/mochitest_options.py",
            ),
            ("xpcshell/runxpcshelltests.py", "testing/xpcshell/runxpcshelltests.py"),
            (
                "xpcshell/xpcshellcommandline.py",
                "testing/xpcshell/xpcshellcommandline.py",
            ),
        ):
            (support / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / source_path, support / path)
        (support / "bin").mkdir()
        helpers = {
            name: __import__("qa3_native_io").elf_identity(elf(support / "bin" / name))
            for name in ("xpcshell", "ssltunnel", "certutil", "pk12util")
        }
        offline = self.environment()
        shutil.copytree(offline, support / "python-environment")
        changes = install_canaries(source, support, plan)
        write_json(support / "plan.json", plan)
        inventory = capture_tree(support)
        pack_tree(support, inputs / "support/test-support.tar.gz")
        proof = {
            "schemaVersion": 1,
            "executionKind": "native-debug-build-producer",
            "context": ctx,
            "workerBootSha256": "f" * 64,
            "preparation": preparation,
            "primarySha256": file_digest(inputs / "primary/runtime.tar.xz"),
            "primaryIdentity": identities,
            "supportSha256": file_digest(inputs / "support/test-support.tar.gz"),
            "supportInventory": inventory,
            "planSha256": file_digest(source / ".github/qa/linux-proof-plan.json"),
            "toolchainSha256": "e" * 64,
            "pythonEnvironmentSha256": capture_tree(offline)["sha256"],
            "effectiveConfig": {
                "substs": {
                    "ENABLE_TESTS": "1",
                    "MOZ_DEBUG": "1",
                    "TARGET_CPU": "x86_64",
                    "OS_TARGET": "Linux",
                }
            },
            "helpers": helpers,
            "canaryTransforms": changes,
            "commands": [
                {
                    "name": name,
                    "exit": 0,
                    "stop": None,
                    "ownedCleanupComplete": True,
                    "argv": ["fixture-only"],
                }
                for name in (
                    "configure",
                    "effective-config",
                    "native-build",
                    "primary-package",
                    "package-tests",
                )
            ],
            "consumerVerdict": "UNVERIFIED",
            "nativeQualification": "UNVERIFIED",
            "publicationAuthorized": False,
        }
        binding = {
            "schemaVersion": 1,
            "context": ctx,
            "primarySha256": proof["primarySha256"],
            "primaryIdentity": identities,
            "publicationAuthorized": False,
        }
        write_json(inputs / "primary/primary.json", binding)
        write_json(inputs / "support/proof.json", proof)
        shutil.copy2(receipt / "baseline.json", inputs / "support/baseline.json")
        shutil.copy2(receipt / "final.json", inputs / "support/final.json")
        write_json(inputs / "context.json", ctx)
        args = argparse.Namespace(
            recipe=source,
            runtime=runtime,
            inputs=inputs,
            primary_id=42,
            support_id=43,
            primary_sha256="1" * 64,
            support_sha256="2" * 64,
            builder_toolchain_sha256="e" * 64,
            plan_sha256=proof["planSha256"],
            python_environment_sha256=proof["pythonEnvironmentSha256"],
        )
        for kind, identifier, wanted in (
            ("primary", 42, "1" * 64),
            ("support", 43, "2" * 64),
        ):
            write_json(
                inputs / (kind + "-transport.json"),
                {
                    "artifactId": identifier,
                    "archiveSha256": wanted,
                    "authenticatedRepository": ctx["executionRepository"],
                    "metadata": {
                        "id": identifier,
                        "name": f"qa3-{kind}-7-2",
                        "expired": False,
                        "digest": "sha256:" + wanted,
                        "size_in_bytes": 10,
                        "workflow_run": {"id": 7, "head_sha": ctx["controllerHead"]},
                    },
                },
            )
        with mock.patch("qa3_native_consume.os.access", return_value=False), mock.patch(
            "qa3_native_consume.worker_boot_identity", return_value="d" * 64
        ):
            output = self.root / "valid-output"
            output.mkdir()
            actual, selected, _, bundled = verify_inputs(
                args, ctx, output, IOBudget(output, 1024**2)
            )
            self.assertEqual(selected, plan)
            self.assertEqual(actual["nativeQualification"], "UNVERIFIED")
            for case in plan["selection"]:
                self.assertIn(
                    "qa3_assertion.js", canary_case(case, bundled, proof)["id"]
                )
            with (inputs / "primary/runtime.tar.xz").open("ab") as out:
                out.write(b"corrupt")
            bad_output = self.root / "bad-output"
            bad_output.mkdir()
            with self.assertRaises(ValueError):
                verify_inputs(args, ctx, bad_output, IOBudget(bad_output, 1024**2))

    def test_parse_only_probe_accepts_hidden_cli_flags_without_native_execution(self):
        support = self.root / "probe"
        (support / "mochitest").mkdir(parents=True)
        (support / "xpcshell").mkdir()
        module = "import argparse\ndef parser():\n p=argparse.ArgumentParser()\n"
        flags = [
            "--manifest",
            "--xre-path",
            "--utility-path",
            "--testing-modules-dir",
            "--log-raw",
            "--flavor",
            "--appname",
            "--certificate-path",
            "--timeout",
            "--profile-path",
            "--xpcshell",
            "--app-path",
        ]
        for flag in flags:
            module += f" p.add_argument('{flag}',help=argparse.SUPPRESS)\n"
        for flag in ("--headless", "--sequential", "--no-logfiles"):
            module += f" p.add_argument('{flag}',action='store_true')\n"
        module += " p.add_argument('test_paths',nargs='*')\n return p\n"
        (support / "mochitest/mochitest_options.py").write_text(
            module + "def MochitestArgumentParser(app):\n return parser()\n"
        )
        (support / "xpcshell/xpcshellcommandline.py").write_text(
            module + "def parser_desktop():\n return parser()\n"
        )
        write_json(
            support / "plan.json", read_json(ROOT / ".github/qa/linux-proof-plan.json")
        )
        output = self.root / "conformance.json"
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / ".github/workflows/scripts/qa3_harness_probe.py"),
                "--support",
                str(support),
                "--app",
                str(self.root / "app"),
                "--output",
                str(output),
            ],
            check=True,
        )
        self.assertEqual(read_json(output)["parserVerdict"], "PASS")
        self.assertIs(read_json(output)["nativeExecuted"], False)

    def test_readonly_recipe_must_match_runtime_raw_blobs_and_modes(self):
        source = self.root / "fixture-source"
        _, runtime = fixture(source)
        tree = git(source, "ls-tree", "-r", "-z", runtime, "--", ".github").stdout
        entries = tree_index_entries(tree)
        check_raw_index(source, entries, scope=".github")
        target = source / ".github/assets/branding/base"
        target.write_bytes(b"altered readonly helper input")
        target.chmod(0o444)
        with self.assertRaises(ValueError):
            check_raw_index(source, entries, scope=".github")

    def test_recipe_scope_cannot_hide_vcs_or_mozconfig_additions(self):
        source = self.root / "fixture-source"
        _, runtime = fixture(source)
        entries = tree_index_entries(
            git(source, "ls-tree", "-r", "-z", runtime, "--", ".github").stdout
        )
        for name in (".git/extra-helper", ".hg/extra-helper", "mozconfig"):
            target = source / ".github" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("untracked helper")
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_raw_index(source, entries, scope=".github")
            target.unlink()
            if target.parent.name in {".git", ".hg"}:
                target.parent.rmdir()

    def test_xpcshell_api_adapter_disables_retry_and_preserves_native_exit_mapping(
        self,
    ):
        parser = argparse.ArgumentParser()
        parser.set_defaults(
            xpcshell="/explicit/helper", app_binary=None, interactive=False
        )
        observed = []
        for value, expected in ((True, 0), (False, 1), (4, 4)):
            tests = mock.Mock()
            tests.runTests.side_effect = lambda options: (
                observed.append(options.retry) or value
            )
            harness = mock.Mock(TBPL_RETRY=4)
            harness.parser_desktop.return_value = parser
            harness.XPCShellTests.return_value = tests
            with mock.patch.object(sys, "argv", ["fixture"]), mock.patch.dict(
                "os.environ", {"MOZ_AUTOMATION": "1"}
            ):
                self.assertEqual(run_xpcshell_once(harness), expected)
                harness.symbolicate_profiles.assert_called_once()
        self.assertEqual(observed, [False, False, False])


class PrivateWorkflowContracts(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / ".github/workflows/qa3-linux-debug-proof.yml").read_text()

    def test_only_private_reusable_entry_and_no_publication_gate_change(self):
        self.assertIn("workflow_call:", self.text)
        self.assertNotIn("workflow_dispatch:", self.text)
        self.assertNotIn("pull_request:", self.text)
        self.assertIn('test "$IS_PRIVATE" = true', self.text)
        self.assertNotIn("contents: write", self.text)
        self.assertNotIn("id-token: write", self.text)
        self.assertNotIn("gh release", self.text)

    def test_full_builder_source_and_cold_consumer_no_persisted_credentials(self):
        self.assertEqual(self.text.count("persist-credentials: false"), 2)
        self.assertEqual(self.text.count("fetch-depth: 0"), 1)
        self.assertEqual(self.text.count("sparse-checkout: .github"), 1)
        self.assertEqual(self.text.count("GITHUB_TOKEN: ${{ github.token }}"), 2)
        self.assertEqual(
            self.text.count("sudo -n /var/lib/qa3-tools/bin/launch-native-proof"), 2
        )

    def test_protected_tool_paths_are_exact_for_each_native_role(self):
        tool_root = "/var/lib/qa3-tools"
        self.assertNotIn("/opt/qa3", self.text)
        hash_line = (
            r"""printf '%s  %s\n' "$LAUNCHER" """
            f"{tool_root}/bin/launch-native-proof | sha256sum --check --status"
        )
        self.assertEqual(self.text.count(hash_line), 2)
        lines = self.text.splitlines()
        self.assertEqual(sum(line.strip().startswith("sudo -n ") for line in lines), 2)
        for role in ("builder", "consumer"):
            with self.subTest(role=role):
                prefix = f"sudo -n {tool_root}/bin/launch-native-proof {role} "
                starts = [
                    index
                    for index, line in enumerate(lines)
                    if line.strip().startswith(prefix)
                ]
                self.assertEqual(len(starts), 1)
                self.assertGreater(starts[0], 0)
                self.assertEqual(lines[starts[0] - 1].strip(), hash_line)
                command = []
                for line in lines[starts[0] :]:
                    command.append(line.strip().removesuffix("\\"))
                    if not line.rstrip().endswith("\\"):
                        break
                argv = shlex.split(" ".join(command))
                self.assertEqual(
                    argv[:11],
                    [
                        "sudo",
                        "-n",
                        f"{tool_root}/bin/launch-native-proof",
                        role,
                        "$GITHUB_RUN_ID",
                        "$GITHUB_RUN_ATTEMPT",
                        "--",
                        f"{tool_root}/python/bin/python3",
                        "-B",
                        "$GITHUB_WORKSPACE/runtime-recipe/.github/workflows/scripts/qa3_native_worker.py",
                        role,
                    ],
                )
                for flag, expected in (
                    ("--toolchain-lock", f"{tool_root}/{role}-toolchain-lock.json"),
                    ("--python-environment", f"{tool_root}/python-environment"),
                ):
                    self.assertEqual(argv.count(flag), 1)
                    self.assertEqual(argv[argv.index(flag) + 1], expected)

    def test_distinct_same_attempt_primary_support_and_failure_evidence(self):
        for name in (
            "qa3-primary-",
            "qa3-support-",
            "qa3-producer-evidence-",
            "qa3-consumer-evidence-",
        ):
            self.assertIn(
                name + "${{ github.run_id }}-${{ github.run_attempt }}", self.text
            )
        self.assertEqual(self.text.count("if: always()"), 2)
        self.assertIn(
            "primary-sha256: ${{ steps.primary.outputs.artifact-digest }}", self.text
        )
        self.assertIn(
            '--primary-id "$PRIMARY_ID" --primary-sha256 "$PRIMARY_SHA"', self.text
        )
        self.assertNotIn("overwrite: true", self.text)
        self.assertIn("needs: producer", self.text)
        self.assertIn("cancel-in-progress: false", self.text)


if __name__ == "__main__":
    unittest.main()
