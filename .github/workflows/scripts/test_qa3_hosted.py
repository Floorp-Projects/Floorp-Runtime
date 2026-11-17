# SPDX-License-Identifier: MPL-2.0

import ast
import contextlib
import copy
import errno
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import qa3_bootstrap_probe as bootstrap_probe
import qa3_hosted as hosted
import qa3_hosted_boundary as boundary
from qa3_build_profile import ac_options, enable_hosted_test_support, profile
from qa3_hosted_support import PLAN_PATH, extra_packaged_materials, native_schedule
from qa3_mozlog import verify_mozlog
from qa3_native_io import GIB, IOBudget, extract_archive, read_json, write_json
from qa3_native_transport import verify_artifact_metadata
from qa3_source_cohort import file_digest

SOURCE = Path(__file__).resolve().parents[3]
SHA = "a" * 40
DIGEST = "b" * 64
BOOT = "c" * 64
HOST = {
    "os": "ubuntu",
    "version": "24.04",
    "machine": "x86_64",
    "pythonABI": "cp312",
    "libc": ["glibc", "2.39"],
}
PHASES = [
    "cold-venv",
    "offline-install",
    "pip-check",
    "native-0-required",
    "native-0-assertion-canary",
    "native-1-required",
    "native-1-assertion-canary",
    "native-2-required",
    "native-3-required",
]


def loopback_network(fallbacks=False):
    links = [
        {
            "ifindex": 1,
            "ifname": "lo",
            "link_type": "loopback",
            "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "operstate": "UNKNOWN",
        }
    ]
    addresses = [
        {
            "ifindex": 1,
            "ifname": "lo",
            "link_type": "loopback",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "127.0.0.1",
                    "prefixlen": 8,
                    "scope": "host",
                },
                {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"},
            ],
        }
    ]
    if fallbacks:
        for index, (name, (kind, link_type)) in enumerate(
            boundary.FALLBACK_TUNNELS.items(), 2
        ):
            data = {"local": "any", "remote": "any", "ttl": 0}
            if name == "sit0":
                data.update(ttl=64, prefix="2002::", prefixlen=16)
            links.append({
                "ifindex": index,
                "ifname": name,
                "link_type": link_type,
                "flags": ["NOARP"],
                "operstate": "DOWN",
                "link_index": 0,
                "linkinfo": {"info_kind": kind, "info_data": data},
            })
            addresses.append({
                "ifindex": index,
                "ifname": name,
                "link_type": link_type,
                "addr_info": [],
            })
    return {
        "queryErrors": {},
        "links": links,
        "addresses": addresses,
        "ipv4Routes": [
            {
                "type": "local",
                "dst": "127.0.0.0/8",
                "dev": "lo",
                "table": "local",
                "scope": "host",
                "prefsrc": "127.0.0.1",
            },
            {
                "type": "broadcast",
                "dst": "127.255.255.255",
                "dev": "lo",
                "table": "local",
                "scope": "link",
                "prefsrc": "127.0.0.1",
            },
        ],
        "ipv6Routes": [{"type": "local", "dst": "::1", "dev": "lo", "table": "local"}],
    }


ORIGINAL_BUILD_STEP_DIGESTS = {
    "Validate build identity": "1db4d544a310a669ba8ecd55bf89e33c83a6d121ee13e12ff254b87f58490dc0",
    "Setup Node.js": "849ad66f6e99d7d823c487f689dbec3b3813e38283f197decfeb11205f87746d",
    "Checkout repository": "4aa7df71361cc2f7e93867ca8943d6e8510878717baebf483f997150a92a3d54",
    "Download macOS SDK": "0228e12ea23df96c9e7c2c259f087d3d697de6d25d4412c4190e8526fac5cb6f",
    "Setup macOS cross-compilation": "0ab58a044180bb159b0779bd6f4042b2adac69744b3a5007a21b0e92093d6f41",
    "Apply upstream patches": "294c76de999bdaffd10d47cde1756eb623f71cb297797087abd7014b8e13eeeb",
    "Setup sccache": "c0938be9679c1b22619d82963429b6baa32b12cbd35749a5432e8f65ceddee64",
    "Setup Rust toolchain": "cb02c53ff90ac371f670c905b5acd67eb6484ff64d2fb10199180da75c3da00c",
    "Allocate swap space": "05005de237107f34d0ccfcb2a6b04923560479589d65d86626293f5dad520d38",
    "Download PGO artifact": "069e23f3dd5a03d63e8747dc59c80aafbb0cd357da890068d152ba295cd5fdf6",
    "Setup floorp configuration": "595ce2e09ae1d8445abd1dadad60229545509b13ca6bc337eb374ff2b4163ae2",
    "Build and package": "84aea376e5ce3c3c4c89770eb449cdd561c44600d68c17cf61bf93f3f55b2326",
    "Verify and record compiled Runtime source": "ea2661cd2b3c1488f7514100b90540fd63c2b7d49ad2e60c482e56f95dde1e72",
    "Upload build artifact": "ebe9da54032640ac1c9574621b862c92ddc353a04c191482fcb2572e5d953f71",
    "Upload PGO profile generation package (Windows)": "26e87d3c02eadf4418f623378eb4a4978ce254f37702e5f5c95333d51d49a0b9",
    "Upload PGO profile generation package (Linux)": "344bd62536afaef56bbf506b43c27c40dfa0621e6a8aa574787d5e6f62cf9865",
    "Upload PGO profile generation package (Mac)": "cfb1dff2447d1709d23fd86332ef5496ea133c8f6bb024f01bbd14aa81c1b6d8",
    "Upload dist/host for MAR": "b0756e3841526acf4fecdaee31e865091a3a67386815275a855e11154602540c",
    "Upload application.ini for MAR": "bca285ffc9e5d815fec3c9c1921fdbe9e88cc76f120d5208a4e275a68baabf79",
}


def context():
    return {
        "schema": "qa3-hosted-context-v1",
        "profile": hosted.PROFILE,
        "executionRepository": hosted.REPOSITORY,
        "controllerHead": SHA,
        "runtimeRecipe": SHA,
        "run": 10,
        "attempt": 1,
        "buildID": "20261011000000",
        "publicationAuthorized": False,
    }


def effective():
    return {
        "schemaVersion": 1,
        "source": "/source",
        "objdir": "/source/obj",
        "substs": {
            "ENABLE_TESTS": True,
            "MOZ_DEBUG": True,
            "MOZ_AUTOMATION": True,
            "COMPILE_ENVIRONMENT": True,
            "JS_DISABLE_SHELL": None,
            "LINK_GTEST_DURING_COMPILE": True,
            "MOZ_ARTIFACT_BUILDS": False,
            "MOZ_PROFILE_GENERATE": False,
            "MOZ_PROFILE_USE": False,
            "TARGET_CPU": "x86_64",
            "OS_TARGET": "Linux",
            "target": "x86_64-pc-linux-gnu",
        },
    }


def producer():
    pin = read_json(SOURCE / ".github/runtime-upstream.json")
    identities = {
        name: {"sha256": DIGEST, "gnuBuildID": "ab", "machine": "x86_64"}
        for name in ("floorp", "libxul.so")
    }
    return {
        "schema": "qa3-hosted-debug-producer-v1",
        "status": "PACKAGED_NOT_CONSUMED",
        "context": context(),
        "producer": "existing-common-build-github-hosted",
        "consumerVerdict": "UNVERIFIED",
        "publicationAuthorized": False,
        "bootSha256": BOOT,
        "host": HOST,
        "objdir": "/source/obj",
        "effectiveConfig": effective(),
        "effectiveConfigAfterTests": effective(),
        "sourceDeltaBeforeTestsSha256": DIGEST,
        "testInstallManifest": {
            "schema": "qa3-test-install-manifest-v1",
            "verdict": "PASS_GENERATED_MANIFEST_NORMALIZATION",
            "nativeExecuted": False,
            "manifest": "/source/obj/_build_manifests/install/_test_files",
            "beforeSha256": "a" * 64,
            "afterSha256": "b" * 64,
            "expandedDirectoryCount": 1,
            "expandedFileCount": 1,
            "expandedDirectories": [{}],
        },
        "runtimeUpstream": pin,
        "sourcePolicy": read_json(SOURCE / ".github/qa/source-policy.json"),
        "compiledSource": {
            "schema_version": 1,
            "runtime_commit": SHA,
            "upstream": pin["upstream"],
            "floorp_patch": pin["floorp_patch"],
        },
        "archives": [
            {"kind": k, "bytes": 1, "sha256": DIGEST}
            for k in ("common", "mochitest", "xpcshell")
        ],
        "commands": [
            {"name": n, "exit": 0, "stop": None, "ownedCleanupComplete": True}
            for n in (
                "effective-config",
                "prepare-test-install",
                "package-tests",
                "effective-after-tests",
                "decode-common",
                "decode-mochitest",
                "decode-xpcshell",
            )
        ],
        "primaryIdentity": identities,
        "compiledIdentity": copy.deepcopy(identities),
        "compiledIdentityAfterTests": copy.deepcopy(identities),
        **{
            n: DIGEST
            for n in (
                "primarySha256",
                "supportSha256",
                "planSha256",
                "pythonEnvironmentSha256",
                "actualSourceDeltaSha256",
            )
        },
    }


class HostedEntryBudgets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def probe(self, role, mode):
        maximum, reserve = (
            (30 * GIB, 20 * GIB)
            if role == "producer"
            else (
                50 * GIB,
                10 * GIB,
            )
        )
        inputs = self.root / "inputs"
        inputs.mkdir()
        archive = inputs / "runtime.tar.xz"
        with tarfile.open(archive, "w:xz") as output:
            member = tarfile.TarInfo("fixture")
            member.size = 4
            output.addfile(member, io.BytesIO(b"data"))
        state = self.root / "state"
        source = self.root / "source"
        source.mkdir()
        args = SimpleNamespace(
            source=source,
            objdir=source / "obj",
            output=state,
            primary=inputs,
            build_id=context()["buildID"],
        )
        value = producer()
        value["primarySha256"] = file_digest(archive)
        (inputs / "test-support.tar.gz").write_bytes(b"synthetic support")
        value["supportSha256"] = file_digest(inputs / "test-support.tar.gz")
        write_json(inputs / "producer.json", value)
        budgets = []

        class ProbeComplete(Exception):
            pass

        def extract(path, destination, *, budget, expansion):
            self.assertIsInstance(budget, IOBudget)
            self.assertEqual(budget.root, state)
            self.assertEqual(budget.maximum, maximum)
            self.assertEqual(budget.minimum_free, reserve)
            budgets.append(budget)
            if mode == "cumulative":
                budget.used = maximum
            extract_archive(path, destination, budget=budget, expansion=expansion)
            self.assertEqual((destination / "fixture").read_bytes(), b"data")
            raise ProbeComplete

        def command(argv, cwd, env, logs, name, timeout, **kwargs):
            self.assertEqual(name, "effective-config")
            config = effective()
            config.update(source=str(source), objdir=str(args.objdir))
            write_json(state / "effective-config.json", config)
            return {"name": name, "exit": 0}

        expected = ProbeComplete if mode == "available" else ValueError
        message = {
            "available": "",
            "reserve": "native I/O would consume reserved free space",
            "cumulative": "cumulative staging byte budget exceeded",
        }[mode]
        free = reserve if mode == "reserve" else 100 * GIB
        with mock.patch.dict(
            os.environ, {"HOME": str(self.root), "PATH": os.defpath}, clear=True
        ), mock.patch.object(
            hosted, "context_from_environment", return_value=context()
        ), mock.patch.object(
            hosted, "raw_git", return_value=(SHA + "\n").encode()
        ), mock.patch.object(
            hosted, "host_identity", return_value=HOST
        ), mock.patch.object(
            hosted, "worker_boot_identity", return_value="d" * 64
        ), mock.patch.object(hosted.os, "geteuid", return_value=1001), mock.patch(
            "qa3_native_io.shutil.disk_usage", return_value=SimpleNamespace(free=free)
        ), mock.patch.object(
            hosted, "run_owned", side_effect=command
        ) as commands, mock.patch.object(
            hosted, "extract_archive", side_effect=extract
        ) as extracts, self.assertRaisesRegex(expected, message):
            if role == "producer":
                hosted.produce(args)
            else:
                hosted.consume(inputs, state, SOURCE, context())
        self.assertEqual(commands.call_count, 1 if role == "producer" else 0)
        self.assertEqual(extracts.call_count, 1)
        self.assertEqual(len(budgets), 1)
        self.assertEqual(
            budgets[0].used,
            maximum if mode == "cumulative" else 4 if mode == "available" else 0,
        )

    def test_producer_entry_extracts_with_bounded_real_io(self):
        self.probe("producer", "available")

    def test_producer_entry_rejects_reserved_space_exhaustion(self):
        self.probe("producer", "reserve")

    def test_producer_entry_rejects_cumulative_staging_overflow(self):
        self.probe("producer", "cumulative")

    def test_consumer_entry_extracts_with_bounded_real_io(self):
        self.probe("consumer", "available")

    def test_consumer_entry_rejects_reserved_space_exhaustion(self):
        self.probe("consumer", "reserve")

    def test_consumer_entry_rejects_cumulative_staging_overflow(self):
        self.probe("consumer", "cumulative")


class HostedSourceStamping(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        hosted.raw_git(self.source, "init", "-q", "--initial-branch=qa3")
        hosted.raw_git(
            self.source,
            "-c",
            "user.name=QA3 fixture",
            "-c",
            "user.email=qa3@example.invalid",
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "-q",
            "-m",
            "QA3 source fixture",
        )
        self.sha = hosted.raw_git(self.source, "rev-parse", "HEAD").decode().strip()
        self.value = context()
        self.value.update(controllerHead=self.sha, runtimeRecipe=self.sha)
        self.event = self.root / "event.json"
        self.event.write_text(json.dumps({"created": True, "deleted": False}))
        self.github_env = self.root / "github-env"
        self.github_env.write_text("EXISTING=value\n")
        self.environment = {
            "HOME": str(self.root),
            "PATH": os.defpath,
            "GITHUB_WORKSPACE": str(self.source),
            "GITHUB_REPOSITORY": hosted.REPOSITORY,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + hosted.BRANCH,
            "GITHUB_SHA": self.sha,
            "GITHUB_WORKFLOW_SHA": self.sha,
            "GITHUB_WORKFLOW_REF": hosted.REPOSITORY
            + "/"
            + hosted.WORKFLOW
            + "@refs/heads/"
            + hosted.BRANCH,
            "GITHUB_RUN_ID": "10",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_PATH": str(self.event),
            "GITHUB_ENV": str(self.github_env),
            "QA3_PLATFORM": "linux",
            "QA3_ARCH": "x86_64",
            "QA3_DEBUG": "true",
            "QA3_PGO": "false",
            "QA3_PGO_MODE": "",
            "QA3_BUILD_ID": self.value["buildID"],
        }

    def workflow_entry(self, overrides=None):
        workflow = (SOURCE / ".github/workflows/common-build.yml").read_text()
        step = workflow.split("      - name: Validate opt-in Debug test route\n", 1)[1]
        step = step.split("\n      - name:", 1)[0]
        code = step.split("python3.12 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        code = "\n".join(line[10:] for line in code.splitlines())
        with mock.patch.dict(
            os.environ, {**self.environment, **(overrides or {})}, clear=True
        ):
            exec(
                compile(code, "common-build:Validate opt-in Debug test route", "exec"),
                {},
            )

    def test_workflow_emits_full_verified_checkout_and_canonical_repository(self):
        self.workflow_entry()
        self.assertEqual(
            self.github_env.read_text(),
            "EXISTING=value\nMOZ_SOURCE_REPO=https://github.com/"
            + hosted.REPOSITORY
            + "\nMOZ_SOURCE_CHANGESET="
            + self.sha
            + "\nMH_BRANCH="
            + hosted.BRANCH
            + "\nMOZ_AUTOMATION=1\nMOZ_OBJDIR="
            + str(self.source / "obj-x86_64-pc-linux-gnu")
            + "\nUPLOAD_DIR="
            + str(self.source / "obj-x86_64-pc-linux-gnu" / "qa3-artifact-metrics")
            + "\nMACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE=pip\n"
            + "TASKCLUSTER_ROOT_URL=https://firefox-ci-tc.services.mozilla.com\n"
            + "MOZ_SCM_LEVEL=3\n"
            + "".join(
                "MOZ_AUTOMATION_" + name + "=0\n" for name in hosted.AUTOMATION_PHASES
            ),
        )

    def test_foreign_checkout_cannot_emit_configure_source_identity(self):
        with self.assertRaisesRegex(ValueError, "checkout differs from original R"):
            self.workflow_entry({"GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA})
        self.assertEqual(self.github_env.read_text(), "EXISTING=value\n")

    def test_conflicting_inherited_stamp_is_rejected_before_environment_write(self):
        for key, value in (
            ("MOZ_SOURCE_REPO", "https://example.invalid/foreign"),
            ("MOZ_SOURCE_CHANGESET", self.sha[:12]),
            ("MH_BRANCH", "foreign-build-tree"),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "conflicting inherited source identity"
            ):
                self.workflow_entry({key: value})
            self.assertEqual(self.github_env.read_text(), "EXISTING=value\n")

    def test_matching_inherited_source_identity_is_preserved(self):
        self.workflow_entry({
            "MOZ_SOURCE_REPO": "https://github.com/" + hosted.REPOSITORY,
            "MOZ_SOURCE_CHANGESET": self.sha,
            "MH_BRANCH": hosted.BRANCH,
        })
        self.assertIn(
            "MOZ_SOURCE_CHANGESET=" + self.sha + "\n", self.github_env.read_text()
        )

    def test_packaging_tree_identity_is_never_inherited_by_native_child(self):
        with mock.patch.dict(os.environ, {"MH_BRANCH": hosted.BRANCH}, clear=True):
            native = hosted.child_environment(self.source)
        self.assertNotIn("MH_BRANCH", native)

    def test_producer_command_keeps_source_identity_without_controller_secret(self):
        class ProbeComplete(Exception):
            pass

        def command(argv, cwd, env, logs, name, timeout, **kwargs):
            self.assertEqual(name, "effective-config")
            self.assertEqual(
                env["MOZ_SOURCE_REPO"], "https://github.com/" + hosted.REPOSITORY
            )
            self.assertEqual(env["MOZ_SOURCE_CHANGESET"], self.sha)
            self.assertEqual(env["MH_BRANCH"], hosted.BRANCH)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertEqual(env["MOZ_BUILD_DATE"], self.value["buildID"])
            raise ProbeComplete

        args = SimpleNamespace(
            source=self.source,
            objdir=self.source / "obj",
            output=self.root / "output",
            primary=self.root / "primary",
            build_id=self.value["buildID"],
        )
        with mock.patch.dict(
            os.environ,
            {**self.environment, "GITHUB_TOKEN": "synthetic-secret"},
            clear=True,
        ), mock.patch.object(
            hosted, "context_from_environment", return_value=self.value
        ), mock.patch.object(hosted, "host_identity", return_value=HOST), mock.patch(
            "qa3_native_io.shutil.disk_usage",
            return_value=SimpleNamespace(free=100 * GIB),
        ), mock.patch.object(
            hosted, "run_owned", side_effect=command
        ), self.assertRaises(ProbeComplete):
            hosted.produce(args)

    def test_primary_rejects_missing_abbreviated_or_foreign_stamp_in_each_ini(self):
        app = self.root / "primary" / "floorp"
        app.mkdir(parents=True)

        def ini(path, section, stamp):
            text = "[" + section + "]\nBuildID=" + self.value["buildID"] + "\n"
            if stamp is not None:
                text += "SourceStamp=" + stamp + "\n"
            path.write_text(text)

        with mock.patch(
            "qa3_hosted_support.elf_identity", return_value={"fixture": True}
        ):
            for name, section in (
                ("application.ini", "App"),
                ("platform.ini", "Build"),
            ):
                ini(app / name, section, self.sha)
            hosted.verify_primary(app.parent, self.value)
            for name, section in (
                ("application.ini", "App"),
                ("platform.ini", "Build"),
            ):
                for stamp in (None, self.sha[:12], SHA):
                    with self.subTest(name=name, stamp=stamp), self.assertRaisesRegex(
                        ValueError, "packaged source stamp differs from Runtime recipe"
                    ):
                        ini(app / name, section, stamp)
                        hosted.verify_primary(app.parent, self.value)
                    ini(app / name, section, self.sha)


class HostedContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.event = self.root / "event.json"
        self.event.write_text(json.dumps({"created": True, "deleted": False}))
        self.environment = {
            "GITHUB_REPOSITORY": hosted.REPOSITORY,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + hosted.BRANCH,
            "GITHUB_SHA": SHA,
            "GITHUB_WORKFLOW_SHA": SHA,
            "GITHUB_WORKFLOW_REF": hosted.REPOSITORY
            + "/"
            + hosted.WORKFLOW
            + "@refs/heads/"
            + hosted.BRANCH,
            "GITHUB_RUN_ID": "10",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_PATH": str(self.event),
        }

    def validate(self, value):
        with mock.patch.object(
            hosted, "host_identity", return_value=HOST
        ), mock.patch.object(hosted, "worker_boot_identity", return_value="d" * 64):
            return hosted.validate_producer(value, context())

    def test_original_context(self):
        with mock.patch.dict(os.environ, self.environment, clear=True):
            self.assertEqual(
                hosted.context_from_environment(context()["buildID"]), context()
            )

    def test_foreign_run_source_workflow_attempt_fail_closed(self):
        for key, value in {
            "GITHUB_REPOSITORY": "fork/runtime",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/heads/nora-0.2.0",
            "GITHUB_WORKFLOW_SHA": "e" * 40,
            "GITHUB_WORKFLOW_REF": "foreign",
            "GITHUB_RUN_ID": "0",
            "GITHUB_RUN_ATTEMPT": "2",
        }.items():
            with self.subTest(key=key), mock.patch.dict(
                os.environ, {**self.environment, key: value}, clear=True
            ):
                with self.assertRaises(ValueError):
                    hosted.context_from_environment(context()["buildID"])

    def test_branch_update_and_deletion_are_not_admitted(self):
        for event in (
            {"created": False, "deleted": False},
            {"created": True, "deleted": True},
            {},
        ):
            self.event.write_text(json.dumps(event))
            with self.subTest(event=event), mock.patch.dict(
                os.environ, self.environment, clear=True
            ):
                with self.assertRaises(ValueError):
                    hosted.context_from_environment(context()["buildID"])

    def test_context_has_typed_attempt_and_no_publication(self):
        for key, change in (
            ("run", True),
            ("attempt", True),
            ("attempt", 2),
            ("publicationAuthorized", True),
            ("runtimeRecipe", "e" * 40),
        ):
            value = {**context(), key: change}
            with self.subTest(key=key, change=change), self.assertRaises(ValueError):
                hosted.validate_context(value)

    def test_canonical_debug_only(self):
        hosted.validate_mode("linux", "x86_64", True, False)
        for args in (
            ("linux", "aarch64", True, False, ""),
            ("mac", "x86_64", True, False, ""),
            ("linux", "x86_64", False, False, ""),
            ("linux", "x86_64", True, True, ""),
            ("linux", "x86_64", True, False, "use"),
            ("linux", "x86_64", 1, 0, ""),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                hosted.validate_mode(*args)

    def test_effective_debug_tests_required(self):
        hosted.validate_effective(effective(), Path("/source"), Path("/source/obj"))
        for flag in ("ENABLE_TESTS", "MOZ_DEBUG"):
            value = effective()
            value["substs"][flag] = False
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                hosted.validate_effective(value, Path("/source"), Path("/source/obj"))

    def test_effective_pgo_and_artifact_forbidden(self):
        for flag in ("MOZ_PROFILE_USE", "MOZ_PROFILE_GENERATE", "MOZ_ARTIFACT_BUILDS"):
            value = effective()
            value["substs"][flag] = True
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                hosted.validate_effective(value, Path("/source"), Path("/source/obj"))

    def test_effective_objdir_source_target_must_match(self):
        for key in ("source", "objdir"):
            value = {**effective(), key: "/other"}
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.validate_effective(value, Path("/source"), Path("/source/obj"))
        value = effective()
        value["substs"]["TARGET_CPU"] = "aarch64"
        with self.assertRaises(ValueError):
            hosted.validate_effective(value, Path("/source"), Path("/source/obj"))

    def test_producer_preserves_existing_mach_state_and_build_id(self):
        with mock.patch.dict(
            os.environ,
            {"HOME": str(self.root), "MOZBUILD_STATE_PATH": "/existing/state"},
            clear=True,
        ):
            value = hosted.producer_environment(
                self.root, self.root / "obj", context()["buildID"]
            )
        self.assertEqual(value["MOZBUILD_STATE_PATH"], "/existing/state")
        self.assertEqual(value["HOME"], str(self.root))
        self.assertEqual(value["MOZ_BUILD_DATE"], context()["buildID"])

    def test_valid_packaging_is_not_consumer_or_product_pass(self):
        self.assertEqual(self.validate(producer())["consumerVerdict"], "UNVERIFIED")

    def test_missing_failing_retried_producer_phase_rejected(self):
        for change in (
            "missing",
            "retry",
            "exit",
            "stop",
            "cleanup",
            "boolean",
            "cancelled",
        ):
            value = producer()
            if change == "missing":
                value["commands"].pop()
            elif change == "retry":
                value["commands"].append(value["commands"][-1])
            else:
                key, item = {
                    "exit": ("exit", 1),
                    "stop": ("stop", "TIMEOUT"),
                    "cleanup": ("ownedCleanupComplete", False),
                    "boolean": ("exit", False),
                    "cancelled": ("cancelled", True),
                }[change]
                value["commands"][1][key] = item
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_missing_test_archive_rejected(self):
        value = producer()
        value["archives"].pop()
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_distribution_source_pin_must_match(self):
        for field in ("upstream", "floorp_patch", "runtime_commit"):
            value = producer()
            value["compiledSource"][field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_packaged_binary_must_match_compiled_build_id(self):
        value = producer()
        value["compiledIdentity"]["floorp"]["gnuBuildID"] = "ef"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_same_boot_is_not_cold_proof(self):
        value = producer()
        value["bootSha256"] = "d" * 64
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_wrong_os_python_abi_rejected(self):
        for field, change in (
            ("version", "22.04"),
            ("machine", "aarch64"),
            ("pythonABI", "cp313"),
        ):
            value = producer()
            value["host"] = {**HOST, field: change}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_exact_same_run_artifact_metadata(self):
        meta = {
            "id": 12,
            "name": "qa3-support-10-1",
            "expired": False,
            "digest": "sha256:" + DIGEST,
            "size_in_bytes": 1,
            "workflow_run": {"id": 10, "head_sha": SHA},
        }
        self.assertEqual(
            verify_artifact_metadata(meta, context(), 12, "support", DIGEST), 1
        )
        for key, value in (
            ("expired", True),
            ("name", "qa3-support-10-2"),
            ("id", 13),
            ("digest", "sha256:" + "e" * 64),
            ("workflow_run", {"id": 11, "head_sha": SHA}),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_artifact_metadata(
                    {**meta, key: value}, context(), 12, "support", DIGEST
                )

    def test_acquire_uses_pr84_transport_and_original_run_creation(self):
        class TransferReached(Exception):
            pass

        # Preserve the shared function signature available in PR84, before QA334.
        def original_transport(
            ctx, artifact_id, kind, digest, destination, opener=None, budget=None
        ):
            self.assertEqual(ctx, context())
            self.assertEqual((artifact_id, kind, digest), (12, "support", DIGEST))
            raise TransferReached

        payload = {
            "id": 10,
            "head_sha": SHA,
            "run_attempt": 1,
            "event": "push",
            "path": hosted.WORKFLOW,
            "head_branch": hosted.BRANCH,
            "created_at": "2026-10-11T00:00:00Z",
        }
        args = SimpleNamespace(
            build_id=context()["buildID"],
            artifact_id=12,
            artifact_sha256=DIGEST,
            output=self.root / "download",
            recipe=SOURCE,
        )
        for changes in (
            {},
            {"run_attempt": 2},
            {"head_sha": "e" * 40},
            {"created_at": "2026-10-11T00:00:01Z"},
        ):
            with self.subTest(changes=changes), mock.patch.dict(
                os.environ, {**self.environment, "GITHUB_TOKEN": "fixture"}, clear=True
            ), mock.patch.object(
                hosted, "fetch_actions_run", return_value={**payload, **changes}
            ), mock.patch.object(
                hosted, "download_artifact", side_effect=original_transport
            ) as transfer:
                with self.assertRaises(ValueError if changes else TransferReached):
                    hosted.acquire(args)
                self.assertEqual(transfer.call_count, 0 if changes else 1)

    def test_seed_and_wheel_lock_are_exact_and_offline(self):
        lock = read_json(SOURCE / ".github/qa/hosted-consumer-python.lock.json")
        seed = SOURCE / ".github/qa/hosted-consumer-seed.zip"
        self.assertEqual(file_digest(seed), hosted.SEED_SHA)
        self.assertEqual(lock["readiness"], "INPUTS_LOCKED_NOT_TARGET_QUALIFIED")
        self.assertIs(lock["publicationAuthorized"], False)
        self.assertEqual(len(lock["wheels"]), 40)
        with zipfile.ZipFile(seed) as archive:
            raw = archive.read("profiles/consumer/requirements.lock")
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(), lock["requirementsSha256"]
            )
            hashes = set(re.findall(r"sha256:([a-f0-9]{64})", raw.decode()))
            self.assertEqual(hashes, {r["sha256"] for r in lock["wheels"]})
            for row in lock["wheels"]:
                if row["source"].startswith("source-wheels/"):
                    data = archive.read(row["source"])
                    self.assertEqual(len(data), row["bytes"])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
                else:
                    self.assertTrue(
                        row["url"].startswith("https://files.pythonhosted.org/")
                    )

    def test_service_has_no_controller_env_network_or_privileges(self):
        argv = boundary.service_command({
            "root": "/var/lib/test",
            "state": "/var/lib/test/state",
            "unit": "qa3.service",
            "controllerPaths": [
                "/home/runner/work/runtime",
                "/home/runner/work/_temp/qa3",
            ],
            "uid": 900,
            "gid": 900,
        })
        for value in (
            "--property=PrivateNetwork=yes",
            "--property=NoNewPrivileges=yes",
            "--property=ProtectHome=yes",
            "--property=ProtectProc=invisible",
            "--property=CapabilityBoundingSet=",
            "--property=KillMode=control-group",
            "--property=MemoryMax=" + str(14 * GIB),
            "--property=MemorySwapMax=0",
            "--property=TasksMax=512",
            "--property=CPUQuota=400%",
            "--property=RuntimeMaxSec=1500s",
            "-i",
        ):
            self.assertIn(value, argv)
        self.assertFalse(any("GITHUB" in a or "TOKEN" in a for a in argv))
        self.assertIn("--property=UMask=0077", argv)

    def test_staged_module_import_closure_is_complete(self):
        copied = {Path(n).stem for n in boundary.FILES}
        for name in boundary.FILES:
            tree = ast.parse((SOURCE / ".github/workflows/scripts" / name).read_text())
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith(("qa3_", "runtime_build"))
                ):
                    self.assertIn(node.module, copied)

    def test_existing_build_steps_and_default_route_are_preserved(self):
        current = (SOURCE / ".github/workflows/common-build.yml").read_text()
        current = current.replace(
            "          retention-days: ${{ inputs.qa3-debug-tests && !inputs.native-debug-artifacts && 1 || 0 }}\n", ""
        )

        def steps(text):
            return {
                part.splitlines()[0].strip(): part
                for part in text.split("      - name: ")[1:]
            }

        before = ORIGINAL_BUILD_STEP_DIGESTS
        after = steps(current.split("\n  qa3-consumer:")[0])
        for name, original in before.items():
            # New opt-in steps are inserted only between the original steps.
            self.assertEqual(
                hashlib.sha256(after[name].rstrip().encode()).hexdigest(),
                original,
                name,
            )
        self.assertIn(
            "inputs.qa3-debug-tests && 'ubuntu-24.04' || 'ubuntu-latest'", current
        )
        self.assertIn("qa3-debug-tests:", current)
        caller = (SOURCE / ".github/workflows/qa3-hosted-linux-debug.yml").read_text()
        self.assertNotIn("workflow_dispatch", caller)
        self.assertNotIn("secrets:", caller)
        self.assertIn("event.get('created') is not True", caller)
        self.assertNotIn("github.run_attempt == 1", caller)


class HostedBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_root_git_uses_exact_safe_directory_and_no_replacements(self):
        with mock.patch.object(
            hosted.subprocess, "check_output", return_value=b"original"
        ) as call:
            hosted.raw_git(self.root, "cat-file", "blob", SHA + ":script.py")
        self.assertIn(
            "safe.directory=" + str(self.root.resolve()), call.call_args.args[0]
        )
        env = call.call_args.kwargs["env"]
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")

    def test_rerun_or_updated_branch_is_failed_instead_of_all_jobs_skipped(self):
        text = (SOURCE / ".github/workflows/qa3-hosted-linux-debug.yml").read_text()
        start = text.index("          import json, os\n")
        end = text.index("          PY\n", start)
        code = "\n".join(line[10:] for line in text[start:end].splitlines())
        event = self.root / "event.json"
        for created, deleted, attempt in (
            (True, False, "1"),
            (False, False, "1"),
            (True, True, "1"),
            (True, False, "2"),
        ):
            event.write_text(json.dumps({"created": created, "deleted": deleted}))
            with self.subTest(
                created=created, deleted=deleted, attempt=attempt
            ), mock.patch.dict(
                os.environ,
                {"GITHUB_EVENT_PATH": str(event), "GITHUB_RUN_ATTEMPT": attempt},
                clear=True,
            ):
                if created and not deleted and attempt == "1":
                    exec(compile(code, "<controller-gate>", "exec"), {})
                else:
                    with self.assertRaises(ValueError):
                        exec(compile(code, "<controller-gate>", "exec"), {})

    def test_early_acquisition_failure_still_exports_incomplete_receipt(self):
        destination = self.root / "evidence"
        with mock.patch.object(
            boundary, "ROOT", self.root / "missing"
        ), mock.patch.object(
            boundary, "context_from_environment", return_value=context()
        ), mock.patch.object(
            boundary, "protected", side_effect=FileNotFoundError
        ), mock.patch.dict(
            os.environ,
            {"QA3_ACQUIRE_OUTCOME": "failure", "QA3_LAUNCH_OUTCOME": "skipped"},
            clear=True,
        ), mock.patch.object(
            boundary.sys,
            "argv",
            [
                "collect",
                "collect",
                "--output",
                str(destination),
                "--build-id",
                context()["buildID"],
            ],
        ):
            with self.assertRaises(FileNotFoundError):
                boundary.main()
        self.assertEqual(
            read_json(destination / "collection.json")["acquireOutcome"], "failure"
        )
        result = read_json(destination / "collection-result.json")
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIs(result["publicationAuthorized"], False)

    def test_late_original_step_failure_cannot_emit_pass_verdict(self):
        root = self.root / "native/10-1"
        (root / "evidence").mkdir(parents=True)
        write_json(
            root / "evidence/final.json",
            {
                "schema": "qa3-hosted-root-supervision-v1",
                "context": context(),
                "status": "PASS",
                "reason": None,
                "scopeEmpty": True,
                "serviceExit": 0,
                "publicationAuthorized": False,
                "export": [],
            },
        )
        output = self.root / "github-output"
        output.write_bytes(b"")
        destination = self.root / "evidence"
        from types import SimpleNamespace

        with mock.patch.object(boundary, "ROOT", root.parent), mock.patch.object(
            boundary, "context_from_environment", return_value=context()
        ), mock.patch.object(
            boundary, "protected", side_effect=lambda p: p
        ), mock.patch.dict(
            os.environ,
            {
                "QA3_LAUNCH_OUTCOME": "failure",
                "QA3_ACQUIRE_OUTCOME": "success",
                "GITHUB_OUTPUT": str(output),
            },
            clear=True,
        ):
            with self.assertRaises(ValueError):
                boundary.collect(
                    SimpleNamespace(output=destination, build_id=context()["buildID"])
                )
        self.assertEqual(output.read_bytes(), b"")

    def test_root_entry_seals_every_module_before_import(self):
        text = (SOURCE / ".github/workflows/common-build.yml").read_text()
        start = text.index("          import os, re, stat, subprocess, sys\n")
        end = text.index("          PY\n", start)
        code = "\n".join(line[10:] for line in text[start:end].splitlines())
        tree = ast.parse(code)
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        modules.update(
            a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
        )
        self.assertFalse(any(name.startswith("qa3_") for name in modules))
        names = next(
            n.value
            for n in tree.body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "names" for t in n.targets)
        )
        self.assertEqual(ast.literal_eval(names), boundary.FILES)
        self.assertIn("GIT_NO_REPLACE_OBJECTS", code)
        self.assertLess(code.index("raw !="), code.index("os.execve"))
        self.assertIn("sudo -n /usr/bin/python3.12 -I -", text)

    def test_dedicated_inputs_do_not_inherit_private_parent_mode(self):
        source = self.root / "controller"
        source.mkdir(mode=0o700)
        (source / "payload").write_bytes(b"original")
        destination = self.root / "native-inputs"
        previous = os.umask(0o077)
        try:
            boundary.stage_inputs(source, destination)
        finally:
            os.umask(previous)
        self.assertEqual(source.stat().st_mode & 0o777, 0o700)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o555)
        self.assertEqual((destination / "payload").stat().st_mode & 0o777, 0o444)
        destination.chmod(0o700)

    def test_controller_symlink_is_not_staged(self):
        source = self.root / "controller"
        source.mkdir()
        (source / "payload").symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            boundary.stage_inputs(source, self.root / "copy")

    def test_compiled_symlink_is_limited_to_same_objdir(self):
        from qa3_hosted_support import verify_primary

        objdir = self.root / "obj"
        app = objdir / "dist/bin"
        app.mkdir(parents=True)
        for name in ("floorp", "libxul.so"):
            (objdir / name).write_bytes(b"compiled")
            (app / name).symlink_to(objdir / name)
        for name, section in (("application.ini", "App"), ("platform.ini", "Build")):
            (app / name).write_text(
                "["
                + section
                + "]\nBuildID="
                + context()["buildID"]
                + "\nSourceStamp="
                + SHA
                + "\n"
            )
        with mock.patch(
            "qa3_hosted_support.elf_identity", side_effect=lambda p: {"path": str(p)}
        ) as call:
            result = verify_primary(objdir, context(), app=app, object_root=objdir)
        self.assertEqual(result["floorp"]["path"], str(objdir / "floorp"))
        self.assertEqual(call.call_count, 2)

    def test_compiled_symlink_escape_rejected(self):
        from qa3_hosted_support import verify_primary

        objdir = self.root / "obj"
        app = objdir / "dist/bin"
        app.mkdir(parents=True)
        (self.root / "outside").write_bytes(b"foreign")
        (app / "floorp").symlink_to(self.root / "outside")
        with self.assertRaises(ValueError):
            verify_primary(objdir, context(), app=app, object_root=objdir)

    def wrapper(self, extra=None):
        archive = self.root / "artifact.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for name in sorted(hosted.WRAPPER_FILES):
                output.writestr(name, b"x")
            if extra:
                output.writestr(extra, b"outside")
        destination = self.root / "expanded"
        destination.mkdir()
        return archive, destination

    def test_exact_three_member_wrapper(self):
        archive, destination = self.wrapper()
        hosted.unpack_wrapper(archive, destination)
        self.assertEqual({p.name for p in destination.iterdir()}, hosted.WRAPPER_FILES)

    def test_wrapper_traversal_or_extra_member_rejected(self):
        archive, destination = self.wrapper("../outside")
        with self.assertRaises(ValueError):
            hosted.unpack_wrapper(archive, destination)
        self.assertFalse((self.root / "outside").exists())

    def test_wrapper_declared_expansion_budget_is_enforced(self):
        archive, destination = self.wrapper()
        with mock.patch.object(hosted, "MAX_TRANSFER", 2), self.assertRaises(
            ValueError
        ):
            hosted.unpack_wrapper(archive, destination)

    def test_wrapper_special_member_rejected(self):
        archive = self.root / "special.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for name in hosted.WRAPPER_FILES:
                info = zipfile.ZipInfo(name)
                info.external_attr = 0o120777 << 16
                output.writestr(info, b"target")
        destination = self.root / "expanded"
        destination.mkdir()
        with self.assertRaises(ValueError):
            hosted.unpack_wrapper(archive, destination)

    def test_ignored_namespace_property_fails_closed(self):
        spec = {
            "uid": 900,
            "gid": 900,
            "controllerNamespaces": {"mnt": "same", "net": "same", "user": "same"},
        }
        with mock.patch.object(
            boundary.os, "getuid", return_value=900
        ), mock.patch.object(
            boundary.os, "getgid", return_value=900
        ), mock.patch.object(
            boundary.os, "geteuid", return_value=900
        ), mock.patch.object(
            boundary.os, "getegid", return_value=900
        ), mock.patch.object(
            Path,
            "read_text",
            return_value="NoNewPrivs:\t1\nCapEff:\t0000000000000000\n",
        ), mock.patch.object(
            boundary.os, "readlink", return_value="same"
        ), self.assertRaisesRegex(ValueError, "namespace was not isolated"):
            boundary.verify_worker(spec)

    def worker_verification(self, *, visible=False, interfaces=None, readable=None):
        network = loopback_network()
        spec = {
            "uid": 900,
            "gid": 901,
            "unit": "qa3-fixture.service",
            "controllerPID": 1234,
            "controllerPaths": ["/controller/recipe", "/controller/download"],
            "controllerNamespaces": {
                name: "controller-" + name for name in ("mnt", "net", "user")
            },
        }
        proc = {
            "/proc/self/status": "NoNewPrivs:\t1\nCapEff:\t0000000000000000\n",
            "/proc/self/cgroup": "0::/system.slice/qa3-fixture.service\n",
            "/proc/self/uid_map": "0 0 1\n900 900 1\n",
            "/proc/self/gid_map": "0 0 1\n901 901 1\n",
            "/proc/self/mountinfo": (
                "1 2 0:3 / /proc rw,nosuid,nodev,noexec - proc proc "
                "rw,hidepid=invisible\n"
            ),
        }
        group = "/sys/fs/cgroup/system.slice/qa3-fixture.service/"
        for name, value in (
            ("memory.max", str(14 * GIB)),
            ("memory.swap.max", "0"),
            ("pids.max", "512"),
            ("cpu.max", "400000 100000"),
            ("memory.events", "oom 0\noom_kill 0\n"),
        ):
            proc[group + name] = value
        mocks = [
            mock.patch.object(boundary.os, "getuid", return_value=900),
            mock.patch.object(boundary.os, "geteuid", return_value=900),
            mock.patch.object(boundary.os, "getgid", return_value=901),
            mock.patch.object(boundary.os, "getegid", return_value=901),
            mock.patch.object(
                boundary.os, "readlink", side_effect=lambda path: "worker-" + path[-3:]
            ),
            mock.patch.object(
                boundary.socket,
                "if_nameindex",
                return_value=[(1, "lo")] if interfaces is None else interfaces,
            ),
            mock.patch.object(
                boundary,
                "capture_ip",
                side_effect=lambda arguments, maximum: json.dumps(
                    network[
                        {
                            "-d": "links",
                            "addr": "addresses",
                            "-4": "ipv4Routes",
                            "-6": "ipv6Routes",
                        }[arguments[0]]
                    ]
                ).encode(),
            ),
            mock.patch.object(
                Path,
                "read_text",
                side_effect=lambda path, **kwargs: proc[str(path)],
                autospec=True,
            ),
            mock.patch.object(Path, "exists", return_value=visible),
            mock.patch.object(
                Path, "open", side_effect=FileNotFoundError(errno.ENOENT, "hidden")
            ),
            mock.patch.object(
                boundary.os, "access", side_effect=lambda path, mode: path == readable
            ),
        ]
        return spec, proc, mocks

    def test_worker_visibility_failure_reports_each_original_predicate(self):
        for arguments, condition, message in (
            ({"visible": True}, "controllerProcessHidden", "process remains visible"),
            (
                {"interfaces": [(1, "lo"), (2, "eth0")]},
                "loopbackOnly",
                "network is not loopback-only",
            ),
            (
                {"readable": "/controller/download"},
                "controllerInputsUnreadable",
                "inputs remain readable",
            ),
        ):
            spec, proc, mocks = self.worker_verification(**arguments)
            with self.subTest(condition=condition), contextlib.ExitStack() as stack:
                for patch in mocks:
                    stack.enter_context(patch)
                printer = stack.enter_context(mock.patch("builtins.print"))
                with self.assertRaisesRegex(ValueError, message):
                    boundary.verify_worker(spec)
                observations = [
                    json.loads(call.args[0]) for call in printer.call_args_list
                ]
                visibility = next(
                    value
                    for value in observations
                    if value["schema"] == "qa3-worker-visibility-v1"
                )
                self.assertIs(visibility["checks"][condition], False)
                self.assertIn("procMounts", visibility)
                self.assertIn("uidMap", visibility)
                self.assertIn("cgroup", visibility)
                self.assertNotIn("nativeProductExecuted", visibility)

    def test_worker_requires_effective_native_account_and_preserves_cgroup_limits(self):
        spec, proc, mocks = self.worker_verification()
        with contextlib.ExitStack() as stack:
            for patch in mocks:
                stack.enter_context(patch)
            stack.enter_context(mock.patch("builtins.print"))
            observed = boundary.verify_worker(spec)
            self.assertEqual(observed["limits"]["memory.max"], str(14 * GIB))
            with mock.patch.object(boundary.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "wrong native account"):
                    boundary.verify_worker(spec)
            key = "/sys/fs/cgroup/system.slice/qa3-fixture.service/cpu.max"
            proc[key] = "max 100000"
            with self.assertRaisesRegex(ValueError, "consumer limits differ"):
                boundary.verify_worker(spec)

    def test_boundary_probe_has_same_policy_and_distinct_worker_operation(self):
        spec = {
            "root": "/var/lib/qa3-hosted-boundary-probe/fixture",
            "state": "/var/lib/qa3-hosted-boundary-probe/fixture/state",
            "unit": "qa3-fixture.service",
            "uid": 900,
            "gid": 901,
            "account": "qa3-boundary-probe",
            "controllerPaths": ["/controller/recipe"],
        }
        native = boundary.service_command(spec)
        probe = boundary.service_command(spec, "probe-worker")
        self.assertEqual(
            [arg for arg in native if arg != "worker"],
            [arg for arg in probe if arg != "probe-worker"],
        )
        self.assertIn("--property=PrivateNetwork=yes", probe)
        self.assertIn("--property=ProtectProc=invisible", probe)
        self.assertIn("USER=qa3-boundary-probe", probe)

    def test_boundary_probe_build_prerequisite_raw_recipe_and_artifact_bounds(self):
        workflow = (SOURCE / ".github/workflows/qa3-hosted-linux-debug.yml").read_text()
        preflight = workflow.split("  boundary-preflight:\n", 1)[1].split(
            "  runtime:\n", 1
        )[0]
        self.assertIn("needs: contracts", preflight)
        self.assertIn("runs-on: blacksmith-8vcpu-ubuntu-2404", preflight)
        self.assertIn("timeout-minutes: 5", preflight)
        self.assertIn("ref: ${{ github.sha }}", preflight)
        self.assertIn("persist-credentials: false", preflight)
        self.assertIn("GIT_NO_LAZY_FETCH", preflight)
        self.assertIn("GIT_NO_REPLACE_OBJECTS", preflight)
        self.assertIn("['rev-parse', 'HEAD']", preflight)
        self.assertIn("['cat-file', 'blob', sha + ':' + relative]", preflight)
        self.assertIn("raw != (source / relative).read_bytes()", preflight)
        self.assertIn("os.O_EXCL | os.O_NOFOLLOW, 0o444", preflight)
        self.assertIn("'qa3_hosted_boundary.py'), 'probe'", preflight)
        self.assertIn("if: always()", preflight)
        self.assertIn("/qa3-boundary-probe/*.json", preflight)
        self.assertIn("/qa3-boundary-probe/*.stdout", preflight)
        self.assertIn("/qa3-boundary-probe/*.stderr", preflight)
        self.assertIn("retention-days: 1", preflight)
        self.assertIn("compression-level: 0", preflight)
        self.assertNotIn("overwrite:", preflight)
        self.assertIn("needs: [contracts, context, boundary-preflight]", workflow)

    def test_probe_worker_does_not_consume_or_claim_native_product_execution(self):
        state = self.root / "probe-state"
        state.mkdir()
        spec = self.root / "probe-spec.json"
        write_json(spec, {"boundaryProbe": True, "state": str(state)})
        with mock.patch.object(
            boundary, "protected", side_effect=lambda path: path
        ), mock.patch.object(
            boundary, "verify_worker", return_value={}
        ), mock.patch.object(boundary, "consume") as consumer, mock.patch.object(
            sys, "argv", ["boundary", "probe-worker", "--spec", str(spec)]
        ):
            boundary.main()
        consumer.assert_not_called()
        result = read_json(state / "probe-result.json")
        self.assertEqual(result["status"], "PASS_BOUNDARY_ONLY")
        self.assertIs(result["nativeProductExecuted"], False)
        self.assertIs(result["publicationAuthorized"], False)
        self.assertNotIn("context", result)

    def test_foreign_probe_spec_rejected_before_worker_observation(self):
        spec = self.root / "foreign-probe-spec.json"
        write_json(spec, {})
        with mock.patch.object(
            boundary, "protected", side_effect=lambda path: path
        ), mock.patch.object(boundary, "verify_worker") as worker, mock.patch.object(
            sys, "argv", ["boundary", "probe-worker", "--spec", str(spec)]
        ), self.assertRaisesRegex(ValueError, "foreign boundary probe"):
            boundary.main()
        worker.assert_not_called()

    def test_whole_run_budget_counts_existing_duplicate_artifacts(self):
        primary = self.root / "bundle"
        primary.mkdir()
        (primary / "floorp-application.ini").write_bytes(b"ini")
        (primary / "dist-host").mkdir()
        (primary / "dist-host/tool").write_bytes(b"host")
        output = self.root / "output"
        output.mkdir()
        for name in ("runtime.tar.xz", "test-support.tar.gz"):
            (output / name).write_bytes(b"payload")
        value = hosted.artifact_storage_budget(primary, output)
        self.assertEqual(value["primaryBundleBytes"], 7)
        self.assertEqual(value["distHostDuplicateBytes"], 4)
        self.assertEqual(value["applicationDuplicateBytes"], 3)
        self.assertEqual(value["retentionDays"], 1)
        with mock.patch.object(hosted, "MAX_ARTIFACT_STORAGE", 1), self.assertRaises(
            ValueError
        ):
            hosted.artifact_storage_budget(primary, output)


class WorkerNetwork(unittest.TestCase):
    def accepted(self, value, interfaces=None):
        if interfaces is None:
            interfaces = [(row["ifindex"], row["ifname"]) for row in value["links"]]
        return all(boundary.network_checks(value, interfaces).values())

    def test_loopback_and_inactive_kernel_fallbacks_are_accepted(self):
        self.assertTrue(self.accepted(loopback_network()))
        self.assertTrue(self.accepted(loopback_network(fallbacks=True)))

    def test_unknown_down_devices_and_wrong_fallback_types_are_rejected(self):
        for name, kind, link_type in (
            ("eth0", "veth", "ether"),
            ("tunl7", "ipip", "ipip"),
            ("tunl0", "veth", "ether"),
            ("tunl0", "ipip", "ether"),
            ("ip6gre0", "ip6gre", "tunnel6"),
        ):
            value = loopback_network(fallbacks=True)
            row = value["links"][1]
            row.update(ifname=name, link_type=link_type)
            row["linkinfo"]["info_kind"] = kind
            value["addresses"][1].update(ifname=name, link_type=link_type)
            with self.subTest(name=name, kind=kind, link_type=link_type):
                self.assertFalse(self.accepted(value))

    def test_up_or_configured_fallbacks_are_rejected(self):
        for target, field, value in (
            ("link", "flags", ["NOARP", "UP"]),
            ("link", "flags", ["NOARP", "LOWER_UP"]),
            ("link", "operstate", "UNKNOWN"),
            ("link", "master", "lo"),
            ("link", "link_index", 1),
            ("link", "link_netnsid", 0),
            ("data", "local", "192.0.2.1"),
            ("data", "remote", "192.0.2.2"),
            ("data", "link", "lo"),
            ("data", "external", True),
            ("data", "encap", "fou"),
            ("data", "ikey", "0.0.0.1"),
            ("data", "fwmark", "0x1"),
            ("data", "encap_dport", 1234),
        ):
            fixture = loopback_network(fallbacks=True)
            row = fixture["links"][1]
            selected = row if target == "link" else row["linkinfo"]["info_data"]
            selected[field] = value
            with self.subTest(target=target, field=field, value=value):
                self.assertFalse(self.accepted(fixture))

    def test_non_loopback_addresses_and_routes_are_rejected(self):
        address = {
            "family": "inet",
            "local": "192.0.2.1",
            "prefixlen": 24,
            "scope": "global",
        }
        for index in (0, 1):
            value = loopback_network(fallbacks=True)
            value["addresses"][index]["addr_info"].append(address)
            self.assertFalse(self.accepted(value))
        for field, route in (
            ("ipv4Routes", {"dst": "default", "dev": "lo"}),
            ("ipv4Routes", {"dst": "192.0.2.0/24", "dev": "lo", "table": 100}),
            ("ipv4Routes", {"dst": "127.0.0.1", "dev": "tunl0"}),
            ("ipv4Routes", {"dst": "127.0.0.1", "dev": "lo", "gateway": "192.0.2.2"}),
            ("ipv4Routes", {"dst": "127.0.0.1", "dev": "lo", "multipath": []}),
            ("ipv6Routes", {"dst": "ff00::/8", "dev": "lo"}),
        ):
            value = loopback_network(fallbacks=True)
            value[field].append(route)
            with self.subTest(route=route):
                self.assertFalse(self.accepted(value))

    def test_driver_default_6rd_prefix_is_allowed_but_configured_6rd_is_rejected(self):
        value = loopback_network(fallbacks=True)
        self.assertTrue(self.accepted(value))
        for field, configured in (
            ("prefix", "2001:db8::"),
            ("prefixlen", 32),
            ("relay_prefix", "192.0.2.0"),
            ("relay_prefixlen", 24),
        ):
            fixture = copy.deepcopy(value)
            fixture["links"][2]["linkinfo"]["info_data"][field] = configured
            with self.subTest(field=field):
                self.assertFalse(self.accepted(fixture))

    def test_incomplete_inventory_and_missing_loopback_are_rejected(self):
        for field in ("flags", "link_type", "operstate"):
            value = loopback_network()
            del value["links"][0][field]
            self.assertFalse(self.accepted(value))
        value = loopback_network(fallbacks=True)
        del value["links"][1]["linkinfo"]["info_data"]["remote"]
        self.assertFalse(self.accepted(value))
        value = loopback_network()
        value["addresses"][0]["addr_info"].pop()
        self.assertFalse(self.accepted(value))
        self.assertFalse(self.accepted(loopback_network(), [(1, "lo"), (2, "eth0")]))
        value = loopback_network()
        value["queryErrors"]["links"] = "failed"
        self.assertFalse(self.accepted(value))

    def test_network_queries_are_all_table_and_failures_are_diagnostic(self):
        value = loopback_network(fallbacks=True)
        answers = [
            value[key] for key in ("links", "addresses", "ipv4Routes", "ipv6Routes")
        ]
        with mock.patch.object(
            boundary,
            "capture_ip",
            side_effect=[json.dumps(row).encode() for row in answers],
        ) as query, mock.patch("builtins.print") as printer:
            observation = boundary.worker_network([
                (row["ifindex"], row["ifname"]) for row in value["links"]
            ])
        self.assertTrue(all(observation["checks"].values()))
        self.assertEqual(
            [call.args[0] for call in query.call_args_list],
            [
                ["-d", "link", "show"],
                ["addr", "show"],
                ["-4", "route", "show", "table", "all"],
                ["-6", "route", "show", "table", "all"],
            ],
        )
        self.assertLessEqual(
            len(printer.call_args.args[0].encode()), boundary.MAX_NETWORK_JSON
        )
        with mock.patch.object(
            boundary, "capture_ip", side_effect=FileNotFoundError(errno.ENOENT, "ip")
        ), mock.patch("builtins.print") as printer:
            observation = boundary.worker_network([(1, "lo")])
        self.assertFalse(any(observation["checks"].values()))
        self.assertEqual(observation["queryErrors"]["links"]["errno"], errno.ENOENT)
        self.assertEqual(json.loads(printer.call_args.args[0]), observation)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux subprocess pipes")
    def test_capture_ip_clean_environment_and_output_timeout_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "ip"
            fake.write_text(
                "#!/usr/bin/python3\nimport os, sys\n"
                "assert sys.argv[1] == '-j'\n"
                "assert set(os.environ) <= {'PATH','LANG','LC_ALL'}\n"
                "sys.stdout.write('[]')\n"
            )
            fake.chmod(0o700)
            with mock.patch.object(
                Path, "resolve", return_value=fake
            ), mock.patch.object(boundary, "protected", side_effect=lambda path: path):
                self.assertEqual(boundary.capture_ip(["link", "show"], 100), b"[]")
                fake.write_text("#!/usr/bin/python3\nprint('x' * 10000)\n")
                with self.assertRaisesRegex(ValueError, "output budget exceeded"):
                    boundary.capture_ip(["link", "show"], 100)
                fake.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(10)\n")
                with self.assertRaisesRegex(ValueError, "query timeout"):
                    boundary.capture_ip(["link", "show"], 100)


class OriginalConsumerEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "logs").mkdir()
        self.support = self.root / "support"
        self.support.mkdir()
        self.plan = read_json(SOURCE / PLAN_PATH)
        schedule = native_schedule(self.plan)
        commands, cases = [], []
        for index, name in enumerate(PHASES):
            events = []
            if index >= 3:
                _, case, _ = schedule[index - 3]
                canary = name.endswith("assertion-canary")
                test = case["id"]
                events = [
                    {"action": "suite_start", "tests": [test]},
                    {"action": "test_start", "test": test},
                    {
                        "action": "test_status",
                        "test": test,
                        "status": "FAIL" if canary else "PASS",
                        "expected": "PASS",
                        "subtest": "QA3_EXPECTED_ASSERTION" if canary else "assert",
                    },
                    {
                        "action": "test_end",
                        "test": test,
                        "status": "FAIL" if canary else "OK",
                    },
                    {"action": "suite_end"},
                ]
                if not canary:
                    events[2:3] = [
                        dict(events[2], subtest=f"assert-{i}")
                        for i in range(case["minimumAssertions"])
                    ]
                if canary and case["suite"] == "xpcshell":
                    events[2].update(
                        subtest="run_test",
                        message="[run_test : 4] QA3_EXPECTED_ASSERTION - false == true",
                    )
                elif canary:
                    events[2].update(
                        subtest="qa3_expected_assertion",
                        message="QA3_EXPECTED_ASSERTION",
                    )
            (self.root / "logs" / (name + ".stdout")).write_text(
                "TEST-INFO | checking window state\nBrowser Chrome Test Summary\n"
                if index >= 3
                else ""
            )
            (self.root / "logs" / (name + ".stderr")).write_bytes(b"")
            command = {
                "name": name,
                "exit": 1 if name.endswith("assertion-canary") else 0,
                "stop": None,
                "ownedCleanupComplete": True,
                "stdoutIsData": False,
                "stdoutSha256": file_digest(self.root / "logs" / (name + ".stdout")),
                "stderrSha256": file_digest(self.root / "logs" / (name + ".stderr")),
            }
            if index >= 3:
                raw_path = self.root / "logs" / (name + ".mozlog")
                raw_path.write_text("".join(json.dumps(e) + "\n" for e in events))
                identity = hosted.raw_log_identity(raw_path)
                command["watchedLogs"] = {raw_path.name: identity}
            write_json(self.root / "logs" / (name + ".process.json"), command)
            commands.append(command)
            if index >= 3:
                cases.append({
                    "name": name,
                    "suite": case["suite"],
                    "canary": canary,
                    "process": command,
                    "rawLog": {"path": "logs/" + raw_path.name, **identity},
                    "mozlog": verify_mozlog(
                        raw_path,
                        case,
                        self.support,
                        command,
                        canary=canary,
                    ),
                })
        self.value = {
            "schema": "qa3-hosted-cold-consumer-v1",
            "status": "PASS",
            "context": context(),
            "producerBootSha256": BOOT,
            "consumerBootSha256": "d" * 64,
            "commands": commands,
            "cases": cases,
            "nativeProductQualification": "UNVERIFIED",
            "publicationAuthorized": False,
        }

    def check(self):
        path = self.root / "consumer.json"
        path.unlink(missing_ok=True)
        write_json(path, self.value)
        with mock.patch.object(
            hosted, "verify_support", return_value=self.plan
        ), mock.patch.object(
            hosted, "canary_case", side_effect=lambda case, *_: case
        ), mock.patch.object(hosted, "worker_boot_identity", return_value="d" * 64):
            return hosted.verify_consumer(
                self.root, self.support, producer(), context()
            )

    def test_six_original_pass_and_assertion_canaries(self):
        self.assertEqual(self.check()["status"], "PASS")

    def test_new_required_cases_cannot_be_missing_or_reordered(self):
        for change in ("missing-tab", "missing-ini", "reordered", "duplicate"):
            original = copy.deepcopy(self.value)
            if change == "missing-tab":
                self.value["cases"].pop(4)
            elif change == "missing-ini":
                self.value["cases"].pop(5)
            elif change == "reordered":
                self.value["cases"][4:6] = reversed(self.value["cases"][4:6])
            else:
                self.value["cases"][5] = self.value["cases"][4]
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check()
            self.value = original

    def test_unchanged_manifest_canaries_are_installed_once_per_suite(self):
        write_json(self.support / "plan.json", self.plan)
        for case in self.plan["selection"]:
            path = (
                self.support
                / Path(case["archivePath"]).parent
                / Path(case["manifest"]).name
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((SOURCE / case["manifest"]).read_bytes())
        original_tabs = file_digest(
            self.support
            / "mochitest/browser/browser/components/tabbrowser/test/browser/tabs/browser.toml"
        )
        changes = hosted.install_canaries(SOURCE, self.support, self.plan)
        self.assertEqual(
            [row["suite"] for row in changes], ["browser-chrome", "xpcshell"]
        )
        self.assertEqual(len(changes), 2)
        self.assertEqual(
            file_digest(
                self.support
                / "mochitest/browser/browser/components/tabbrowser/test/browser/tabs/browser.toml"
            ),
            original_tabs,
        )
        for _, case, canary in native_schedule(self.plan):
            if canary:
                selected = hosted.canary_case(
                    case, self.support, {"canaryTransforms": changes}
                )
                self.assertTrue((self.support / selected["archivePath"]).is_file())

    def test_finite_selection_rejects_weakened_or_extra_cases(self):
        for change in ("fewer", "extra", "reorder", "weaker", "conditions", "untyped"):
            plan = copy.deepcopy(self.plan)
            if change == "fewer":
                plan["selection"].pop()
            elif change == "extra":
                plan["selection"].append(plan["selection"][3])
            elif change == "reorder":
                plan["selection"][2:4] = reversed(plan["selection"][2:4])
            elif change == "weaker":
                plan["selection"][3]["minimumAssertions"] = 1
            elif change == "conditions":
                plan["selection"][2]["declaredConditions"] = {"skip-if": ["true"]}
            else:
                plan["selection"][0]["minimumAssertions"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                native_schedule(plan)

    def test_new_required_skip_is_rejected_with_matching_process_and_raw_hashes(self):
        for index in (4, 5):
            original = copy.deepcopy(self.value)
            name = self.value["cases"][index]["name"]
            path = self.root / "logs" / (name + ".mozlog")
            raw = path.read_bytes()
            events = [json.loads(line) for line in raw.splitlines()]
            events[-2]["status"] = "SKIP"
            path.write_text("".join(json.dumps(e) + "\n" for e in events))
            identity = hosted.raw_log_identity(path)
            command = self.value["commands"][index + 3]
            command["watchedLogs"] = {path.name: identity}
            self.value["cases"][index]["rawLog"] = {
                "path": "logs/" + path.name,
                **identity,
            }
            receipt = self.root / "logs" / (name + ".process.json")
            receipt.unlink()
            write_json(receipt, command)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check()
            self.value = original
            path.write_bytes(raw)
            receipt.unlink()
            write_json(receipt, self.value["commands"][index + 3])

    def test_new_support_bytes_remain_source_pinned_after_inventory_is_rejoined(self):
        from qa3_native_io import capture_material_tree

        bindings = (
            [(case["id"], case["archivePath"]) for case in self.plan["selection"]]
            + list(extra_packaged_materials())
            + [
                ("testing/mochitest/runtests.py", "mochitest/runtests.py"),
                (
                    "testing/mochitest/mochitest_options.py",
                    "mochitest/mochitest_options.py",
                ),
                (
                    "testing/xpcshell/runxpcshelltests.py",
                    "xpcshell/runxpcshelltests.py",
                ),
                (
                    "testing/xpcshell/xpcshellcommandline.py",
                    "xpcshell/xpcshellcommandline.py",
                ),
                (
                    "browser/base/content/test/browser-performance/head.js",
                    "mochitest/browser/browser/base/content/test/browser-performance/head.js",
                ),
                (
                    "xpcom/tests/unit/head_xpcom.js",
                    "xpcshell/tests/xpcom/tests/unit/head_xpcom.js",
                ),
                (
                    "xpcom/geckoprocesstypes_generator/geckoprocesstypes/__init__.py",
                    "tools/geckoprocesstypes_generator/geckoprocesstypes/__init__.py",
                ),
                (
                    "testing/mozbase/setup_development.py",
                    "mozbase/setup_development.py",
                ),
            ]
        )
        plan = copy.deepcopy(self.plan)
        for source, archive in bindings:
            path = self.support / archive
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            row = next(row for row in plan["sourceMaterials"] if row["path"] == source)
            row["sha256"] = file_digest(path)
        write_json(self.support / "plan.json", plan)
        for name in ("gmp-fake", "gmp-fakeopenh264"):
            path = self.support / "bin/plugins" / name / "1.0/plugin"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"same-build-plugin-fixture")
        value = {
            "supportInventory": capture_material_tree(self.support),
            "planSha256": file_digest(self.support / "plan.json"),
            "pythonEnvironmentSha256": DIGEST,
            "canaryTransforms": [{}, {}],
            "helpers": dict.fromkeys(
                ("xpcshell", "ssltunnel", "certutil", "pk12util"), {}
            ),
        }
        with mock.patch.object(hosted, "verify_python_environment"), mock.patch.object(
            hosted, "canary_case"
        ), mock.patch.object(hosted, "elf_identity", return_value={}):
            self.assertEqual(hosted.verify_support(self.support, value), plan)
            for archive in (
                "modules/TabGroupTestUtils.sys.mjs",
                "mochitest/browser/browser/components/tabbrowser/test/browser/tabs/head.js",
                "mochitest/browser/browser/components/tabbrowser/test/browser/tabs/browser.toml",
                "xpcshell/tests/xpcom/tests/unit/data/iniparser17.ini",
                "xpcshell/tests/xpcom/tests/unit/data/iniparser16-utf8BOM.ini",
            ):
                path = self.support / archive
                raw = path.read_bytes()
                path.write_bytes(raw + b"changed")
                value["supportInventory"] = capture_material_tree(self.support)
                with self.subTest(archive=archive), self.assertRaises(ValueError):
                    hosted.verify_support(self.support, value)
                path.write_bytes(raw)
                value["supportInventory"] = capture_material_tree(self.support)

    def test_failure_export_keeps_new_original_logs_and_rejects_arbitrary_outputs(self):
        import shutil

        campaign = self.root / "campaign"
        output = campaign / "state/output"
        output.mkdir(parents=True)
        shutil.copytree(self.root / "logs", output / "logs")
        plan = campaign / "recipe" / PLAN_PATH
        plan.parent.mkdir(parents=True)
        plan.write_bytes((SOURCE / PLAN_PATH).read_bytes())
        with mock.patch.object(boundary, "protected", side_effect=lambda p: p):
            rows = boundary.export_after_stop(campaign, False, context())
        self.assertIn("logs/native-3-required.mozlog", {row["path"] for row in rows})
        self.assertEqual(len(rows), 33)
        shutil.rmtree(campaign / "export")
        (output / "untrusted-output").write_text("not a permitted native receipt")
        with mock.patch.object(
            boundary, "protected", side_effect=lambda p: p
        ), self.assertRaisesRegex(ValueError, "arbitrary"):
            boundary.export_after_stop(campaign, False, context())

    def test_missing_original_case_or_command_rejected(self):
        self.value["cases"].pop()
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_retry_cannot_recover_first_failure(self):
        self.value["commands"].append(self.value["commands"][-1])
        with self.assertRaises(ValueError):
            self.check()

    def test_raw_log_tamper_rejected(self):
        (self.root / "logs/native-0-required.mozlog").write_bytes(b"")
        with self.assertRaises(ValueError):
            self.check()

    def test_raw_mozlog_requires_one_bounded_regular_file(self):
        path = self.root / "logs/native-0-required.mozlog"
        original = path.read_bytes()
        target = self.root / "other.log"
        target.write_bytes(original)
        for change in ("missing", "symlink", "hardlink", "empty", "oversized"):
            path.unlink()
            if change == "symlink":
                path.symlink_to(target)
            elif change == "hardlink":
                os.link(target, path)
            elif change == "empty":
                path.write_bytes(b"")
            elif change == "oversized":
                with path.open("wb") as stream:
                    stream.truncate(16 * 1024**2 + 1)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check()
            path.unlink(missing_ok=True)
            path.write_bytes(original)

    def test_console_tamper_rejected_without_reinterpreting_it_as_mozlog(self):
        (self.root / "logs/native-0-required.stdout").write_bytes(b"")
        with self.assertRaises(ValueError):
            self.check()

    def test_raw_mozlog_identity_and_location_are_required(self):
        for change in ("missing", "path", "digest", "watcher"):
            original = copy.deepcopy(self.value)
            if change == "missing":
                del self.value["cases"][0]["rawLog"]
            elif change == "path":
                self.value["cases"][0]["rawLog"]["path"] = "logs/other.mozlog"
            elif change == "digest":
                self.value["cases"][0]["rawLog"]["sha256"] = "e" * 64
            else:
                self.value["commands"][3]["watchedLogs"] = {}
                process = self.root / "logs/native-0-required.process.json"
                process.unlink()
                write_json(process, self.value["commands"][3])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check()
            self.value = original
            process = self.root / "logs/native-0-required.process.json"
            process.unlink()
            write_json(process, self.value["commands"][3])

    def rejoin_raw_identity(self, path):
        command = self.value["commands"][3]
        identity = hosted.raw_log_identity(path)
        command["watchedLogs"] = {path.name: identity}
        self.value["cases"][0]["rawLog"] = {"path": "logs/" + path.name, **identity}
        process = self.root / "logs/native-0-required.process.json"
        process.unlink()
        write_json(process, command)

    def test_raw_process_tamper_rejected(self):
        (self.root / "logs/native-0-required.process.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.check()

    def test_required_skip_rejected_after_raw_hashes_are_rejoined(self):
        path = self.root / "logs/native-0-required.mozlog"
        events = [json.loads(line) for line in path.read_text().splitlines()]
        events[-2]["status"] = "SKIP"
        path.write_text("".join(json.dumps(e) + "\n" for e in events))
        self.rejoin_raw_identity(path)
        with self.assertRaises(ValueError):
            self.check()

    def test_internal_retry_rejected_after_raw_hashes_are_rejoined(self):
        path = self.root / "logs/native-0-required.mozlog"
        with path.open("a") as stream:
            stream.write(
                json.dumps({
                    "action": "log",
                    "level": "INFO",
                    "message": "retrying original failure",
                })
                + "\n"
            )
        self.rejoin_raw_identity(path)
        with self.assertRaises(ValueError):
            self.check()

    def test_initial_failure_or_cancel_cannot_become_pass(self):
        self.value["commands"][0]["exit"] = 1
        with self.assertRaises(ValueError):
            self.check()

    def test_canary_must_fail_with_original_normal_exit(self):
        self.value["commands"][4]["exit"] = 0
        with self.assertRaises(ValueError):
            self.check()

    def test_product_or_publication_claim_rejected(self):
        self.value["publicationAuthorized"] = True
        with self.assertRaises(ValueError):
            self.check()


class HostedPackagingDependencies(unittest.TestCase):
    def test_consumer_requires_successful_original_test_install_preparation(self):
        with mock.patch.object(
            hosted, "host_identity", return_value=HOST
        ), mock.patch.object(hosted, "worker_boot_identity", return_value="d" * 64):
            hosted.validate_producer(producer(), context())
            for change in (
                "missing-record",
                "unchanged",
                "missing-command",
                "failed",
                "source-delta",
            ):
                value = producer()
                record = value["testInstallManifest"]
                if change == "missing-record":
                    del value["testInstallManifest"]
                elif change == "unchanged":
                    record["afterSha256"] = record["beforeSha256"]
                elif change == "missing-command":
                    del value["commands"][1]
                elif change == "source-delta":
                    value["actualSourceDeltaSha256"] = "e" * 64
                else:
                    value["commands"][1]["exit"] = 1
                with self.subTest(change=change), self.assertRaises(ValueError):
                    hosted.validate_producer(value, context())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_generated_hosted_config_enables_all_observed_stage_prerequisites(self):
        expected = profile("linux", "x86_64", True, False)
        original = (
            "ac_add_options --target=x86_64-pc-linux-gnu\n"
            "ac_add_options --enable-debug\nac_add_options --enable-tests\n"
            "export MOZ_PACKAGE_JSSHELL=1\n"
        )
        result = enable_hosted_test_support(original, expected)
        self.assertNotIn("--enable-js-shell", ac_options(original))
        self.assertEqual(ac_options(result).count("--enable-js-shell"), 1)
        self.assertEqual(ac_options(result).count("--enable-gtest-in-build"), 1)
        self.assertEqual(enable_hosted_test_support(result, expected), result)
        for name in ("js-shell", "gtest-in-build"):
            for suffix in (
                "ac_add_options --disable-" + name + "\n",
                "ac_add_options --enable-" + name + "=unknown\n",
            ):
                with self.subTest(name=name, suffix=suffix), self.assertRaises(
                    ValueError
                ):
                    enable_hosted_test_support(original + suffix, expected)

    def test_hosted_support_cannot_change_production_pgo_or_foreign_target(self):
        for args in (
            ("linux", "x86_64", False, False),
            ("linux", "aarch64", True, False),
            ("windows", "x86_64", True, False),
            ("mac", "aarch64", True, False),
            ("linux", "x86_64", False, True, "generate", ""),
            ("linux", "x86_64", False, True, "use", "profile"),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                enable_hosted_test_support("unchanged\n", profile(*args))

    def test_packaging_cannot_change_configuration_or_compiled_primary_bytes(self):
        before = effective()
        identities = producer()["compiledIdentity"]
        source, objdir = Path("/source"), Path("/source/obj")
        hosted.verify_packaged_build_cohort(
            before,
            copy.deepcopy(before),
            identities,
            copy.deepcopy(identities),
            source,
            objdir,
        )
        after = copy.deepcopy(before)
        after["substs"]["CXX"] = ["/foreign/compiler"]
        with self.assertRaisesRegex(ValueError, "test packaging changed"):
            hosted.verify_packaged_build_cohort(
                before, after, identities, identities, source, objdir
            )
        changed = copy.deepcopy(identities)
        changed["libxul.so"]["sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "test packaging changed"):
            hosted.verify_packaged_build_cohort(
                before, before, identities, changed, source, objdir
            )

    def test_consumer_requires_original_successful_post_packaging_cohort(self):
        with mock.patch.object(
            hosted, "host_identity", return_value=HOST
        ), mock.patch.object(hosted, "worker_boot_identity", return_value="d" * 64):
            hosted.validate_producer(producer(), context())
            for key in ("effectiveConfigAfterTests", "compiledIdentityAfterTests"):
                changed = producer()
                del changed[key]
                with self.subTest(key=key), self.assertRaises(ValueError):
                    hosted.validate_producer(changed, context())
            for modification in ("missing", "failed", "repeated"):
                changed = producer()
                commands = changed["commands"]
                index = next(
                    i
                    for i, item in enumerate(commands)
                    if item["name"] == "effective-after-tests"
                )
                if modification == "missing":
                    del commands[index]
                elif modification == "failed":
                    commands[index]["exit"] = 1
                else:
                    commands.insert(index, copy.deepcopy(commands[index]))
                with self.subTest(modification=modification), self.assertRaises(
                    ValueError
                ):
                    hosted.validate_producer(changed, context())

    def test_effective_staging_config_rejects_missing_or_disabled_prerequisites(self):
        source, objdir = Path("/source"), Path("/source/obj")
        hosted.validate_effective(effective(), source, objdir)
        for name in (
            "MOZ_AUTOMATION",
            "COMPILE_ENVIRONMENT",
            "LINK_GTEST_DURING_COMPILE",
        ):
            for value in (None, False, "0"):
                changed = effective()
                changed["substs"][name] = value
                with self.subTest(name=name, value=value), self.assertRaises(
                    ValueError
                ):
                    hosted.validate_effective(changed, source, objdir)
        for value in (True, 1, "1", "unknown"):
            changed = effective()
            changed["substs"]["JS_DISABLE_SHELL"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                hosted.validate_effective(changed, source, objdir)
        missing = effective()
        del missing["substs"]["JS_DISABLE_SHELL"]
        with self.assertRaises(ValueError):
            hosted.validate_effective(missing, source, objdir)

    def test_scrubbed_producer_selects_pip_without_controller_secrets(self):
        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.root),
                "MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE": "system",
                "GITHUB_TOKEN": "private-controller-token",
                "PIP_REQUIREMENT": "/private/lock",
                "SCCACHE_GHA_RW_MODE": "READ_WRITE",
                "QA3_KEEP_CARGO_FOR_TEST_PACKAGING": "1",
            },
            clear=True,
        ):
            env = hosted.producer_environment(
                self.root, self.root / "obj", context()["buildID"]
            )
            consumer = hosted.child_environment(self.root)
        self.assertEqual(env["MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE"], "pip")
        self.assertEqual(env["MOZ_AUTOMATION"], "1")
        self.assertEqual(env["SCCACHE_GHA_RW_MODE"], "READ_ONLY")
        for name in ("GITHUB_TOKEN", "PIP_REQUIREMENT"):
            self.assertNotIn(name, env)
        self.assertNotIn("MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE", consumer)
        self.assertNotIn("SCCACHE_GHA_RW_MODE", consumer)
        self.assertNotIn("QA3_KEEP_CARGO_FOR_TEST_PACKAGING", env)
        self.assertNotIn("QA3_KEEP_CARGO_FOR_TEST_PACKAGING", consumer)

    def material(self):
        support = self.root / "support"
        for name in (
            "modules",
            *("mozbase/" + name for name in hosted.MOZBASE_MODULES),
            "tools/geckoprocesstypes_generator/geckoprocesstypes",
        ):
            (support / name).mkdir(parents=True)
        (support / "plan.json").write_bytes((SOURCE / PLAN_PATH).read_bytes())
        (support / "mozbase/setup_development.py").write_bytes(
            (SOURCE / "testing/mozbase/setup_development.py").read_bytes()
        )
        (
            support / "tools/geckoprocesstypes_generator/geckoprocesstypes/__init__.py"
        ).write_text("process_types = ['fixed-packaged-fixture']\n")
        return support

    def test_fixed_common_tools_path_imports_in_scrubbed_child(self):
        import subprocess
        import sys

        support = self.material()
        roots = hosted.consumer_module_roots(support)
        env = hosted.child_environment(
            self.root, {"PYTHONPATH": ":".join(map(str, roots))}
        )
        original = dict(env, PYTHONPATH=":".join(map(str, roots[:-1])))
        argv = [
            sys.executable,
            "-s",
            "-c",
            "import geckoprocesstypes; print(geckoprocesstypes.process_types)",
        ]
        before = subprocess.run(
            argv,
            cwd=self.root,
            env=original,
            capture_output=True,
            timeout=20,
            check=False,
        )
        after = subprocess.run(
            argv, cwd=self.root, env=env, capture_output=True, timeout=20, check=False
        )
        self.assertEqual(before.returncode, 1)
        self.assertIn(b"ModuleNotFoundError", before.stderr)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(after.stdout, b"['fixed-packaged-fixture']\n")

    def test_missing_or_linked_common_tools_module_is_rejected(self):
        support = self.material()
        module = (
            support / "tools/geckoprocesstypes_generator/geckoprocesstypes/__init__.py"
        )
        original = module.read_bytes()
        module.unlink()
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(support)
        outside = self.root / "outside.py"
        outside.write_bytes(original)
        module.symlink_to(outside)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(support)

    def test_actual_nonzero_process_retains_failure_and_safe_typed_diagnostics(self):
        import contextlib
        import sys

        logs = self.root / "logs"
        logs.mkdir()
        env = hosted.child_environment(self.root)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(ValueError):
            hosted.run_diagnosed(
                [
                    sys.executable,
                    "-c",
                    "print('::error::private-token-value'); raise ModuleNotFoundError(\"No module named 'qa3_missing_fixture'\")",
                ],
                self.root,
                env,
                logs,
                "diagnostic-fixture",
                20,
                memory=GIB,
                log_limit=1024**2,
            )
        value = json.loads(output.getvalue())
        self.assertEqual(value["exit"], 1)
        self.assertTrue(value["ownedCleanupComplete"])
        self.assertNotIn("private-token-value", output.getvalue())
        self.assertNotIn("::error::", output.getvalue())
        stderr = next(v for v in value["boundedTypedTails"] if v["stream"] == "stderr")
        self.assertEqual(stderr["missingModules"], ["qa3_missing_fixture"])
        self.assertEqual(stderr["exceptionClasses"], ["ModuleNotFoundError"])
        self.assertIn(
            b"private-token-value", (logs / "diagnostic-fixture.stdout").read_bytes()
        )
        self.assertEqual(read_json(logs / "diagnostic-fixture.process.json")["exit"], 1)

    def test_diagnostic_output_failure_does_not_replace_original_process_failure(self):
        import sys

        logs = self.root / "logs"
        logs.mkdir()
        env = hosted.child_environment(self.root)
        with mock.patch.object(
            hosted, "emit_owned_failure", side_effect=BrokenPipeError
        ), mock.patch("builtins.print", side_effect=BrokenPipeError):
            with self.assertRaisesRegex(
                ValueError, "diagnostic-broken-output failed: NONZERO_EXIT"
            ):
                hosted.run_diagnosed(
                    [sys.executable, "-c", "raise SystemExit(7)"],
                    self.root,
                    env,
                    logs,
                    "diagnostic-broken-output",
                    20,
                    memory=GIB,
                    log_limit=1024**2,
                )
        self.assertEqual(
            read_json(logs / "diagnostic-broken-output.process.json")["exit"], 7
        )

    def test_data_stdout_is_never_inspected_as_text_diagnostics(self):
        import contextlib

        logs = self.root / "logs"
        logs.mkdir()
        write_json(
            logs / "decode-fixture.process.json",
            {
                "name": "decode-fixture",
                "exit": 1,
                "stop": None,
                "stdoutIsData": True,
                "ownedCleanupComplete": True,
            },
        )
        (logs / "decode-fixture.stdout").write_bytes(
            b"No module named 'binary_data_must_not_be_read'"
        )
        (logs / "decode-fixture.stderr").write_bytes(
            b"ModuleNotFoundError: No module named 'stderr_fixture'\n"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            hosted.emit_owned_failure(logs, "decode-fixture")
        value = json.loads(output.getvalue())
        self.assertEqual([v["stream"] for v in value["boundedTypedTails"]], ["stderr"])
        self.assertNotIn("binary_data_must_not_be_read", output.getvalue())

    def test_preflight_is_scoped_before_build_with_original_diagnostics(self):
        import yaml

        workflow = yaml.safe_load(
            (SOURCE / ".github/workflows/common-build.yml").read_text()
        )
        steps = workflow["jobs"]["build"]["steps"]
        name = "Check scoped Debug packaging Python before build"
        preflight = next(v for v in steps if v.get("name") == name)
        self.assertEqual(preflight["if"], "inputs.qa3-debug-tests")
        self.assertLess(
            next(
                i
                for i, v in enumerate(steps)
                if v.get("name") == "Setup floorp configuration"
            ),
            steps.index(preflight),
        )
        self.assertLess(
            steps.index(preflight),
            next(
                i for i, v in enumerate(steps) if v.get("name") == "Build and package"
            ),
        )
        self.assertIn("--hosted-test-support", preflight["run"])
        self.assertLess(
            preflight["run"].index("qa3_build_profile.py"),
            preflight["run"].index("qa3_hosted.py preflight"),
        )
        diagnostics = next(
            v
            for v in steps
            if v.get("name") == "Preserve original Debug packaging diagnostics"
        )
        self.assertIn(
            "qa3-packaging-preflight/logs/*.process.json", diagnostics["with"]["path"]
        )
        self.assertEqual(diagnostics["with"]["retention-days"], 1)


class HostedBootstrapPrerequisites(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def catalog(self):
        return {
            "schema": "qa3-hosted-bootstrap-catalog-v1",
            "source": "/source",
            "state": "/state",
            "sourceCacheKey": DIGEST,
            "cacheBytes": 100,
            "cacheSha256": DIGEST,
            "catalogBytes": 120,
            "catalogSha256": DIGEST,
            "catalogTasks": 10,
            "dynamicInputs": ["taskcluster/scripts/misc/build-clang.sh"],
            "cacheEnvironment": {
                "TASKCLUSTER_ROOT_URL": bootstrap_probe.ROOT_URL,
                "MOZ_SCM_LEVEL": "3",
            },
            "nativeExecuted": False,
            "publicationAuthorized": False,
        }

    def test_build_and_packaging_share_local_metrics_without_native_inheritance(self):
        source = self.root / "source"
        source.mkdir()
        objdir = source / "obj-x86_64-pc-linux-gnu"
        with mock.patch.dict(os.environ, {"UPLOAD_DIR": "/controller/private"}):
            with mock.patch("qa3_hosted.source_stamp_environment", return_value={}):
                initial = hosted.build_environment(source, {})
                packaged = hosted.producer_environment(source, objdir, "20261012000000")
                native = hosted.child_environment(source)
        self.assertEqual(initial["UPLOAD_DIR"], packaged["UPLOAD_DIR"])
        self.assertTrue(Path(packaged["UPLOAD_DIR"]).is_absolute())
        self.assertTrue(Path(packaged["UPLOAD_DIR"]).is_relative_to(objdir))
        self.assertNotEqual(packaged["UPLOAD_DIR"], "/controller/private")
        self.assertNotIn("UPLOAD_DIR", native)
        self.assertEqual(initial["MOZ_AUTOMATION"], "1")
        for name in hosted.AUTOMATION_PHASES:
            self.assertEqual(initial["MOZ_AUTOMATION_" + name], "0")

    def test_only_metadata_child_omits_automation_and_controller_secrets(self):
        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.root),
                "GITHUB_TOKEN": "private-controller-token",
                "PIP_REQUIREMENT": "/private/lock",
            },
            clear=True,
        ):
            build = hosted.producer_environment(
                self.root, self.root / "obj", context()["buildID"]
            )
        before = copy.deepcopy(build)
        metadata = hosted.bootstrap_metadata_environment(build)
        self.assertNotIn("MOZ_AUTOMATION", metadata)
        self.assertEqual(build, before)
        self.assertEqual(build["MOZ_AUTOMATION"], "1")
        self.assertEqual(
            metadata, {k: v for k, v in build.items() if k != "MOZ_AUTOMATION"}
        )
        self.assertNotIn("GITHUB_TOKEN", metadata)
        self.assertNotIn("PIP_REQUIREMENT", metadata)
        bootstrap_probe.validate_environment("prepare", metadata)
        bootstrap_probe.validate_environment("verify", build)

    def test_false_or_empty_automation_is_still_not_standalone_metadata(self):
        env = {
            "TASKCLUSTER_ROOT_URL": bootstrap_probe.ROOT_URL,
            "MOZ_SCM_LEVEL": "3",
            "MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE": "pip",
        }
        bootstrap_probe.validate_environment("prepare", env)
        for value in ("0", "", "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bootstrap_probe.validate_environment(
                    "prepare", {**env, "MOZ_AUTOMATION": value}
                )
        for key in ("TASK_ID", "MACH_NO_FUNC_CACHE"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.bootstrap_metadata_environment({**env, key: ""})
        for key, value in (
            ("TASK_ID", "fake"),
            ("MACH_NO_FUNC_CACHE", ""),
            ("TASKCLUSTER_ROOT_URL", "https://example.invalid"),
            ("MOZ_SCM_LEVEL", "1"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                bootstrap_probe.validate_environment("prepare", {**env, key: value})

    def test_missing_or_changed_catalog_identity_cannot_reach_build(self):
        original = self.catalog()
        hosted.verify_bootstrap_catalog(
            original, copy.deepcopy(original), Path("/source"), Path("/state")
        )
        for key in original:
            missing = copy.deepcopy(original)
            del missing[key]
            with self.subTest(key=key, change="missing"), self.assertRaises(ValueError):
                hosted.verify_bootstrap_catalog(
                    missing, missing, Path("/source"), Path("/state")
                )
            changed = copy.deepcopy(original)
            changed[key] = None
            with self.subTest(key=key, change="drift"), self.assertRaises(ValueError):
                hosted.verify_bootstrap_catalog(
                    original, changed, Path("/source"), Path("/state")
                )
        for key, value in (
            ("cacheSha256", "invalid"),
            ("cacheBytes", True),
            ("catalogBytes", 0),
            ("catalogTasks", 10001),
            ("dynamicInputs", []),
            ("nativeExecuted", True),
            ("publicationAuthorized", True),
        ):
            changed = {**original, key: value}
            with self.subTest(key=key, change="invalid"), self.assertRaises(ValueError):
                hosted.verify_bootstrap_catalog(
                    changed, changed, Path("/source"), Path("/state")
                )
        for source, state in (("/foreign", "/state"), ("/source", "/foreign")):
            with self.subTest(source=source, state=state), self.assertRaises(
                ValueError
            ):
                hosted.verify_bootstrap_catalog(
                    original, original, Path(source), Path(state)
                )

    def test_verify_audit_hook_rejects_real_subprocess_in_fresh_process(self):
        import subprocess
        import sys

        code = (
            "import sys,subprocess; from qa3_bootstrap_probe import prohibit_subprocess; "
            "sys.addaudithook(prohibit_subprocess); "
            "subprocess.run([sys.executable,'-c',\"print('must-not-run')\"])"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=SOURCE / ".github/workflows/scripts",
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            b"expected source cache hit attempted a subprocess", result.stderr
        )
        self.assertNotIn(b"must-not-run\n", result.stdout)

    def test_bootstrap_metadata_failure_prevents_decoder_and_build(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                source=Path(directory),
                objdir=Path(directory) / "obj",
                output=Path(directory) / "output",
                build_id=context()["buildID"],
            )
            with mock.patch.object(
                hosted, "context_from_environment", return_value=context()
            ), mock.patch.object(
                hosted, "source_stamp_environment", return_value={}
            ), mock.patch.object(
                hosted, "producer_environment", return_value={"MOZ_AUTOMATION": "1"}
            ), mock.patch.object(
                hosted,
                "run_diagnosed",
                side_effect=ValueError("original metadata failure"),
            ) as run:
                with self.assertRaisesRegex(ValueError, "original metadata failure"):
                    hosted.packaging_preflight(args)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[4], "bootstrap-catalog-prepare")


class HostedMozbaseArchiveShape(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.support = HostedPackagingDependencies.material(self)

    def test_contract_checkout_covers_exact_pinned_archive_shape_sources(self):
        import yaml

        workflow = yaml.safe_load(
            (SOURCE / ".github/workflows/qa3-hosted-linux-debug.yml").read_text()
        )
        checkout = next(
            step["with"]
            for step in workflow["jobs"]["contracts"]["steps"]
            if step.get("uses") == "actions/checkout@v4"
        )
        self.assertIs(checkout["sparse-checkout-cone-mode"], False)
        source_hashes = {
            row["path"]: row["sha256"]
            for row in read_json(self.support / "plan.json")["sourceMaterials"]
        }
        metadata = {
            "testing/mozbase/moz.build",
            "testing/mozbase/setup_development.py",
            "browser/base/content/test/browser-performance/browser.toml",
            "browser/components/tabbrowser/test/browser/tabs/browser.toml",
            "xpcom/tests/unit/xpcshell.toml",
        }
        self.assertTrue(metadata <= source_hashes.keys())
        self.assertEqual(
            set(checkout["sparse-checkout"].splitlines()),
            {"/.github/**", *("/" + name for name in metadata)},
        )

    def test_registered_roots_match_source_and_packaged_metadata_is_not_a_root(self):
        build = ast.parse((SOURCE / "testing/mozbase/moz.build").read_bytes())
        registered = next(
            ast.literal_eval(node.value)
            for node in build.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "python_modules"
                for target in node.targets
            )
        )
        self.assertEqual(list(hosted.MOZBASE_MODULES), registered)
        plan = read_json(self.support / "plan.json")
        source_hashes = {row["path"]: row["sha256"] for row in plan["sourceMaterials"]}
        for name in ("moz.build", "setup_development.py"):
            self.assertEqual(
                file_digest(SOURCE / "testing/mozbase" / name),
                source_hashes["testing/mozbase/" + name],
            )
        roots = hosted.consumer_module_roots(self.support)
        self.assertEqual(
            roots[2:-1], [self.support / "mozbase" / name for name in registered]
        )
        self.assertNotIn(self.support / "mozbase/setup_development.py", roots)

    def test_unknown_root_file_and_directory_are_rejected(self):
        unknown = self.support / "mozbase/unknown"
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                if kind == "file":
                    unknown.write_text("unexpected")
                else:
                    unknown.mkdir()
                with self.assertRaises(ValueError):
                    hosted.consumer_module_roots(self.support)
                if kind == "file":
                    unknown.unlink()
                else:
                    unknown.rmdir()

    def test_missing_module_and_linked_module_are_rejected(self):
        module = self.support / "mozbase/manifestparser"
        module.rmdir()
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)
        outside = self.root / "outside"
        outside.mkdir()
        module.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)

    def test_missing_changed_or_linked_metadata_is_rejected(self):
        metadata = self.support / "mozbase/setup_development.py"
        original = metadata.read_bytes()
        metadata.unlink()
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)
        metadata.write_bytes(original + b"\nchanged = True\n")
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)
        metadata.unlink()
        outside = self.root / "setup_development.py"
        outside.write_bytes(original)
        metadata.symlink_to(outside)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)

    def test_linked_mozbase_root_is_rejected(self):
        root = self.support / "mozbase"
        outside = self.root / "outside"
        root.rename(outside)
        root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)


class HostedCargoPackagingClosure(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, directory, platform, arch, pgo, flag):
        import subprocess

        directory.mkdir()
        home = directory / "home"
        cargo = home / ".cargo"
        cargo.mkdir(parents=True)
        (cargo / "configured-tool-fixture").write_text("retained tool fixture")
        commands = directory / "bin"
        commands.mkdir()
        helpers = {
            "nproc": "printf '4\\n'\n",
            "sudo": "exit 0\n",
            "xvfb-run": 'shift 3\nexec "$@"\n',
        }
        for name, body in helpers.items():
            target = commands / name
            target.write_text("#!/usr/bin/env bash\n" + body)
            target.chmod(0o755)
        mach = directory / "mach"
        mach.write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s\\n" "$1" >> fixture-mach-invocations\n'
            'if [[ "$1" == "package" ]]; then\n'
            "  mkdir -p obj-x86_64-pc-linux-gnu/dist/{bin,host}\n"
            "  printf 'fixture' > obj-x86_64-pc-linux-gnu/dist/floorp-fixture.tar.xz\n"
            "  printf 'fixture' > obj-x86_64-pc-linux-gnu/dist/host/fixture\n"
            '  printf "BuildID=%s\\n" "$MOZ_BUILD_DATE" > obj-x86_64-pc-linux-gnu/dist/bin/application.ini\n'
            '  printf \'#!/usr/bin/env bash\\nprintf "%%s %%s\\\\n" "$MOZ_BUILD_DATE" "$MOZ_BUILD_DATE"\\n\' > obj-x86_64-pc-linux-gnu/dist/bin/floorp\n'
            "  chmod +x obj-x86_64-pc-linux-gnu/dist/bin/floorp\n"
            "fi\n"
        )
        mach.chmod(0o755)
        env = {
            "HOME": str(home),
            "PATH": str(commands) + ":/usr/bin:/bin",
            "LANG": "C.UTF-8",
        }
        if flag is not None:
            env["QA3_KEEP_CARGO_FOR_TEST_PACKAGING"] = flag
        result = subprocess.run(
            [
                "/bin/bash",
                str(SOURCE / ".github/workflows/scripts/build-and-package.sh"),
                platform,
                arch,
                "20261011000000",
                pgo,
            ],
            cwd=directory,
            env=env,
            capture_output=True,
            timeout=20,
            check=False,
        )
        return result, cargo

    def test_actual_shell_keeps_only_opt_in_tools_and_default_cleanup_is_preserved(
        self,
    ):
        for index, flag in enumerate((None, "0", "1")):
            with self.subTest(flag=flag):
                directory = self.root / str(index)
                result, cargo = self.invoke(directory, "linux", "x86_64", "", flag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(cargo.exists(), flag == "1")
                self.assertEqual(
                    (directory / "fixture-mach-invocations").read_text(),
                    "configure\nbuild\npackage\n",
                )
                self.assertTrue(
                    (
                        directory
                        / "home/output/floorp-linux-x86_64-moz-artifact-bundle/floorp-linux-x86_64-moz-artifact.tar.xz"
                    ).is_file()
                )

    def test_invalid_opt_in_routes_are_rejected_before_any_mach_command(self):
        for index, (platform, arch, pgo, flag) in enumerate((
            ("mac", "x86_64", "", "1"),
            ("windows", "x86_64", "", "1"),
            ("linux", "aarch64", "", "1"),
            ("linux", "x86_64", "generate", "1"),
            ("linux", "x86_64", "use", "1"),
            ("linux", "x86_64", "", "true"),
        )):
            with self.subTest(platform=platform, arch=arch, pgo=pgo, flag=flag):
                directory = self.root / str(index)
                result, cargo = self.invoke(directory, platform, arch, pgo, flag)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(cargo.is_dir())
                self.assertFalse((directory / "fixture-mach-invocations").exists())


if __name__ == "__main__":
    unittest.main()
