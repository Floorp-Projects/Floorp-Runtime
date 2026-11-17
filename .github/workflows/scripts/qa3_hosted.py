# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Same-run hosted Debug packaging and cold-consumer contracts."""

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qa3_hosted_support import (
    PLAN_PATH,
    canary_case,
    extra_packaged_materials,
    harness_argv,
    install_canaries,
    merge_materials,
    native_schedule,
    stage_mochitest,
    verify_primary,
    verify_python_environment,
)
from qa3_mozlog import verify_mozlog
from qa3_native_io import (
    GIB,
    ExpansionBudget,
    IOBudget,
    capture_material_tree,
    child_environment,
    elf_identity,
    extract_archive,
    fresh,
    pack_tree,
    read_json,
    run_owned,
    write_json,
)
from qa3_native_transport import API, download_artifact, worker_boot_identity
from qa3_source_cohort import file_digest, hash_value, verify_patches
from runtime_build_context import derive_build_id, fetch_actions_run

REPOSITORY = "Floorp-Projects/Floorp-Runtime"
BRANCH = "codex/qa3-actions-native-proof-qa337-17"
WORKFLOW = ".github/workflows/qa3-hosted-linux-debug.yml"
PROFILE = "github-hosted-debug-to-blacksmith-consumer"
SEED_SHA = "5e9159d4b0e9d099125bf0b12bae9577f8da096f484ddd2a5d0ed5c334f103c9"
MAX_TRANSFER = 20 * GIB
MAX_ARTIFACT_STORAGE = 40 * GIB
WRAPPER_FILES = {"runtime.tar.xz", "test-support.tar.gz", "producer.json"}
AUTOMATION_PHASES = (
    "BUILD_SYMBOLS",
    "PACKAGE",
    "PACKAGE_TESTS",
    "PACKAGE_GENERATED_SOURCES",
    "UPLOAD_SYMBOLS",
    "UPLOAD",
    "CHECK",
)
MOZBASE_MODULES = (
    "manifestparser",
    "mozcrash",
    "mozdebug",
    "mozdevice",
    "mozfile",
    "mozgeckoprofiler",
    "mozhttpd",
    "mozinfo",
    "mozinstall",
    "mozleak",
    "mozlog",
    "moznetwork",
    "mozpower",
    "mozprocess",
    "mozprofile",
    "mozproxy",
    "mozrunner",
    "mozscreenshot",
    "mozserve",
    "mozshellutil",
    "mozsystemmonitor",
    "moztest",
    "mozversion",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_mode(platform_name, arch, debug, pgo, mode=""):
    require(
        type(debug) is bool
        and type(pgo) is bool
        and (platform_name, arch, debug, pgo, mode)
        == ("linux", "x86_64", True, False, ""),
        "hosted proof requires native Linux x64 canonical Debug without PGO",
    )


def context_from_environment(build_id):
    if os.environ.get("RUNTIME_NATIVE_DEBUG_ARTIFACTS") == "true":
        from runtime_native_debug import context_from_environment as normal_context
        return normal_context(build_id)
    require(re.fullmatch(r"[0-9]{14}", build_id), "invalid BuildID")
    sha = hash_value(os.environ["GITHUB_SHA"], 40)
    require(
        os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_EVENT_NAME") == "push"
        and os.environ.get("GITHUB_REF") == "refs/heads/" + BRANCH
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        and os.environ.get("GITHUB_WORKFLOW_SHA") == sha
        and os.environ.get("GITHUB_WORKFLOW_REF")
        == REPOSITORY + "/" + WORKFLOW + "@refs/heads/" + BRANCH,
        "foreign hosted workflow, source, branch or attempt",
    )
    event = read_json(Path(os.environ["GITHUB_EVENT_PATH"]))
    require(
        event.get("created") is True and event.get("deleted") is False,
        "proof is limited to first branch creation",
    )
    run = os.environ["GITHUB_RUN_ID"]
    require(re.fullmatch(r"[1-9][0-9]*", run), "invalid run")
    return {
        "schema": "qa3-hosted-context-v1",
        "profile": PROFILE,
        "executionRepository": REPOSITORY,
        "controllerHead": sha,
        "runtimeRecipe": sha,
        "run": int(run),
        "attempt": 1,
        "buildID": build_id,
        "publicationAuthorized": False,
    }


def validate_context(value):
    if value.get("profile") in {"runtime-native-debug-artifact-v2", "runtime-native-debug-validation-v2"}:
        from runtime_native_debug import validate_context as normal_validate
        return normal_validate(value)
    require(
        set(value)
        == {
            "schema",
            "profile",
            "executionRepository",
            "controllerHead",
            "runtimeRecipe",
            "run",
            "attempt",
            "buildID",
            "publicationAuthorized",
        }
        and value["schema"] == "qa3-hosted-context-v1"
        and value["profile"] == PROFILE
        and value["executionRepository"] == REPOSITORY
        and value["controllerHead"] == value["runtimeRecipe"]
        and type(value["run"]) is int
        and value["run"] > 0
        and type(value["attempt"]) is int
        and value["attempt"] == 1
        and value["publicationAuthorized"] is False
        and re.fullmatch(r"[0-9]{14}", value["buildID"]),
        "invalid hosted context",
    )
    hash_value(value["runtimeRecipe"], 40)
    return value


def host_identity():
    release = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    value = {
        "os": release.get("ID", "").strip('"'),
        "version": release.get("VERSION_ID", "").strip('"'),
        "machine": platform.machine(),
        "pythonABI": f"cp{sys.version_info.major}{sys.version_info.minor}",
        "libc": list(platform.libc_ver()),
    }
    require(
        value["os"] == "ubuntu"
        and value["version"] == "24.04"
        and value["machine"] == "x86_64"
        and value["pythonABI"] == "cp312"
        and value["libc"][0] == "glibc",
        "unqualified hosted OS/architecture/Python/libc",
    )
    return value


def validate_effective(value, source, objdir):
    require(
        value.get("schemaVersion") == 1
        and value.get("source") == str(source.resolve())
        and value.get("objdir") == str(objdir.resolve()),
        "effective source/OBJDIR differs from existing build",
    )
    substs = value["substs"]
    for name in (
        "ENABLE_TESTS",
        "MOZ_DEBUG",
        "MOZ_AUTOMATION",
        "COMPILE_ENVIRONMENT",
        "LINK_GTEST_DURING_COMPILE",
    ):
        require(
            type(substs.get(name)) in {bool, int, str}
            and substs[name] in (True, 1, "1"),
            "effective Debug/test staging prerequisites missing",
        )
    require(
        "JS_DISABLE_SHELL" in substs
        and substs["JS_DISABLE_SHELL"] in (None, False, 0, "", "0"),
        "effective JS shell disabled or unknown",
    )
    for name in ("MOZ_ARTIFACT_BUILDS", "MOZ_PROFILE_GENERATE", "MOZ_PROFILE_USE"):
        require(substs.get(name) in (None, False, 0, "", "0"), "artifact/PGO build")
    require(
        substs.get("TARGET_CPU") == "x86_64"
        and substs.get("OS_TARGET") == "Linux"
        and substs.get("target") == "x86_64-pc-linux-gnu",
        "wrong effective native target",
    )


def raw_git(source, *args):
    return subprocess.check_output(
        [
            "/usr/bin/git",
            "-C",
            str(source),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "safe.directory=" + str(source.resolve()),
            *args,
        ],
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
        timeout=60,
    )


def source_stamp_environment(source, context):
    validate_context(context)
    require(
        raw_git(source, "rev-parse", "HEAD").decode().strip()
        == context["runtimeRecipe"],
        "checkout differs from original R",
    )
    values = {
        "MOZ_SOURCE_REPO": "https://github.com/" + REPOSITORY,
        "MOZ_SOURCE_CHANGESET": context["runtimeRecipe"],
        "MH_BRANCH": BRANCH,
    }
    require(
        all(os.environ.get(name) in (None, value) for name, value in values.items()),
        "conflicting inherited source identity",
    )
    return values


def read_seed_metadata(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate seed JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def verify_seed_archive(path, lock):
    require(not path.is_symlink() and path.is_file(), "seed is not a regular file")
    raw = path.read_bytes()
    require(len(raw) <= 8 * 1024**2 and hashlib.sha256(raw).hexdigest() == lock["seedSha256"], "seed pin mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        require(0 < len(names) <= 256 and len(set(names)) == len(names), "duplicate or excessive seed entries")
        require(len({name.casefold() for name in names}) == len(names), "case-alias seed entries")
        for entry in entries:
            name = entry.filename
            require(name and not name.startswith("/") and "\\" not in name and ":" not in name and all(part not in ("", ".", "..") for part in name.split("/")), "unsafe seed entry path")
            require(not entry.is_dir() and stat.S_ISREG(entry.external_attr >> 16) and not entry.flag_bits & 1, "nonregular or encrypted seed entry")
        require(sum(entry.file_size for entry in entries) <= 16 * 1024**2, "oversized seed payload")
        data = {name: archive.read(name) for name in names}
    digest = lambda value: hashlib.sha256(value).hexdigest()
    manifest = read_seed_metadata(data["manifest.json"])
    rows = manifest["payloads"]
    require(manifest["schema"] == "qa335-static-seed-manifest-v1" and manifest["publicationAuthorized"] is False, "seed manifest schema")
    require(len(rows) == len({row["path"] for row in rows}) and {row["path"] for row in rows} == set(names) - {"manifest.json"}, "seed manifest inventory mismatch")
    for row in rows:
        payload = data[row["path"]]
        require(type(row["bytes"]) is int and row["bytes"] == len(payload) and row["sha256"] == digest(payload), "seed payload digest mismatch")
    inputs = read_seed_metadata(data["inputs.json"])
    require(inputs["runtimeBaseline"] == lock["runtimeBaseline"] and re.fullmatch(r"[0-9a-f]{40}", inputs["runtimeBaseline"]), "seed runtime provenance mismatch")
    require(inputs["schema"] == "qa335-static-preparation-seed-v1" and inputs["publicationAuthorized"] is False, "seed inputs schema")
    source = read_seed_metadata(data["reference/source-wheels.provenance.json"])
    marionette = read_seed_metadata(data["reference/marionette-source-wheel.provenance.json"])
    require(source["runtimeSource"] == marionette["runtime"] == inputs["runtimeBaseline"] and all(row["runtimeSource"] == inputs["runtimeBaseline"] for row in source["packages"]), "source provenance identity mismatch")
    source_names = {name for name in names if name.startswith("source-wheels/")}
    require(inputs["sourceWheels"]["count"] == len(source_names) and inputs["sourceWheels"]["bytes"] == sum(len(data[name]) for name in source_names), "source wheel aggregate mismatch")
    profiles = inputs["profiles"]
    require(len(profiles) == len({p["profile"] for p in profiles}) and {p["profile"] for p in profiles} == {"build", "taskgraph", "consumer"}, "seed profile inventory mismatch")
    for profile in profiles:
        requirements = data["profiles/" + profile["profile"] + "/requirements.lock"]
        require(profile["requirementsSha256"] == digest(requirements), "seed requirements hash mismatch")
        wheels = profile["wheels"]
        require(len(wheels) == len({w["filename"] for w in wheels}), "duplicate profile wheel")
        require(set(re.findall(r"--hash=sha256:([0-9a-f]{64})", requirements.decode())) == {w["sha256"] for w in wheels}, "profile requirement wheel mismatch")
        for wheel in wheels:
            if wheel["source"].startswith("source-wheels/"):
                require(wheel["source"] in source_names and PurePosixPath(wheel["source"]).name == wheel["filename"], "source wheel filename mismatch")
                payload = data[wheel["source"]]
                require(wheel["bytes"] == len(payload) and wheel["sha256"] == digest(payload), "source wheel digest mismatch")
        if profile["profile"] == "consumer":
            require(profile["requirementsSha256"] == lock["requirementsSha256"], "consumer requirements lock mismatch")
            fields = ("filename", "bytes", "sha256", "source")
            require([{k: w[k] for k in fields} for w in wheels] == [{k: w[k] for k in fields} for w in lock["wheels"]], "consumer wheel lock mismatch")
            require({w["source"] for w in wheels if w["source"].startswith("source-wheels/")} == source_names, "unbound source wheel")
    return {"entries": len(names), "sourceWheels": len(source_names), "sha256": digest(raw)}


def python_inputs(source, runtime, destination):
    lock = read_json(source / ".github/qa/hosted-consumer-python.lock.json")
    seed = source / ".github/qa/hosted-consumer-seed.zip"
    require(lock["seedSha256"] == SEED_SHA == file_digest(seed), "seed changed")
    require(
        lock.get("schema") == "qa3-hosted-consumer-python-lock-v1"
        and lock.get("readiness") == "INPUTS_LOCKED_NOT_TARGET_QUALIFIED"
        and lock.get("pythonABI") == "cp312"
        and lock.get("target") == "x86_64-pc-linux-gnu"
        and lock.get("publicationAuthorized") is False
        and len(lock["wheels"]) == 40
        and len({r["filename"] for r in lock["wheels"]}) == 40
        and all(
            type(r["bytes"]) is int and 0 < r["bytes"] <= 64 * 1024**2
            for r in lock["wheels"]
        )
        and sum(r["bytes"] for r in lock["wheels"]) <= 4 * 1024**2,
        "unqualified Python wheel lock",
    )
    fresh(destination)
    (destination / "wheelhouse").mkdir()
    verify_seed_archive(seed, lock)
    with zipfile.ZipFile(seed) as z:
        provenance = [
            read_seed_json(z, "reference/source-wheels.provenance.json"),
            read_seed_json(z, "reference/marionette-source-wheel.provenance.json"),
        ]
        groups = provenance[0]["packages"]
        for package in groups:
            rows = package["trackedFiles"]
            expected = {r["path"] for r in rows}
            actual = set(
                raw_git(
                    source,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    runtime,
                    "--",
                    package["sourcePath"],
                )
                .decode()
                .splitlines()
            )
            require(actual == expected, "source wheel package tree changed at R")
            for row in rows:
                raw = raw_git(source, "cat-file", "blob", runtime + ":" + row["path"])
                require(
                    len(raw) == row["bytes"]
                    and hashlib.sha256(raw).hexdigest() == row["sha256"],
                    "source wheel blob changed at R",
                )
        marionette = provenance[1]["files"]
        require(
            set(
                raw_git(
                    source,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    runtime,
                    "--",
                    "testing/marionette/client",
                )
                .decode()
                .splitlines()
            )
            == {r["path"] for r in marionette},
            "marionette source tree changed",
        )
        for row in marionette:
            raw = raw_git(source, "cat-file", "blob", runtime + ":" + row["path"])
            require(
                len(raw) == row["bytes"]
                and hashlib.sha256(raw).hexdigest() == row["sha256"],
                "marionette source differs at R",
            )
        raw = z.read("profiles/consumer/requirements.lock")
        require(
            hashlib.sha256(raw).hexdigest() == lock["requirementsSha256"],
            "requirements changed",
        )
        (destination / "requirements.lock").write_bytes(raw)
        for item in lock["wheels"]:
            name = item["filename"]
            require(re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", name), "unsafe wheel")
            target = destination / "wheelhouse" / name
            if item["source"].startswith("source-wheels/"):
                raw = z.read(item["source"])
            else:
                parsed = urllib.parse.urlsplit(item["url"])
                require(
                    parsed.scheme == "https"
                    and parsed.hostname == "files.pythonhosted.org"
                    and not parsed.query
                    and not parsed.username,
                    "foreign wheel URL",
                )
                with urllib.request.urlopen(item["url"], timeout=30) as response:
                    raw = response.read(item["bytes"] + 1)
            require(
                len(raw) == item["bytes"]
                and hashlib.sha256(raw).hexdigest() == item["sha256"],
                "wheel bytes/hash differ",
            )
            target.write_bytes(raw)
    snapshot = capture_material_tree(destination)
    verify_python_environment(destination, snapshot["sha256"])
    return snapshot["sha256"]


def read_seed_json(z, name):
    from runtime_build_context import parse_rest_json

    return parse_rest_json(z.read(name))


def verify_compiled_source(value, pin, runtime):
    require(
        value.get("schema_version") == pin.get("schema_version") == 1
        and value.get("runtime_commit") == runtime
        and value.get("upstream") == pin.get("upstream")
        and value.get("floorp_patch") == pin.get("floorp_patch"),
        "compiled Firefox/Floorp source receipt differs from pinned distribution",
    )
    hash_value(pin["upstream"]["commit"], 40)
    hash_value(pin["floorp_patch"]["commit"], 40)
    hash_value(pin["floorp_patch"]["sha256"])


def verify_recipe_metadata(recipe, value):
    if value.get("context", {}).get("profile") in {"runtime-native-debug-artifact-v2", "runtime-native-debug-validation-v2"}:
        from runtime_native_debug import assertion_source_identity
        require(value.get("assertionSourceSha256") == assertion_source_identity(recipe, working_tree=False),
                "assertion source differs from trusted Runtime recipe")
    require(
        read_json(recipe / ".github/runtime-upstream.json") == value["runtimeUpstream"]
        and read_json(recipe / ".github/qa/source-policy.json") == value["sourcePolicy"]
        and file_digest(recipe / PLAN_PATH) == value["planSha256"],
        "producer metadata differs from original Runtime recipe",
    )


def verify_support(support, value):
    require(
        capture_material_tree(support) == value["supportInventory"],
        "support inventory changed",
    )
    verify_python_environment(
        support / "python-environment", value["pythonEnvironmentSha256"]
    )
    for name in ("gmp-fake", "gmp-fakeopenh264"):
        plugin = support / "bin/plugins" / name / "1.0"
        require(
            plugin.is_dir()
            and not plugin.is_symlink()
            and any(path.is_file() for path in plugin.iterdir()),
            "same-build GMP test plugin is missing",
        )
    require(file_digest(support / "plan.json") == value["planSha256"], "plan changed")
    plan = read_json(support / "plan.json")
    require(
        plan.get("role") == "canonical-debug"
        and plan.get("target") == "x86_64-pc-linux-gnu"
        and plan.get("publicationAuthorized") is False,
        "finite required Debug selection differs",
    )
    schedule = native_schedule(plan)
    source_hashes = {r["path"]: r["sha256"] for r in plan["sourceMaterials"]}
    require(len(source_hashes) == len(plan["sourceMaterials"]), "duplicate source pin")
    for case in plan["selection"]:
        require(
            case["requiredNoSkip"] is True
            and type(case["minimumAssertions"]) is int
            and case["minimumAssertions"] > 0
            and file_digest(support / case["archivePath"]) == source_hashes[case["id"]],
            "required packaged test differs from pinned source",
        )
    require(len(value["canaryTransforms"]) == 2, "canary transform count differs")
    for _, case, canary in schedule:
        if canary:
            canary_case(case, support, value)
    for source, archive in (
        *extra_packaged_materials(),
        ("testing/mochitest/runtests.py", "mochitest/runtests.py"),
        ("testing/mochitest/mochitest_options.py", "mochitest/mochitest_options.py"),
        ("testing/xpcshell/runxpcshelltests.py", "xpcshell/runxpcshelltests.py"),
        ("testing/xpcshell/xpcshellcommandline.py", "xpcshell/xpcshellcommandline.py"),
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
        ("testing/mozbase/setup_development.py", "mozbase/setup_development.py"),
    ):
        require(
            file_digest(support / archive) == source_hashes[source],
            "packaged Mozilla harness differs",
        )
    require(
        {
            name: elf_identity(support / "bin" / name)
            for name in ("xpcshell", "ssltunnel", "certutil", "pk12util")
        }
        == value["helpers"],
        "same-build helper identity differs",
    )
    return plan


def build_environment(source, context):
    require(
        "TASK_ID" not in os.environ and "MACH_NO_FUNC_CACHE" not in os.environ,
        "hosted route requires standalone source cache metadata",
    )
    values = source_stamp_environment(source, context)
    values.update(
        MOZ_AUTOMATION="1",
        MOZ_OBJDIR=str(source.resolve() / "obj-x86_64-pc-linux-gnu"),
        UPLOAD_DIR=str(
            source.resolve() / "obj-x86_64-pc-linux-gnu" / "qa3-artifact-metrics"
        ),
        MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE="pip",
        TASKCLUSTER_ROOT_URL="https://firefox-ci-tc.services.mozilla.com",
        MOZ_SCM_LEVEL="3",
    )
    values.update({"MOZ_AUTOMATION_" + name: "0" for name in AUTOMATION_PHASES})
    return values


def producer_environment(source, objdir, build_id):
    env = child_environment(
        source, {"MOZ_BUILD_DATE": build_id, "MOZ_OBJDIR": str(objdir.resolve())}
    )
    env["MOZBUILD_STATE_PATH"] = os.environ.get(
        "MOZBUILD_STATE_PATH", str(Path(env["HOME"]) / ".mozbuild")
    )
    env["MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE"] = "pip"
    env["SCCACHE_GHA_RW_MODE"] = "READ_ONLY"
    env["TASKCLUSTER_ROOT_URL"] = "https://firefox-ci-tc.services.mozilla.com"
    env["MOZ_SCM_LEVEL"] = "3"
    env["UPLOAD_DIR"] = str(objdir.resolve() / "qa3-artifact-metrics")
    return env


def bootstrap_metadata_environment(env):
    prepared = dict(env)
    require(
        "TASK_ID" not in prepared and "MACH_NO_FUNC_CACHE" not in prepared,
        "hosted metadata cannot impersonate Taskcluster or disable source cache",
    )
    prepared.pop("MOZ_AUTOMATION", None)
    return prepared


def verify_bootstrap_catalog(prepared, verified, source, state):
    require(
        set(prepared)
        == {
            "schema",
            "source",
            "state",
            "sourceCacheKey",
            "cacheBytes",
            "cacheSha256",
            "catalogBytes",
            "catalogSha256",
            "catalogTasks",
            "dynamicInputs",
            "cacheEnvironment",
            "nativeExecuted",
            "publicationAuthorized",
        },
        "missing bootstrap catalog evidence",
    )
    for name in ("sourceCacheKey", "cacheSha256", "catalogSha256"):
        require(
            isinstance(prepared[name], str)
            and re.fullmatch(r"[a-f0-9]{64}", prepared[name]),
            "invalid bootstrap catalog digest",
        )
    for name, maximum in (
        ("cacheBytes", 8 * 1024**2),
        ("catalogBytes", 8 * 1024**2),
        ("catalogTasks", 10000),
    ):
        require(
            type(prepared[name]) is int and 0 < prepared[name] <= maximum,
            "invalid bootstrap catalog size",
        )
    require(
        isinstance(prepared["dynamicInputs"], list)
        and 0 < len(prepared["dynamicInputs"]) <= 4096
        and all(isinstance(name, str) and name for name in prepared["dynamicInputs"]),
        "missing bootstrap catalog source inputs",
    )
    require(
        prepared == verified
        and prepared.get("schema") == "qa3-hosted-bootstrap-catalog-v1"
        and prepared.get("source") == str(source.resolve())
        and prepared.get("state") == str(state.resolve())
        and prepared.get("nativeExecuted") is False
        and prepared.get("publicationAuthorized") is False
        and prepared.get("cacheEnvironment")
        == {
            "TASKCLUSTER_ROOT_URL": "https://firefox-ci-tc.services.mozilla.com",
            "MOZ_SCM_LEVEL": "3",
        },
        "metadata preparation and automated build source cache differ",
    )


def emit_owned_failure(logs, name, *, data_stdout=False):
    require(re.fullmatch(r"[a-z0-9-]{1,80}", name), "invalid diagnostic phase")
    value = {"schema": "qa3-owned-failure-diagnostic-v1", "phase": name}
    receipt = logs / (name + ".process.json")
    if (
        receipt.is_file()
        and not receipt.is_symlink()
        and receipt.stat().st_size <= 65536
    ):
        process = read_json(receipt)
        exit_code = process.get("exit")
        stop = process.get("stop")
        value.update(
            exit=exit_code if type(exit_code) is int else None,
            stop=stop
            if isinstance(stop, str) and re.fullmatch(r"[A-Z_]{1,80}", stop)
            else None,
            ownedCleanupComplete=process.get("ownedCleanupComplete") is True,
        )
        data_stdout = data_stdout or process.get("stdoutIsData") is True
    tails = []
    for kind in ("stderr", "stdout"):
        if kind == "stdout" and data_stdout:
            continue
        path = logs / (name + "." + kind)
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 16384))
            raw = stream.read(16384)
        text = raw.decode("utf-8", errors="replace")
        tails.append({
            "stream": kind,
            "originalBytes": path.stat().st_size,
            "inspectedTailBytes": len(raw),
            "tailSha256": hashlib.sha256(raw).hexdigest(),
            "exceptionClasses": sorted(
                set(re.findall(r"\b([A-Za-z_]\w*(?:Error|Exception))\b", text))
            )[:8],
            "missingModules": sorted(
                set(
                    re.findall(
                        r"No module named ['\"]([A-Za-z0-9_.]{1,120})['\"]", text
                    )
                )
            )[:8],
            "makeExitCodes": sorted(
                set(map(int, re.findall(r"\*\*\* .* Error ([0-9]{1,3})\b", text)))
            )[:8],
        })
    value["boundedTypedTails"] = tails
    print(json.dumps(value, sort_keys=True), flush=True)


def run_diagnosed(argv, cwd, env, logs, name, timeout, **kwargs):
    try:
        return run_owned(argv, cwd, env, logs, name, timeout, **kwargs)
    except BaseException:
        try:
            emit_owned_failure(
                logs, name, data_stdout=kwargs.get("data_stdout") is True
            )
        except BaseException:
            try:
                print(
                    json.dumps({
                        "schema": "qa3-owned-failure-diagnostic-v1",
                        "phase": name,
                        "diagnosticUnavailable": True,
                    }),
                    flush=True,
                )
            except BaseException:
                pass
        raise


def verify_source_patch_policy(source):
    policy = read_json(source / ".github/qa/source-policy.json")
    for field, directory in (("commonPatches", "upstream"), ("debugPatches", "debug")):
        verify_patches(source, policy[field], ".github/patches/" + directory)
    return policy


def packaging_preflight(args):
    verify_seed_archive(args.source / ".github/qa/hosted-consumer-seed.zip",
                        read_json(args.source / ".github/qa/hosted-consumer-python.lock.json"))
    verify_source_patch_policy(args.source)
    context = context_from_environment(args.build_id)
    env = producer_environment(args.source, args.objdir, context["buildID"])
    env.update(source_stamp_environment(args.source, context))
    output = fresh(args.output)
    logs = fresh(output / "logs")
    bootstrap_processes = []
    bootstrap_records = []
    for phase in ("prepare", "verify"):
        record = output / ("bootstrap-" + phase + ".json")
        bootstrap_processes.append(
            run_diagnosed(
                [
                    "/usr/bin/python3.12",
                    str(args.source / "mach"),
                    "python",
                    "--virtualenv",
                    "build",
                    str(Path(__file__).parent / "qa3_bootstrap_probe.py"),
                    "--source",
                    str(args.source),
                    "--phase",
                    phase,
                    "--output",
                    str(record),
                ],
                args.source,
                bootstrap_metadata_environment(env) if phase == "prepare" else env,
                logs,
                "bootstrap-catalog-" + phase,
                180,
                log_limit=16 * 1024**2,
            )
        )
        bootstrap_records.append(read_json(record))
    verify_bootstrap_catalog(
        *bootstrap_records, args.source, Path(env["MOZBUILD_STATE_PATH"])
    )
    decoder_version = run_diagnosed(
        ["/usr/bin/zstd", "--version"],
        args.source,
        env,
        logs,
        "packaging-decoder-version",
        10,
        log_limit=1024**2,
    )
    result = run_diagnosed(
        [
            "/usr/bin/python3.12",
            str(args.source / "mach"),
            "python",
            "--virtualenv",
            "build",
            str(Path(__file__).parent / "qa3_packaging_probe.py"),
            "--source",
            str(args.source),
            "--output",
            str(output / "probe.json"),
        ],
        args.source,
        env,
        logs,
        "packaging-python-preflight",
        180,
        log_limit=16 * 1024**2,
    )
    probe = read_json(output / "probe.json")
    require(
        probe.get("verdict") == "PASS_SOURCE_ARCHIVE_ONLY",
        "packaging Python preflight failed",
    )
    archive = output / "probe-fixture.tar.zst"
    require(
        archive.stat().st_size <= 65536
        and file_digest(archive) == probe["probeArchiveSha256"],
        "packaging decoder fixture changed",
    )
    decoder = run_diagnosed(
        ["/usr/bin/zstd", "-d", "--stdout", "--", str(archive)],
        args.source,
        env,
        logs,
        "packaging-decoder-roundtrip",
        10,
        data_stdout=True,
        data_limit=16384,
        io_budget=IOBudget(output, maximum=32 * 1024**2, minimum_free=GIB),
        log_limit=1024**2,
    )
    require(
        file_digest(logs / "packaging-decoder-roundtrip.stdout")
        == probe["probeTarSha256"],
        "packaging decoder roundtrip differs",
    )
    write_json(
        output / "preflight.json",
        {
            "context": context,
            "probe": probe,
            "process": result,
            "decoderVersionProcess": decoder_version,
            "decoderProcess": decoder,
            "bootstrapCatalog": bootstrap_records[0],
            "bootstrapProcesses": bootstrap_processes,
            "publicationAuthorized": False,
        },
    )
    print(
        json.dumps(
            {
                "schema": "qa3-packaging-preflight-v1",
                "context": context,
                "probe": probe,
                "fixedDecoderRoundtrip": "PASS_SOURCE_FIXTURE_ONLY",
                "bootstrapCatalog": bootstrap_records[0],
            },
            sort_keys=True,
        ),
        flush=True,
    )


def consumer_module_roots(support):
    mozbase = support / "mozbase"
    require(mozbase.is_dir() and not mozbase.is_symlink(), "missing packaged mozbase")
    require(
        {path.name for path in mozbase.iterdir()}
        == {*MOZBASE_MODULES, "setup_development.py"},
        "unexpected packaged mozbase entries",
    )
    metadata = mozbase / "setup_development.py"
    source_hashes = {
        row["path"]: row["sha256"]
        for row in read_json(support / "plan.json")["sourceMaterials"]
    }
    require(
        metadata.is_file()
        and not metadata.is_symlink()
        and file_digest(metadata)
        == source_hashes.get("testing/mozbase/setup_development.py"),
        "packaged mozbase metadata differs from pinned source",
    )
    process_types = support / "tools/geckoprocesstypes_generator"
    require(
        process_types.is_dir()
        and not process_types.is_symlink()
        and (process_types / "geckoprocesstypes/__init__.py").is_file()
        and not (process_types / "geckoprocesstypes/__init__.py").is_symlink(),
        "missing packaged Gecko process-type module",
    )
    modules = [
        support / "modules",
        support,
        *(mozbase / name for name in MOZBASE_MODULES),
        process_types,
    ]
    require(
        all(p.is_dir() and not p.is_symlink() for p in modules), "missing mozbase roots"
    )
    return modules


def artifact_storage_budget(primary, output):
    entries = capture_material_tree(primary)["entries"]
    sizes = {row["path"]: (primary / row["path"]).stat().st_size for row in entries}
    primary_bytes = sum(sizes.values())
    host_bytes = sum(
        size for path, size in sizes.items() if path.startswith("dist-host/")
    )
    application_bytes = sizes["floorp-application.ini"]
    support_bytes = sum(
        (output / name).stat().st_size
        for name in ("runtime.tar.xz", "test-support.tar.gz")
    )
    total = (
        primary_bytes
        + host_bytes
        + application_bytes
        + support_bytes
        + 16 * 1024**2
        + 512 * 1024**2
    )
    require(total <= MAX_ARTIFACT_STORAGE, "whole-run artifact storage budget exceeded")
    return {
        "maximumBytes": MAX_ARTIFACT_STORAGE,
        "boundedBytes": total,
        "retentionDays": 1,
        "primaryBundleBytes": primary_bytes,
        "distHostDuplicateBytes": host_bytes,
        "applicationDuplicateBytes": application_bytes,
        "consumerAndDiagnosticsReservedBytes": 512 * 1024**2,
    }


def verify_packaged_build_cohort(
    before, after, primary_before, primary_after, source, objdir
):
    validate_effective(before, source, objdir)
    validate_effective(after, source, objdir)
    require(
        before == after and primary_before == primary_after,
        "test packaging changed effective configuration or compiled primary",
    )


def verify_test_install(value, objdir):
    require(
        value.get("schema") == "qa3-test-install-manifest-v1"
        and value.get("verdict") == "PASS_GENERATED_MANIFEST_NORMALIZATION"
        and value.get("nativeExecuted") is False
        and value.get("manifest")
        == str(objdir / "_build_manifests/install/_test_files")
        and type(value.get("expandedDirectoryCount")) is int
        and type(value.get("expandedFileCount")) is int
        and 0 <= value["expandedDirectoryCount"] <= value["expandedFileCount"]
        and value["expandedDirectoryCount"]
        == len(value.get("expandedDirectories", [])),
        "missing generated test-manifest normalization evidence",
    )
    hash_value(value["beforeSha256"])
    hash_value(value["afterSha256"])
    require(
        value["expandedDirectoryCount"] == 0
        or value["beforeSha256"] != value["afterSha256"],
        "directory test links were not normalized",
    )


def produce(args):
    context = context_from_environment(args.build_id)
    require(
        raw_git(args.source, "rev-parse", "HEAD").decode().strip()
        == context["runtimeRecipe"],
        "checkout differs from original R",
    )
    host = host_identity()
    output = fresh(args.output)
    logs = fresh(output / "logs")
    budget = IOBudget(output, maximum=30 * GIB, minimum_free=20 * GIB)
    expansion = ExpansionBudget()
    env = producer_environment(args.source, args.objdir, context["buildID"])
    env.update(source_stamp_environment(args.source, context))
    commands = []

    def command(name, argv, timeout, **kwargs):
        result = run_diagnosed(
            argv,
            args.source,
            env,
            logs,
            name,
            timeout,
            log_limit=16 * 1024**2,
            **kwargs,
        )
        commands.append(result)
        return result

    effective = output / "effective-config.json"
    command(
        "effective-config",
        [
            "/usr/bin/python3.12",
            str(args.source / "mach"),
            "python",
            "--virtualenv",
            "build",
            str(Path(__file__).parent / "qa3_config_probe.py"),
            "--source",
            str(args.source),
            "--objdir",
            str(args.objdir),
            "--output",
            str(effective),
        ],
        120,
    )
    effective_value = read_json(effective)
    validate_effective(effective_value, args.source, args.objdir)
    packages = sorted(args.primary.glob("*.tar.xz"))
    require(
        len(packages) == 1 and not packages[0].is_symlink(),
        "existing primary package missing",
    )
    primary = output / "runtime.tar.xz"
    shutil.copyfile(packages[0], primary)
    primary_root = output / "primary-expanded"
    extract_archive(primary, primary_root, budget=budget, expansion=expansion)
    identity = verify_primary(primary_root, context)
    compiled_identity = verify_primary(
        args.objdir / "dist",
        context,
        app=args.objdir / "dist/bin",
        object_root=args.objdir,
    )
    require(
        all(
            identity[k]["gnuBuildID"] == compiled_identity[k]["gnuBuildID"]
            for k in identity
        ),
        "packaged primary differs from same OBJDIR build",
    )
    test_install = output / "test-install-manifest.json"
    source_before_tests = hashlib.sha256(
        raw_git(args.source, "diff", "--binary", "HEAD", "--", ".", ":(exclude).github")
    ).hexdigest()
    command(
        "prepare-test-install",
        [
            "/usr/bin/python3.12",
            str(args.source / "mach"),
            "python",
            "--virtualenv",
            "build",
            str(Path(__file__).parent / "qa3_test_install.py"),
            "--source",
            str(args.source),
            "--objdir",
            str(args.objdir),
            "--output",
            str(test_install),
        ],
        120,
    )
    test_install_value = read_json(test_install)
    verify_test_install(test_install_value, args.objdir.resolve())
    command(
        "package-tests",
        [
            "/usr/bin/python3.12",
            str(args.source / "mach"),
            "build",
            "--jobs=1",
            "package-tests-common",
            "package-tests-mochitest",
            "package-tests-xpcshell",
        ],
        1800,
    )
    effective_after = output / "effective-config-after-tests.json"
    command(
        "effective-after-tests",
        [
            "/usr/bin/python3.12",
            str(args.source / "mach"),
            "python",
            "--virtualenv",
            "build",
            str(Path(__file__).parent / "qa3_config_probe.py"),
            "--source",
            str(args.source),
            "--objdir",
            str(args.objdir),
            "--output",
            str(effective_after),
        ],
        120,
    )
    effective_after_value = read_json(effective_after)
    compiled_after = verify_primary(
        args.objdir / "dist",
        context,
        app=args.objdir / "dist/bin",
        object_root=args.objdir,
    )
    verify_packaged_build_cohort(
        effective_value,
        effective_after_value,
        compiled_identity,
        compiled_after,
        args.source,
        args.objdir,
    )
    support = fresh(output / "support-expanded")
    archives = []
    for kind in ("common", "mochitest", "xpcshell"):
        matches = sorted((args.objdir / "dist").rglob(f"*.{kind}.tests.*"))
        require(
            len(matches) == 1 and not matches[0].is_symlink(),
            "missing same-OBJDIR tests",
        )
        archive = matches[0]
        archives.append({
            "kind": kind,
            "sha256": file_digest(archive),
            "bytes": archive.stat().st_size,
        })
        require(archive.name.endswith(".tar.zst"), "unqualified test archive format")
        command(
            "decode-" + kind,
            ["/usr/bin/zstd", "-d", "--stdout", "--", str(archive)],
            600,
            data_stdout=True,
            data_limit=30 * GIB,
            io_budget=budget,
        )
        archive = logs / ("decode-" + kind + ".stdout")
        stage = output / ("archive-" + kind)
        extract_archive(
            archive,
            stage,
            budget=budget,
            expansion=expansion,
            normalize_member_paths=True,
        )
        merge_materials(stage, support, budget)
        budget.release_tree(stage)
        if archive.parent == logs:
            budget.release_tree(archive)
    plan = read_json(args.source / PLAN_PATH)
    for row in plan["sourceMaterials"]:
        require(
            file_digest(args.source / row["path"]) == row["sha256"],
            "actual source differs from pinned harness/test selection",
        )
    native_schedule(plan)
    transforms = install_canaries(args.source, support, plan)
    shutil.copyfile(args.source / PLAN_PATH, support / "plan.json")
    python_sha = python_inputs(
        args.source, context["runtimeRecipe"], support / "python-environment"
    )
    helpers = {
        name: elf_identity(support / "bin" / name)
        for name in ("xpcshell", "ssltunnel", "certutil", "pk12util")
    }
    for name in ("modules", "certs", "mozbase", "mochitest", "xpcshell"):
        require(
            (support / name).is_dir() and any((support / name).iterdir()),
            "incomplete support",
        )
    consumer_module_roots(support)
    support_sha = pack_tree(support, output / "test-support.tar.gz", budget)
    source_record = read_json(args.primary / "runtime-source-provenance.json")
    upstream = read_json(args.source / ".github/runtime-upstream.json")
    verify_compiled_source(source_record, upstream, context["runtimeRecipe"])
    policy = verify_source_patch_policy(args.source)
    changes = raw_git(
        args.source, "diff", "--binary", "HEAD", "--", ".", ":(exclude).github"
    )
    source_after_tests = hashlib.sha256(changes).hexdigest()
    require(
        source_before_tests == source_after_tests,
        "test packaging changed the compiled source tree",
    )
    receipt = {
        "schema": "qa3-hosted-debug-producer-v1",
        "status": "PACKAGED_NOT_CONSUMED",
        "context": context,
        "bootSha256": worker_boot_identity(),
        "host": host,
        "objdir": str(args.objdir.resolve()),
        "effectiveConfig": effective_value,
        "effectiveConfigAfterTests": effective_after_value,
        "testInstallManifest": test_install_value,
        "runtimeUpstream": upstream,
        "sourcePolicy": policy,
        "actualSourceDeltaSha256": source_after_tests,
        "sourceDeltaBeforeTestsSha256": source_before_tests,
        "compiledSource": source_record,
        "archives": archives,
        "commands": commands,
        "primarySha256": file_digest(primary),
        "primaryIdentity": identity,
        "compiledIdentity": compiled_identity,
        "compiledIdentityAfterTests": compiled_after,
        "supportSha256": support_sha,
        "supportInventory": capture_material_tree(support),
        "pythonEnvironmentSha256": python_sha,
        "helpers": helpers,
        "planSha256": file_digest(support / "plan.json"),
        "canaryTransforms": transforms,
        "producer": "existing-common-build-github-hosted",
        "consumerVerdict": "UNVERIFIED",
        "publicationAuthorized": False,
        "artifactStorageBudget": artifact_storage_budget(args.primary, output),
    }
    if context["profile"] in {"runtime-native-debug-artifact-v2", "runtime-native-debug-validation-v2"}:
        from runtime_native_debug import verify_product_profile
        receipt["productProfile"] = verify_product_profile(args.source)
        from runtime_native_debug import assertion_source_identity
        receipt["assertionSourceSha256"] = assertion_source_identity(args.source)
    verify_support(support, receipt)
    write_json(output / "producer.json", receipt)
    require(
        (output / "producer.json").stat().st_size <= 16 * 1024**2,
        "producer receipt budget exceeded",
    )
    require(
        sum((output / name).stat().st_size for name in WRAPPER_FILES)
        <= MAX_TRANSFER - 1024**2,
        "producer transport budget exceeded",
    )
    return receipt


def validate_producer(value, context):
    validate_context(context)
    require(
        value.get("schema") == "qa3-hosted-debug-producer-v1"
        and value.get("status") == "PACKAGED_NOT_CONSUMED"
        and value.get("context") == context
        and value.get("producer") == "existing-common-build-github-hosted"
        and value.get("consumerVerdict") == "UNVERIFIED"
        and value.get("publicationAuthorized") is False,
        "foreign or incomplete producer",
    )
    if context["profile"] in {"runtime-native-debug-artifact-v2", "runtime-native-debug-validation-v2"}:
        from runtime_native_debug import PRODUCT_PROFILE
        require(value.get("productProfile") == PRODUCT_PROFILE, "native product profile mismatch")
        from runtime_native_debug import ASSERTION_SOURCE_FILES
        require(set(value.get("assertionSourceSha256", {})) == set(ASSERTION_SOURCE_FILES), "missing assertion source identity")
        for digest in value["assertionSourceSha256"].values(): hash_value(digest)
    hash_value(value["bootSha256"])
    require(
        value["bootSha256"] != worker_boot_identity(), "consumer reused producer boot"
    )
    require(value["host"] == host_identity(), "producer/consumer OS ABI differs")
    verify_compiled_source(
        value["compiledSource"], value["runtimeUpstream"], context["runtimeRecipe"]
    )
    require(
        all(
            value["primaryIdentity"][k]["gnuBuildID"]
            == value["compiledIdentity"][k]["gnuBuildID"]
            for k in ("floorp", "libxul.so")
        ),
        "same OBJDIR binary identity differs",
    )
    effective = value["effectiveConfig"]
    validate_effective(effective, Path(effective["source"]), Path(value["objdir"]))
    verify_test_install(value.get("testInstallManifest", {}), Path(value["objdir"]))
    require(
        value.get("sourceDeltaBeforeTestsSha256") == value["actualSourceDeltaSha256"],
        "missing or changed compiled source after test packaging",
    )
    require(
        value.get("effectiveConfigAfterTests") == effective
        and value.get("compiledIdentityAfterTests") == value["compiledIdentity"],
        "missing or changed post-packaging configure/build cohort",
    )
    require(
        [r["kind"] for r in value["archives"]] == ["common", "mochitest", "xpcshell"],
        "missing original test archives",
    )
    for row in value["archives"]:
        hash_value(row["sha256"])
        require(
            type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_TRANSFER,
            "invalid original test archive size",
        )
    for name in (
        "primarySha256",
        "supportSha256",
        "planSha256",
        "pythonEnvironmentSha256",
        "actualSourceDeltaSha256",
    ):
        hash_value(value[name])
    require(
        all(
            type(c.get("exit")) is int
            and c["exit"] == 0
            and c.get("stop") is None
            and c.get("ownedCleanupComplete") is True
            and not c.get("cancelled")
            and not c.get("error")
            and not c.get("cleanupErrors")
            for c in value["commands"]
        )
        and [c["name"] for c in value["commands"]]
        == [
            "effective-config",
            "prepare-test-install",
            "package-tests",
            "effective-after-tests",
            "decode-common",
            "decode-mochitest",
            "decode-xpcshell",
        ],
        "unexecuted, skipped, retried or failing producer phase",
    )
    return value


def acquire(args):
    context = context_from_environment(args.build_id)
    payload = fetch_actions_run(
        api_url=API,
        repository=REPOSITORY,
        workflow_run_id=str(context["run"]),
        github_token=os.environ["GITHUB_TOKEN"],
    )
    require(
        payload.get("id") == context["run"]
        and payload.get("head_sha") == context["runtimeRecipe"]
        and payload.get("run_attempt") == 1
        and payload.get("event") == "push"
        and payload.get("path") == WORKFLOW
        and payload.get("head_branch") == BRANCH,
        "REST run differs from original same-workflow producer",
    )
    require(
        derive_build_id(payload["created_at"]) == context["buildID"],
        "BuildID differs from original run creation",
    )
    fresh(args.output)
    archive = args.output / "original.zip"
    download_artifact(
        context,
        args.artifact_id,
        "support",
        args.artifact_sha256,
        archive,
    )
    destination = fresh(args.output / "inputs")
    unpack_wrapper(archive, destination)
    producer = validate_producer(read_json(destination / "producer.json"), context)
    verify_recipe_metadata(args.recipe, producer)
    require(
        file_digest(destination / "runtime.tar.xz") == producer["primarySha256"]
        and file_digest(destination / "test-support.tar.gz")
        == producer["supportSha256"],
        "original producer payload differs",
    )
    write_json(destination / "context.json", context)
    write_json(
        destination / "transport.json",
        {
            "artifactId": args.artifact_id,
            "zipSha256": args.artifact_sha256,
            "context": context,
        },
    )


def unpack_wrapper(archive, destination):
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        require(
            len(members) == len(WRAPPER_FILES)
            and {m.filename for m in members} == WRAPPER_FILES
            and sum(m.file_size for m in members) <= MAX_TRANSFER,
            "unsafe original artifact wrapper",
        )
        for m in members:
            require(
                not m.flag_bits & 1
                and (m.external_attr >> 16) & 0o170000 in (0, 0o100000),
                "special/encrypted artifact member",
            )
            with z.open(m) as source, (destination / m.filename).open("xb") as sink:
                shutil.copyfileobj(source, sink, 1024**2)


def raw_log_identity(path):
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("missing complete raw mozlog") from exc
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and 0 < info.st_size <= 16 * 1024**2,
        "missing, linked or oversized complete raw mozlog",
    )
    return {"bytes": info.st_size, "sha256": file_digest(path)}


def consume(inputs, state, recipe, context):
    require(
        os.geteuid() > 0
        and not any(
            k.startswith(("GITHUB", "ACTIONS"))
            or any(s in k.upper() for s in ("TOKEN", "SECRET", "PASSWORD"))
            for k in os.environ
        ),
        "native worker sees controller credentials",
    )
    value = validate_producer(read_json(inputs / "producer.json"), context)
    require(
        file_digest(inputs / "runtime.tar.xz") == value["primarySha256"]
        and file_digest(inputs / "test-support.tar.gz") == value["supportSha256"],
        "input bytes changed",
    )
    output = fresh(state / "output")
    logs = fresh(output / "logs")
    env = child_environment(state)
    budget = IOBudget(state, maximum=50 * GIB, minimum_free=10 * GIB)
    expansion = ExpansionBudget()
    commands = []

    def command(name, argv, timeout, **kw):
        result = run_diagnosed(
            argv,
            state,
            env,
            logs,
            name,
            timeout,
            memory=kw.pop("memory", 14 * GIB),
            log_limit=16 * 1024**2,
            **kw,
        )
        commands.append(result)
        return result

    app_root = state / "primary"
    support = state / "support"
    extract_archive(
        inputs / "runtime.tar.xz", app_root, budget=budget, expansion=expansion
    )
    extract_archive(
        inputs / "test-support.tar.gz", support, budget=budget, expansion=expansion
    )
    require(
        verify_primary(app_root, context) == value["primaryIdentity"],
        "binary ELF identity changed",
    )
    verify_recipe_metadata(recipe, value)
    plan = verify_support(support, value)
    app = app_root / "floorp"
    venv = state / "venv"
    command("cold-venv", ["/usr/bin/python3.12", "-I", "-m", "venv", str(venv)], 120)
    python = str(venv / "bin/python")
    offline = support / "python-environment"
    command(
        "offline-install",
        [
            python,
            "-I",
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-index",
            "--require-hashes",
            "--only-binary=:all:",
            "--find-links",
            str(offline / "wheelhouse"),
            "-r",
            str(offline / "requirements.lock"),
        ],
        180,
    )
    command("pip-check", [python, "-I", "-m", "pip", "check"], 60)
    modules = consumer_module_roots(support)
    env.update(
        PYTHONPATH=":".join(map(str, modules)),
        MOZ_HEADLESS="1",
        LIBGL_ALWAYS_SOFTWARE="1",
        LD_LIBRARY_PATH=str(app) + ":" + str(support / "bin"),
    )
    cases = []
    for name, case, canary in native_schedule(plan):
        selected = canary_case(case, support, value) if canary else case
        raw_log = logs / (name + ".mozlog")
        mochitest_root = None
        copied_bytes = 0
        if selected["suite"] == "browser-chrome":
            before_copy = budget.used
            mochitest_root = stage_mochitest(
                support, state / (name + "-harness") / "mochitest", budget
            )
            copied_bytes = budget.used - before_copy
        argv = [
            "/usr/bin/xvfb-run",
            "-a",
            *harness_argv(
                python,
                support,
                app,
                selected,
                state / (name + "-profile"),
                raw_log=raw_log,
                mochitest_root=mochitest_root,
            ),
        ]
        if selected["suite"] == "xpcshell":
            argv[4] = str(recipe / ".github/workflows/scripts/qa3_xpcshell_entry.py")
            env["QA3_XPCSHELL_SUPPORT"] = str(support)
            env.pop("QA3_MOCHITEST_ROOT", None)
        else:
            env.pop("QA3_XPCSHELL_SUPPORT", None)
            env["QA3_MOCHITEST_ROOT"] = str(mochitest_root)
        result = command(
            name,
            argv,
            600,
            # RLBox reserves 16 GiB of virtual space; the service still caps
            # physical memory at 14 GiB with swap disabled.
            memory=None,
            allow_nonzero=canary,
            watched_logs={raw_log.name: 16 * 1024**2},
            io_budget=budget,
        )
        raw_identity = raw_log_identity(raw_log)
        require(
            result.get("watchedLogs") == {raw_log.name: raw_identity},
            "supervised raw mozlog differs",
        )
        verdict = verify_mozlog(raw_log, selected, support, result, canary=canary)
        if mochitest_root is not None:
            current_bytes = sum(
                path.stat().st_size
                for path in mochitest_root.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
            budget.consume(max(0, current_bytes - copied_bytes))
            budget.release_tree(mochitest_root)
        cases.append({
            "name": name,
            "suite": case["suite"],
            "canary": canary,
            "process": result,
            "rawLog": {
                "path": "logs/" + raw_log.name,
                **raw_identity,
            },
            "mozlog": verdict,
        })
    require(
        capture_material_tree(support) == value["supportInventory"]
        and verify_primary(app_root, context) == value["primaryIdentity"],
        "harness mutated inputs",
    )
    receipt = {
        "schema": "qa3-hosted-cold-consumer-v1",
        "status": "PASS",
        "context": context,
        "producerBootSha256": value["bootSha256"],
        "consumerBootSha256": worker_boot_identity(),
        "commands": commands,
        "cases": cases,
        "nativeProductQualification": "UNVERIFIED",
        "publicationAuthorized": False,
    }
    write_json(output / "consumer.json", receipt)
    return receipt


def verify_consumer(output, support, producer, context):
    value = read_json(output / "consumer.json")
    require(
        value.get("schema") == "qa3-hosted-cold-consumer-v1"
        and value.get("status") == "PASS"
        and value.get("context") == context
        and value.get("producerBootSha256") == producer["bootSha256"]
        and value.get("consumerBootSha256") == worker_boot_identity()
        and value.get("nativeProductQualification") == "UNVERIFIED"
        and value.get("publicationAuthorized") is False,
        "incomplete native result",
    )
    plan = verify_support(support, producer)
    schedule = native_schedule(plan)
    phases = [
        "cold-venv",
        "offline-install",
        "pip-check",
        *(name for name, _, _ in schedule),
    ]
    require(
        [r["name"] for r in value["commands"]] == phases
        and len(value["cases"]) == len(schedule),
        "native phase skipped, duplicated or retried",
    )
    for command in value["commands"]:
        name = command["name"]
        require(
            type(command.get("exit")) is int
            and command["exit"] == (1 if name.endswith("assertion-canary") else 0)
            and command.get("stop") is None
            and command.get("ownedCleanupComplete") is True
            and command.get("stdoutIsData") is False
            and not command.get("cancelled")
            and not command.get("error")
            and not command.get("cleanupErrors"),
            "original native phase failed",
        )
        require(
            read_json(output / "logs" / (name + ".process.json")) == command
            and file_digest(output / "logs" / (name + ".stdout"))
            == command["stdoutSha256"]
            and file_digest(output / "logs" / (name + ".stderr"))
            == command["stderrSha256"],
            "original native raw evidence differs",
        )
    for index, item in enumerate(value["cases"]):
        _, case, canary = schedule[index]
        selected = canary_case(case, support, producer) if canary else case
        command = value["commands"][index + 3]
        raw_name = command["name"] + ".mozlog"
        raw_path = output / "logs" / raw_name
        identity = raw_log_identity(raw_path)
        require(
            item.get("rawLog") == {"path": "logs/" + raw_name, **identity}
            and command.get("watchedLogs") == {raw_name: identity},
            "original complete raw mozlog differs",
        )
        require(
            item["name"] == command["name"]
            and item["suite"] == case["suite"]
            and item["canary"] is canary
            and item["process"] == command
            and item["mozlog"]
            == verify_mozlog(
                raw_path,
                selected,
                support,
                command,
                canary=canary,
            ),
            "raw Mozilla outcome differs",
        )
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation", choices=("preflight", "produce", "acquire", "worker")
    )
    for name in (
        "source",
        "objdir",
        "primary",
        "output",
        "inputs",
        "state",
        "recipe",
        "context",
    ):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--build-id")
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--artifact-sha256")
    args = parser.parse_args()
    if args.operation == "preflight":
        packaging_preflight(args)
    elif args.operation == "produce":
        try:
            produce(args)
        except BaseException as exc:
            if args.output and args.output.is_dir():
                write_json(
                    args.output / "failure.json",
                    {
                        "schema": "qa3-hosted-failure-v1",
                        "phase": "producer",
                        "type": type(exc).__name__,
                        "status": "FAIL",
                        "publicationAuthorized": False,
                    },
                )
            raise
    elif args.operation == "acquire":
        acquire(args)
    else:
        consume(
            args.inputs,
            args.state,
            args.recipe,
            validate_context(read_json(args.context)),
        )


if __name__ == "__main__":
    main()
