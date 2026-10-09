# SPDX-License-Identifier: MPL-2.0

import argparse
import configparser
import os
import re
import shlex
import shutil
import sys
from pathlib import Path

from qa3_native_io import (
    GIB,
    MAX_COMPRESSED,
    ExpansionBudget,
    IOBudget,
    capture_material_tree,
    child_environment,
    copy_file,
    elf_identity,
    extract_archive,
    fresh,
    outside,
    pack_tree,
    read_json,
    run_owned,
    verify_budget,
    verify_group_limits,
    write_json,
)
from qa3_native_transport import load_native_context, worker_boot_identity
from qa3_source_cohort import file_digest, hash_value, verify_final_source
from qa3_source_prepare import prepare_source

TOOL_ARGUMENTS = {
    "python": ["--version"],
    "make": ["--version"],
    "zstd": ["--version"],
    "xvfb-run": ["--help"],
    "clang": ["--version"],
    "clang++": ["--version"],
    "rustc": ["--version"],
    "cargo": ["--version"],
    "ld.lld": ["--version"],
    "prlimit": ["--version"],
    "git": ["--version"],
}


def verify_toolchain(lock_path, expected_digest, state, logs, required=None):
    if file_digest(lock_path) != hash_value(expected_digest):
        raise ValueError("worker toolchain lock differs from controller pin")
    lock = read_json(lock_path)
    if set(lock) != {"schemaVersion", "tools"} or lock["schemaVersion"] != 1:
        raise ValueError("invalid worker toolchain lock")
    required = set(TOOL_ARGUMENTS) if required is None else set(required)
    if {t["name"] for t in lock["tools"]} != required or len(lock["tools"]) != len(
        required
    ):
        raise ValueError("missing or duplicate pinned worker tool")
    for tool in lock["tools"]:
        if set(tool) != {"name", "path", "sha256", "versionStdoutSha256"}:
            raise ValueError("invalid worker tool binding")
        path = Path(tool["path"])
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("missing pinned worker executable")
        if file_digest(path) != hash_value(tool["sha256"]):
            raise ValueError("worker executable bytes changed")
        name = "tool-" + tool["name"].replace("+", "plus")
        result = run_owned(
            [str(path), *TOOL_ARGUMENTS[tool["name"]]],
            state,
            child_environment(state),
            logs,
            name,
            30,
            memory=2 * GIB,
        )
        if result["stdoutSha256"] != hash_value(tool["versionStdoutSha256"]):
            raise ValueError("worker tool version output changed")
    if next(t["path"] for t in lock["tools"] if t["name"] == "git") != "/usr/bin/git":
        raise ValueError("source ingestion/replay Git differs from pinned worker Git")
    if (
        next(t["path"] for t in lock["tools"] if t["name"] == "prlimit")
        != "/usr/bin/prlimit"
    ):
        raise ValueError("supervisor limiter is not the pinned native limiter")
    if (
        Path(next(t["path"] for t in lock["tools"] if t["name"] == "python")).resolve()
        != Path(sys.executable).resolve()
    ):
        raise ValueError("producer Python differs from pinned worker Python")
    return lock


def verify_effective_config(value, source, objdir, toolchain):
    if (
        set(value) != {"schemaVersion", "source", "objdir", "substs"}
        or value["schemaVersion"] != 1
    ):
        raise ValueError("invalid effective configure record")
    if value["source"] != str(source.resolve()) or value["objdir"] != str(
        objdir.resolve()
    ):
        raise ValueError("configure source or OBJDIR mismatch")
    substs = value["substs"]
    for name in ("ENABLE_TESTS", "MOZ_DEBUG"):
        if type(substs.get(name)) not in {bool, int, str} or substs.get(name) not in (
            True,
            1,
            "1",
        ):
            raise ValueError("effective configure did not enable Debug and tests")
    if substs.get("TARGET_CPU") != "x86_64" or substs.get("OS_TARGET") != "Linux":
        raise ValueError("effective native target differs")
    if substs.get("target") not in {None, "x86_64-pc-linux-gnu"}:
        raise ValueError("effective configure target triple differs")
    for name in ("MOZ_ARTIFACT_BUILDS", "MOZ_PROFILE_GENERATE", "MOZ_PROFILE_USE"):
        if substs.get(name) not in (None, False, 0, "", "0"):
            raise ValueError("artifact build or PGO is active")
    by_name = {t["name"]: t for t in toolchain["tools"]}
    for field, name in (
        ("CC", "clang"),
        ("CXX", "clang++"),
        ("RUSTC", "rustc"),
        ("CARGO", "cargo"),
    ):
        command = substs.get(field)
        if isinstance(command, str):
            command = shlex.split(command)
        if (
            not isinstance(command, list)
            or not command
            or not isinstance(command[0], str)
        ):
            raise ValueError("effective compiler is unverified")
        resolved = (
            Path(command[0])
            if Path(command[0]).is_absolute()
            else Path(shutil.which(command[0]) or "/missing")
        )
        if (
            resolved.resolve() != Path(by_name[name]["path"]).resolve()
            or file_digest(resolved) != by_name[name]["sha256"]
        ):
            raise ValueError("configure compiler differs from pinned worker toolchain")
    return value


def verify_primary(root, context):
    app = root / "floorp"
    identities = {name: elf_identity(app / name) for name in ("floorp", "libxul.so")}
    for name, section in (("application.ini", "App"), ("platform.ini", "Build")):
        ini = configparser.ConfigParser(interpolation=None, strict=True)
        ini.read(app / name, encoding="utf-8")
        if ini[section].get("BuildID") != context["buildID"]:
            raise ValueError("packaged application/platform BuildID differs")
        if ini[section].get("SourceStamp") != context["runtimeRecipe"]:
            raise ValueError("packaged source stamp differs from Runtime recipe")
    return identities


def merge_materials(source, destination, budget):
    for item in sorted(source.rglob("*")):
        rel = item.relative_to(source)
        target = destination / rel
        if item.is_symlink():
            raise ValueError("test archive contains unsupported material symlink")
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if file_digest(target) != file_digest(item) or bool(
                    target.stat().st_mode & 0o111
                ) != bool(item.stat().st_mode & 0o111):
                    raise ValueError("conflicting common/test archive member")
            else:
                copy_file(item, target, budget)
        else:
            raise ValueError("special test material")


def install_canaries(source, support, plan):
    changes = []
    for case in plan["selection"]:
        name = (
            "browser_qa3_assertion.js"
            if case["suite"] == "browser-chrome"
            else "test_qa3_assertion.js"
        )
        manifest = (
            support
            / case["archivePath"].rsplit("/", 1)[0]
            / Path(case["manifest"]).name
        )
        if not manifest.is_file() or manifest.is_symlink():
            raise ValueError(
                "selected original test manifest missing from same-build support"
            )
        input_manifest = next(
            x["sha256"]
            for x in plan["sourceMaterials"]
            if x["path"] == case["manifest"]
        )
        if file_digest(manifest) != input_manifest:
            raise ValueError("packaged selected manifest differs from pinned source")
        target = manifest.parent / name
        if target.exists():
            raise ValueError("canary collision")
        fixture = source / ".github/qa/canaries" / name
        shutil.copy2(fixture, target)
        before = file_digest(manifest)
        with manifest.open("a") as stream:
            stream.write('\n["' + name + '"]\n')
        changes.append({
            "suite": case["suite"],
            "manifest": manifest.relative_to(support).as_posix(),
            "beforeSha256": before,
            "afterSha256": file_digest(manifest),
            "fixturePath": target.relative_to(support).as_posix(),
            "fixtureSha256": file_digest(target),
            "reason": "QA3_EXPECTED_ASSERTION",
        })
    return changes


def verify_python_environment(root, expected_digest):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("private offline Python environment is missing")
    snapshot = capture_material_tree(root)
    if snapshot["sha256"] != hash_value(expected_digest):
        raise ValueError("offline Python environment differs from controller pin")
    entries = snapshot["entries"]
    if not 1 < len(entries) <= 200:
        raise ValueError("missing or excessive Python wheel inputs")
    for item in entries:
        if item["type"] != "file" or not (
            item["path"] == "requirements.lock"
            or re.fullmatch(r"wheelhouse/[A-Za-z0-9_.+-]+\.whl", item["path"])
        ):
            raise ValueError("unexpected offline Python environment input")
    requirements = (root / "requirements.lock").read_text()
    hashes = set()
    for line in requirements.splitlines():
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(
            r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+(?: --hash=sha256:[0-9a-f]{64})+", line
        ):
            raise ValueError("unlocked dependency, URL, sdist or pip option")
        hashes.update(re.findall(r"sha256:([0-9a-f]{64})", line))
    wheel_hashes = {x["sha256"] for x in entries if x["path"].endswith(".whl")}
    if not hashes or hashes != wheel_hashes:
        raise ValueError("offline wheel inventory and requirements hashes differ")
    if sum((root / x["path"]).stat().st_size for x in entries) > 2 * GIB:
        raise ValueError("offline Python environment budget exceeded")
    return snapshot


def build_proof(args):
    context = load_native_context(
        args.context, args.context_sha256, args.runtime, args.controller
    )
    source = args.source.resolve()
    outside(source, args.output)
    outside(source, args.objdir)
    outside(source, args.state)
    output = fresh(args.output)
    logs = fresh(output / "logs")
    state = fresh(args.state)
    if args.objdir.exists() or args.objdir.is_symlink():
        raise ValueError("OBJDIR is not fresh")
    group = verify_group_limits("builder", context)
    resources = verify_budget(output, 140 * GIB, 28 * GIB, 8)
    budget = IOBudget(output, 30 * GIB, 20 * GIB)
    expansion = ExpansionBudget()
    toolchain = verify_toolchain(
        args.toolchain_lock, args.toolchain_sha256, state, logs
    )
    environment = verify_python_environment(
        args.python_environment, args.python_environment_sha256
    )
    if file_digest(source / ".github/qa/linux-proof-plan.json") != hash_value(
        args.plan_sha256
    ):
        raise ValueError("fixed plan differs from controller pin")
    preparation, inventory, plan = prepare_source(
        source, args.runtime, args.objdir, output
    )
    paths = {x["name"]: x["path"] for x in toolchain["tools"]}
    path = ":".join(
        dict.fromkeys(str(Path(x["path"]).parent) for x in toolchain["tools"])
    )
    env = child_environment(
        state,
        {
            "MOZCONFIG": str(source / "mozconfig"),
            "MOZ_BUILD_DATE": context["buildID"],
            "MOZ_NUM_JOBS": "6",
            "MOZ_OBJDIR": str(args.objdir.resolve()),
            "LIBGL_ALWAYS_SOFTWARE": "1",
        },
    )
    env["PATH"] = path + ":/usr/bin:/bin"
    env["PIP_NO_INDEX"] = "1"
    env["PIP_FIND_LINKS"] = str(args.python_environment / "wheelhouse")
    env["PIP_REQUIRE_HASHES"] = "1"
    commands = []

    def command(name, argv, timeout):
        result = run_owned(
            argv, source, env, logs, name, timeout, minimum_free=20 * GIB
        )
        commands.append(result)
        verify_budget(output, 20 * GIB, 28 * GIB, 8)
        verify_group_limits("builder", context)
        verify_final_source(source, inventory)
        if file_digest(source / "mozconfig") != preparation["configSha256"]:
            raise ValueError("mozconfig changed during build")
        return result

    python = paths["python"]
    xvfb = paths["xvfb-run"]
    command("configure", [xvfb, "-a", str(source / "mach"), "configure"], 900)
    effective_path = output / "effective-config.json"
    command(
        "effective-config",
        [
            python,
            str(source / "mach"),
            "python",
            "--virtualenv",
            "build",
            str(source / ".github/workflows/scripts/qa3_config_probe.py"),
            "--source",
            str(source),
            "--objdir",
            str(args.objdir.resolve()),
            "--output",
            str(effective_path),
        ],
        120,
    )
    effective = verify_effective_config(
        read_json(effective_path), source, args.objdir, toolchain
    )
    command(
        "native-build", [xvfb, "-a", str(source / "mach"), "build", "--jobs=6"], 14400
    )
    command("primary-package", [str(source / "mach"), "package"], 600)
    primary_packages = sorted((args.objdir / "dist").rglob("floorp-*.tar.xz"))
    if len(primary_packages) != 1 or primary_packages[0].is_symlink():
        raise ValueError("missing or ambiguous same-build primary package")
    primary_dir = fresh(output / "primary")
    primary = primary_dir / "runtime.tar.xz"
    copy_file(primary_packages[0], primary, budget)
    primary_sha = file_digest(primary)
    primary_root = output / "primary-expanded"
    expanded = extract_archive(
        primary, primary_root, budget=budget, expansion=expansion
    )
    primary_identity = verify_primary(primary_root, context)
    command(
        "package-tests",
        [
            str(source / "mach"),
            "build",
            "--jobs=1",
            "package-tests-common",
            "package-tests-mochitest",
            "package-tests-xpcshell",
        ],
        1800,
    )
    support = fresh(output / "support-expanded")
    archive_inputs = []
    for kind in ("common", "mochitest", "xpcshell"):
        matches = sorted((args.objdir / "dist").rglob(f"*.{kind}.tests.*"))
        if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
            raise ValueError("missing or ambiguous same-OBJDIR test archive")
        archive = matches[0]
        archive_inputs.append({
            "kind": kind,
            "sha256": file_digest(archive),
            "bytes": archive.stat().st_size,
        })
        if archive.name.endswith(".tar.zst"):
            result = run_owned(
                [paths["zstd"], "-d", "--stdout", "--", str(archive)],
                source,
                env,
                logs,
                "decode-" + kind,
                600,
                minimum_free=20 * GIB,
                data_stdout=True,
                io_budget=budget,
                data_limit=30 * GIB,
            )
            commands.append(result)
            archive = logs / ("decode-" + kind + ".stdout")
        elif not archive.name.endswith(".zip"):
            raise ValueError("unsupported pinned test archive format")
        stage = output / ("archive-" + kind)
        extract_archive(archive, stage, budget=budget, expansion=expansion)
        merge_materials(stage, support, budget)
        budget.release_tree(stage)
        if archive.parent == logs:
            budget.release_tree(archive)
    budget.consume(4096)
    changes = install_canaries(source, support, plan)
    python_inputs = fresh(support / "python-environment")
    merge_materials(args.python_environment, python_inputs, budget)
    write_json(support / "plan.json", plan)
    for case in plan["selection"]:
        test = support / case["archivePath"]
        wanted = next(
            x["sha256"] for x in plan["sourceMaterials"] if x["path"] == case["id"]
        )
        if test.is_symlink() or file_digest(test) != wanted:
            raise ValueError("same-build selected test bytes differ from frozen plan")
    helpers = {
        name: elf_identity(support / "bin" / name)
        for name in ("xpcshell", "ssltunnel", "certutil", "pk12util")
    }
    for name in ("modules", "certs", "mozbase", "mochitest", "xpcshell"):
        if not (support / name).is_dir() or not any((support / name).iterdir()):
            raise ValueError("same-build test-support dependency missing")
    support_dir = fresh(output / "test-support")
    support_archive = support_dir / "test-support.tar.gz"
    support_inventory = capture_material_tree(support)
    pack_tree(support, support_archive, budget)
    if primary_sha != file_digest(primary) or primary_sha != file_digest(
        primary_packages[0]
    ):
        raise ValueError("support preparation modified the primary package")
    verify_final_source(source, inventory)
    if primary.stat().st_size + support_archive.stat().st_size > MAX_COMPRESSED:
        raise ValueError("combined compressed native input budget exceeded")
    proof = {
        "schemaVersion": 1,
        "executionKind": "native-debug-build-producer",
        "context": context,
        "workerBootSha256": worker_boot_identity(),
        "groupLimits": group,
        "resources": resources,
        "stagingBytes": budget.used,
        "decodedInputBytes": expansion.bytes,
        "preparation": preparation,
        "effectiveConfig": effective,
        "effectiveConfigSha256": file_digest(effective_path),
        "toolchainSha256": args.toolchain_sha256,
        "toolchain": toolchain,
        "pythonEnvironmentSha256": environment["sha256"],
        "planSha256": args.plan_sha256,
        "primarySha256": primary_sha,
        "primaryIdentity": primary_identity,
        "primaryExpanded": expanded,
        "supportSha256": file_digest(support_archive),
        "supportInventory": support_inventory,
        "helpers": helpers,
        "testArchives": archive_inputs,
        "canaryTransforms": changes,
        "commands": commands,
        "consumerVerdict": "UNVERIFIED",
        "nativeQualification": "UNVERIFIED",
        "publicationAuthorized": False,
    }
    write_json(
        primary_dir / "primary.json",
        {
            "schemaVersion": 1,
            "context": context,
            "primarySha256": primary_sha,
            "primaryIdentity": primary_identity,
            "publicationAuthorized": False,
        },
    )
    write_json(support_dir / "proof.json", proof)
    for name in ("baseline.json", "final.json"):
        shutil.copy2(output / name, support_dir / name)
    write_json(
        output / "producer-result.json",
        {
            "schemaVersion": 1,
            "producerVerdict": "PASS",
            "consumerVerdict": "UNVERIFIED",
            "nativeQualification": "UNVERIFIED",
            "publicationAuthorized": False,
            "context": context,
            "proofSha256": file_digest(support_dir / "proof.json"),
        },
    )
    return proof


def main():
    parser = argparse.ArgumentParser()
    for name in (
        "source",
        "objdir",
        "output",
        "state",
        "toolchain-lock",
        "python-environment",
        "context",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in (
        "runtime",
        "controller",
        "plan-sha256",
        "toolchain-sha256",
        "python-environment-sha256",
        "context-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        build_proof(args)
    except Exception as exc:
        if args.output.is_dir() and not (args.output / "producer-result.json").exists():
            write_json(
                args.output / "producer-result.json",
                {
                    "schemaVersion": 1,
                    "producerVerdict": "INCOMPLETE",
                    "consumerVerdict": "UNVERIFIED",
                    "nativeQualification": "UNVERIFIED",
                    "publicationAuthorized": False,
                },
            )
        if args.output.is_dir() and not (args.output / "failure.json").exists():
            write_json(
                args.output / "failure.json",
                {
                    "schemaVersion": 1,
                    "errorType": type(exc).__name__,
                    "message": str(exc),
                    "verdict": "INCOMPLETE",
                    "publicationAuthorized": False,
                },
            )
        print(
            "Native proof producer stopped; complete private logs retain the failed phase.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
