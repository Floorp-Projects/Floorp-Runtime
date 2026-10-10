# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import base64
import hashlib
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from qa3_mozlog import verify_mozlog
from qa3_native_build import verify_primary, verify_python_environment, verify_toolchain
from qa3_native_io import (
    GIB,
    MAX_COMPRESSED,
    ExpansionBudget,
    IOBudget,
    capture_material_tree,
    child_environment,
    elf_identity,
    extract_archive,
    fresh,
    read_json,
    run_owned,
    verify_budget,
    verify_group_limits,
    write_json,
)
from qa3_native_transport import (
    load_native_context,
    same_execution,
    verify_artifact_metadata,
    worker_boot_identity,
)
from qa3_source_cohort import (
    diagnostic_expectation,
    file_digest,
    hash_value,
    safe_path,
    verify_common,
    verify_inventory,
    verify_patches,
)


def verify_source_receipt(recipe, proof, baseline, final, runtime):
    verify_inventory(baseline)
    verify_inventory(final)
    record = proof["preparation"]
    common = record["common"]
    verify_common(common)
    policy = read_json(recipe / ".github/qa/source-policy.json")
    upstream = read_json(recipe / ".github/runtime-upstream.json")["upstream"]
    if len(policy["commonPatches"]) != 27 or len(policy["debugPatches"]) != 3:
        raise ValueError("reduced source policy")
    verify_patches(recipe, policy["commonPatches"], ".github/patches/upstream")
    verify_patches(recipe, policy["debugPatches"], ".github/patches/debug")
    if common["R"] != runtime or common["U"]["fullRevision"] != upstream["commit"]:
        raise ValueError("source receipt U/R mismatch")
    if (
        common["P"] != policy["commonPatches"]
        or record["delta"] != policy["debugPatches"]
    ):
        raise ValueError("source receipt reordered or reduced P/D")
    if common["B"] != baseline["sha256"] or record["finalTree"] != final["sha256"]:
        raise ValueError("baseline/final source receipt mismatch")
    ingestion = record["ingestion"]
    if (
        ingestion.get("runtime"),
        ingestion.get("upstream"),
        ingestion.get("relation"),
        ingestion.get("fullCheckout"),
    ) != (runtime, upstream["commit"], "verified-ancestor", True):
        raise ValueError("actual complete source ingestion is unverified")
    allowed = set()
    for patch in policy["debugPatches"]:
        text = (recipe / patch["path"]).read_text()
        allowed.update(re.findall(r"^--- a/(.+)$", text, re.M))
    before = {v["path"]: v for v in baseline["entries"]}
    after = {v["path"]: v for v in final["entries"]}
    if (
        set(before) != set(after)
        or {p for p in before if before[p] != after[p]} - allowed
    ):
        raise ValueError("undeclared diagnostic source delta")
    preimages = record["diagnosticPreimages"]
    if (
        not isinstance(preimages, list)
        or {v["path"] for v in preimages} != allowed
        or len(preimages) != len(allowed)
    ):
        raise ValueError("missing, extra or duplicate diagnostic replay preimage")
    with tempfile.TemporaryDirectory(prefix="qa3-consumer-diagnostic-") as name:
        scratch = Path(name)
        total = 0
        for item in preimages:
            if (
                set(item) != {"path", "sha256", "executable", "contentBase64"}
                or type(item["executable"]) is not bool
            ):
                raise ValueError("invalid diagnostic preimage binding")
            data = base64.b64decode(item["contentBase64"], validate=True)
            total += len(data)
            if (
                total > 8 * 1024**2
                or hashlib.sha256(data).hexdigest() != item["sha256"]
            ):
                raise ValueError("diagnostic replay preimage hash or budget mismatch")
            expected = before[item["path"]]
            if (
                expected["type"] != "file"
                or expected["sha256"] != item["sha256"]
                or expected["executable"] != item["executable"]
            ):
                raise ValueError(
                    "diagnostic replay preimage differs from full baseline"
                )
            target = scratch / safe_path(item["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o755 if item["executable"] else 0o644)
        for item in policy["debugPatches"]:
            target = scratch / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(recipe / item["path"], target)
        expected_final = diagnostic_expectation(
            scratch, baseline, policy["debugPatches"], require_full_baseline=False
        )
        if final != expected_final:
            raise ValueError("required diagnostic D was not applied exactly")
    if (
        record.get("executionKind") != "actual-source-preparation"
        or record.get("publicationAuthorized") is not False
    ):
        raise ValueError(
            "source receipt lacks actual execution or has publication authority"
        )
    return record


def verify_inputs(args, context, output, budget):
    inputs = args.inputs
    if (
        inputs.is_symlink()
        or not inputs.is_dir()
        or any(p.is_symlink() for p in inputs.rglob("*"))
    ):
        raise ValueError("unsafe authenticated consumer input")
    if any(os.access(p, os.W_OK) for p in inputs.rglob("*")):
        raise ValueError("native UID can modify authenticated consumer inputs")
    allowed = {
        "context.json",
        "primary/runtime.tar.xz",
        "primary/primary.json",
        "support/test-support.tar.gz",
        "support/proof.json",
        "support/baseline.json",
        "support/final.json",
        "primary-transport.json",
        "support-transport.json",
    }
    if {
        p.relative_to(inputs).as_posix() for p in inputs.rglob("*") if p.is_file()
    } != allowed:
        raise ValueError(
            "unexpected authenticated input or cold source/OBJDIR material"
        )
    same_execution(read_json(inputs / "context.json"), context)
    primary = inputs / "primary/runtime.tar.xz"
    support = inputs / "support/test-support.tar.gz"
    if primary.stat().st_size + support.stat().st_size > MAX_COMPRESSED:
        raise ValueError("combined compressed consumer input exceeded")
    for kind in ("primary", "support"):
        receipt = read_json(inputs / (kind + "-transport.json"))
        identifier = getattr(args, kind + "_id")
        wanted = getattr(args, kind + "_sha256")
        if (
            receipt["artifactId"],
            receipt["archiveSha256"],
            receipt["authenticatedRepository"],
        ) != (identifier, wanted, context["executionRepository"]):
            raise ValueError("transport receipt differs from controller artifact pin")
        verify_artifact_metadata(receipt["metadata"], context, identifier, kind, wanted)
    proof = read_json(inputs / "support/proof.json")
    binding = read_json(inputs / "primary/primary.json")
    if (
        proof.get("schemaVersion") != 1
        or proof.get("executionKind") != "native-debug-build-producer"
    ):
        raise ValueError("consumer has no actual native producer receipt")
    same_execution(proof["context"], context)
    same_execution(binding["context"], context)
    if proof["workerBootSha256"] == worker_boot_identity():
        raise ValueError("consumer requires a different cold worker boot")
    hash_value(proof["workerBootSha256"])
    for value in (proof, binding):
        if value.get("publicationAuthorized") is not False or value[
            "primarySha256"
        ] != file_digest(primary):
            raise ValueError("primary artifact bytes or authority differ")
    if proof["toolchainSha256"] != hash_value(args.builder_toolchain_sha256):
        raise ValueError("producer toolchain differs from controller builder pin")
    effective = proof["effectiveConfig"]["substs"]
    for key in ("ENABLE_TESTS", "MOZ_DEBUG"):
        if type(effective.get(key)) not in {bool, int, str} or effective[key] not in (
            True,
            1,
            "1",
        ):
            raise ValueError("producer effective Debug/tests are unverified")
    if effective.get("TARGET_CPU") != "x86_64" or effective.get("OS_TARGET") != "Linux":
        raise ValueError("producer effective target differs")
    for key in ("MOZ_ARTIFACT_BUILDS", "MOZ_PROFILE_GENERATE", "MOZ_PROFILE_USE"):
        if effective.get(key) not in (None, False, 0, "", "0"):
            raise ValueError("producer effective role is not canonical Debug")
    if proof["supportSha256"] != file_digest(support):
        raise ValueError("test-support bytes differ from producer receipt")
    if (
        proof.get("consumerVerdict") != "UNVERIFIED"
        or proof.get("nativeQualification") != "UNVERIFIED"
    ):
        raise ValueError("producer preissued qualification")
    source = verify_source_receipt(
        args.recipe,
        proof,
        read_json(inputs / "support/baseline.json"),
        read_json(inputs / "support/final.json"),
        args.runtime,
    )
    if (
        source["planSha256"] != args.plan_sha256
        or proof["planSha256"] != args.plan_sha256
    ):
        raise ValueError("producer plan differs from controller pin")
    if file_digest(args.recipe / ".github/qa/linux-proof-plan.json") != hash_value(
        args.plan_sha256
    ):
        raise ValueError("consumer recipe plan differs")
    expansion = ExpansionBudget()
    primary_root = output / "primary-expanded"
    support_root = output / "support-expanded"
    extract_archive(primary, primary_root, budget=budget, expansion=expansion)
    extract_archive(support, support_root, budget=budget, expansion=expansion)
    if (
        verify_primary(primary_root, context) != proof["primaryIdentity"]
        or binding["primaryIdentity"] != proof["primaryIdentity"]
    ):
        raise ValueError("primary ELF/build identity differs")
    verify_inventory(proof["supportInventory"])
    if capture_material_tree(support_root) != proof["supportInventory"]:
        raise ValueError("test-support full inventory differs")
    plan = read_json(support_root / "plan.json")
    if plan != read_json(args.recipe / ".github/qa/linux-proof-plan.json"):
        raise ValueError("embedded fixed plan differs")
    environment = verify_python_environment(
        support_root / "python-environment", args.python_environment_sha256
    )
    if proof["pythonEnvironmentSha256"] != environment["sha256"]:
        raise ValueError("producer Python dependencies differ from controller pin")
    for name in ("xpcshell", "ssltunnel", "certutil", "pk12util"):
        if elf_identity(support_root / "bin" / name) != proof["helpers"][name]:
            raise ValueError("same-build native helper changed")
    for path, source_path in (
        ("mochitest/runtests.py", "testing/mochitest/runtests.py"),
        ("mochitest/mochitest_options.py", "testing/mochitest/mochitest_options.py"),
        ("xpcshell/runxpcshelltests.py", "testing/xpcshell/runxpcshelltests.py"),
        ("xpcshell/xpcshellcommandline.py", "testing/xpcshell/xpcshellcommandline.py"),
    ):
        wanted = next(
            x["sha256"] for x in plan["sourceMaterials"] if x["path"] == source_path
        )
        if file_digest(support_root / path) != wanted:
            raise ValueError("same-build Mozilla harness source differs from fixed pin")
    for case in plan["selection"]:
        wanted = next(
            x["sha256"] for x in plan["sourceMaterials"] if x["path"] == case["id"]
        )
        if file_digest(support_root / case["archivePath"]) != wanted:
            raise ValueError("selected native test differs from fixed source")
    if (
        not isinstance(proof["commands"], list)
        or not proof["commands"]
        or any(
            v["exit"] != 0 or v["stop"] or v["ownedCleanupComplete"] is not True
            for v in proof["commands"]
        )
    ):
        raise ValueError("producer command failure or incomplete cleanup")
    names = [v["name"] for v in proof["commands"]]
    required = [
        "configure",
        "effective-config",
        "native-build",
        "primary-package",
        "package-tests",
    ]
    if names[:5] != required or names[5:] not in (
        [],
        ["decode-common", "decode-mochitest", "decode-xpcshell"],
    ):
        raise ValueError("producer required phases missing, reordered or repeated")
    return proof, plan, primary_root / "floorp", support_root


def harness_argv(python, support, app, case, profile):
    manifest = (
        support / case["archivePath"].rsplit("/", 1)[0] / Path(case["manifest"]).name
    )
    test = support / case["archivePath"]
    common = [
        "--manifest",
        str(manifest),
        "--xre-path",
        str(app),
        "--utility-path",
        str(support / "bin"),
        "--testing-modules-dir",
        str(support / "modules"),
        "--log-raw",
        "-",
    ]
    if case["suite"] == "browser-chrome":
        return [
            python,
            "-s",
            str(support / "mochitest/runtests.py"),
            "--flavor",
            "browser",
            "--appname",
            str(app / "floorp"),
            "--certificate-path",
            str(support / "certs"),
            "--headless",
            "--timeout",
            "120",
            "--profile-path",
            str(profile),
            *common,
            str(test),
        ]
    if case["suite"] == "xpcshell":
        return [
            python,
            "-s",
            str(support / "xpcshell/runxpcshelltests.py"),
            "--xpcshell",
            str(support / "bin/xpcshell"),
            "--app-path",
            str(app),
            "--sequential",
            "--no-logfiles",
            *common,
            str(test),
        ]
    raise ValueError("unapproved native suite")


def canary_case(case, support, proof):
    changes = [v for v in proof["canaryTransforms"] if v["suite"] == case["suite"]]
    if len(changes) != 1:
        raise ValueError("missing or duplicate canary transform")
    change = changes[0]
    name = (
        "browser_qa3_assertion.js"
        if case["suite"] == "browser-chrome"
        else "test_qa3_assertion.js"
    )
    path = case["archivePath"].rsplit("/", 1)[0] + "/" + name
    manifest = path.rsplit("/", 1)[0] + "/" + Path(case["manifest"]).name
    wanted = next(
        v["sha256"]
        for v in read_json(support / "plan.json")["sourceMaterials"]
        if v["path"] == ".github/qa/canaries/" + name
    )
    if (
        change["fixturePath"],
        change["manifest"],
        change["reason"],
        change["fixtureSha256"],
    ) != (path, manifest, "QA3_EXPECTED_ASSERTION", wanted):
        raise ValueError("unbound assertion-canary identity or reason")
    if (
        file_digest(support / path) != wanted
        or file_digest(support / manifest) != change["afterSha256"]
    ):
        raise ValueError("canary bytes or transformed manifest changed")
    original = next(
        v["sha256"]
        for v in read_json(support / "plan.json")["sourceMaterials"]
        if v["path"] == case["manifest"]
    )
    if change["beforeSha256"] != original:
        raise ValueError("canary was not appended to frozen original manifest")
    return {
        **case,
        "id": case["id"].rsplit("/", 1)[0] + "/" + name,
        "archivePath": path,
    }


def consume_proof(args):
    context = load_native_context(
        args.context, args.context_sha256, args.runtime, args.controller
    )
    output = fresh(args.output)
    state = fresh(args.state)
    logs = fresh(output / "logs")
    group = verify_group_limits("consumer", context)
    resources = verify_budget(output, 80 * GIB, 14 * GIB, 4)
    budget = IOBudget(output, 50 * GIB, 10 * GIB)
    toolchain = verify_toolchain(
        args.toolchain_lock,
        args.toolchain_sha256,
        state,
        logs,
        required={"python", "xvfb-run", "prlimit", "git"},
    )
    proof, plan, app, support = verify_inputs(args, context, output, budget)
    primary_inventory = capture_material_tree(app.parent)
    paths = {v["name"]: v["path"] for v in toolchain["tools"]}
    env = child_environment(state)
    env["PATH"] = (
        ":".join(dict.fromkeys(str(Path(v).parent) for v in paths.values()))
        + ":/usr/bin:/bin"
    )
    env["PIP_NO_INDEX"] = "1"
    commands = []
    results = []

    def command(name, argv, timeout, allow_nonzero=False):
        result = run_owned(
            argv,
            output,
            env,
            logs,
            name,
            timeout,
            memory=14 * GIB,
            minimum_free=10 * GIB,
            allow_nonzero=allow_nonzero,
        )
        commands.append(result)
        verify_group_limits("consumer", context)
        if capture_material_tree(support) != proof["supportInventory"]:
            raise ValueError("harness modified input support")
        if (
            capture_material_tree(app.parent) != primary_inventory
            or verify_primary(app.parent, context) != proof["primaryIdentity"]
        ):
            raise ValueError("harness modified primary bytes/identity")
        return result

    venv = state / "venv"
    command("python-venv", [paths["python"], "-s", "-m", "venv", str(venv)], 120)
    python = str(venv / "bin/python")
    offline = support / "python-environment"
    command(
        "offline-install",
        [
            python,
            "-s",
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
    modules = [support / "modules", support, *sorted((support / "mozbase").iterdir())]
    if any(not p.is_dir() for p in modules):
        raise ValueError("cold mozbase module roots missing")
    env["PYTHONPATH"] = ":".join(str(p) for p in modules)
    env["MOZ_HEADLESS"] = "1"
    env["LIBGL_ALWAYS_SOFTWARE"] = "1"
    env["LD_LIBRARY_PATH"] = str(app) + ":" + str(support / "bin")
    command(
        "cold-parser-conformance",
        [
            python,
            "-s",
            str(args.recipe / ".github/workflows/scripts/qa3_harness_probe.py"),
            "--support",
            str(support),
            "--app",
            str(app),
            "--output",
            str(state / "parser-conformance.json"),
        ],
        60,
    )
    conformance = read_json(state / "parser-conformance.json")
    if conformance != {
        "schemaVersion": 1,
        "parserVerdict": "PASS",
        "nativeExecuted": False,
        "suites": ["browser-chrome", "xpcshell"],
    }:
        raise ValueError("cold Mozilla parser contract unavailable")
    for index, case in enumerate(plan["selection"]):
        for canary in (False, True):
            selected = canary_case(case, support, proof) if canary else case
            name = f"native-{index}-{'assertion-canary' if canary else 'required'}"
            profile = state / (name + "-profile")
            argv = [
                paths["xvfb-run"],
                "-a",
                *harness_argv(python, support, app, selected, profile),
            ]
            if selected["suite"] == "xpcshell":
                argv[4] = str(
                    args.recipe / ".github/workflows/scripts/qa3_xpcshell_entry.py"
                )
                env["QA3_XPCSHELL_SUPPORT"] = str(support)
            else:
                env.pop("QA3_XPCSHELL_SUPPORT", None)
            result = command(name, argv, 600, allow_nonzero=canary)
            results.append(
                verify_mozlog(
                    logs / (name + ".stdout"), selected, support, result, canary=canary
                )
            )
    write_json(
        output / "consumer-result.json",
        {
            "schemaVersion": 1,
            "consumerProofVerdict": "PASS",
            "nativeQualification": "UNVERIFIED",
            "executionKind": "limited-cold-debug-proof",
            "context": context,
            "producerProofSha256": file_digest(args.inputs / "support/proof.json"),
            "primarySha256": proof["primarySha256"],
            "supportSha256": proof["supportSha256"],
            "planSha256": args.plan_sha256,
            "workerBootSha256": worker_boot_identity(),
            "consumerToolchainSha256": args.toolchain_sha256,
            "consumerToolchain": toolchain,
            "pythonEnvironmentSha256": args.python_environment_sha256,
            "groupLimits": group,
            "resources": resources,
            "commands": commands,
            "cases": results,
            "productArtifactQualification": "UNVERIFIED",
            "publicationAuthorized": False,
        },
    )


def main():
    parser = argparse.ArgumentParser()
    for name in ("recipe", "inputs", "output", "state", "toolchain-lock", "context"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in (
        "runtime",
        "controller",
        "plan-sha256",
        "toolchain-sha256",
        "context-sha256",
        "python-environment-sha256",
        "primary-sha256",
        "support-sha256",
        "builder-toolchain-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    for kind in ("primary", "support"):
        parser.add_argument("--" + kind + "-id", type=int, required=True)
    args = parser.parse_args()
    try:
        consume_proof(args)
    except Exception as exc:
        if args.output.is_dir() and not (args.output / "consumer-result.json").exists():
            write_json(
                args.output / "consumer-result.json",
                {
                    "schemaVersion": 1,
                    "consumerProofVerdict": "INCOMPLETE",
                    "nativeQualification": "UNVERIFIED",
                    "productArtifactQualification": "UNVERIFIED",
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
            "Cold proof consumer stopped; complete private logs retain the failed phase.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
