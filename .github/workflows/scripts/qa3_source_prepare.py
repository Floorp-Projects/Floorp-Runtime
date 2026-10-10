# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import hashlib
import os
import re
import shlex
import shutil
import stat
import subprocess

from qa3_build_profile import enable_debug_tests, profile, verify_config
from qa3_native_io import outside, read_json, write_json
from qa3_source_cohort import (
    SCOPE,
    capture_tree,
    diagnostic_expectation,
    digest,
    file_digest,
    hash_value,
    safe_file,
    verify_final_source,
    verify_patches,
    verify_upstream_ancestor,
)

OLD_URL = "https://@MOZ_APPUPDATE_HOST@/update/6/%PRODUCT%/%VERSION%/%BUILD_ID%/%BUILD_TARGET%/%LOCALE%/%CHANNEL%/%OS_VERSION%/%SYSTEM_CAPABILITIES%/%DISTRIBUTION%/%DISTRIBUTION_VERSION%/update.xml"
NEW_URL = "https://%NORA_UPDATE_HOST%update.xml"


def git(root, *args, check=True, index=None, data=None):
    env = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL="/dev/null",
        GIT_NO_LAZY_FETCH="1",
        GIT_TERMINAL_PROMPT="0",
    )
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    return subprocess.run(
        ["git", "-C", str(root), *args],
        env=env,
        check=check,
        input=data,
        capture_output=True,
        timeout=60,
    )


def check_raw_index(root, entries, scope=None):
    expected = set()
    for item in entries.split(b"\0"):
        if not item:
            continue
        header, encoded = item.split(b"\t", 1)
        mode, blob, stage = header.split()
        relative = encoded.decode("utf-8", "strict")
        from qa3_source_cohort import safe_path

        path = root / safe_path(relative)
        if stage != b"0" or mode not in {b"100644", b"100755", b"120000"}:
            raise ValueError("unmerged index, gitlink or unsupported source entry")
        expected.add(relative)
        for parent in path.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError("tracked source traverses a symlink")
        actual = path.lstat()
        if mode == b"120000":
            if not stat.S_ISLNK(actual.st_mode):
                raise ValueError("tracked symlink kind changed")
            data = os.fsencode(os.readlink(path))
            value = hashlib.sha1(
                b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False
            )
        else:
            if not stat.S_ISREG(actual.st_mode) or bool(actual.st_mode & 0o111) != (
                mode == b"100755"
            ):
                raise ValueError("raw source executable mode or kind differs from Git")
            value = hashlib.sha1(
                b"blob " + str(actual.st_size).encode() + b"\0", usedforsecurity=False
            )
            with path.open("rb") as stream:
                while block := stream.read(1024**2):
                    value.update(block)
        if value.hexdigest().encode() != blob:
            raise ValueError("raw source bytes differ from independent Git blob")
    if scope and any(
        (root / scope / name).exists() or (root / scope / name).is_symlink()
        for name in (".git", ".hg", "mozconfig")
    ):
        raise ValueError(
            "recipe contains a path excluded from preconfigure source scope"
        )
    snapshot = capture_tree(root / scope if scope else root)
    actual_paths = {
        (scope + "/" if scope else "") + e["path"] for e in snapshot["entries"]
    }
    if (
        actual_paths != expected
        or scope is None
        and (root / "mozconfig").exists()
        or scope is None
        and (root / "mozconfig").is_symlink()
    ):
        raise ValueError("undeclared, missing or excluded source input")
    return snapshot


def tree_index_entries(tree):
    return b"\0".join(
        item.split(b"\t", 1)[0].split()[0]
        + b" "
        + item.split(b"\t", 1)[0].split()[2]
        + b" 0\t"
        + item.split(b"\t", 1)[1]
        for item in tree.split(b"\0")
        if item
    )


def check_expected_index(root, index):
    return check_raw_index(
        root, git(root, "ls-files", "--stage", "-z", index=index).stdout
    )


def expected_file(root, index, relative, data, executable):
    blob = git(root, "hash-object", "-w", "--stdin", data=data).stdout.decode().strip()
    mode = "100755" if executable else "100644"
    git(
        root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"{mode},{blob},{relative}",
        index=index,
    )


def verify_checkout(root, runtime, upstream):
    hash_value(runtime, 40)
    hash_value(upstream, 40)
    if git(root, "rev-parse", "HEAD").stdout.decode().strip() != runtime:
        raise ValueError("actual Runtime HEAD differs from controller expectation")
    if git(root, "rev-parse", "--is-shallow-repository").stdout.strip() != b"false":
        raise ValueError("source ingestion requires complete Git history")
    sparse = git(root, "config", "--bool", "core.sparseCheckout", check=False)
    if sparse.returncode not in {0, 1} or sparse.stdout.strip() not in {b"", b"false"}:
        raise ValueError("source ingestion rejects sparse checkout")
    entries = git(root, "ls-files", "-t", "-z").stdout.split(b"\0")
    if not any(entries) or any(e.startswith(b"S ") for e in entries):
        raise ValueError("empty checkout or skip-worktree source")
    verify_upstream_ancestor(root, upstream, runtime)
    immutable = git(root, "ls-tree", "-r", "-z", runtime).stdout
    entries_raw = tree_index_entries(immutable)
    snapshot = check_raw_index(root, entries_raw)
    return {
        "runtime": runtime,
        "upstream": upstream,
        "relation": "verified-ancestor",
        "initialTreeSha256": snapshot["sha256"],
        "trackedPaths": len(entries) - 1,
        "fullCheckout": True,
    }


def verify_plan(root, plan_path):
    plan = read_json(plan_path)
    fields = {
        "schemaVersion",
        "id",
        "role",
        "target",
        "sourceMaterials",
        "selection",
        "nativeExecution",
        "coldHarnessCLI",
        "coldRequirements",
        "publicationAuthorized",
    }
    if set(plan) != fields or plan["schemaVersion"] != 1:
        raise ValueError("unsupported fixed native plan")
    if (plan["id"], plan["role"], plan["target"]) != (
        "linux-x64-runtime-l1-proof-v1",
        "canonical-debug",
        "x86_64-pc-linux-gnu",
    ) or plan["publicationAuthorized"] is not False:
        raise ValueError("wrong plan role, target or authority")
    if {v["suite"] for v in plan["selection"]} != {"browser-chrome", "xpcshell"} or len(
        plan["selection"]
    ) != 2:
        raise ValueError("reduced or extra fixed suite selection")
    paths = []
    for item in plan["sourceMaterials"]:
        if set(item) != {"path", "sha256"}:
            raise ValueError("invalid source material declaration")
        paths.append(item["path"])
        if file_digest(safe_file(root, item["path"])) != hash_value(item["sha256"]):
            raise ValueError("pinned harness or selected test source differs")
    if not paths or len(paths) != len(set(paths)):
        raise ValueError("missing or duplicate source materials")
    ids = []
    for case in plan["selection"]:
        if set(case) != {
            "suite",
            "id",
            "manifest",
            "archivePath",
            "minimumAssertions",
            "declaredConditions",
            "requiredNoSkip",
        }:
            raise ValueError("invalid selection declaration")
        if (
            case["id"] not in paths
            or case["manifest"] not in paths
            or case["requiredNoSkip"] is not True
        ):
            raise ValueError("selection lacks pinned source/manifest")
        if type(case["minimumAssertions"]) is not int or case["minimumAssertions"] < 1:
            raise ValueError("selection permits assertion-free execution")
        ids.append(case["id"])
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate selection")
    return plan


def prepare_source(root, runtime, objdir, output):
    root = root.resolve()
    outside(root, objdir)
    outside(root, output)
    pin = read_json(root / ".github/runtime-upstream.json")["upstream"]
    if pin["repository"] != "mozilla-firefox/firefox":
        raise ValueError("unexpected canonical upstream repository")
    ingestion = verify_checkout(root, runtime, pin["commit"])
    policy = read_json(root / ".github/qa/source-policy.json")
    if set(policy) != {
        "schemaVersion",
        "comparisonPolicy",
        "commonPatches",
        "debugPatches",
    }:
        raise ValueError("invalid source policy")
    if (
        policy["schemaVersion"] != 1
        or policy["comparisonPolicy"] != "common-baseline-with-diagnostics"
    ):
        raise ValueError("unsupported source preparation policy")
    if len(policy["commonPatches"]) != 27 or len(policy["debugPatches"]) != 3:
        raise ValueError("reduced source patch policy")
    verify_patches(root, policy["commonPatches"], ".github/patches/upstream")
    verify_patches(root, policy["debugPatches"], ".github/patches/debug")
    plan = verify_plan(root, root / ".github/qa/linux-proof-plan.json")
    operations = []
    expected_index = output / "common.expected.index"
    git(root, "read-tree", runtime, index=expected_index)
    for item in policy["commonPatches"]:
        git(
            root,
            "apply",
            "--check",
            "--ignore-space-change",
            "--ignore-whitespace",
            item["path"],
        )
        git(root, "apply", "--ignore-space-change", "--ignore-whitespace", item["path"])
        git(
            root,
            "apply",
            "--cached",
            "--ignore-space-change",
            "--ignore-whitespace",
            item["path"],
            index=expected_index,
        )
        operations.append({"kind": "common-patch", **item})
    check_expected_index(root, expected_index)
    assets = root / ".github/assets/branding"
    if not assets.is_dir() or assets.is_symlink():
        raise ValueError("missing common branding assets")
    asset_inputs = []
    branding_outputs = []
    for source in sorted(assets.rglob("*")):
        rel = source.relative_to(assets)
        if source.is_symlink() or not (source.is_file() or source.is_dir()):
            raise ValueError("unsupported branding asset")
        target = root / "browser/branding" / rel
        if target.is_symlink() or any(
            p.is_symlink() for p in target.parents if p != root
        ):
            raise ValueError("unsafe branding destination")
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            if target.is_symlink() or any(
                p.is_symlink() for p in target.parents if p != root
            ):
                raise ValueError("unsafe branding destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            expected_file(
                root,
                expected_index,
                target.relative_to(root).as_posix(),
                source.read_bytes(),
                bool(source.stat().st_mode & 0o111),
            )
            asset_inputs.append({
                "path": source.relative_to(root).as_posix(),
                "sha256": file_digest(source),
            })
            branding_outputs.append({
                "path": target.relative_to(root).as_posix(),
                "sha256": file_digest(target),
            })
    if not asset_inputs:
        raise ValueError("empty branding assets")
    application = safe_file(root, "build/application.ini.in")
    before = application.read_bytes()
    if before.count(OLD_URL.encode()) != 1 or NEW_URL.encode() in before:
        raise ValueError(
            "update URL transform is missing, duplicated or already applied"
        )
    expected_url = before.replace(OLD_URL.encode(), NEW_URL.encode())
    application.write_bytes(expected_url)
    expected_file(
        root,
        expected_index,
        "build/application.ini.in",
        expected_url,
        bool(application.stat().st_mode & 0o111),
    )
    transforms = [
        {"path": ".github/assets/branding", "sha256": digest(asset_inputs)},
        {"path": "build/application.ini.in", "sha256": file_digest(application)},
    ]
    operations.append({
        "kind": "branding",
        "inputs": asset_inputs,
        "outputs": branding_outputs,
    })
    operations.append({
        "kind": "update-url",
        "beforeSha256": __import__("hashlib").sha256(before).hexdigest(),
        "afterSha256": file_digest(application),
        "replacementCount": 1,
    })
    check_expected_index(root, expected_index)
    expected_git_tree = (
        git(root, "write-tree", index=expected_index).stdout.decode().strip()
    )
    baseline = capture_tree(root)
    preimage_paths = sorted({
        name
        for item in policy["debugPatches"]
        for name in re.findall(
            r"^--- a/(.+)$", safe_file(root, item["path"]).read_text(), re.M
        )
    })
    if (
        sum(safe_file(root, name).stat().st_size for name in preimage_paths)
        > 8 * 1024**2
    ):
        raise ValueError("diagnostic replay preimage budget exceeded")
    preimages = [
        {
            "path": name,
            "sha256": file_digest(safe_file(root, name)),
            "executable": bool(safe_file(root, name).stat().st_mode & 0o111),
            "contentBase64": base64.b64encode(
                safe_file(root, name).read_bytes()
            ).decode("ascii"),
        }
        for name in preimage_paths
    ]
    expected = diagnostic_expectation(root, baseline, policy["debugPatches"])
    for item in policy["debugPatches"]:
        git(
            root,
            "apply",
            "--check",
            "--ignore-space-change",
            "--ignore-whitespace",
            item["path"],
        )
        git(root, "apply", "--ignore-space-change", "--ignore-whitespace", item["path"])
        operations.append({"kind": "diagnostic-patch", **item})
    verify_final_source(root, expected)
    config = root / "mozconfig"
    if config.exists() or config.is_symlink():
        raise ValueError("preexisting mozconfig")
    template = safe_file(
        root, ".github/workflows/mozconfigs/linux-x86_64.mozconfig"
    ).read_text()
    text = enable_debug_tests(template, True, False)
    text += "\nac_add_options --enable-debug\nac_add_options --with-branding=browser/branding/floorp-daylight\n"
    text += "ac_add_options --enable-chrome-format=flat\n"
    text += "mk_add_options MOZ_OBJDIR=" + shlex.quote(str(objdir.resolve())) + "\n"
    verify_config(text, profile("linux", "x86_64", True, False))
    config.write_text(text)
    common = {
        "schemaVersion": 1,
        "scope": SCOPE,
        "U": {
            "vcs": "git",
            "repository": "https://github.com/mozilla-firefox/firefox",
            "fullRevision": pin["commit"],
        },
        "R": runtime,
        "P": policy["commonPatches"],
        "transforms": transforms,
        "B": baseline["sha256"],
    }
    record = {
        "schemaVersion": 1,
        "executionKind": "actual-source-preparation",
        "ingestion": ingestion,
        "common": common,
        "delta": policy["debugPatches"],
        "finalTree": expected["sha256"],
        "configSha256": file_digest(config),
        "expectedCommonGitTree": expected_git_tree,
        "diagnosticPreimages": preimages,
        "planSha256": file_digest(root / ".github/qa/linux-proof-plan.json"),
        "operations": operations,
        "nativeQualification": "UNVERIFIED",
        "publicationAuthorized": False,
    }
    write_json(output / "baseline.json", baseline)
    write_json(output / "final.json", expected)
    write_json(output / "source-preparation.json", record)
    return record, expected, plan
