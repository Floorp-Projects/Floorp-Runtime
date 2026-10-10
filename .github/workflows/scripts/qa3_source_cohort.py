#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from qa3_build_profile import TARGETS

ROOT = Path(__file__).resolve().parents[3]
SCOPE = "qa3-preconfigure-source-v1"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def hash_value(value, length=64):
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
        raise ValueError("invalid immutable digest")
    return value


def safe_path(value):
    if not isinstance(value, str) or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("invalid source path")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or any(p in {".", ".."} for p in path.parts)
    ):
        raise ValueError("noncanonical source path")
    return value


def safe_file(root, relative):
    path = root / safe_path(relative)
    if (
        path.is_symlink()
        or not path.is_file()
        or not path.resolve().is_relative_to(root.resolve())
    ):
        raise ValueError("unsafe or missing source file")
    return path


def verify_patches(root, entries, directory):
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty patch policy")
    paths = []
    for entry in entries:
        if set(entry) != {"path", "sha256"}:
            raise ValueError("invalid patch entry")
        name = safe_path(entry["path"])
        path = safe_file(root, name)
        if not name.startswith(directory + "/"):
            raise ValueError("missing or unsafe patch")
        if file_digest(path) != hash_value(entry["sha256"]):
            raise ValueError("patch bytes differ from policy")
        paths.append(name)
    actual = sorted(
        (p.relative_to(root).as_posix() for p in (root / directory).rglob("*.patch")),
        key=lambda p: p.encode(),
    )
    if paths != actual or len(paths) != len(set(paths)):
        raise ValueError("extra, missing, duplicate, or reordered patch")
    return entries


def capture_tree(root):
    entries = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        dirs[:] = [d for d in dirs if not (base == root and d in {".git", ".hg"})]
        for name in list(dirs):
            if (base / name).is_symlink():
                files.append(name)
                dirs.remove(name)
        for name in files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if base == root and name in {".git", ".hg", "mozconfig"}:
                continue
            safe_path(relative)
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                try:
                    target = path.resolve(strict=True).relative_to(root.resolve())
                except (OSError, RuntimeError, ValueError) as error:
                    raise ValueError(
                        "source symlink leaves the inventoried tree or is unresolved"
                    ) from error
                if (
                    not target.parts
                    or target.parts[0] in {".git", ".hg"}
                    or target.as_posix() == "mozconfig"
                ):
                    raise ValueError("source symlink targets excluded input")
                entry = {
                    "path": relative,
                    "type": "symlink",
                    "target": os.readlink(path),
                }
            elif stat.S_ISREG(mode):
                entry = {
                    "path": relative,
                    "type": "file",
                    "executable": bool(mode & 0o111),
                    "sha256": file_digest(path),
                }
            else:
                raise ValueError("special source entry")
            entries.append(entry)
    entries.sort(key=lambda v: v["path"].encode())
    return {"scope": SCOPE, "entries": entries, "sha256": digest(entries)}


def verify_inventory(inventory):
    if set(inventory) != {"scope", "entries", "sha256"} or inventory["scope"] != SCOPE:
        raise ValueError("source inventory scope mismatch")
    entries = inventory["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty source inventory")
    paths = []
    for entry in entries:
        paths.append(safe_path(entry["path"]))
        if entry["type"] == "file":
            if (
                set(entry) != {"path", "type", "executable", "sha256"}
                or type(entry["executable"]) is not bool
            ):
                raise ValueError("invalid source file entry")
            hash_value(entry["sha256"])
        elif entry["type"] == "symlink":
            if set(entry) != {"path", "type", "target"} or not isinstance(
                entry["target"], str
            ):
                raise ValueError("invalid source symlink entry")
        else:
            raise ValueError("unsupported source entry")
    if paths != sorted(set(paths), key=lambda p: p.encode()) or digest(
        entries
    ) != hash_value(inventory["sha256"]):
        raise ValueError("noncanonical or modified source inventory")
    return inventory


def diagnostic_expectation(root, baseline, patches):
    verify_inventory(baseline)
    if capture_tree(root) != baseline:
        raise ValueError("baseline bytes changed before diagnostic preparation")
    paths = set()
    for patch in patches:
        if file_digest(safe_file(root, patch["path"])) != hash_value(patch["sha256"]):
            raise ValueError("diagnostic patch bytes mismatch")
        data = (root / patch["path"]).read_text()
        old = re.findall(r"^--- a/(.+)$", data, re.M)
        new = re.findall(r"^\+\+\+ b/(.+)$", data, re.M)
        if (
            not old
            or old != new
            or any(
                marker in data
                for marker in (
                    "GIT binary patch",
                    "rename from ",
                    "new file mode ",
                    "deleted file mode ",
                    "old mode ",
                    "new mode ",
                )
            )
        ):
            raise ValueError("unsupported diagnostic source transform")
        paths.update(safe_path(p) for p in old)
    by_path = {e["path"]: dict(e) for e in baseline["entries"]}
    with tempfile.TemporaryDirectory(prefix="qa3-diagnostic-") as name:
        scratch = Path(name)
        for path in paths:
            if by_path.get(path, {}).get("type") != "file":
                raise ValueError("diagnostic delta requires existing regular files")
            target = scratch / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(safe_file(root, path), target)
        subprocess.run(["git", "init", "-q", str(scratch)], check=True, timeout=30)
        for patch in patches:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(scratch),
                    "apply",
                    "--ignore-space-change",
                    "--ignore-whitespace",
                    str((root / patch["path"]).resolve()),
                ],
                check=True,
                timeout=30,
                capture_output=True,
            )
        for path in paths:
            by_path[path]["sha256"] = file_digest(scratch / path)
        entries = sorted(by_path.values(), key=lambda e: e["path"].encode())
    return {"scope": SCOPE, "entries": entries, "sha256": digest(entries)}


def verify_final_source(actual_root, expected):
    verify_inventory(expected)
    actual = capture_tree(actual_root)
    if actual != expected:
        raise ValueError("undeclared or incorrect source delta")
    return actual["sha256"]


def verify_common(common):
    if (
        set(common) != {"schemaVersion", "U", "R", "P", "transforms", "B", "scope"}
        or type(common["schemaVersion"]) is not int
        or common["schemaVersion"] != 1
    ):
        raise ValueError("invalid common baseline schema")
    if common["scope"] != SCOPE:
        raise ValueError("wrong common source scope")
    upstream = common["U"]
    if (
        set(upstream) != {"vcs", "repository", "fullRevision"}
        or upstream["vcs"] != "git"
        or upstream["repository"] != "https://github.com/mozilla-firefox/firefox"
    ):
        raise ValueError("upstream VCS namespace mismatch")
    hash_value(upstream["fullRevision"], 40)
    hash_value(common["R"], 40)
    hash_value(common["B"])
    if not common["P"] or not common["transforms"]:
        raise ValueError("missing common patch or transform evidence")
    for entries in (common["P"], common["transforms"]):
        names = []
        for entry in entries:
            if set(entry) != {"path", "sha256"}:
                raise ValueError("invalid common input entry")
            names.append(safe_path(entry["path"]))
            hash_value(entry["sha256"])
        if len(names) != len(set(names)):
            raise ValueError("duplicate common input")
    return digest(common)


def same_cohort(actual, expected):
    verify_common(actual)
    verify_common(expected)
    if actual != expected:
        raise ValueError(
            "upstream, Runtime, ordered patches, transforms, or baseline mismatch"
        )
    return digest(actual)


def verify_upstream_ancestor(root, upstream, runtime):
    hash_value(upstream, 40)
    hash_value(runtime, 40)
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != runtime:
        raise ValueError("Runtime checkout mismatch")
    result = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", upstream, runtime],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ValueError("upstream ingestion relation is unverified or incompatible")


def verify_profile(profile, producer, consumer, profdata, jarlog, workload):
    fields = {
        "producerSubjectSha256",
        "producerArtifactSha256",
        "producerRun",
        "producerAttempt",
        "workloadSha256",
        "profdataSha256",
        "jarlogSha256",
    }
    if set(profile) != fields:
        raise ValueError("missing or extra PGO profile provenance")
    verify_subject(producer)
    verify_subject(consumer)
    same_cohort(producer["common"], consumer["common"])
    if producer["role"] != "profile-generate" or consumer["role"] != "profile-use":
        raise ValueError("wrong PGO producer/consumer role")
    for key in ("target", "toolchainSha256", "delta", "finalTree"):
        if producer[key] != consumer[key]:
            raise ValueError("PGO target, toolchain, or source delta mismatch")
    for key in ("producerRun", "producerAttempt"):
        if type(profile[key]) is not int or profile[key] <= 0:
            raise ValueError("invalid PGO producer run/attempt")
    if (
        profile["producerRun"] != producer["run"]
        or profile["producerAttempt"] != producer["attempt"]
    ):
        raise ValueError("PGO producer attempt mismatch")
    if profile["producerSubjectSha256"] != digest(producer) or profile[
        "producerArtifactSha256"
    ] != hash_value(producer["artifactSha256"]):
        raise ValueError("PGO generating binary mismatch")
    if profile["workloadSha256"] != hash_value(workload):
        raise ValueError("PGO workload mismatch")
    for path, field in ((profdata, "profdataSha256"), (jarlog, "jarlogSha256")):
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size == 0
            or file_digest(path) != hash_value(profile[field])
        ):
            raise ValueError("PGO profdata/jarlog bytes mismatch")


def verify_subject(subject):
    fields = {
        "schemaVersion",
        "common",
        "role",
        "target",
        "delta",
        "finalTree",
        "configSha256",
        "toolchainSha256",
        "artifactSha256",
        "run",
        "attempt",
    }
    if (
        set(subject) != fields
        or type(subject["schemaVersion"]) is not int
        or subject["schemaVersion"] != 1
    ):
        raise ValueError("invalid build subject schema")
    verify_common(subject["common"])
    if subject["target"] not in TARGETS.values() or subject["role"] not in {
        "canonical-debug",
        "production-opt",
        "profile-generate",
        "profile-use",
    }:
        raise ValueError("unknown native target or canonical role")
    if subject["target"] == TARGETS[("linux", "aarch64")] and subject[
        "role"
    ].startswith("profile-"):
        raise ValueError("Linux ARM uses production-opt")
    for field in ("finalTree", "configSha256", "toolchainSha256", "artifactSha256"):
        hash_value(subject[field])
    for field in ("run", "attempt"):
        if type(subject[field]) is not int or subject[field] <= 0:
            raise ValueError("invalid build producer run/attempt")
    if (
        not isinstance(subject["delta"], list)
        or subject["role"] != "canonical-debug"
        and subject["delta"]
    ):
        raise ValueError("undeclared diagnostic source role")
    if not subject["delta"] and subject["finalTree"] != subject["common"]["B"]:
        raise ValueError("empty diagnostic delta requires the common baseline tree")
    paths = []
    for entry in subject["delta"]:
        if set(entry) != {"path", "sha256"}:
            raise ValueError("invalid diagnostic entry")
        paths.append(safe_path(entry["path"]))
        hash_value(entry["sha256"])
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate diagnostic source entry")
    return digest(subject)


def verify_build_subject(actual, expected, actual_root, expected_inventory):
    verify_subject(actual)
    verify_subject(expected)
    if actual != expected:
        raise ValueError("build subject differs from trusted expectation")
    if verify_final_source(actual_root, expected_inventory) != actual["finalTree"]:
        raise ValueError("final source bytes do not match the build subject")
    return digest(actual)


def preflight(root, expected_runtime):
    hash_value(expected_runtime, 40)
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output([
        "git",
        "-C",
        str(root),
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--ignored",
        "--",
        ".github",
    ])
    if head != expected_runtime or dirty:
        raise ValueError("unexpected or dirty Runtime recipe checkout")
    policy = json.loads((root / ".github/qa/source-policy.json").read_text())
    if (
        set(policy)
        != {"schemaVersion", "comparisonPolicy", "commonPatches", "debugPatches"}
        or type(policy["schemaVersion"]) is not int
        or policy["comparisonPolicy"] != "common-baseline-with-diagnostics"
        or policy["schemaVersion"] != 1
    ):
        raise ValueError("unsupported source comparison policy")
    if len(policy["commonPatches"]) != 27 or len(policy["debugPatches"]) != 3:
        raise ValueError("reduced Runtime patch policy")
    verify_patches(root, policy["commonPatches"], ".github/patches/upstream")
    verify_patches(root, policy["debugPatches"], ".github/patches/debug")
    upstream = json.loads((root / ".github/runtime-upstream.json").read_text())[
        "upstream"
    ]
    hash_value(upstream["commit"], 40)
    if upstream["repository"] != "mozilla-firefox/firefox":
        raise ValueError("unexpected upstream repository")
    return {
        "schemaVersion": 1,
        "stage": "shadow",
        "executionKind": "policy-preflight-only",
        "U": {
            "vcs": "git",
            "repository": "https://github.com/mozilla-firefox/firefox",
            "fullRevision": upstream["commit"],
        },
        "R": head,
        "P": policy["commonPatches"],
        "diagnosticDeltas": policy["debugPatches"],
        "recipeSha256": file_digest(root / ".github/workflows/scripts/setup-floorp.sh"),
        "B": None,
        "F": None,
        "upstreamIngestion": "UNVERIFIED",
        "nativeQualification": "UNVERIFIED",
        "officialFirefoxMatch": "unverified",
        "officialMatchMode": "advisory",
        "publicationAuthorized": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-runtime", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        result = {
            "schemaVersion": 1,
            "stage": "shadow",
            "executionKind": "policy-preflight-only",
            "expectedRuntime": args.expected_runtime,
            "preflightVerdict": "INCOMPLETE",
            "workflowRun": os.environ.get("GITHUB_RUN_ID"),
            "workflowAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "B": None,
            "F": None,
            "nativeQualification": "UNVERIFIED",
            "officialFirefoxMatch": "unverified",
            "publicationAuthorized": False,
        }
        try:
            result.update(preflight(ROOT, args.expected_runtime))
            result["preflightVerdict"] = "PASS"
        except (
            ValueError,
            TypeError,
            KeyError,
            OSError,
            subprocess.SubprocessError,
        ) as error:
            result["preflightVerdict"] = "FAIL"
            result["error"] = str(error)
        output.write(json.dumps(result, indent=2) + "\n")
    sys.exit(0 if result["preflightVerdict"] == "PASS" else 1)
