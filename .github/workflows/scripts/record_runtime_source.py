#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import argparse
import hashlib
import json
import re
import stat
import subprocess
from pathlib import Path


NATIVE_MANIFEST = Path(".github/runtime-native-patches.json")
NATIVE_PATCH = ".github/patches/upstream/windows-sandbox-extended-path.patch"
NATIVE_SOURCE = "security/sandbox/win/src/sandboxbroker/sandboxBroker.cpp"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "Unexpected native patch schema")


def digest(value, length=64):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value), "Invalid native patch digest")


def read_regular(path):
    path = Path(path)
    for part in (path, *path.parents):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "Native patch path is a link")
    require(path.is_file(), "Native patch path is not a regular file")
    return path.read_bytes()


def git_bytes(revision, path):
    return subprocess.check_output(["git", "show", f"{revision}:{path}"])


def validate_native_patches(runtime_commit):
    if not NATIVE_MANIFEST.exists():
        require(not Path(NATIVE_PATCH).exists(), "Native patch exists without its manifest")
        return None
    manifest_bytes = read_regular(NATIVE_MANIFEST)
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "Duplicate native manifest key")
            value[key] = item
        return value
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    exact_keys(manifest, ("schema_version", "scope", "base_runtime_commit", "patches"))
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, "Unsupported native manifest version")
    require(manifest["scope"] == "windows-graphics-native-rebuild-diagnostic", "Unsupported native patch scope")
    base = manifest["base_runtime_commit"]
    digest(base, 40)
    require(subprocess.run(["git", "merge-base", "--is-ancestor", base, runtime_commit], check=False).returncode == 0, "Native patch base is not an ancestor")
    require(isinstance(manifest["patches"], list) and len(manifest["patches"]) == 1, "Expected exactly one diagnostic native patch")
    patch = manifest["patches"][0]
    exact_keys(patch, ("runtime_path", "sha256", "origin", "source_files"))
    require(patch["runtime_path"] == NATIVE_PATCH, "Unexpected native patch path")
    digest(patch["sha256"])
    patch_bytes = read_regular(NATIVE_PATCH)
    require(hashlib.sha256(patch_bytes).hexdigest() == patch["sha256"], "Native patch hash mismatch")
    headers = [line for line in patch_bytes.decode("utf-8").splitlines() if line.startswith(("--- ", "+++ "))]
    require(headers == ["--- a/" + NATIVE_SOURCE, "+++ b/" + NATIVE_SOURCE], "Native patch modifies unexpected paths")
    origin = patch["origin"]
    exact_keys(origin, ("repository", "commit", "path"))
    require(origin["repository"] == "Floorp-Projects/Floorp" and origin["path"] == ".github/patches/floorp-runtime/native-rebuild/windows-sandbox-extended-path.patch", "Unexpected native patch origin")
    digest(origin["commit"], 40)
    exact_keys(patch["source_files"], (NATIVE_SOURCE,))
    hashes = patch["source_files"][NATIVE_SOURCE]
    exact_keys(hashes, ("base_sha256", "patched_sha256"))
    for value in hashes.values():
        digest(value)
    for revision in (base, runtime_commit):
        require(hashlib.sha256(git_bytes(revision, NATIVE_SOURCE)).hexdigest() == hashes["base_sha256"], "Native source preimage mismatch")
    actual = hashlib.sha256(read_regular(NATIVE_SOURCE)).hexdigest()
    require(actual == hashes["patched_sha256"], "Native source postimage mismatch")
    return {
        "schema_version": 1,
        "runtime_commit": runtime_commit,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "manifest": manifest,
        "actual_patched_sha256": {NATIVE_SOURCE: actual},
        "recorder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def record_source(output: Path) -> None:
    pin_path = Path(".github/runtime-upstream.json")
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    for path in (
        "browser/config/version.txt",
        "browser/config/version_display.txt",
        "config/milestone.txt",
    ):
        versions = [
            line.strip()
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if versions != [pin["upstream"]["version"]]:
            raise ValueError(f"Runtime version does not match upstream pin: {path}")

    patch = pin["floorp_patch"]
    if hashlib.sha256(Path(patch["runtime_path"]).read_bytes()).hexdigest() != patch["sha256"]:
        raise ValueError("Runtime patch does not match the pinned Floorp patch")
    for path, expected_hash in patch["patched_files"].items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected_hash:
            raise ValueError(f"Compiled Runtime source does not match the pin: {path}")

    provenance = {
        "schema_version": 1,
        "runtime_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "upstream": pin["upstream"],
        "floorp_patch": patch,
    }
    native_provenance = validate_native_patches(provenance["runtime_commit"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    if native_provenance is not None:
        output.with_name("runtime-native-patch-provenance.json").write_text(
            json.dumps(native_provenance, indent=2) + "\n", encoding="utf-8"
        )
    print(f"Verified Runtime source provenance: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    record_source(parser.parse_args().output)
