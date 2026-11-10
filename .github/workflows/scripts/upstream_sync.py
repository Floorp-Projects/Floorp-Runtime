# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# SPDX-License-Identifier: MPL-2.0

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def git(root, *args, env=None):
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        env=env,
        capture_output=True,
        check=False,
    )
    # Git may emit non-UTF-8 pathname bytes in its diagnostics. Decode
    # losslessly for logs instead of hiding an apply failure behind a
    # UnicodeDecodeError.
    stdout = result.stdout.decode("utf-8", errors="backslashreplace").strip()
    stderr = result.stderr.decode("utf-8", errors="backslashreplace").strip()
    if result.returncode:
        raise ValueError(
            f"Git {args[0]} failed (exit {result.returncode}): "
            f"{stderr or '(no diagnostic output)'}"
        )
    return stdout


def sync_action(root, upstream, base_manifest=None):
    current = git(upstream, "rev-parse", "HEAD")
    manifest = root / ".github/runtime-upstream.json"
    if not manifest.exists():
        if base_manifest is None or not base_manifest.exists():
            return "sync"
        manifest = base_manifest
    recorded = json.loads(manifest.read_text())["upstream"]["commit"]
    if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{40}", recorded):
        raise ValueError("Invalid recorded immutable upstream commit")
    if recorded == current:
        return "skip"
    return "integrate"


# Reviewed Firefox 159 -> 160 Cocoa conflicts. These are Git blob identities,
# not branch names: any change to any input must go through ordinary 3-way
# integration and, if still conflicting, a new review. Never select ours/theirs
# wholesale or relax the required-patch checks to make an update pass.
REVIEWED_COCOA_BLOBS = {
    "widget/cocoa/moz.build": (
        "42b17196b4c05f4c291be52782203bc6f02d9071",
        "2fecc34acaf876603ea07603d9b7ef3201a4de1e",
        "ffb56bbb414f65208180e00fee5e89542382f7de",
    ),
    "widget/cocoa/nsMenuUtilsX.mm": (
        "b6816b90b37bda889cabb29c5e9223903bb6e3b9",
        "7803eed2ef3bd4b45e0a08751e5ac14b56404178",
        "b1b4f27fb5e5207aa7611e3daa90f6af37491664",
    ),
}


def resolve_reviewed_cocoa(path, base, ours, theirs):
    """Combine the reviewed edits without discarding either side's behavior."""
    if path == "widget/cocoa/moz.build":
        # Both sides appended at EOF. Preserve upstream's complete header
        # inventory and Floorp's complete ARC/link/include/App Shim block.
        if not ours.startswith(base) or not ours[len(base):].startswith(
            b"\n# App Shim sources use ARC independently"
        ):
            raise ValueError("Reviewed App Shim build baseline differs")
        return theirs + ours[len(base):]
    if path == "widget/cocoa/nsMenuUtilsX.mm":
        before = b"  if (hiddenWindowWidgetNoCOMPtr) {\n"
        guarded = (
            b"  if (hiddenWindowWidgetNoCOMPtr &&\n"
            b"      !hiddenWindowWidgetNoCOMPtr->IsMacWebAppWidget()) {\n"
        )
        new_condition = b"  if (hiddenWindowWidget) {\n"
        if (
            base.count(before) != 1
            or base.replace(before, guarded) != ours
            or theirs.count(new_condition) != 1
        ):
            raise ValueError("Reviewed hidden-window menu baseline differs")
        # Keep Mozilla's owning nsCOMPtr and already_AddRefed return type.
        # A MacWebAppWidget is not an nsCocoaWindow and must not be cast to one.
        return theirs.replace(
            new_condition,
            b"  if (hiddenWindowWidget && !hiddenWindowWidget->IsMacWebAppWidget()) {\n",
        )
    raise ValueError("Unreviewed Cocoa resolution path: " + path)


def stage_reviewed_cocoa(root, recorded, current, env, temporary):
    """Stage only exact, reviewed inputs in the disposable integration index."""
    resolved = []
    for path, expected in REVIEWED_COCOA_BLOBS.items():
        entries = [
            git(root, "ls-tree", ref, "--", path).split()
            for ref in (recorded, "HEAD", current)
        ]
        if any(len(entry) != 4 or entry[:2] != ["100644", "blob"]
               for entry in entries):
            continue
        if tuple(entry[2] for entry in entries) != expected:
            continue
        inputs = [subprocess.check_output(
            ["git", "-C", str(root), "cat-file", "blob", oid]
        ) for oid in expected]
        content = resolve_reviewed_cocoa(path, *inputs)
        output = Path(temporary) / ("resolved-" + Path(path).name)
        output.write_bytes(content)
        oid = git(root, "hash-object", "-w", str(output))
        git(root, "update-index", "--add", "--cacheinfo", "100644", oid,
            path, env=env)
        resolved.append(path)
        print(f"Reviewed Cocoa resolution: {path}: {expected} -> {oid}")
    return resolved


def integrate_upstream(root, upstream, base_manifest=None):
    manifest = root / ".github/runtime-upstream.json"
    if not manifest.exists():
        raise ValueError("Recorded integration requires the selected branch manifest")
    pin = json.loads(manifest.read_text())
    recorded = pin["upstream"]["commit"]
    current = git(upstream, "rev-parse", "HEAD")
    if sync_action(root, upstream, base_manifest) != "integrate":
        raise ValueError("Recorded integration requires an upstream advancement")
    if pin["upstream"]["repository"] != "mozilla-firefox/firefox":
        raise ValueError("Unexpected upstream repository")
    if git(root, "status", "--porcelain"):
        raise ValueError("Recorded integration requires a clean checkout")
    patches = required_patches(root)
    native = pin["floorp_patch"]
    if hashlib.sha256((root / native["runtime_path"]).read_bytes()).hexdigest() != native["sha256"]:
        raise ValueError("Pinned native patch changed")
    git(upstream, "fetch", "--depth=1", "origin", recorded)
    git(root, "fetch", "--no-tags", str(upstream), recorded, current)
    with tempfile.TemporaryDirectory(prefix="upstream-integration-") as temporary:
        index = Path(temporary) / "index"
        env = {**os.environ, "GIT_INDEX_FILE": str(index.resolve())}
        git(root, "read-tree", "HEAD", env=env)
        resolved = stage_reviewed_cocoa(root, recorded, current, env, temporary)
        delta = Path(temporary) / "upstream.patch"
        with delta.open("wb") as stream:
            subprocess.run(
                ["git", "-C", str(root), "diff", "--binary", "--full-index",
                 recorded, current, "--", ".", ":(exclude).github",
                 ":(exclude)floorp", ":(exclude).gitmodules", ":(exclude)README.md",
                 *[":(exclude)" + path for path in resolved]],
                stdout=stream, check=True,
            )
        if delta.stat().st_size:
            git(root, "apply", "--cached", "--3way", str(delta), env=env)
        integrated_tree = git(root, "write-tree", env=env)
        for patch in patches:
            git(root, "apply", "--cached", "--whitespace=error-all", str(patch), env=env)
        for path in native["patched_files"]:
            content = subprocess.check_output(
                ["git", "-C", str(root), "show", ":" + path], env=env,
            )
            native["patched_files"][path] = hashlib.sha256(content).hexdigest()
        version = git(upstream, "show", "HEAD:browser/config/version.txt").strip()
        if not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", version):
            raise ValueError("Invalid upstream version")
        pin["upstream"].update({
            "version": version, "tag": None, "tracking_ref": "refs/heads/release",
            "commit": current, "tree": git(upstream, "rev-parse", "HEAD^{tree}"),
            "previous_commit": recorded, "previous_tag": pin["upstream"].get("tag"),
        })
        with delta.open("wb") as stream:
            subprocess.run(
                ["git", "-C", str(root), "diff", "--binary", "--full-index",
                 "HEAD", integrated_tree], stdout=stream, check=True,
            )
        if delta.stat().st_size:
            git(root, "apply", "--index", str(delta))
        manifest.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")


def required_patches(root):
    directory = root / ".github/patches/upstream"
    paths = sorted(directory.glob("*.patch"))
    policy = root / ".github/qa/source-policy.json"
    if not policy.exists():
        return paths
    entries = json.loads(policy.read_text())["commonPatches"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Missing required upstream patch inventory")
    required = []
    for entry in entries:
        relative = Path(entry["path"])
        if (
            relative.parent != Path(".github/patches/upstream")
            or relative.suffix != ".patch"
        ):
            raise ValueError("Invalid required upstream patch path")
        patch = root / relative
        if hashlib.sha256(patch.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("Required upstream patch hash changed: " + str(relative))
        required.append(patch)
    if len(set(required)) != len(required) or set(required) != set(paths):
        raise ValueError("Required upstream patch inventory differs from source policy")
    return required


def check_patches(root):
    patches = required_patches(root)
    with tempfile.TemporaryDirectory(prefix="upstream-patch-check-") as temporary:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(temporary).resolve() / "index")}
        git(root, "read-tree", "HEAD", env=env)
        git(root, "add", "--all", "--force", ".", env=env)
        for patch in patches:
            try:
                git(
                    root,
                    "apply",
                    "--cached",
                    "--whitespace=error-all",
                    str(patch),
                    env=env,
                )
            except ValueError as error:
                raise ValueError(
                    f"Required upstream patch {patch.name}: {error}"
                ) from error
    return len(patches)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("--upstream", required=True, type=Path)
    guard.add_argument("--base-manifest", type=Path)
    guard.add_argument("--output", type=Path, default=os.environ.get("GITHUB_OUTPUT"))
    integrate = commands.add_parser("integrate")
    integrate.add_argument("--upstream", required=True, type=Path)
    integrate.add_argument("--base-manifest", type=Path)
    commands.add_parser("check-patches")
    args = parser.parse_args()
    root = Path.cwd()
    try:
        if args.command == "guard":
            action = sync_action(root, args.upstream, args.base_manifest)
            if args.output:
                with args.output.open("a") as stream:
                    stream.write("action=" + action + "\n")
            print("Upstream sync action: " + action)
        elif args.command == "integrate":
            integrate_upstream(root, args.upstream, args.base_manifest)
            print("Integrated upstream and verified required patches")
        else:
            print(f"All {check_patches(root)} required upstream patches apply cleanly")
    except (KeyError, TypeError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
