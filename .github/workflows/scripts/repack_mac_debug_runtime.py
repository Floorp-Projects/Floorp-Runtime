#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import argparse
import configparser
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(SOURCE_ROOT / "python/mozbuild"))
sys.path.insert(0, str(SOURCE_ROOT / "config"))
sys.path.insert(0, str(SOURCE_ROOT / "third_party/python/packaging"))

from createprecomplete import generate_precomplete
from mozpack.chrome.manifest import is_manifest
from mozpack.copier import FileCopier
from mozpack.executables import MACHO, get_type
from mozpack.packager import SimplePackager
from mozpack.packager.formats import OmniJarFormatter
from mozpack.packager.unpack import UnpackFinder
from verify_full_version import validate_expected_build_id


def digest(stream):
    result = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        result.update(block)
    return result.hexdigest()


def resource_inventory(finder):
    inventory = {}
    for name, file in finder.find("*"):
        if is_manifest(name):
            continue
        stream = file.open()
        manager = stream if isinstance(stream, io.IOBase) else contextlib.nullcontext(stream)
        with manager as stream:
            inventory[name] = digest(stream)
    return inventory


def native_inventory(app):
    inventory = {}
    for file in sorted(app.rglob("*")):
        if file.is_file():
            with file.open("rb") as stream:
                if get_type(stream) != MACHO:
                    continue
                stream.seek(0)
                inventory[file.relative_to(app).as_posix()] = digest(stream)
    if not inventory:
        raise ValueError("The application has no Mach-O binaries")
    return inventory


def repack(app, expected_build_id, evidence_path, compiled_source_commit):
    expected_build_id = validate_expected_build_id(expected_build_id)
    app = app.resolve(strict=True)
    resources = app / "Contents/Resources"
    identity = {}
    for filename, section in (("application.ini", "App"), ("platform.ini", "Build")):
        config = configparser.ConfigParser(interpolation=None)
        config.read(resources / filename, encoding="utf-8")
        if config[section]["BuildID"] != expected_build_id:
            raise ValueError(f"Unexpected {filename} BuildID")
        identity[filename] = dict(config[section])
    expected_version = json.loads(
        (SOURCE_ROOT / ".github/runtime-upstream.json").read_text()
    )["upstream"]["version"]
    if identity["application.ini"]["version"] != expected_version:
        raise ValueError("The package does not match the upstream version pin")

    binaries = native_inventory(app)
    finder = UnpackFinder(str(resources), omnijar_name="omni.ja", unpack_xpi=False)
    original_format = finder.kind
    before = resource_inventory(finder)
    with tempfile.TemporaryDirectory(prefix="runtime-omni-", dir=app.parent) as work:
        output = Path(work) / "Resources"
        copier = FileCopier()
        packager = SimplePackager(OmniJarFormatter(copier, "omni.ja"))
        for name, file in finder.find("*"):
            packager.add(name, file)
        packager.close()
        copier.copy(str(output), skip_if_older=False)
        packed = UnpackFinder(str(output), omnijar_name="omni.ja", unpack_xpi=False)
        if packed.kind != "omni" or not (output / "omni.ja").is_file():
            raise ValueError("Mozilla's formatter did not create a GRE omnijar")
        if resource_inventory(packed) != before:
            raise ValueError("Repacking changed unpacked resource contents")
        if not any(name.startswith("modules/") for name in before):
            raise ValueError("The GRE package has no modules")
        backup = Path(work) / "original-resources"
        resources.rename(backup)
        try:
            output.rename(resources)
            generate_precomplete(str(resources))
            if native_inventory(app) != binaries:
                raise ValueError("Repacking changed a compiled Mach-O binary")
        except Exception:
            if resources.exists():
                shutil.rmtree(resources)
            backup.rename(resources)
            raise

    evidence = {
        "version": expected_version,
        "build_id": expected_build_id,
        "compiled_source_commit": compiled_source_commit,
        "original_resource_format": original_format,
        "resource_format": "omni",
        "resource_files_preserved": len(before),
        "native_binaries_unchanged": True,
        "native_binaries_sha256": binaries,
        "gre_omnijar_bytes": (resources / "omni.ja").stat().st_size,
    }
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    print("Repacked macOS Debug Runtime with unchanged native binaries: " + json.dumps(evidence))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--expected-build-id", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--compiled-source-commit", default=os.environ.get("GITHUB_SHA", ""))
    args = parser.parse_args()
    repack(args.app, args.expected_build_id, args.evidence, args.compiled_source_commit)
