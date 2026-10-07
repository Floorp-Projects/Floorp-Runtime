#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import argparse
import configparser
import hashlib
import json
import os
import platform
import struct
import subprocess
import tempfile
from pathlib import Path

from verify_full_version import validate_expected_build_id


def verify_debug_runtime(binary: Path, output_dir: Path, expected_build_id: str) -> None:
    expected_build_id = validate_expected_build_id(expected_build_id)
    binary = binary.resolve(strict=True)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    package_root = binary.parent
    if platform.system() == "Darwin":
        package_root = binary.parent.parent / "Resources"

    identity = {}
    for filename, section in (("application.ini", "App"), ("platform.ini", "Build")):
        paths = list(package_root.rglob(filename))
        if len(paths) != 1:
            raise ValueError(f"Expected one packaged {filename}, found {len(paths)}")
        config = configparser.ConfigParser(interpolation=None)
        config.read(paths[0], encoding="utf-8")
        build_id = config[section]["BuildID"]
        if build_id != expected_build_id:
            raise ValueError(f"Packaged {filename} BuildID does not match {expected_build_id}")
        identity[filename] = {"build_id": build_id}
        if filename == "application.ini":
            identity[filename]["version"] = config[section]["Version"]

    pin = Path(".github/runtime-upstream.json")
    if pin.exists():
        expected_version = json.loads(pin.read_text(encoding="utf-8"))["upstream"]["version"]
        if identity["application.ini"]["version"] != expected_version:
            raise ValueError("Packaged Runtime version does not match the source pin")

    page = output_dir / "native-render.html"
    page.write_text(
        '<!doctype html><meta charset="utf-8"><title>Runtime native verification</title>'
        '<body style="margin:0;background:#123456;color:white;font:24px sans-serif">'
        "Floorp Runtime native rendering verification</body>",
        encoding="utf-8",
    )
    screenshot = output_dir / "native-render.png"
    screenshot.unlink(missing_ok=True)
    environment = os.environ.copy()
    environment.pop("XUL_APP_FILE", None)
    with tempfile.TemporaryDirectory(prefix="profile-", dir=output_dir) as profile:
        with (output_dir / "browser.log").open("wb") as log:
            result = subprocess.run(
                [
                    str(binary),
                    "--no-remote",
                    "--profile",
                    profile,
                    "--headless",
                    "--window-size",
                    "800,600",
                    "--screenshot",
                    str(screenshot),
                    page.as_uri(),
                ],
                cwd=binary.parent,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=180,
                check=False,
            )
    if result.returncode != 0:
        raise RuntimeError(f"Native Runtime exited with code {result.returncode}")
    png = screenshot.read_bytes()
    if len(png) < 64 or png[:8] != b"\x89PNG\r\n\x1a\n" or png[12:16] != b"IHDR":
        raise ValueError("Native Runtime did not render a valid PNG")
    dimensions = struct.unpack(">II", png[16:24])
    if dimensions != (800, 600):
        raise ValueError(f"Native screenshot has unexpected dimensions: {dimensions}")
    evidence = {
        "success": True,
        "native_system": platform.system(),
        "native_arch": platform.machine(),
        "packaged_identity": identity,
        "screenshot_dimensions": dimensions,
        "screenshot_sha256": hashlib.sha256(png).hexdigest(),
    }
    (output_dir / "native-debug-results.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print("Verified native startup and rendering: " + json.dumps(evidence))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-build-id", required=True)
    args = parser.parse_args()
    verify_debug_runtime(args.binary, args.output_dir, args.expected_build_id)
