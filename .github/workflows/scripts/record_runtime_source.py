#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


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
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(f"Verified Runtime source provenance: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    record_source(parser.parse_args().output)
