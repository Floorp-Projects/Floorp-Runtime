#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import argparse
import hashlib
import re
import shlex
from pathlib import Path

TARGETS = {
    ("linux", "x86_64"): "x86_64-pc-linux-gnu",
    ("linux", "aarch64"): "aarch64-unknown-linux-gnu",
    ("windows", "x86_64"): "x86_64-pc-windows-msvc",
    ("mac", "x86_64"): "x86_64-apple-darwin",
    ("mac", "aarch64"): "aarch64-apple-darwin",
}


def boolean(value):
    if value not in {"true", "false"}:
        raise ValueError("boolean must be true or false")
    return value == "true"


def profile(platform, arch, debug, pgo, mode="", artifact=""):
    if (
        (platform, arch) not in TARGETS
        or type(debug) is not bool
        or type(pgo) is not bool
    ):
        raise ValueError("unsupported target or non-boolean build mode")
    if not pgo and (mode or artifact):
        raise ValueError("non-PGO builds cannot consume a profile")
    if pgo and (
        mode not in {"generate", "use"} or platform == "linux" and arch == "aarch64"
    ):
        raise ValueError("unsupported PGO mode or target")
    if pgo and ((mode == "use") != bool(artifact)):
        raise ValueError("only profile-use requires a profile artifact")
    role = (
        f"profile-{mode}" if pgo else "canonical-debug" if debug else "production-opt"
    )
    if debug and pgo:
        role = f"legacy-debug-{role}"
    return {
        "target": TARGETS[(platform, arch)],
        "role": role,
        "debug": debug,
        "pgo": pgo,
        "testsOverride": debug and not pgo,
        "qualificationEligible": role == "canonical-debug",
    }


def ac_options(text):
    options = []
    for line in text.splitlines():
        words = shlex.split(line, comments=True)
        if words and words[0] == "ac_add_options":
            options.extend(words[1:])
    return options


def enable_debug_tests(text, debug, pgo):
    if type(debug) is not bool or type(pgo) is not bool:
        raise ValueError("non-boolean build mode")
    if not debug or pgo:
        return text
    lines = [
        line
        for line in text.splitlines()
        if not re.fullmatch(
            r"\s*ac_add_options\s+--(?:disable|enable)-tests\s*(?:#.*)?", line
        )
    ]
    result = "\n".join(lines) + "\nac_add_options --enable-tests\n"
    test_options = [
        v
        for v in ac_options(result)
        if v.startswith(("--enable-tests", "--disable-tests"))
    ]
    if test_options != ["--enable-tests"]:
        raise ValueError("ambiguous tests configuration")
    return result


def verify_config(text, expected):
    options = ac_options(text)
    if [v for v in options if v.startswith("--target=")] != [
        f"--target={expected['target']}"
    ]:
        raise ValueError("mozconfig target mismatch")
    debug_options = [
        v for v in options if v.startswith(("--enable-debug", "--disable-debug"))
    ]
    if debug_options != (["--enable-debug"] if expected["debug"] else []):
        raise ValueError("mozconfig debug mismatch")
    profiling = [
        v for v in options if v.startswith(("--enable-profile-", "--disable-profile-"))
    ]
    role = expected["role"]
    wanted = []
    if expected["pgo"]:
        mode = "generate" if role.endswith("generate") else "use"
        wanted = [f"--enable-profile-{mode}=cross"]
    if profiling != wanted:
        raise ValueError("mozconfig profiling mismatch")
    if expected["testsOverride"]:
        tests = [
            v for v in options if v.startswith(("--enable-tests", "--disable-tests"))
        ]
        if tests != ["--enable-tests"]:
            raise ValueError("canonical Debug requires explicit tests")
    if expected["pgo"] and role.endswith("use"):
        if not re.search(r"^export MOZ_LTO=cross$", text, re.M):
            raise ValueError("profile-use requires cross LTO")
        for prefix in ("--with-pgo-profile-path=", "--with-pgo-jarlog="):
            if len([v for v in options if v.startswith(prefix)]) != 1:
                raise ValueError("profile-use requires profdata and jarlog paths")
    return {
        "kind": "generated-mozconfig-only",
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "configureExecuted": False,
        "nativeTestsExecuted": False,
        "publicationAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--debug", required=True)
    parser.add_argument("--pgo", required=True)
    args = parser.parse_args()
    text = args.config.read_text()
    updated = enable_debug_tests(text, boolean(args.debug), boolean(args.pgo))
    if updated != text:
        args.config.write_text(updated)


if __name__ == "__main__":
    main()
