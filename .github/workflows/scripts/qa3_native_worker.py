# SPDX-License-Identifier: MPL-2.0

import argparse
import os
import subprocess
import sys
from pathlib import Path

from qa3_native_io import fresh, verify_group_limits
from qa3_native_transport import load_native_context
from qa3_source_cohort import hash_value
from qa3_source_prepare import check_raw_index, git, tree_index_entries


def worker(args):
    context = load_native_context(
        args.context, args.context_sha256, args.runtime, args.controller
    )
    verify_group_limits(args.role, context)
    root = (
        Path("/var/lib/qa3-native/jobs")
        / f"{context['run']}-{context['attempt']}-{args.role}"
    )
    fresh(root)
    recipe = args.recipe.resolve()
    if any(
        p.is_symlink() or os.access(p, os.W_OK)
        for p in [recipe, recipe / ".github", *(recipe / ".github").rglob("*")]
    ):
        raise ValueError("native UID can modify the controller-owned helper recipe")
    if (
        subprocess.check_output(
            [
                "git",
                "-c",
                "safe.directory=" + str(recipe),
                "-C",
                str(recipe),
                "rev-parse",
                "HEAD",
            ],
            text=True,
        ).strip()
        != args.runtime
    ):
        raise ValueError("worker helper checkout differs from pinned Runtime revision")
    tree = git(
        recipe,
        "-c",
        "safe.directory=" + str(recipe),
        "ls-tree",
        "-r",
        "-z",
        args.runtime,
        "--",
        ".github",
    ).stdout
    check_raw_index(recipe, tree_index_entries(tree), scope=".github")
    scripts = recipe / ".github/workflows/scripts"
    common = [
        "--runtime",
        args.runtime,
        "--controller",
        args.controller,
        "--plan-sha256",
        args.plan_sha256,
        "--toolchain-lock",
        str(args.toolchain_lock),
        "--toolchain-sha256",
        args.toolchain_sha256,
        "--context",
        str(args.context),
        "--context-sha256",
        args.context_sha256,
        "--python-environment-sha256",
        args.python_environment_sha256,
        "--output",
        str(root / "output"),
        "--state",
        str(root / "state"),
    ]
    if args.role == "builder":
        source = root / "source"
        env = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
        env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL="/dev/null",
            GIT_NO_LAZY_FETCH="1",
            GIT_TERMINAL_PROMPT="0",
            PYTHONDONTWRITEBYTECODE="1",
        )
        subprocess.run(
            [
                "git",
                "-c",
                "safe.directory=" + str(recipe),
                "-c",
                "core.autocrlf=false",
                "clone",
                "--shared",
                "--no-checkout",
                "--",
                str(recipe),
                str(source),
            ],
            check=True,
            env=env,
            timeout=300,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "core.autocrlf=false",
                "checkout",
                "--detach",
                args.runtime,
            ],
            check=True,
            env=env,
            timeout=900,
        )
        command = [
            sys.executable,
            "-B",
            str(scripts / "qa3_native_build.py"),
            *common,
            "--source",
            str(source),
            "--objdir",
            str(root / "obj"),
            "--python-environment",
            str(args.python_environment),
        ]
    else:
        command = [
            sys.executable,
            "-B",
            str(scripts / "qa3_native_consume.py"),
            *common,
            "--builder-toolchain-sha256",
            args.builder_toolchain_sha256,
            "--recipe",
            str(recipe),
            "--inputs",
            str(args.context.parent),
            "--primary-id",
            str(args.primary_id),
            "--primary-sha256",
            args.primary_sha256,
            "--support-id",
            str(args.support_id),
            "--support-sha256",
            args.support_sha256,
        ]
    os.execv(sys.executable, command)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("builder", "consumer"))
    for name in ("recipe", "context", "toolchain-lock", "python-environment"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in (
        "runtime",
        "controller",
        "context-sha256",
        "plan-sha256",
        "toolchain-sha256",
        "python-environment-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--builder-toolchain-sha256")
    for kind in ("primary", "support"):
        parser.add_argument("--" + kind + "-id", type=int)
        parser.add_argument("--" + kind + "-sha256")
    args = parser.parse_args()
    for name in (
        "context_sha256",
        "plan_sha256",
        "toolchain_sha256",
        "python_environment_sha256",
    ):
        hash_value(getattr(args, name))
    try:
        worker(args)
    except (OSError, ValueError, subprocess.SubprocessError):
        print(
            "Native worker prerequisites failed; no phase was promoted.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
