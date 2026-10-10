# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--objdir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve() / "build"))
    import buildconfig

    if (
        Path(buildconfig.topsrcdir).resolve() != args.source.resolve()
        or Path(buildconfig.topobjdir).resolve() != args.objdir.resolve()
    ):
        raise ValueError("configure resolved a different source or OBJDIR")
    names = (
        "ENABLE_TESTS",
        "MOZ_DEBUG",
        "MOZ_ARTIFACT_BUILDS",
        "MOZ_PROFILE_GENERATE",
        "MOZ_PROFILE_USE",
        "TARGET_CPU",
        "OS_TARGET",
        "target",
        "MOZ_BUILD_APP",
        "MOZ_CRASHREPORTER",
        "CC",
        "CXX",
        "RUSTC",
        "CARGO",
    )
    value = {
        "schemaVersion": 1,
        "source": str(args.source.resolve()),
        "objdir": str(args.objdir.resolve()),
        "substs": {key: buildconfig.substs.get(key) for key in names},
    }
    with args.output.open("x") as out:
        json.dump(value, out, indent=2, allow_nan=False)
        out.write("\n")


if __name__ == "__main__":
    main()
