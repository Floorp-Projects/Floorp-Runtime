# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import sys
from pathlib import Path

from qa3_native_consume import harness_argv
from qa3_native_io import read_json, write_json


def probe(support, app, output):
    plan = read_json(support / "plan.json")
    sys.path.insert(0, str(support / "mochitest"))
    import mochitest_options

    sys.path.insert(0, str(support / "xpcshell"))
    import xpcshellcommandline

    for case in plan["selection"]:
        parser = (
            mochitest_options.MochitestArgumentParser(app="generic")
            if case["suite"] == "browser-chrome"
            else xpcshellcommandline.parser_desktop()
        )
        for name in (
            Path(case["archivePath"]).name,
            "browser_qa3_assertion.js"
            if case["suite"] == "browser-chrome"
            else "test_qa3_assertion.js",
        ):
            selected = {
                **case,
                "archivePath": case["archivePath"].rsplit("/", 1)[0] + "/" + name,
            }
            argv = harness_argv(
                sys.executable, support, app, selected, output.parent / "probe-profile"
            )
            parser.parse_args(argv[3:])
    write_json(
        output,
        {
            "schemaVersion": 1,
            "parserVerdict": "PASS",
            "nativeExecuted": False,
            "suites": ["browser-chrome", "xpcshell"],
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("support", "app", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    probe(args.support, args.app, args.output)
