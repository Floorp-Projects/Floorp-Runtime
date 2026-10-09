# SPDX-License-Identifier: MPL-2.0

import os
import sys
from pathlib import Path


def run(harness):
    parser = harness.parser_desktop()
    options = parser.parse_args()
    if (
        options.xpcshell is None
        or options.app_binary is not None
        or options.interactive
    ):
        raise ValueError("fixed proof requires explicit noninteractive xpcshell helper")
    options.retry = False
    log = harness.commandline.setup_logging("XPCShell", options, {"raw": sys.stdout})
    tests = harness.XPCShellTests(log)
    result = tests.runTests(options)
    if "MOZ_AUTOMATION" in os.environ:
        harness.symbolicate_profiles()
    if result == harness.TBPL_RETRY:
        return 4
    return 0 if result else 1


if __name__ == "__main__":
    support = Path(os.environ["QA3_XPCSHELL_SUPPORT"])
    sys.path.insert(0, str(support / "xpcshell"))
    import runxpcshelltests

    sys.exit(run(runxpcshelltests))
