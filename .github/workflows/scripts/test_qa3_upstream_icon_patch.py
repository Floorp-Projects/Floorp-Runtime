# SPDX-License-Identifier: MPL-2.0

import tempfile
import unittest
from pathlib import Path

from upstream_sync import git

BRANDING = '''for icon in ("firefox", "document", "newwindow", "newtab", "pbmode", "document_pdf"):
    DEFINES[icon.upper() + "_ICO"] = '\\"%s/%s/%s.ico\\"' % (
        TOPSRCDIR,
        CONFIG["MOZ_BRANDING_DIRECTORY"],
        icon,
    )

'''
CUSTOM_ICONS = '''for icon in ("retro2004", "minimal-dark"):
    macro = "CUSTOM_" + icon.upper().replace("-", "_") + "_ICO"
    DEFINES[macro] = '\\"%s/browser/components/shell/icons/%s.ico\\"' % (
        TOPSRCDIR,
        icon,
    )

'''
CONSOLE = '''if CONFIG["MOZ_ASAN"] or CONFIG["MOZ_DEBUG"]:
    WINCONSOLE = True
else:
    WINCONSOLE = False
'''
HEADERS = '\nSOURCE_HEADERS += [\n    "ApplicationData.h",\n    "BrowserDefines.h",\n]\n'


class UpstreamIconPatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "core.autocrlf", "false")
        self.source = self.root / "browser/app/moz.build"
        self.source.parent.mkdir(parents=True)
        self.patch = Path(__file__).resolve().parents[2] / "patches/upstream/brandingFileIcon.patch"

    def apply(self, text):
        self.source.write_text(text, encoding="utf-8", newline="\n")
        git(self.root, "apply", "--check", "--whitespace=error-all", str(self.patch))
        git(self.root, "apply", "--whitespace=error-all", str(self.patch))
        result = self.source.read_text()
        compile(result, "moz.build", "exec")
        return result

    def assert_definitions(self, result, headers):
        for os_target, folder in (("WINNT", "windows"), ("Darwin", "mac"), ("Linux", "linux")):
            for debug, asan in ((False, False), (True, False), (False, True)):
                with self.subTest(os=os_target, debug=debug, asan=asan):
                    env = {
                        "CONFIG": {"OS_TARGET": os_target, "MOZ_BRANDING_DIRECTORY": "floorp/branding",
                                   "MOZ_DEBUG": debug, "MOZ_ASAN": asan},
                        "TOPSRCDIR": "/source", "DEFINES": {}, "SOURCE_HEADERS": [],
                    }
                    exec(compile(result, "moz.build", "exec"), env)
                    for name in ("document", "document_pdf"):
                        self.assertEqual(env["DEFINES"][name.upper() + "_ICO"],
                                         f'"/source/floorp/branding/content/{folder}/{name}.ico"')
                    for name in ("firefox", "newwindow", "newtab", "pbmode"):
                        self.assertEqual(env["DEFINES"][name.upper() + "_ICO"],
                                         f'"/source/floorp/branding/{name}.ico"')
                    self.assertEqual(env["WINCONSOLE"], debug or asan)
                    self.assertEqual(env["SOURCE_HEADERS"], headers)

    def test_firefox_159_end_of_file_layout(self):
        result = self.apply(BRANDING + CONSOLE)
        self.assertTrue(result.endswith(CONSOLE))
        self.assert_definitions(result, [])

    def test_firefox_160_headers_and_custom_icons_are_preserved(self):
        result = self.apply(BRANDING + CUSTOM_ICONS + CONSOLE + HEADERS)
        self.assertTrue(result.endswith(CONSOLE + HEADERS))
        self.assertIn(CUSTOM_ICONS, result)
        self.assert_definitions(result, ["ApplicationData.h", "BrowserDefines.h"])

    def test_unknown_console_layout_is_rejected_without_writes(self):
        text = BRANDING + CONSOLE.replace("WINCONSOLE = False", "WINCONSOLE = CONFIG['OTHER']") + HEADERS
        self.source.write_text(text)
        before = self.source.read_bytes()
        with self.assertRaises(ValueError):
            git(self.root, "apply", str(self.patch))
        self.assertEqual(self.source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
