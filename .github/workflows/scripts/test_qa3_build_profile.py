# SPDX-License-Identifier: MPL-2.0

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from qa3_build_profile import (
    TARGETS,
    ac_options,
    enable_debug_tests,
    profile,
    verify_config,
)

ROOT = Path(__file__).resolve().parents[3]
CONFIGS = {
    ("linux", "x86_64"): "linux-x86_64",
    ("linux", "aarch64"): "linux-aarch64",
    ("windows", "x86_64"): "windows-x86_64",
    ("mac", "x86_64"): "macosx64-x86_64",
    ("mac", "aarch64"): "macosx64-aarch64",
}


class BuildProfileTests(unittest.TestCase):
    def generated(self, platform, arch, debug, pgo, mode="", artifact=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / ".github/workflows/scripts"
            scripts.mkdir(parents=True)
            configs = root / ".github/workflows/mozconfigs"
            configs.mkdir()
            for file in (ROOT / ".github/workflows/mozconfigs").glob("*.mozconfig"):
                shutil.copy2(file, configs / file.name)
            for name in ("setup-floorp.sh", "qa3_build_profile.py"):
                shutil.copy2(ROOT / ".github/workflows/scripts" / name, scripts / name)
            patches = root / ".github/patches/debug"
            patches.mkdir(parents=True)
            (root / "build").mkdir()
            (root / "build/application.ini.in").write_text("fixture\n")
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name in ("sudo", "rustup"):
                path = bin_dir / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o700)
            mach = root / "mach"
            mach.write_text("#!/bin/sh\nexit 0\n")
            mach.chmod(0o700)
            env = {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "GITHUB_WORKSPACE": str(root),
                "SCCACHE_PATH": "/fixture/sccache",
            }
            subprocess.run(
                [
                    "bash",
                    str(scripts / "setup-floorp.sh"),
                    platform,
                    arch,
                    str(debug).lower(),
                    str(pgo).lower(),
                    mode,
                    artifact,
                    "20261009000000",
                ],
                cwd=root,
                env=env,
                check=True,
                capture_output=True,
                timeout=15,
            )
            return (root / "mozconfig").read_text()

    def test_real_setup_generates_canonical_debug_on_all_five_targets(self):
        for platform, arch in TARGETS:
            with self.subTest(platform=platform, arch=arch):
                result = self.generated(platform, arch, True, False)
                self.assertNotIn("--disable-tests", ac_options(result))
                self.assertEqual(ac_options(result).count("--enable-tests"), 1)
                evidence = verify_config(result, profile(platform, arch, True, False))
                self.assertFalse(evidence["configureExecuted"])
                self.assertFalse(evidence["nativeTestsExecuted"])

    def test_production_opt_and_pgo_preserve_tests_and_profile_flags(self):
        for platform, arch in TARGETS:
            base = (
                ROOT
                / f".github/workflows/mozconfigs/{CONFIGS[(platform, arch)]}.mozconfig"
            ).read_text()
            wanted_tests = [v for v in ac_options(base) if v.endswith("-tests")]
            modes = (
                [""]
                if (platform, arch) == ("linux", "aarch64")
                else ["", "generate", "use"]
            )
            for mode in modes:
                with self.subTest(platform=platform, arch=arch, mode=mode):
                    artifact = "fixture-profile" if mode == "use" else ""
                    result = self.generated(
                        platform, arch, False, bool(mode), mode, artifact
                    )
                    self.assertEqual(
                        [v for v in ac_options(result) if v.endswith("-tests")],
                        wanted_tests,
                    )
                    verify_config(
                        result,
                        profile(platform, arch, False, bool(mode), mode, artifact),
                    )

    def test_legacy_debug_pgo_is_not_canonical_qualification(self):
        for platform, arch in TARGETS:
            if (platform, arch) == ("linux", "aarch64"):
                continue
            expected = profile(platform, arch, True, True, "use", "fixture-profile")
            self.assertFalse(expected["testsOverride"])
            self.assertFalse(expected["qualificationEligible"])
            result = self.generated(
                platform, arch, True, True, "use", "fixture-profile"
            )
            self.assertNotIn("--enable-tests", ac_options(result))
            verify_config(result, expected)

    def test_invalid_targets_modes_and_profile_inputs_are_rejected(self):
        for args in (
            ("windows", "aarch64", False, False),
            ("linux", "aarch64", False, True, "generate"),
            ("linux", "x86_64", True, False, "use", "old-profile"),
            ("mac", "aarch64", False, True, "use"),
            ("mac", "x86_64", False, True, "generate", "old-profile"),
            ("linux", "x86_64", "false", False),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                profile(*args)

    def test_wrong_target_debug_tests_and_profiling_are_rejected(self):
        text = self.generated("mac", "aarch64", True, False)
        expected = profile("mac", "aarch64", True, False)
        changes = [
            text.replace("aarch64-apple-darwin", "x86_64-apple-darwin"),
            text.replace("--enable-tests", "--disable-tests"),
            text.replace("--enable-debug", "--disable-debug"),
            text + "ac_add_options --enable-profile-generate=cross\n",
            text + "ac_add_options --enable-tests\n",
        ]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                verify_config(changed, expected)

    def test_profile_use_requires_lto_profdata_and_jarlog(self):
        text = self.generated("linux", "x86_64", False, True, "use", "fixture-profile")
        expected = profile("linux", "x86_64", False, True, "use", "fixture-profile")
        for marker in (
            "export MOZ_LTO=cross",
            "ac_add_options --with-pgo-profile-path",
            "ac_add_options --with-pgo-jarlog",
        ):
            changed = "\n".join(
                line for line in text.splitlines() if not line.startswith(marker)
            )
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                verify_config(changed, expected)

    def test_debug_test_override_is_idempotent_and_rejects_ambiguous_flags(self):
        text = "# ac_add_options --disable-tests\nac_add_options --disable-tests\n"
        result = enable_debug_tests(text, True, False)
        self.assertEqual(enable_debug_tests(result, True, False), result)
        with self.assertRaises(ValueError):
            enable_debug_tests("ac_add_options --disable-tests --other\n", True, False)
        for debug, pgo in ((False, False), (False, True), (True, True)):
            self.assertEqual(enable_debug_tests(text, debug, pgo), text)


if __name__ == "__main__":
    unittest.main()
