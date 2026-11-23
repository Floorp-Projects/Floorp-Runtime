# SPDX-License-Identifier: MPL-2.0

import subprocess
import tempfile
import unittest
from pathlib import Path

from upstream_sync import check_patches, git


BOOTSTRAP_PREFIX = '''from mozboot.windows import WindowsBootstrapper

APPLICATION_CHOICE = """
Note on Artifact Mode:

Artifact builds download prebuilt C++ components rather than building
them locally. Artifact builds are faster!

Artifact builds are recommended for people working on Firefox or
Firefox for Android frontends, or the GeckoView Java API. They are unsuitable
for those working on C++ code. For more information see:
https://firefox-source-docs.mozilla.org/contributing/build/artifact_builds.html.

Please choose the version of Firefox you want to build (see note above):
%s
Your choice: """

APPLICATIONS = {
    "Firefox for Desktop Artifact Mode": "browser_artifact_mode",
    "Firefox for Desktop": "browser",
    "GeckoView/Firefox for Android Artifact Mode": "mobile_android_artifact_mode",
    "GeckoView/Firefox for Android": "mobile_android",
    "SpiderMonkey JavaScript engine": "js",
}

FINISHED = """
Your system should be ready to build %s!
"""
'''
OLD_GIT = '''        # Offer to configure Git, if the current checkout or repo type is Git.
        elif git and checkout_type == "git":
            should_configure_git = False
            if not self.instance.no_interactive:
                should_configure_git = self.instance.prompt_yesno(prompt=CONFIGURE_GIT)
            else:
                # Assuming default configuration setting applies to all VCS.
                should_configure_git = self.hg_configure

            if should_configure_git:
                repo.configure(state_dir)
'''
NEW_GIT = '''        # Offer to configure Git, if the current checkout or repo type is Git.
        if git and checkout_type == "git":
            should_configure_git = False
            if not self.instance.no_interactive:
                should_configure_git = self.instance.prompt_yesno(prompt=CONFIGURE_GIT)
            else:
                should_configure_git = self.git_configure

            if should_configure_git:
                repo.configure(
                    state_dir, no_system_changes=self.instance.no_system_changes
                )
'''


class UpstreamPatchCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "core.autocrlf", "false")
        self.patch_file = (
            Path(__file__).resolve().parents[2] / "patches/upstream/bootstrap.py.patch"
        )

    def save(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        return path

    def commit(self):
        git(self.root, "add", "--all")
        git(self.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
            "commit", "-qm", "fixture")

    def apply_bootstrap(self, block):
        source = self.save("python/mozboot/mozboot/bootstrap.py",
                           BOOTSTRAP_PREFIX + "\n" + block)
        self.commit()
        git(self.root, "apply", "--check", "--whitespace=error-all", str(self.patch_file))
        git(self.root, "apply", "--whitespace=error-all", str(self.patch_file))
        result = source.read_text()
        self.assertIn("Please choose the version of Noraneko you want to build:", result)
        self.assertNotIn("SpiderMonkey JavaScript engine", result)
        self.assertNotIn("prompt_yesno(prompt=CONFIGURE_GIT)", result)
        expected_block = block.replace(
            "                should_configure_git = self.instance.prompt_yesno(prompt=CONFIGURE_GIT)",
            "                # Do not configure Mozilla's Git tooling for the Floorp fork.\n"
            "                should_configure_git = False",
        )
        self.assertTrue(result.endswith(expected_block))
        return result

    def test_bootstrap_preserves_firefox_159_noninteractive_default(self):
        self.assertIn("should_configure_git = self.hg_configure",
                      self.apply_bootstrap(OLD_GIT))

    def test_bootstrap_preserves_firefox_160_git_default_and_configure_arguments(self):
        result = self.apply_bootstrap(NEW_GIT)
        self.assertIn("should_configure_git = self.git_configure", result)
        self.assertIn("no_system_changes=self.instance.no_system_changes", result)

    def test_bootstrap_changed_prompt_fails_without_partial_application(self):
        source = self.save("python/mozboot/mozboot/bootstrap.py",
                           BOOTSTRAP_PREFIX + "\n" + NEW_GIT.replace(
                               "prompt=CONFIGURE_GIT", "prompt=DIFFERENT_PROMPT"))
        self.commit()
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            git(self.root, "apply", "--whitespace=error-all", str(self.patch_file))
        self.assertEqual(source.read_bytes(), before)

    def source_patch(self, name, source, before, after):
        return self.save(
            ".github/patches/upstream/" + name + ".patch",
            f"--- a/{source}\n+++ b/{source}\n@@ -1 +1 @@\n-{before}\n+{after}\n",
        )

    def test_all_patch_failures_are_named_and_real_index_remains_unchanged(self):
        self.save("one.txt", "old\n")
        self.save("two.txt", "old\n")
        self.save("three.txt", "old\n")
        self.source_patch("a-first", "one.txt", "missing", "fixed")
        self.source_patch("b-compatible", "two.txt", "old", "fixed")
        self.source_patch("c-third", "three.txt", "missing", "fixed")
        self.commit()
        before_index = (self.root / ".git/index").read_bytes()
        with self.assertRaises(ValueError) as failure:
            check_patches(self.root)
        message = str(failure.exception)
        self.assertIn("Required upstream patch a-first.patch", message)
        self.assertIn("Required upstream patch c-third.patch", message)
        self.assertNotIn("Required upstream patch b-compatible.patch", message)
        self.assertEqual((self.root / ".git/index").read_bytes(), before_index)
        for name in ("one.txt", "two.txt", "three.txt"):
            self.assertEqual((self.root / name).read_text(), "old\n")

    def test_successful_dependent_patch_sequence_keeps_order(self):
        source = self.save("source.txt", "old\n")
        self.source_patch("a-first", "source.txt", "old", "middle")
        self.source_patch("b-second", "source.txt", "middle", "new")
        self.commit()
        before_index = (self.root / ".git/index").read_bytes()
        self.assertEqual(check_patches(self.root), 2)
        self.assertEqual(source.read_text(), "old\n")
        self.assertEqual((self.root / ".git/index").read_bytes(), before_index)


if __name__ == "__main__":
    unittest.main()
