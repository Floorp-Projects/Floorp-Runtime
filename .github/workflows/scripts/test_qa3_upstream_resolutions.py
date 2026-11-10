# SPDX-License-Identifier: MPL-2.0

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import upstream_sync as sync

BUILD = "widget/cocoa/moz.build"
MENU = "widget/cocoa/nsMenuUtilsX.mm"
BASE_BUILD = b'SOURCES += ["native.mm"]\n'
APP_SHIM = (
    b'\n# App Shim sources use ARC independently of the existing Cocoa widget code.\n'
    b'app_shim_arc_sources = ["appshim/MacWebAppWidget.mm"]\n'
    b'SOURCES += app_shim_arc_sources\n'
    b'for source in app_shim_arc_sources:\n'
    b'    SOURCES[source].flags += ["-fobjc-arc"]\n'
    b'LOCAL_INCLUDES += ["/widget/cocoa/appshim"]\n'
    b'OS_LIBS += ["-framework Security"]\n'
    b'DIRS += ["appshim/shim"]\n'
)
BASE_MENU = b'''nsMenuBarX* nsMenuUtilsX::GetHiddenWindowMenuBar() {
  if (gfxPlatform::IsHeadless()) {
    return nullptr;
  }
  nsIWidget* hiddenWindowWidgetNoCOMPtr = nsCocoaUtils::GetHiddenWindowWidget();
  if (hiddenWindowWidgetNoCOMPtr) {
    return static_cast<nsCocoaWindow*>(hiddenWindowWidgetNoCOMPtr)->GetMenuBar();
  }
  return nullptr;
}
'''
OURS_MENU = BASE_MENU.replace(
    b'  if (hiddenWindowWidgetNoCOMPtr) {\n',
    b'  if (hiddenWindowWidgetNoCOMPtr &&\n'
    b'      !hiddenWindowWidgetNoCOMPtr->IsMacWebAppWidget()) {\n',
)
NEW_MENU = b'''already_AddRefed<nsMenuBarX> nsMenuUtilsX::GetHiddenWindowMenuBar() {
  if (gfxPlatform::IsHeadless()) {
    return nullptr;
  }
  nsCOMPtr<nsIWidget> hiddenWindowWidget = nsCocoaUtils::GetHiddenWindowWidget();
  if (hiddenWindowWidget) {
    return static_cast<nsCocoaWindow*>(hiddenWindowWidget.get())->GetMenuBar();
  }
  return nullptr;
}
'''
NEW_BUILD = BASE_BUILD + b'\nSOURCE_HEADERS += ["native.h"]\n'


def save(root, name, content):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def commit(root):
    sync.git(root, "add", "--all")
    sync.git(root, "-c", "user.name=Sync test", "-c", "user.email=sync@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
             "commit", "-qm", "fixture")
    return sync.git(root, "rev-parse", "HEAD")


class ReviewedCocoaIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.upstream = self.root / "upstream"
        self.runtime = self.root / "runtime"
        sync.git(self.root, "init", "-q", str(self.upstream))
        sync.git(self.upstream, "config", "core.autocrlf", "false")
        for name, data in {
            BUILD: BASE_BUILD, MENU: BASE_MENU,
            "browser/config/version.txt": b"159.0.2\n",
            "source.txt": b"old\n", "shared.txt": b"base\n",
            "binary.dat": b"\0old\xff\n",
        }.items():
            save(self.upstream, name, data)
        self.recorded = commit(self.upstream)
        sync.git(self.upstream, "remote", "add", "origin", str(self.upstream))
        sync.git(self.root, "clone", "-q", str(self.upstream), str(self.runtime))
        sync.git(self.runtime, "config", "core.autocrlf", "false")
        save(self.runtime, BUILD, BASE_BUILD + APP_SHIM)
        save(self.runtime, MENU, OURS_MENU)
        native_patch = save(
            self.runtime, ".github/patches/upstream/native.patch",
            b"--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-old\n+patched\n",
        )
        entry = {"path": native_patch.relative_to(self.runtime).as_posix(),
                 "sha256": hashlib.sha256(native_patch.read_bytes()).hexdigest()}
        save(self.runtime, ".github/qa/source-policy.json",
             json.dumps({"commonPatches": [entry]}).encode())
        self.manifest = save(self.runtime, ".github/runtime-upstream.json", json.dumps({
            "schema_version": 1,
            "upstream": {"repository": "mozilla-firefox/firefox",
                         "version": "159.0.2", "commit": self.recorded, "tag": None},
            "floorp_patch": {"runtime_path": entry["path"], "sha256": entry["sha256"],
                             "patched_files": {"source.txt": hashlib.sha256(b"patched\n").hexdigest()}},
        }).encode())
        self.local = commit(self.runtime)
        save(self.upstream, BUILD, NEW_BUILD)
        save(self.upstream, MENU, NEW_MENU)
        save(self.upstream, "browser/config/version.txt", b"160.0.1\n")
        save(self.upstream, "shared.txt", b"security fix\n")
        save(self.upstream, "binary.dat", b"\0new\xa0\xff\n")
        self.current = commit(self.upstream)
        sync.git(self.runtime, "fetch", "--no-tags", str(self.upstream), self.current)
        self.approved = {
            path: tuple(sync.git(self.runtime, "rev-parse", f"{ref}:{path}")
                        for ref in (self.recorded, self.local, self.current))
            for path in (BUILD, MENU)
        }
        self.approval = patch.object(sync, "REVIEWED_COCOA_BLOBS", self.approved)
        self.approval.start()
        self.addCleanup(self.approval.stop)

    def snapshot(self):
        return (
            sync.git(self.runtime, "rev-parse", "HEAD"),
            (self.runtime / ".git/index").read_bytes(),
            {str(p.relative_to(self.runtime)): p.read_bytes()
             for p in self.runtime.rglob("*")
             if p.is_file() and ".git" not in p.relative_to(self.runtime).parts},
        )

    def integrate(self):
        sync.integrate_upstream(self.runtime, self.upstream)

    def assert_failed_unchanged(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.integrate()
        self.assertEqual(self.snapshot(), before)

    def test_real_git_reproduces_both_conflicts_without_reviewed_resolutions(self):
        with patch.object(sync, "REVIEWED_COCOA_BLOBS", {}):
            self.assert_failed_unchanged()

    def test_integration_keeps_both_build_blocks_and_menu_ownership_guard(self):
        self.integrate()
        self.assertEqual((self.runtime / BUILD).read_bytes(), NEW_BUILD + APP_SHIM)
        menu = (self.runtime / MENU).read_bytes()
        self.assertEqual(menu, NEW_MENU.replace(
            b"if (hiddenWindowWidget)",
            b"if (hiddenWindowWidget && !hiddenWindowWidget->IsMacWebAppWidget())",
        ))
        self.assertIn(b"already_AddRefed<nsMenuBarX>", menu)
        self.assertIn(b"nsCOMPtr<nsIWidget>", menu)
        self.assertIn(b"hiddenWindowWidget.get()", menu)
        self.assertEqual((self.runtime / "binary.dat").read_bytes(), b"\0new\xa0\xff\n")
        self.assertEqual((self.runtime / "source.txt").read_bytes(), b"old\n")
        self.assertEqual(sync.check_patches(self.runtime), 1)
        pin = json.loads(self.manifest.read_text())
        self.assertEqual(pin["upstream"]["commit"], self.current)
        self.assertEqual(pin["upstream"]["version"], "160.0.1")
        self.assertEqual(pin["upstream"]["previous_commit"], self.recorded)

    def test_resolution_only_changes_disposable_index(self):
        before = self.snapshot()
        with tempfile.TemporaryDirectory() as temp:
            env = {**os.environ, "GIT_INDEX_FILE": str(Path(temp) / "index")}
            sync.git(self.runtime, "read-tree", "HEAD", env=env)
            paths = sync.stage_reviewed_cocoa(
                self.runtime, self.recorded, self.current, env, temp)
            self.assertEqual(paths, [BUILD, MENU])
            self.assertEqual(self.snapshot(), before)
            actual = subprocess.check_output(
                ["git", "-C", str(self.runtime), "show", ":" + BUILD], env=env)
            self.assertEqual(actual, NEW_BUILD + APP_SHIM)

    def test_changed_local_content_is_not_silently_overwritten(self):
        save(self.runtime, MENU, OURS_MENU.replace(b"->GetMenuBar()", b"->CustomMenu()"))
        commit(self.runtime)
        self.assert_failed_unchanged()

    def test_changed_upstream_content_requires_new_review(self):
        save(self.upstream, MENU, NEW_MENU.replace(b"->GetMenuBar()", b"->OtherMenu()"))
        commit(self.upstream)
        self.assert_failed_unchanged()

    def test_wrong_base_identity_is_rejected(self):
        base, ours, theirs = self.approved[MENU]
        self.approved[MENU] = ("0" * 40, ours, theirs)
        self.assert_failed_unchanged()

    def test_wrong_local_identity_is_rejected(self):
        base, ours, theirs = self.approved[MENU]
        self.approved[MENU] = (base, "0" * 40, theirs)
        self.assert_failed_unchanged()

    def test_wrong_upstream_identity_is_rejected(self):
        base, ours, theirs = self.approved[MENU]
        self.approved[MENU] = (base, ours, "0" * 40)
        self.assert_failed_unchanged()

    def test_changed_file_mode_is_not_approved(self):
        sync.git(self.runtime, "update-index", "--chmod=+x", MENU)
        os.chmod(self.runtime / MENU, 0o755)
        commit(self.runtime)
        self.assert_failed_unchanged()

    def test_another_conflict_is_fatal_even_after_both_known_resolutions(self):
        save(self.runtime, "shared.txt", b"Floorp behavior\n")
        commit(self.runtime)
        self.assert_failed_unchanged()

    def test_required_patch_failure_preserves_source_index_and_pin(self):
        save(self.upstream, "source.txt", b"incompatible native source\n")
        commit(self.upstream)
        self.assert_failed_unchanged()

    def test_subsequent_nonconflicting_update_does_not_reapply_old_resolutions(self):
        self.integrate()
        commit(self.runtime)
        self.assertEqual(sync.sync_action(self.runtime, self.upstream), "skip")
        expected_build = (self.runtime / BUILD).read_bytes()
        expected_menu = (self.runtime / MENU).read_bytes()
        save(self.upstream, "shared.txt", b"next security fix\n")
        commit(self.upstream)
        self.integrate()
        self.assertEqual((self.runtime / BUILD).read_bytes(), expected_build)
        self.assertEqual((self.runtime / MENU).read_bytes(), expected_menu)
        self.assertEqual((self.runtime / "shared.txt").read_bytes(), b"next security fix\n")

    def test_recipe_rejects_unexpected_or_ambiguous_inputs(self):
        for path, base, ours, theirs in (
            (BUILD, BASE_BUILD, b"unreviewed change\n", NEW_BUILD),
            (MENU, BASE_MENU, BASE_MENU, NEW_MENU),
            (MENU, BASE_MENU, OURS_MENU, NEW_MENU + NEW_MENU),
            ("unreviewed.mm", BASE_MENU, OURS_MENU, NEW_MENU),
        ):
            with self.subTest(path=path, ours=ours):
                with self.assertRaises(ValueError):
                    sync.resolve_reviewed_cocoa(path, base, ours, theirs)


if __name__ == "__main__":
    unittest.main()
