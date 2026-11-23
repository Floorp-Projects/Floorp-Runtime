# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import configparser
import re
import shutil
from pathlib import Path

from qa3_native_io import (
    GIB,
    capture_material_tree,
    copy_file,
    elf_identity,
    fresh,
    read_json,
)
from qa3_source_cohort import file_digest, hash_value

PLAN_PATH = ".github/qa/hosted-linux-debug-plan.json"
TAB_ROOT = "browser/components/tabbrowser/test/browser/tabs"
SESSIONSTORE_ROOT = "browser/components/sessionstore/test"
HOSTED_SELECTION = (
    (
        "browser-chrome",
        "browser/base/content/test/browser-performance/browser_hiddenwindow_existence.js",
        1,
    ),
    ("xpcshell", "xpcom/tests/unit/test_nsIMutableArray.js", 49),
    ("browser-chrome", TAB_ROOT + "/browser_pinned_and_hidden_tabs.js", 3),
    ("xpcshell", "xpcom/tests/unit/test_iniParser.js", 717),
    *(
        ("browser-chrome", SESSIONSTORE_ROOT + "/" + name, assertions)
        for name, assertions in (
            ("browser_navigation_api_restore.js", 40),
            ("browser_dynamic_frames.js", 12),
            ("browser_frametree.js", 12),
            ("browser_restore_srcdoc.js", 2),
            ("browser_purge_shistory.js", 5),
        )
    ),
    *(
        ("browser-chrome", TAB_ROOT + "/" + name, assertions)
        for name, assertions in (
            ("browser_blank_tab_label.js", 3),
            ("browser_close_tab_by_dblclick.js", 4),
            ("browser_multiselect_tabs_using_Ctrl.js", 15),
            ("browser_multiselect_tabs_using_Shift_and_Ctrl.js", 30),
            ("browser_openURI_background.js", 6),
            ("browser_tabswitch_updatecommands.js", 1),
            ("browser_tab_label_character_cap.js", 4),
            ("browser_long_data_url_label_truncation.js", 3),
            ("browser_tab_aria_posinset_setsize.js", 4),
            ("browser_positional_attributes.js", 6),
            ("browser_tab_aria_level.js", 2),
            ("browser_tab_label_reader_mode.js", 3),
        )
    ),
)


def native_schedule(plan):
    selection = plan["selection"]
    expected = []
    for suite, identity, assertions in HOSTED_SELECTION:
        directory = identity.rsplit("/", 1)[0]
        prefix = (
            "mochitest/browser/" if suite == "browser-chrome" else "xpcshell/tests/"
        )
        expected.append({
            "suite": suite,
            "id": identity,
            "manifest": directory
            + ("/browser.toml" if suite == "browser-chrome" else "/xpcshell.toml"),
            "archivePath": prefix + identity,
            "minimumAssertions": assertions,
            "declaredConditions": {},
            "requiredNoSkip": True,
        })
    if selection != expected or any(
        type(case["minimumAssertions"]) is not int or case["requiredNoSkip"] is not True
        for case in selection
    ):
        raise ValueError("finite required hosted Debug selection differs")
    return tuple(
        (
            f"native-{index}-{'assertion-canary' if canary else 'required'}",
            selection[index],
            canary,
        )
        for index, canary in (
            (0, False),
            (0, True),
            (1, False),
            (1, True),
            *((index, False) for index in range(2, len(selection))),
        )
    )


def extra_packaged_materials():
    tabs = (
        "browser.toml",
        "head.js",
        "audio.ogg",
        "dummy_page.html",
        "file_mediaPlayback.html",
        "helper_origin_attrs_testing.js",
        "file_about_srcdoc.html",
        "file_reader_mode_article.html",
    )
    sessionstore = (
        "browser.toml",
        "head.js",
        "browser_formdata_format_sample.html",
        "browser_formdata_sample.html",
        "browser_formdata_xpath_sample.html",
        "browser_frame_history_a.html",
        "browser_frame_history_b.html",
        "browser_frame_history_c.html",
        "browser_frame_history_c1.html",
        "browser_frame_history_c2.html",
        "browser_frame_history_index.html",
        "browser_frame_history_index2.html",
        "browser_frame_history_index_blank.html",
        "browser_frametree_sample.html",
        "browser_frametree_sample_frameset.html",
        "browser_frametree_sample_iframes.html",
        "browser_policy_container_sample.html",
        "browser_policy_container_sample_frame.html",
        "browser_scrollPositions_readerModeArticle.html",
        "browser_scrollPositions_sample.html",
        "browser_scrollPositions_sample2.html",
        "browser_scrollPositions_sample_frameset.html",
        "browser_sessionHistory_slow.sjs",
        "browser_sessionStorage.html",
        "browser_speculative_connect.html",
        "coopHeaderCommon.sjs",
        "coop_coep.html",
        "coop_coep.html^headers^",
        "empty.html",
        "empty_frame.html",
        "entry1.html",
        "entry2.html",
        "entry3.html",
        "restore_redirect_http.html",
        "restore_redirect_http.html^headers^",
        "restore_redirect_js.html",
        "restore_redirect_target.html",
    )
    ini = (
        *(f"iniparser{index:02}.ini" for index in range(1, 18)),
        *(f"iniparser{index:02}-utf8BOM.ini" for index in range(1, 17)),
    )
    return (
        *(
            (TAB_ROOT + "/" + name, "mochitest/browser/" + TAB_ROOT + "/" + name)
            for name in tabs
        ),
        *(
            (
                SESSIONSTORE_ROOT + "/" + name,
                "mochitest/browser/" + SESSIONSTORE_ROOT + "/" + name,
            )
            for name in sessionstore
        ),
        (
            "browser/components/tabbrowser/test/TabGroupTestUtils.sys.mjs",
            "modules/TabGroupTestUtils.sys.mjs",
        ),
        *(
            (
                "xpcom/tests/unit/data/" + name,
                "xpcshell/tests/xpcom/tests/unit/data/" + name,
            )
            for name in ini
        ),
    )


def verify_primary(root, context, *, app=None, object_root=None):
    app = app or root / "floorp"

    def material(name):
        path = app / name
        if object_root is not None:
            path = path.resolve(strict=True)
            if not path.is_relative_to(object_root.resolve()):
                raise ValueError("compiled identity escapes its own OBJDIR")
        return path

    identities = {
        name: elf_identity(material(name)) for name in ("floorp", "libxul.so")
    }
    for name, section in (("application.ini", "App"), ("platform.ini", "Build")):
        ini = configparser.ConfigParser(interpolation=None, strict=True)
        ini.read(material(name), encoding="utf-8")
        if ini[section].get("BuildID") != context["buildID"]:
            raise ValueError("packaged application/platform BuildID differs")
        if ini[section].get("SourceStamp") != context["runtimeRecipe"]:
            raise ValueError("packaged source stamp differs from Runtime recipe")
    return identities


def merge_materials(source, destination, budget):
    for item in sorted(source.rglob("*")):
        rel = item.relative_to(source)
        target = destination / rel
        if item.is_symlink():
            raise ValueError("test archive contains unsupported material symlink")
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if file_digest(target) != file_digest(item) or bool(
                    target.stat().st_mode & 0o111
                ) != bool(item.stat().st_mode & 0o111):
                    raise ValueError("conflicting common/test archive member")
            else:
                copy_file(item, target, budget)
        else:
            raise ValueError("special test material")


def install_canaries(source, support, plan):
    changes = []
    for _, case, canary in native_schedule(plan):
        if not canary:
            continue
        name = (
            "browser_qa3_assertion.js"
            if case["suite"] == "browser-chrome"
            else "test_qa3_assertion.js"
        )
        manifest = (
            support
            / case["archivePath"].rsplit("/", 1)[0]
            / Path(case["manifest"]).name
        )
        if not manifest.is_file() or manifest.is_symlink():
            raise ValueError(
                "selected original test manifest missing from same-build support"
            )
        input_manifest = next(
            x["sha256"]
            for x in plan["sourceMaterials"]
            if x["path"] == case["manifest"]
        )
        if file_digest(manifest) != input_manifest:
            raise ValueError("packaged selected manifest differs from pinned source")
        target = manifest.parent / name
        if target.exists():
            raise ValueError("canary collision")
        fixture = source / ".github/qa/canaries" / name
        shutil.copy2(fixture, target)
        before = file_digest(manifest)
        with manifest.open("a") as stream:
            stream.write('\n["' + name + '"]\n')
        changes.append({
            "suite": case["suite"],
            "manifest": manifest.relative_to(support).as_posix(),
            "beforeSha256": before,
            "afterSha256": file_digest(manifest),
            "fixturePath": target.relative_to(support).as_posix(),
            "fixtureSha256": file_digest(target),
            "reason": "QA3_EXPECTED_ASSERTION",
        })
    return changes


def verify_python_environment(root, expected_digest):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("private offline Python environment is missing")
    snapshot = capture_material_tree(root)
    if snapshot["sha256"] != hash_value(expected_digest):
        raise ValueError("offline Python environment differs from controller pin")
    entries = snapshot["entries"]
    if not 1 < len(entries) <= 200:
        raise ValueError("missing or excessive Python wheel inputs")
    for item in entries:
        if item["type"] != "file" or not (
            item["path"] == "requirements.lock"
            or re.fullmatch(r"wheelhouse/[A-Za-z0-9_.+-]+\.whl", item["path"])
        ):
            raise ValueError("unexpected offline Python environment input")
    requirements = (root / "requirements.lock").read_text()
    hashes = set()
    for line in requirements.splitlines():
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(
            r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+(?: --hash=sha256:[0-9a-f]{64})+", line
        ):
            raise ValueError("unlocked dependency, URL, sdist or pip option")
        hashes.update(re.findall(r"sha256:([0-9a-f]{64})", line))
    wheel_hashes = {x["sha256"] for x in entries if x["path"].endswith(".whl")}
    if not hashes or hashes != wheel_hashes:
        raise ValueError("offline wheel inventory and requirements hashes differ")
    if sum((root / x["path"]).stat().st_size for x in entries) > 2 * GIB:
        raise ValueError("offline Python environment budget exceeded")
    return snapshot


def stage_mochitest(support, destination, budget):
    source = support / "mochitest"
    inventory = capture_material_tree(source)
    if not inventory["entries"] or any(
        item["type"] != "file" for item in inventory["entries"]
    ):
        raise ValueError("mutable mochitest copy requires regular packaged files")
    if destination.resolve().is_relative_to(support.resolve()):
        raise ValueError("mutable mochitest copy must be outside frozen support")
    destination = fresh(destination)
    merge_materials(source, destination, budget)
    if (
        capture_material_tree(source) != inventory
        or capture_material_tree(destination) != inventory
    ):
        raise ValueError("mutable mochitest copy differs from frozen support")
    return destination


def harness_argv(python, support, app, case, profile, *, raw_log, mochitest_root=None):
    test = support / case["archivePath"]
    if case["suite"] == "browser-chrome":
        mochitest_root = mochitest_root or support / "mochitest"
        test = mochitest_root / Path(case["archivePath"]).relative_to("mochitest")
    manifest = test.parent / Path(case["manifest"]).name
    common = [
        "--manifest",
        str(manifest),
        "--xre-path",
        str(app),
        "--utility-path",
        str(support / "bin"),
        "--testing-modules-dir",
        str(support / "modules"),
        "--log-raw",
        str(raw_log),
    ]
    if case["suite"] == "browser-chrome":
        return [
            python,
            "-s",
            str(Path(__file__).resolve().with_name("qa3_browser_entry.py")),
            "--flavor",
            "browser",
            "--appname",
            str(app / "floorp"),
            "--certificate-path",
            str(support / "certs"),
            "--extra-profile-file",
            str(support / "bin/plugins"),
            "--headless",
            "--timeout",
            "120",
            "--profile-path",
            str(profile),
            *common,
            test.name,
        ]
    if case["suite"] == "xpcshell":
        return [
            python,
            "-s",
            str(support / "xpcshell/runxpcshelltests.py"),
            "--xpcshell",
            str(support / "bin/xpcshell"),
            "--app-path",
            str(app),
            "--sequential",
            "--verbose",
            "--no-logfiles",
            *common,
            str(test),
        ]
    raise ValueError("unapproved native suite")


def canary_case(case, support, proof):
    changes = [v for v in proof["canaryTransforms"] if v["suite"] == case["suite"]]
    if len(changes) != 1:
        raise ValueError("missing or duplicate canary transform")
    change = changes[0]
    name = (
        "browser_qa3_assertion.js"
        if case["suite"] == "browser-chrome"
        else "test_qa3_assertion.js"
    )
    path = case["archivePath"].rsplit("/", 1)[0] + "/" + name
    manifest = path.rsplit("/", 1)[0] + "/" + Path(case["manifest"]).name
    wanted = next(
        v["sha256"]
        for v in read_json(support / "plan.json")["sourceMaterials"]
        if v["path"] == ".github/qa/canaries/" + name
    )
    if (
        change["fixturePath"],
        change["manifest"],
        change["reason"],
        change["fixtureSha256"],
    ) != (path, manifest, "QA3_EXPECTED_ASSERTION", wanted):
        raise ValueError("unbound assertion-canary identity or reason")
    if (
        file_digest(support / path) != wanted
        or file_digest(support / manifest) != change["afterSha256"]
    ):
        raise ValueError("canary bytes or transformed manifest changed")
    original = next(
        v["sha256"]
        for v in read_json(support / "plan.json")["sourceMaterials"]
        if v["path"] == case["manifest"]
    )
    if change["beforeSha256"] != original:
        raise ValueError("canary was not appended to frozen original manifest")
    return {
        **case,
        "id": case["id"].rsplit("/", 1)[0] + "/" + name,
        "archivePath": path,
        "minimumAssertions": 1,
    }
