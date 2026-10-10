#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import configparser
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import plistlib
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback
import zipfile
from pathlib import Path, PurePosixPath

ZIP_SHA = "644b13fdebb7f357b98efff5208bb0fe1d03d95686d9e887f08f483ffb1ee42e"
BUILD_ID = "20261009222456"
TEST_SHA = "39af468b4331fdff4ee3c21ad3665c883348a5990db2fb3364a181d587b62f5b"
TEST_BLOB = "de54988b914645657b11222c6a6141f4f1380c2d"
SCRIPTS = Path(__file__).resolve().parent


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(*args, timeout=60):
    return subprocess.check_output(
        args, stderr=subprocess.STDOUT, timeout=timeout, text=True
    )


def paths():
    return Path(os.environ["QA314_EVIDENCE"]), Path(os.environ["QA314_WORK"])


def macho_sections(path):
    with path.open("rb") as stream:
        magic = stream.read(4)
        if magic == b"\xca\xfe\xba\xbe":
            count = struct.unpack(">I", stream.read(4))[0]
            if count > 8:
                raise ValueError("Unexpected Mach-O slice count")
            slices = [struct.unpack(">IIIII", stream.read(20)) for _ in range(count)]
            offsets = [item[2] for item in slices]
        elif magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            offsets = [0]
        else:
            return None
        result = {}
        for base in offsets:
            stream.seek(base)
            header = stream.read(32)
            if header[:4] != b"\xcf\xfa\xed\xfe":
                raise ValueError("Expected 64-bit little-endian Mach-O")
            cpu, subtype, _, count, command_size, _, _ = struct.unpack(
                "<IIIIIII", header[4:]
            )
            if command_size > 1024 * 1024 or count > 4096:
                raise ValueError("Unexpected Mach-O load commands")
            load_commands = stream.read(command_size)
            cursor = 0
            sections = {}
            for _ in range(count):
                cmd, size = struct.unpack_from("<II", load_commands, cursor)
                if size < 8 or cursor + size > len(load_commands):
                    raise ValueError("Invalid Mach-O load command")
                if cmd == 0x19:
                    segment = (
                        load_commands[cursor + 8 : cursor + 24].rstrip(b"\0").decode()
                    )
                    section_count = struct.unpack_from(
                        "<I", load_commands, cursor + 64
                    )[0]
                    for i in range(section_count):
                        start = cursor + 72 + i * 80
                        if start + 80 > cursor + size:
                            raise ValueError("Invalid Mach-O section")
                        name = load_commands[start : start + 16].rstrip(b"\0").decode()
                        length, offset = struct.unpack_from(
                            "<QI", load_commands, start + 40
                        )
                        flags = struct.unpack_from("<I", load_commands, start + 64)[0]
                        if not offset or flags & 0xFF in (1, 12, 18):
                            continue
                        stream.seek(base + offset)
                        data = stream.read(length)
                        if len(data) != length:
                            raise ValueError("Truncated Mach-O section")
                        sections[f"{segment}/{name}"] = hashlib.sha256(data).hexdigest()
                cursor += size
            result[f"{cpu:08x}/{subtype:08x}"] = sections
        return result


def manifest(app, *, sections=False):
    files, links = {}, {}
    for path in sorted(app.rglob("*")):
        relative = str(path.relative_to(app))
        if path.is_symlink():
            links[relative] = os.readlink(path)
        elif path.is_file():
            files[relative] = {"sha256": digest(path), "bytes": path.stat().st_size}
            if sections and "/_CodeSignature/" not in "/" + relative:
                values = macho_sections(path)
                if values is not None:
                    files[relative]["machoSectionHashes"] = values
    return {"files": files, "symlinks": links}


def prepare():
    evidence, work = paths()
    evidence.mkdir(exist_ok=True, mode=0o700)
    work.mkdir(exist_ok=True, mode=0o700)
    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise RuntimeError("Only the authorized macos-14 ARM64 runner may prepare")
    archive = work / "original-artifact.zip"
    if archive.stat().st_size != 237865129 or digest(archive) != ZIP_SHA:
        raise ValueError("Original ZIP size or digest mismatch")
    entries = []
    selected = {
        "floorp-macOS-universal-moz-artifact.dmg",
        "runtime-packaging-provenance.json",
        "floorp-application.ini",
    }
    with zipfile.ZipFile(archive) as source:
        names = set()
        total = 0
        for item in source.infolist():
            name = item.filename
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in name
                or "\x00" in name
                or name in names
                or item.flag_bits & 1
                or stat.S_ISLNK(item.external_attr >> 16)
            ):
                raise ValueError("Unsafe ZIP entry")
            names.add(name)
            total += item.file_size
            if total > 1024 * 1024 * 1024:
                raise ValueError("Original artifact expands beyond 1 GiB")
            entries.append({"name": name, "bytes": item.file_size, "crc32": item.CRC})
            if name in selected:
                with source.open(item) as src, (work / name).open("xb") as dest:
                    shutil.copyfileobj(src, dest)
                (work / name).chmod(0o400)
        if not selected.issubset(names):
            raise ValueError("Missing expected DMG or packaging identity")
    write_json(evidence / "archive-entries.json", entries)
    shutil.copyfile(
        work / "runtime-packaging-provenance.json",
        evidence / "runtime-packaging-provenance.json",
    )
    shutil.copyfile(
        work / "floorp-application.ini", evidence / "floorp-application.ini"
    )
    dmg = work / "floorp-macOS-universal-moz-artifact.dmg"
    dmg_sha = digest(dmg)
    mount = None
    try:
        result = subprocess.run(
            ["hdiutil", "attach", "-readonly", "-nobrowse", "-plist", str(dmg)],
            capture_output=True,
            timeout=60,
            check=True,
        )
        payload = plistlib.loads(result.stdout)
        points = [
            item["mount-point"]
            for item in payload.get("system-entities", [])
            if item.get("mount-point")
        ]
        if len(points) != 1:
            raise ValueError("Expected one mounted DMG")
        mount = Path(points[0])
        apps = list(mount.glob("*.app"))
        if len(apps) != 1:
            raise ValueError("Expected one original application")
        source = apps[0]
        before = manifest(source, sections=True)
        app = work.parent / "Floorp-native-test.app"
        if app.exists():
            raise ValueError("Disposable app path already exists")
        command("/usr/bin/ditto", str(source), str(app), timeout=120)
        copied = manifest(app)
        if {
            k: {f: v[f] for f in ("sha256", "bytes")}
            for k, v in before["files"].items()
        } != copied["files"] or before["symlinks"] != copied["symlinks"]:
            raise ValueError("Disposable copy differs before development signing")
        write_json(evidence / "original-app-manifest.json", before)
        write_json(evidence / "copy-before-signing.json", copied)
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        binary = app / "Contents/MacOS" / info["CFBundleExecutable"]
        if set(command("lipo", "-archs", str(binary)).split()) != {"arm64", "x86_64"}:
            raise ValueError("Expected both universal slices")
        identity = {}
        for filename, section in (
            ("application.ini", "App"),
            ("platform.ini", "Build"),
        ):
            config = configparser.ConfigParser(interpolation=None)
            ini = app / "Contents/Resources" / filename
            config.read(ini)
            if config[section]["BuildID"] != BUILD_ID:
                raise ValueError(f"{filename} BuildID mismatch")
            identity[filename] = dict(config[section])
        pin = json.loads(Path(".github/runtime-upstream.json").read_text())
        if identity["application.ini"]["version"] != pin["upstream"]["version"]:
            raise ValueError(
                "Application version differs from fixed Runtime source pin"
            )
        write_json(evidence / "packaged-identity.json", identity)
        removed = []
        for path in [app, *app.rglob("*")]:
            if path.is_symlink():
                continue
            for name in command("/usr/bin/xattr", str(path)).splitlines():
                if name in {"com.apple.FinderInfo", "com.apple.ResourceFork"}:
                    command("/usr/bin/xattr", "-d", name, str(path))
                    removed.append({
                        "path": str(path.relative_to(app)),
                        "attribute": name,
                    })
        (evidence / "original-signature.txt").write_text(
            command("/usr/bin/codesign", "--display", "--verbose=4", str(source))
        )
        (evidence / "development-signing.log").write_text(
            command(
                "/usr/bin/codesign",
                "--force",
                "--deep",
                "--sign",
                "-",
                "--timestamp=none",
                str(app),
                timeout=120,
            )
        )
        command("/usr/bin/codesign", "--verify", "--deep", "--strict", str(app))
        (evidence / "development-signature.txt").write_text(
            command("/usr/bin/codesign", "--display", "--verbose=4", str(app))
        )
        after = manifest(app, sections=True)
        changes = []
        for relative in sorted(set(before["files"]) | set(after["files"])):
            a, b = before["files"].get(relative), after["files"].get(relative)
            if a == b:
                continue
            signature_file = "/_CodeSignature/" in "/" + relative
            if not signature_file and (
                not a
                or not b
                or not a.get("machoSectionHashes")
                or a["machoSectionHashes"] != b.get("machoSectionHashes")
            ):
                raise ValueError(
                    f"Development signing changed non-signature payload: {relative}"
                )
            changes.append({
                "path": relative,
                "before": a,
                "after": b,
                "signatureResource": signature_file,
                "machoSectionsUnchanged": not signature_file,
            })
        if (
            before["symlinks"] != after["symlinks"]
            or manifest(source, sections=True) != before
        ):
            raise ValueError("Symlinks or read-only original application changed")
        write_json(evidence / "copy-after-signing.json", after)
        write_json(
            evidence / "development-copy.json",
            {
                "changes": changes,
                "removedMetadata": removed,
                "preSigningCopyIdentical": True,
                "sourceAppUnmodified": True,
                "signatureExcludedSectionPayloadUnmodified": True,
                "productionSignature": False,
            },
        )
        graphics = ctypes.CDLL(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
        )
        graphics.CGPreflightPostEventAccess.restype = ctypes.c_bool
        graphics.CGPreflightScreenCaptureAccess.restype = ctypes.c_bool
        permissions = {
            "eventPosting": bool(graphics.CGPreflightPostEventAccess()),
            "screenCapture": bool(graphics.CGPreflightScreenCaptureAccess()),
            "permissionPromptOpened": False,
            "permissionSettingsChanged": False,
        }
        write_json(evidence / "gui-permissions.json", permissions)
        if not permissions["eventPosting"] or not permissions["screenCapture"]:
            raise RuntimeError(
                "Existing GUI permissions unavailable; no settings changed"
            )
        (evidence / "lldb-version.txt").write_text(
            command("xcrun", "lldb", "--version", timeout=20)
        )
        test = Path("floorp-native-tests/tools/app-shim/test-runtime.py").resolve(
            strict=True
        )
        raw = test.read_bytes()
        blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        if digest(test) != TEST_SHA or blob != TEST_BLOB:
            raise ValueError("Pinned test bytes differ from fixed Floorp commit")
        write_json(
            evidence / "prepared.json",
            {
                "app": str(app),
                "binary": str(binary),
                "test": str(test),
                "testSha256": TEST_SHA,
                "testBlob": blob,
                "dmgSha256": dmg_sha,
                "artifactSha256": ZIP_SHA,
                "preparedAt": time.time(),
                "buildId": BUILD_ID,
                "browserLaunched": False,
                "os": platform.platform(),
                "arch": platform.machine(),
                "wrapperSha256": digest(Path(__file__)),
                "lldbScriptSha256": digest(SCRIPTS / "qa314_lldb_capture.py"),
            },
        )
    finally:
        if mount is not None:
            command("hdiutil", "detach", str(mount), timeout=60)
    if digest(dmg) != dmg_sha or digest(archive) != ZIP_SHA:
        raise ValueError("Read-only original ZIP or DMG changed")
    write_json(
        evidence / "original-recheck.json",
        {
            "artifactSha256": ZIP_SHA,
            "dmgSha256": dmg_sha,
            "originalUnmodified": True,
            "stage": "after preparation",
        },
    )


def safe_environment():
    allow = {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "DEVELOPER_DIR",
        "SDKROOT",
        "QA314_EVIDENCE",
        "QA314_WORK",
    }
    return {key: value for key, value in os.environ.items() if key in allow}


def process_row(pid):
    result = subprocess.run(
        ["/bin/ps", "-ww", "-p", str(pid), "-o", "pid=,lstart=,command="],
        capture_output=True,
        text=True,
        timeout=1,
        check=False,
        env={**os.environ, "LC_ALL": "C"},
    )
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 6)
        if len(fields) == 7 and fields[0].isdigit():
            rows.append([int(fields[0]), " ".join(fields[1:6]), fields[6]])
    return rows[0] if len(rows) == 1 else None


def timeout_cleanup(evidence, work, prepared):
    actions = []
    (evidence / "lldb-stop").touch()
    for filename in (
        "debugger-identity.json",
        "host-identity.json",
        "shim-identity.json",
        "launcher-identity.json",
    ):
        path = evidence / filename
        if not path.exists():
            continue
        record = json.loads(path.read_text())
        expected = [record["pid"], record["startTime"], record["command"]]
        profile = Path(record["profile"])
        if not profile.is_relative_to(work / "native-gui"):
            actions.append({"file": filename, "status": "refused-nonprivate-profile"})
            continue
        if filename == "host-identity.json":
            owned = (
                (
                    record.get("verified") is True
                    or record.get("matchedPrivateLaunch") is True
                )
                and expected[2].startswith(prepared["binary"] + " ")
                and "--profile " + str(profile) in expected[2]
            )
        elif filename == "shim-identity.json":
            bundle = Path(record["bundle"])
            owned = (
                bundle.is_relative_to(work / "native-gui")
                and record.get("authenticated") is True
                and record.get("bundleProfile") == str(profile)
                and expected[2].startswith(
                    str(bundle / "Contents/MacOS/floorp-app-shim")
                )
            )
        elif filename == "debugger-identity.json":
            owned = (
                str(evidence / "lldb-config.json") in expected[2]
                and "lldb" in expected[2]
            )
        else:
            owned = (
                record.get("helperOfVerifiedHost") is True
                and prepared["app"] in expected[2]
                and "--profile " + str(profile) in expected[2]
            )
        if not owned or process_row(record["pid"]) != expected:
            actions.append({
                "file": filename,
                "status": "already-exited-or-identity-mismatch",
            })
            continue
        for value in (signal.SIGTERM, signal.SIGKILL):
            if process_row(record["pid"]) != expected:
                break
            try:
                os.kill(record["pid"], value)
            except ProcessLookupError:
                break
            actions.append({
                "file": filename,
                "pid": record["pid"],
                "signal": value,
                "timeoutFallback": True,
                "time": time.time(),
            })
            deadline = time.monotonic() + 3
            while (
                time.monotonic() < deadline and process_row(record["pid"]) == expected
            ):
                time.sleep(0.1)
        if process_row(record["pid"]) == expected:
            actions.append({"file": filename, "status": "cleanup-incomplete"})
    write_json(
        evidence / "outer-timeout-cleanup.json",
        {
            "actions": actions,
            "retry": False,
            "terminationMayBeInfluencedByTimeoutCleanup": True,
            "originalFaultRecordsRetained": True,
        },
    )


def worker():
    evidence, work = paths()
    prepared = json.loads((evidence / "prepared.json").read_text())
    test = Path(prepared["test"])
    if digest(test) != TEST_SHA:
        raise ValueError("Fixed test changed after preparation")
    removed_names = sorted(key for key in os.environ if key not in safe_environment())
    environment = safe_environment()
    os.environ.clear()
    os.environ.update(environment)
    write_json(
        evidence / "environment-isolation.json",
        {
            "allowlist": sorted(environment),
            "removedNames": removed_names,
            "credentialValuesRecorded": False,
            "browserInheritsOnlyAllowlistAndFixedTestCrashReporterDisable": True,
        },
    )
    spec = importlib.util.spec_from_file_location("qa314_fixed_test", test)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    timeline = (evidence / "timeline.jsonl").open("x", buffering=1)
    state = {
        "phase": "before-main",
        "debugger": None,
        "debuggerLog": None,
        "attached": False,
        "variantRead": False,
        "mainCalls": 0,
        "host": None,
        "debuggerCleanupErrors": [],
    }

    def emit(kind, **values):
        timeline.write(
            json.dumps({
                "time": time.time(),
                "monotonic": time.monotonic(),
                "kind": kind,
                "phase": state["phase"],
                **values,
            })
            + "\n"
        )

    original_command = module.Marionette.command
    original_verify = module.HostProcess.verify_session
    original_close = module.HostProcess.close
    original_poll = module.HostProcess.poll

    def poll(host):
        result = original_poll(host)
        if not host.verified and not (evidence / "host-identity.json").exists():
            expected = " ".join(host.command)
            matches = [
                row for row in module.HostProcess._process_rows() if row[2] == expected
            ]
            if len(matches) == 1:
                row = matches[0]
                write_json(
                    evidence / "host-identity.json",
                    {
                        "pid": row[0],
                        "startTime": row[1],
                        "command": row[2],
                        "profile": str(host.profile),
                        "verified": False,
                        "matchedPrivateLaunch": True,
                    },
                )
            row = process_row(host.process.pid)
            if row is not None and str(host.profile) in row[2]:
                write_json(
                    evidence / "launcher-identity.json",
                    {
                        "pid": row[0],
                        "startTime": row[1],
                        "command": row[2],
                        "profile": str(host.profile),
                        "helperOfVerifiedHost": True,
                    },
                )
        return result

    def traced_command(client, name, parameters=None):
        parameters = parameters or {}
        summary = {"command": name, "sequence": client.sequence + 1}
        if "script" in parameters:
            summary["scriptSha256"] = hashlib.sha256(
                parameters["script"].encode()
            ).hexdigest()
        if name == "Marionette:SetContext":
            summary["context"] = parameters.get("value")
        emit("marionette-start", **summary)
        try:
            value = original_command(client, name, parameters)
        except Exception as error:
            emit(
                "marionette-error",
                errorType=type(error).__name__,
                error=str(error),
                **summary,
            )
            raise
        emit("marionette-finish", **summary)
        return value

    def verify(host, session):
        original_verify(host, session)
        state["host"] = host
        write_json(
            evidence / "host-identity.json",
            {
                "pid": host.pid,
                "startTime": host.identity[1],
                "command": host.identity[2],
                "profile": str(host.profile),
                "verified": True,
                "verifiedAt": time.time(),
                "capabilities": session.get("capabilities", {}),
            },
        )
        emit("verified-host", pid=host.pid, startTime=host.identity[1])
        row = process_row(host.process.pid)
        if row is not None and str(host.profile) in row[2]:
            write_json(
                evidence / "launcher-identity.json",
                {
                    "pid": row[0],
                    "startTime": row[1],
                    "command": row[2],
                    "profile": str(host.profile),
                    "helperOfVerifiedHost": True,
                },
            )

    def record_shim(frame):
        host, shim_pid, bundle = (
            frame.f_locals["host"],
            frame.f_locals["shim_pid"],
            frame.f_locals["bundle"],
        )
        row = process_row(shim_pid)
        binary = str(bundle / "Contents/MacOS/floorp-app-shim")
        info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
        if (
            not row
            or not (row[2] == binary or row[2].startswith(binary + " "))
            or info["FloorpAppShimProfilePath"] != str(host.profile)
        ):
            raise RuntimeError("Authenticated Shim argv or private profile mismatch")
        write_json(
            evidence / "shim-identity.json",
            {
                "pid": row[0],
                "startTime": row[1],
                "command": row[2],
                "profile": str(host.profile),
                "bundle": str(bundle),
                "bundleProfile": info["FloorpAppShimProfilePath"],
                "authenticated": True,
            },
        )

    def attach(host, shim_pid):
        if not host.verified or host._matching_identity(host.pid) != host.identity:
            raise RuntimeError("Exact browser identity changed before debugger attach")
        config = {
            "pid": host.pid,
            "identity": list(host.identity),
            "profile": str(host.profile),
            "binary": str(prepared["binary"]),
            "evidence": str(evidence),
            "maximumSeconds": 300,
            "signalForwardingSeconds": 5,
        }
        write_json(evidence / "lldb-config.json", config)
        literal = repr(str(SCRIPTS / "qa314_lldb_capture.py"))
        config_literal = repr(str(evidence / "lldb-config.json"))
        code = f'script exec(compile(open({literal}).read(), {literal}, "exec")); qa314_capture({config_literal})'
        state["debuggerLog"] = (evidence / "lldb.log").open("x")
        state["debugger"] = subprocess.Popen(
            ["xcrun", "lldb", "--batch", "--no-lldbinit", "--one-line", code],
            stdout=state["debuggerLog"],
            stderr=subprocess.STDOUT,
            env=safe_environment(),
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            ready = evidence / "lldb-ready.json"
            if ready.exists():
                data = json.loads(ready.read_text())
                if (
                    data.get("status") != "attached-running"
                    or data.get("pid") != host.pid
                ):
                    raise RuntimeError(
                        "Debugger attach failed; no permissions changed or second launch attempted"
                    )
                state["attached"] = True
                emit(
                    "debugger-attached", pid=host.pid, debuggerPid=state["debugger"].pid
                )
                return
            if state["debugger"].poll() is not None:
                raise RuntimeError("Debugger exited before confirming attachment")
            time.sleep(0.1)
        raise RuntimeError("Debugger attach exceeded 20 seconds; no retry attempted")

    def close(host):
        emit(
            "host-before-cleanup",
            pid=host.pid,
            kernelExitCode=host.returncode,
            requestedSignal=host.requested_signal,
            alive=host.poll() is None,
        )
        try:
            if state["debugger"]:
                (evidence / "lldb-stop").touch()
                try:
                    state["debugger"].wait(timeout=10)
                except subprocess.TimeoutExpired:
                    emit("debugger-stop-timeout")
                    state["debugger"].terminate()
                    try:
                        state["debugger"].wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        state["debugger"].kill()
                        state["debugger"].wait(timeout=5)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            state["debuggerCleanupErrors"].append({
                "type": type(error).__name__,
                "error": str(error),
            })
            emit(
                "debugger-cleanup-error",
                errorType=type(error).__name__,
                error=str(error),
            )
        finally:
            try:
                original_close(host)
            finally:
                emit(
                    "host-after-cleanup",
                    pid=host.pid,
                    kernelExitCode=host.returncode,
                    requestedSignal=host.requested_signal,
                )

    input_line = (
        next(
            i
            for i, line in enumerate(test.read_text().splitlines(), 1)
            if line.strip() == 'report["phase"] = "native-input"'
        )
        + 1
    )
    variant_line = (
        next(
            i
            for i, line in enumerate(test.read_text().splitlines(), 1)
            if line.strip() == 'report["phase"] = "native-service"'
        )
        + 1
    )

    def trace(frame, event, arg):
        if frame.f_code not in (module.main.__code__, module.native_type.__code__):
            return None
        if frame.f_code is module.main.__code__:
            report = frame.f_locals.get("report", {})
            phase = report.get("phase", state["phase"])
            if phase != state["phase"]:
                state["phase"] = phase
                emit("phase-change", line=frame.f_lineno)
                if phase == "gecko-window":
                    record_shim(frame)
            if (
                event == "line"
                and frame.f_lineno == variant_line
                and not state["variantRead"]
            ):
                state["variantRead"] = True
                value = frame.f_locals["client"].script("""
                    return {
                      nativeDebug: Cc['@mozilla.org/xpcom/debug;1'].getService(Ci.nsIDebug2).isDebugBuild,
                      moduleDebug: ChromeUtils.importESModule('resource://gre/modules/AppConstants.sys.mjs').AppConstants.DEBUG,
                      applicationBuildID: Services.appinfo.appBuildID,
                      platformBuildID: Services.appinfo.platformBuildID,
                      version: Services.appinfo.version,
                    };
                """)
                write_json(evidence / "actual-variant.json", value)
                if (
                    value.get("nativeDebug") is not True
                    or value.get("moduleDebug") is not True
                    or value.get("applicationBuildID") != BUILD_ID
                    or value.get("platformBuildID") != BUILD_ID
                ):
                    raise RuntimeError(
                        "Runtime compiled Debug variant or BuildID mismatch"
                    )
                emit("actual-variant", **value)
            if (
                event == "line"
                and frame.f_lineno == input_line
                and not state["attached"]
            ):
                attach(frame.f_locals["host"], frame.f_locals["shim_pid"])
            if event == "line" and 691 <= frame.f_lineno <= 713:
                emit("native-input-substep", line=frame.f_lineno)
            if event == "exception":
                emit(
                    "test-exception",
                    line=frame.f_lineno,
                    errorType=arg[0].__name__,
                    error=str(arg[1]),
                )
        elif event == "line" and frame.f_lineno >= 368:
            emit(
                "native-type-substep",
                line=frame.f_lineno,
                pid=frame.f_locals.get("pid"),
                keyDown=frame.f_locals.get("down"),
            )
        return trace

    def interrupted(signum, _frame):
        raise RuntimeError(
            f"Diagnostic worker interrupted by signal {signum}; no retry"
        )

    signal.signal(signal.SIGTERM, interrupted)
    module.Marionette.command = traced_command
    module.HostProcess.verify_session = verify
    module.HostProcess.close = close
    module.HostProcess.poll = poll
    sys.argv = [
        str(test),
        "--browser",
        prepared["app"],
        "--output",
        str(work / "native-gui"),
        "--launch-services",
        "--capture-window",
    ]
    sys.settrace(trace)
    exit_code = 1
    try:
        state["mainCalls"] += 1
        emit("test-main-start", calls=state["mainCalls"])
        exit_code = module.main()
        emit("test-main-finish", calls=state["mainCalls"], exitCode=exit_code)
    finally:
        sys.settrace(None)
        cleanup_errors = list(state["debuggerCleanupErrors"])
        try:
            if state["debugger"] and state["debugger"].poll() is None:
                (evidence / "lldb-stop").touch()
                try:
                    state["debugger"].wait(timeout=10)
                except subprocess.TimeoutExpired:
                    state["debugger"].terminate()
                    try:
                        state["debugger"].wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        state["debugger"].kill()
                        state["debugger"].wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as error:
            cleanup_errors.append({"type": type(error).__name__, "error": str(error)})
        finally:
            if state["debuggerLog"]:
                try:
                    state["debuggerLog"].close()
                except OSError as error:
                    cleanup_errors.append({
                        "type": type(error).__name__,
                        "error": str(error),
                    })
        debugger_report = evidence / "lldb-status.json"
        try:
            debugger_data = json.loads(debugger_report.read_text())
            debugger_status = debugger_data.get("status")
        except (OSError, ValueError):
            debugger_data = {}
            debugger_status = "missing-or-invalid"
        reasons = []
        if debugger_status not in {
            "browser-exited",
            "test-cleanup-detach",
            "fault-forwarding-detach",
            "repeated-fault-detach",
        }:
            reasons.append("debugger:" + str(debugger_status))
        if cleanup_errors:
            reasons.append("debugger-cleanup-failed")
        for field in ("detachError", "continueError"):
            if debugger_data.get(field) is not None:
                reasons.append("debugger:" + field)
        if not state["attached"] or not state["variantRead"]:
            reasons.append("attach-or-variant-observation-incomplete")
        original_test_exit = exit_code
        if reasons:
            exit_code = exit_code or 1
        write_json(
            evidence / "execution-summary.json",
            {
                "testMainCalls": state["mainCalls"],
                "exitCode": exit_code,
                "debuggerAttached": state["attached"],
                "actualVariantRead": state["variantRead"],
                "testBytesUnchanged": digest(test) == TEST_SHA,
                "testSha256": digest(test),
                "retry": False,
                "timingInfluence": "Python tracing and a single native-input LLDB attach",
                "originalTestExitCode": original_test_exit,
                "diagnosticQualification": not reasons,
                "diagnosticQualificationReasons": reasons,
                "productQualification": False,
                "debuggerStatus": debugger_status,
                "cleanupErrors": cleanup_errors,
            },
        )
        timeline.close()
    return exit_code


def run_once():
    evidence, _ = paths()
    with (evidence / "test-execution-started.json").open("x") as stream:
        json.dump(
            {"startedAt": time.time(), "maximumMainCalls": 1, "retryAllowed": False},
            stream,
        )
    prepared = json.loads((evidence / "prepared.json").read_text())
    environment = safe_environment()
    with (evidence / "worker.stdout.log").open("x") as stdout, (
        evidence / "worker.stderr.log"
    ).open("x") as stderr:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "worker"],
            env=environment,
            stdout=stdout,
            stderr=stderr,
        )
        try:
            result = process.wait(timeout=360)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGTERM)
            try:
                result = process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                result = 124
                timeout_cleanup(evidence, Path(os.environ["QA314_WORK"]), prepared)
            write_json(
                evidence / "worker-timeout.json",
                {
                    "timeoutSeconds": 360,
                    "result": result,
                    "retry": False,
                    "app": prepared["app"],
                },
            )
    print(f"Only native test worker exited {result}; evidence retained at {evidence}")
    return result


def report_identity(path):
    text = path.read_text(errors="replace")
    if path.suffix == ".ips":
        decoder = json.JSONDecoder()
        first, end = decoder.raw_decode(text.lstrip())
        remainder = text.lstrip()[end:].strip()
        payload = json.loads(remainder) if remainder else first
        return payload.get("pid"), payload.get("procPath")
    pid = re.search(r"^Process:\s+.*\[(\d+)\]", text, re.MULTILINE)
    binary = re.search(r"^Path:\s+(.*)$", text, re.MULTILINE)
    return (int(pid[1]) if pid else None), (binary[1].strip() if binary else None)


def collect():
    evidence, work = paths()
    evidence.mkdir(exist_ok=True, mode=0o700)
    prepared_path = evidence / "prepared.json"
    if not prepared_path.exists():
        write_json(
            evidence / "collection.json",
            {"prepared": False, "nativeTestLaunched": False},
        )
        return
    prepared = json.loads(prepared_path.read_text())
    owned = {}
    for filename in ("host-identity.json", "shim-identity.json"):
        path = evidence / filename
        if path.exists():
            identity = json.loads(path.read_text())
            owned[identity["pid"]] = identity
    native = work / "native-gui"
    copied = []
    for path in sorted(native.glob("run-*/*")):
        if path.is_file() and path.name in {
            "report.json",
            "browser.log",
            "browser.stdout.log",
            "browser.stderr.log",
            "fixture-window.png",
        }:
            target = evidence / "native-gui" / path.relative_to(native)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            copied.append(str(target.relative_to(evidence)))
    reports = evidence / "crash-reports"
    reports.mkdir(exist_ok=True)
    record = {
        "prepared": True,
        "ownedPids": sorted(owned),
        "logs": copied,
        "crashReports": [],
        "crashReportErrors": [],
        "minidumpCollectionEnabled": False,
    }
    deadline = time.monotonic() + 30
    while True:
        for root in [
            Path.home() / "Library/Logs/DiagnosticReports",
            Path("/Library/Logs/DiagnosticReports"),
        ]:
            if not root.exists():
                continue
            try:
                candidates = [*root.glob("*.ips"), *root.glob("*.crash")]
                for path in candidates:
                    if (
                        path.stat().st_mtime < prepared["preparedAt"]
                        or path.stat().st_size > 16 * 1024 * 1024
                    ):
                        continue
                    pid, binary = report_identity(path)
                    if pid not in owned or not binary:
                        continue
                    is_host = (
                        binary == prepared["binary"]
                        and owned[pid].get("verified") is True
                    )
                    is_shim = binary.startswith(str(native) + "/") and binary.endswith(
                        "/floorp-app-shim"
                    )
                    if not is_host and not is_shim:
                        continue
                    target = reports / path.name
                    if not target.exists():
                        shutil.copyfile(path, target)
                        record["crashReports"].append({
                            "path": str(target.relative_to(evidence)),
                            "pid": pid,
                            "binary": binary,
                            "sha256": digest(target),
                        })
            except (OSError, ValueError) as error:
                record["crashReportErrors"].append({
                    "root": str(root),
                    "type": type(error).__name__,
                })
        if record["crashReports"] or not owned or time.monotonic() >= deadline:
            break
        time.sleep(1)
    archive, dmg = (
        work / "original-artifact.zip",
        work / "floorp-macOS-universal-moz-artifact.dmg",
    )
    record["artifactSha256AfterTest"] = digest(archive)
    record["dmgSha256AfterTest"] = digest(dmg)
    record["originalUnmodified"] = (
        record["artifactSha256AfterTest"] == ZIP_SHA
        and record["dmgSha256AfterTest"] == prepared["dmgSha256"]
    )
    write_json(evidence / "collection.json", record)
    if not record["originalUnmodified"]:
        raise ValueError("Original artifact changed during diagnosis")


if __name__ == "__main__":
    phase = sys.argv[1]
    try:
        result = {
            "prepare": prepare,
            "run": run_once,
            "worker": worker,
            "collect": collect,
        }[phase]()
    except Exception as error:
        evidence, _ = paths()
        evidence.mkdir(exist_ok=True, mode=0o700)
        write_json(
            evidence / f"{phase}-error.json",
            {"type": type(error).__name__, "error": str(error)},
        )
        traceback.print_exc()
        result = 1
    raise SystemExit(result or 0)
