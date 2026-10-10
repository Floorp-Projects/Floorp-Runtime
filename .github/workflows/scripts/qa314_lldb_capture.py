#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import signal
import subprocess
import time
import traceback
from pathlib import Path

import lldb


def qa314_capture(config_path):
    config = json.loads(Path(config_path).read_text())
    root = Path(config["evidence"])
    report = {
        "pid": config["pid"],
        "identity": config["identity"],
        "profile": config["profile"],
        "status": "before-attach",
        "attached": False,
        "faults": [],
        "permissionChanges": False,
        "additionalBrowserLaunches": 0,
        "localsOrCoreOrRawMemoryDumped": False,
        "terminationCaveat": "Mach exception Continue/resume-detach may influence kernel termination; compare the independent test kernel status",
    }
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(True)
    process = None
    listener = lldb.SBListener("qa314-owned-browser")

    def save(name, value):
        path = root / name
        temporary = root / (name + ".tmp")
        temporary.write_text(json.dumps(value, indent=2) + "\n")
        temporary.replace(path)

    def same_identity():
        result = subprocess.run(
            ["/bin/ps", "-ww", "-p", str(config["pid"]), "-o", "pid=,lstart=,command="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        rows = []
        for line in result.stdout.splitlines():
            fields = line.split(None, 6)
            if len(fields) == 7 and fields[0].isdigit():
                rows.append([int(fields[0]), " ".join(fields[1:6]), fields[6]])
        return rows == [config["identity"]]

    def configure_signals(stop_faults):
        signals = process.GetUnixSignals()
        if not signals.IsValid():
            raise RuntimeError("Debugger Unix signal configuration unavailable")
        observed = {}
        for value in (signal.SIGSEGV, signal.SIGBUS, signal.SIGABRT, signal.SIGTERM):
            stop = stop_faults and value != signal.SIGTERM
            changed = {
                "suppress": signals.SetShouldSuppress(value, False),
                "stop": signals.SetShouldStop(value, stop),
                "notify": signals.SetShouldNotify(value, True),
            }
            settings = {
                "suppress": signals.GetShouldSuppress(value),
                "stop": signals.GetShouldStop(value),
                "notify": signals.GetShouldNotify(value),
            }
            observed[signal.Signals(value).name] = {
                "setSucceeded": changed,
                "observed": settings,
            }
            if not all(changed.values()) or settings != {
                "suppress": False,
                "stop": stop,
                "notify": True,
            }:
                report["invalidSignalSetting"] = observed
                raise RuntimeError("Debugger signal configuration did not take effect")
        return observed

    def capture_fault():
        target = process.GetTarget()
        data = {
            "time": time.time(),
            "pid": process.GetProcessID(),
            "state": process.GetState(),
            "threads": [],
            "modules": [],
            "registers": [],
        }
        for module in target.modules:
            data["modules"].append({
                "path": str(module.GetFileSpec()),
                "uuid": module.GetUUIDString(),
            })
        lines = []
        for thread in process:
            reason = thread.GetStopReason()
            item = {
                "id": thread.GetThreadID(),
                "reason": reason,
                "description": thread.GetStopDescription(4096),
                "reasonData": [
                    thread.GetStopReasonDataAtIndex(i)
                    for i in range(thread.GetStopReasonDataCount())
                ],
                "frameCount": thread.GetNumFrames(),
                "frames": [],
            }
            lines.append(f"thread {item['id']}: {item['description']}")
            for index in range(min(thread.GetNumFrames(), 256)):
                frame = thread.GetFrameAtIndex(index)
                address = frame.GetPCAddress()
                module = address.GetModule()
                location = frame.GetLineEntry()
                entry = {
                    "index": index,
                    "pc": hex(frame.GetPC()),
                    "function": frame.GetFunctionName(),
                    "module": str(module.GetFileSpec()),
                    "uuid": module.GetUUIDString(),
                    "fileAddress": hex(address.GetFileAddress()),
                    "source": str(location.GetFileSpec()),
                    "line": location.GetLine(),
                }
                item["frames"].append(entry)
                lines.append(
                    f"  #{index} {entry['pc']} {entry['module']} {entry['function']} "
                    f"[{entry['uuid']}, {entry['fileAddress']}] {entry['source']}:{entry['line']}"
                )
            item["framesTruncated"] = thread.GetNumFrames() > 256
            data["threads"].append(item)
            if reason in (lldb.eStopReasonSignal, lldb.eStopReasonException):
                frame = thread.GetFrameAtIndex(0)
                values = {
                    name: frame.FindRegister(name).GetValue()
                    for name in ("pc", "sp", "fp", "lr")
                }
                data["registers"].append({
                    "threadId": thread.GetThreadID(),
                    "values": values,
                })
        index = len(report["faults"]) + 1
        save(f"lldb-fault-{index}.json", data)
        (root / f"lldb-backtrace-{index}.txt").write_text("\n".join(lines) + "\n")
        report["faults"].append({
            "file": f"lldb-fault-{index}.json",
            "time": data["time"],
            "reasons": [
                t["description"]
                for t in data["threads"]
                if t["reason"] in (lldb.eStopReasonSignal, lldb.eStopReasonException)
            ],
        })
        save("lldb-status.json", report)
        return data

    try:
        if not same_identity() or config["profile"] not in config["identity"][2]:
            raise RuntimeError("Exact PID/startTime/profile changed before attach")
        target = debugger.CreateTarget(config["binary"])
        error = lldb.SBError()
        process = target.AttachToProcessWithID(listener, config["pid"], error)
        if (
            error.Fail()
            or not process.IsValid()
            or process.GetProcessID() != config["pid"]
        ):
            raise RuntimeError(
                f"Existing same-user debugger attach refused: {error.GetCString()}"
            )
        if not same_identity():
            raise RuntimeError("Exact PID/startTime/profile changed while attaching")
        report["attached"] = True
        row_result = subprocess.run(
            ["/bin/ps", "-ww", "-p", str(os.getpid()), "-o", "pid=,lstart=,command="],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        row = row_result.stdout.strip().split(None, 6)
        if len(row) != 7 or int(row[0]) != os.getpid():
            raise RuntimeError("Debugger PID identity unavailable")
        save(
            "debugger-identity.json",
            {
                "pid": os.getpid(),
                "startTime": " ".join(row[1:6]),
                "command": row[6],
                "profile": config["profile"],
            },
        )
        report["initialSignalSettings"] = configure_signals(True)
        error = process.Continue()
        if error.Fail():
            raise RuntimeError(f"Cannot resume attached browser: {error.GetCString()}")
        deadline = time.monotonic() + config["maximumSeconds"]
        report["status"] = "attached-running"
        save(
            "lldb-ready.json",
            {"status": report["status"], "pid": config["pid"], "time": time.time()},
        )
        save("lldb-status.json", report)
        fault_deadline = None
        while time.monotonic() < deadline:
            if fault_deadline and time.monotonic() >= fault_deadline:
                report["status"] = "fault-forwarding-detach"
                break
            event = lldb.SBEvent()
            if not listener.WaitForEvent(1, event):
                if (root / "lldb-stop").exists() and not fault_deadline:
                    report["status"] = "test-cleanup-detach"
                    break
                continue
            if not lldb.SBProcess.EventIsProcessEvent(event):
                continue
            state = lldb.SBProcess.GetStateFromEvent(event)
            if lldb.SBProcess.GetRestartedFromEvent(event):
                continue
            if state == lldb.eStateExited:
                report.update(
                    status="browser-exited",
                    exitStatus=process.GetExitStatus(),
                    exitDescription=process.GetExitDescription(),
                    exitObservedAt=time.time(),
                )
                break
            if state in (lldb.eStateStopped, lldb.eStateCrashed):
                if process.GetState() not in (lldb.eStateStopped, lldb.eStateCrashed):
                    continue
                fault = capture_fault()
                fault_threads = [
                    t
                    for t in fault["threads"]
                    if t["reason"]
                    in (lldb.eStopReasonSignal, lldb.eStopReasonException)
                ]
                if not fault_threads:
                    raise RuntimeError(
                        "Unexpected debugger stop without signal/exception"
                    )
                report["faultForwardSignalSettings"] = configure_signals(False)
                report["status"] = "fault-captured-passing-original-signal"
                report["originalSignalSuppressed"] = any(
                    item["observed"]["suppress"]
                    for item in report["faultForwardSignalSettings"].values()
                )
                fault_deadline = time.monotonic() + config["signalForwardingSeconds"]
                error = process.Continue()
                report["continueError"] = error.GetCString() if error.Fail() else None
                save("lldb-status.json", report)
                if error.Fail():
                    break
            if len(report["faults"]) >= 2:
                report["status"] = "repeated-fault-detach"
                break
        else:
            report["status"] = "monitor-timeout"
    except Exception as error:
        report.update(
            status="diagnostic-error", error=str(error), errorType=type(error).__name__
        )
        save(
            "lldb-ready.json",
            {
                "status": "failed",
                "pid": config["pid"],
                "errorType": type(error).__name__,
            },
        )
        (root / "lldb-error.txt").write_text(traceback.format_exc())
    finally:
        if (
            process
            and process.IsValid()
            and process.GetState()
            not in (lldb.eStateExited, lldb.eStateDetached, lldb.eStateUnloaded)
        ):
            error = process.Detach(False)
            report["detachError"] = error.GetCString() if error.Fail() else None
        report["finishedAt"] = time.time()
        save("lldb-status.json", report)
        lldb.SBDebugger.Destroy(debugger)
