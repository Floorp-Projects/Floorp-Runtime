# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""One disposable cold-consumer service; no builder or material publisher."""

import argparse
import errno
import ipaddress
import json
import os
import pwd
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qa3_hosted import (
    PROFILE,
    consume,
    context_from_environment,
    raw_git,
    require,
    validate_context,
    validate_producer,
    verify_consumer,
    verify_recipe_metadata,
)
from qa3_hosted_support import PLAN_PATH, native_schedule
from qa3_native_io import GIB, capture_material_tree, read_json, write_json
from qa3_source_cohort import file_digest

ROOT = Path("/var/lib/qa3-hosted-consumer")
PROBE_ROOT = Path("/var/lib/qa3-hosted-boundary-probe")
FILES = (
    "qa3_hosted.py",
    "qa3_hosted_support.py",
    "qa3_hosted_boundary.py",
    "qa3_native_io.py",
    "qa3_native_transport.py",
    "qa3_mozlog.py",
    "qa3_source_cohort.py",
    "qa3_build_profile.py",
    "runtime_build_context.py",
    "qa3_xpcshell_entry.py",
    "qa3_browser_entry.py",
)
METADATA = (
    ".github/runtime-upstream.json",
    ".github/qa/source-policy.json",
    PLAN_PATH,
)
MAX_EXPORT = 128 * 1024**2
MAX_NETWORK_JSON = 16384
FALLBACK_TUNNELS = {
    "tunl0": ("ipip", "ipip"),
    "gre0": ("gre", "gre"),
    "gretap0": ("gretap", "ether"),
    "erspan0": ("erspan", "ether"),
    "sit0": ("sit", "sit"),
    "ip6tnl0": ("ip6tnl", "tunnel6"),
    "ip6gre0": ("ip6gre", "gre6"),
}


def protected(path):
    for component in (path, *path.parents):
        info = component.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o022,
            "unsafe root-owned ancestor",
        )
    return path


def make_directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o755)
    protected(path)


def stage_inputs(source, destination):
    require(
        all(
            p.is_file() and not p.is_symlink() and p.stat().st_nlink == 1
            for p in source.iterdir()
        ),
        "unsafe controller input",
    )
    shutil.copytree(source, destination)
    destination.chmod(0o555)
    for path in destination.rglob("*"):
        require(not path.is_symlink(), "link in consumer inputs")
        path.chmod(0o555 if path.is_dir() else 0o444)


def service_command(spec, operation="worker"):
    require(operation in {"worker", "probe-worker"}, "invalid native service operation")
    state = spec["state"]
    root = spec["root"]
    return [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--collect",
        "--service-type=exec",
        "--unit=" + spec["unit"],
        "--property=User=" + str(spec["uid"]),
        "--property=Group=" + str(spec["gid"]),
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=RuntimeMaxSec=1500s",
        "--property=CPUQuota=400%",
        "--property=CPUQuotaPeriodSec=100ms",
        f"--property=MemoryMax={14 * GIB}",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=512",
        "--property=UMask=0077",
        "--property=LimitCORE=0",
        f"--property=LimitFSIZE={50 * GIB}",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateNetwork=yes",
        "--property=PrivateDevices=yes",
        "--property=PrivateUsers=yes",
        "--property=ProtectProc=invisible",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectHostname=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=InaccessiblePaths=-/run/user -/run/credentials /etc/shadow /etc/gshadow "
        + " ".join(spec["controllerPaths"]),
        "--property=ReadWritePaths=" + state,
        "--property=StandardInput=null",
        "--property=StandardOutput=append:" + root + "/evidence/native.stdout",
        "--property=StandardError=append:" + root + "/evidence/native.stderr",
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "HOME=" + state + "/home",
        "USER=" + spec.get("account", "qa3-native"),
        "LOGNAME=" + spec.get("account", "qa3-native"),
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "TZ=UTC",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "/usr/bin/python3.12",
        "-I",
        root + "/recipe/.github/workflows/scripts/qa3_hosted_boundary.py",
        operation,
        "--spec",
        root + "/spec.json",
    ]


def capture_ip(arguments, maximum):
    executable = protected(Path("/usr/sbin/ip").resolve(strict=True))
    require(executable.is_file(), "network query executable is not a file")
    process = subprocess.Popen(
        [str(executable), "-j", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + 3
    try:
        with selectors.DefaultSelector() as selector:
            for index, pipe in enumerate((process.stdout, process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "network query timeout")
                for key, _ in selector.select(min(remaining, 0.1)):
                    block = os.read(key.fileobj.fileno(), 4096)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    require(
                        sum(map(len, output)) + len(block) <= maximum,
                        "network query output budget exceeded",
                    )
                    output[key.data].extend(block)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "network query timeout")
            returncode = process.wait(timeout=remaining)
        require(returncode == 0, "network query nonzero exit " + str(returncode))
        require(not output[1], "network query reported stderr")
        return bytes(output[0])
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()


def network_checks(value, interfaces):
    checks = {
        name: False
        for name in (
            "completeInventory",
            "loopbackActive",
            "fallbackTunnelsInactive",
            "loopbackAddressesOnly",
            "loopbackRoutesOnly",
        )
    }
    try:
        require(not value["queryErrors"], "network queries failed")
        links, addresses = value["links"], value["addresses"]
        require(
            isinstance(links, list)
            and isinstance(addresses, list)
            and 1 <= len(links) <= 1 + len(FALLBACK_TUNNELS)
            and len(addresses) == len(links)
            and all(isinstance(row, dict) for row in [*links, *addresses]),
            "invalid network inventory",
        )
        identities = [(row["ifindex"], row["ifname"]) for row in links]
        require(
            all(
                type(index) is int and index > 0 and isinstance(name, str)
                for index, name in identities
            )
            and len(set(identities)) == len(identities)
            and len({name for _, name in identities}) == len(identities)
            and len({index for index, _ in identities}) == len(identities)
            and sorted(identities) == sorted(interfaces)
            and sorted(identities)
            == sorted((row["ifindex"], row["ifname"]) for row in addresses),
            "inconsistent network inventory",
        )
        checks["completeInventory"] = True
        for row in links:
            flags = row["flags"]
            require(
                isinstance(flags, list) and all(isinstance(f, str) for f in flags),
                "invalid interface flags",
            )
            if row["ifname"] == "lo":
                require(
                    row["ifindex"] == 1
                    and row["link_type"] == "loopback"
                    and {"LOOPBACK", "UP", "LOWER_UP"} <= set(flags)
                    and row["operstate"] in {"UP", "UNKNOWN"}
                    and "master" not in row
                    and "linkinfo" not in row,
                    "loopback is not active",
                )
                checks["loopbackActive"] = True
                continue
            kind, link_type = FALLBACK_TUNNELS[row["ifname"]]
            info = row["linkinfo"]
            data = info["info_data"]
            require(
                row["link_type"] == link_type
                and info["info_kind"] == kind
                and isinstance(data, dict)
                and not {"UP", "LOWER_UP", "RUNNING", "LOOPBACK"} & set(flags)
                and row["operstate"] == "DOWN"
                and "master" not in row
                and "link_netnsid" not in row
                and row.get("link_index", 0) == 0
                and data["local"] == data["remote"] == "any"
                and "link" not in data
                and not data.get("external", False)
                and data.get("encap", "none") == "none"
                and all(
                    data.get(key, 0) in {0, "0", "0x0", "0.0.0.0"}
                    for key in ("ikey", "okey", "fwmark", "encap_sport", "encap_dport")
                ),
                "configured or active fallback tunnel",
            )
            require(
                ("prefix" not in data and "prefixlen" not in data)
                or (
                    kind == "sit"
                    and data["prefix"] == "2002::"
                    and data["prefixlen"] == 16
                ),
                "non-default fallback 6rd prefix",
            )
            require(
                data.get("relay_prefix", "0.0.0.0") == "0.0.0.0"
                and data.get("relay_prefixlen", 0) == 0,
                "configured fallback 6rd relay",
            )
        checks["fallbackTunnelsInactive"] = True
        loopback_addresses = set()
        for row in addresses:
            entries = row["addr_info"]
            require(isinstance(entries, list), "invalid address inventory")
            if row["ifname"] != "lo":
                require(not entries, "non-loopback address")
                continue
            require(row["link_type"] == "loopback", "wrong loopback address device")
            for address in entries:
                local = ipaddress.ip_interface(
                    address["local"] + "/" + str(address["prefixlen"])
                )
                require(
                    address["scope"] == "host"
                    and "peer" not in address
                    and (
                        (
                            address["family"] == "inet"
                            and local.version == 4
                            and local.network.subnet_of(
                                ipaddress.ip_network("127.0.0.0/8")
                            )
                        )
                        or (address["family"] == "inet6" and str(local) == "::1/128")
                    ),
                    "non-loopback address",
                )
                loopback_addresses.add(str(local))
        require(
            {"127.0.0.1/8", "::1/128"} <= loopback_addresses,
            "IPv4 or IPv6 loopback address missing",
        )
        checks["loopbackAddressesOnly"] = True
        for field, version, loopback in (
            ("ipv4Routes", 4, "127.0.0.0/8"),
            ("ipv6Routes", 6, "::1/128"),
        ):
            routes = value[field]
            require(isinstance(routes, list) and routes, "loopback routes missing")
            for route in routes:
                destination = ipaddress.ip_network(route["dst"], strict=False)
                require(
                    route["dev"] == "lo"
                    and destination.version == version
                    and destination.subnet_of(ipaddress.ip_network(loopback))
                    and route.get("type", "unicast")
                    in {"local", "broadcast", "unicast"}
                    and not {"gateway", "via", "multipath", "nexthops", "nhid", "encap"}
                    & route.keys()
                    and all(
                        ipaddress.ip_address(route[key]).is_loopback
                        for key in ("prefsrc", "src")
                        if key in route
                    ),
                    "non-loopback route",
                )
        checks["loopbackRoutesOnly"] = True
    except (KeyError, TypeError, ValueError, AttributeError):
        pass
    return checks


def worker_network(interfaces):
    value = {"schema": "qa3-worker-network-v1", "queryErrors": {}}
    used = 0
    for name, arguments in (
        ("links", ["-d", "link", "show"]),
        ("addresses", ["addr", "show"]),
        ("ipv4Routes", ["-4", "route", "show", "table", "all"]),
        ("ipv6Routes", ["-6", "route", "show", "table", "all"]),
    ):
        if value["queryErrors"]:
            value[name] = None
            continue
        try:
            data = capture_ip(arguments, MAX_NETWORK_JSON - used)
            used += len(data)
            value[name] = json.loads(data)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
            value[name] = None
            value["queryErrors"][name] = {
                "type": type(exc).__name__,
                "errno": getattr(exc, "errno", None),
                "message": str(exc)[:256],
            }
    value["checks"] = network_checks(value, interfaces)
    value["nativeExecutionObservation"] = "NOT_CHECKED"
    value["publicationAuthorized"] = False
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > MAX_NETWORK_JSON:
        value = {
            "schema": "qa3-worker-network-v1",
            "queryErrors": {"diagnostic": "network diagnostic budget exceeded"},
            "checks": {name: False for name in value["checks"]},
            "nativeExecutionObservation": "NOT_CHECKED",
            "publicationAuthorized": False,
        }
        encoded = json.dumps(value, sort_keys=True)
    print(encoded, flush=True)
    return value


def worker_visibility(spec):
    interfaces = socket.if_nameindex()
    network = worker_network(interfaces)
    process = Path(f"/proc/{spec['controllerPID']}")
    process_reads = {}
    for name in ("status", "cmdline", "environ", "maps"):
        try:
            with (process / name).open("rb"):
                pass
            process_reads[name] = {"readable": True, "errno": None}
        except OSError as exc:
            process_reads[name] = {"readable": False, "errno": exc.errno}
    paths = {
        path: os.access(path, os.R_OK)
        for path in (
            *spec["controllerPaths"],
            "/etc/shadow",
            "/etc/gshadow",
            "/run/credentials",
            "/run/user",
        )
    }
    proc_mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, separator, after = line.partition(" - ")
        fields, mount = before.split(), after.split()
        if separator and len(fields) >= 6 and len(mount) >= 3 and fields[4] == "/proc":
            proc_mounts.append({
                "filesystem": mount[0],
                "options": fields[5],
                "superOptions": mount[2],
            })
    hidden_proc = (
        len(proc_mounts) == 1
        and proc_mounts[0]["filesystem"] == "proc"
        and bool(
            {"hidepid=2", "hidepid=invisible"}
            & set(proc_mounts[0]["superOptions"].split(","))
        )
    )
    visible = process.exists()
    checks = {
        "loopbackOnly": all(network["checks"].values()),
        "controllerProcessHidden": not visible,
        "controllerProcessUnreadable": all(
            not item["readable"]
            and item["errno"] in {errno.ENOENT, errno.EACCES, errno.EPERM}
            for item in process_reads.values()
        ),
        "controllerInputsUnreadable": all(
            not paths[path] for path in spec["controllerPaths"]
        ),
        "credentialPathsUnreadable": not any(paths.values()),
        "procMountHidesOtherUsers": hidden_proc,
    }
    value = {
        "schema": "qa3-worker-visibility-v1",
        "checks": checks,
        "interfaces": interfaces,
        "controllerPID": spec["controllerPID"],
        "controllerPIDVisible": visible,
        "controllerProcessReads": process_reads,
        "controllerPathsReadable": paths,
        "procMounts": proc_mounts,
        "uid": os.getuid(),
        "effectiveUid": os.geteuid(),
        "gid": os.getgid(),
        "effectiveGid": os.getegid(),
        "namespaces": {
            name: os.readlink("/proc/self/ns/" + name)
            for name in ("mnt", "net", "user")
        },
        "kernel": os.uname().release,
        "cgroup": Path("/proc/self/cgroup").read_text()[:4096],
        "uidMap": Path("/proc/self/uid_map").read_text()[:4096],
        "gidMap": Path("/proc/self/gid_map").read_text()[:4096],
        "controllerUidMap": spec.get("controllerUidMap"),
        "controllerGidMap": spec.get("controllerGidMap"),
        "nativeExecutionObservation": "NOT_CHECKED",
        "publicationAuthorized": False,
    }
    encoded = json.dumps(value, sort_keys=True)
    require(
        len(encoded.encode()) <= 16384, "worker visibility diagnostic budget exceeded"
    )
    print(encoded, flush=True)
    return value


def verify_worker(spec):
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    namespaces = {
        name: os.readlink("/proc/self/ns/" + name) for name in ("mnt", "net", "user")
    }
    security = json.dumps(
        {
            "schema": "qa3-worker-security-v1",
            "uid": os.getuid(),
            "effectiveUid": os.geteuid(),
            "gid": os.getgid(),
            "effectiveGid": os.getegid(),
            "noNewPrivs": status.get("NoNewPrivs", "").strip(),
            "effectiveCapabilities": status.get("CapEff", "").strip(),
            "namespaces": namespaces,
            "controllerNamespaces": spec["controllerNamespaces"],
            "kernel": os.uname().release,
            "cgroup": Path("/proc/self/cgroup").read_text()[:4096],
            "nativeExecutionObservation": "NOT_CHECKED",
            "publicationAuthorized": False,
        },
        sort_keys=True,
    )
    require(
        len(security.encode()) <= 16384, "worker security diagnostic budget exceeded"
    )
    print(security, flush=True)
    require(
        os.getuid() == os.geteuid() == spec["uid"] > 0
        and os.getgid() == os.getegid() == spec["gid"],
        "wrong native account",
    )
    require(
        status["NoNewPrivs"].strip() == "1" and int(status["CapEff"], 16) == 0,
        "worker retained privileges",
    )
    require(
        all(namespaces[n] != spec["controllerNamespaces"][n] for n in namespaces),
        "native mount, network or user namespace was not isolated",
    )
    visibility = worker_visibility(spec)
    for name, message in (
        ("loopbackOnly", "native network is not loopback-only"),
        ("controllerProcessHidden", "native controller process remains visible"),
        (
            "controllerProcessUnreadable",
            "native controller process data remains readable",
        ),
        ("controllerInputsUnreadable", "native controller inputs remain readable"),
        ("credentialPathsUnreadable", "native credential paths remain readable"),
        ("procMountHidesOtherUsers", "native proc mount does not hide other users"),
    ):
        require(visibility["checks"][name], message)
    records = Path("/proc/self/cgroup").read_text().splitlines()
    require(
        len(records) == 1 and records[0].startswith("0::/"),
        "non-unified cgroup: " + repr(records)[:1024],
    )
    relative = Path(records[0][3:])
    require(relative.name == spec["unit"], "wrong dedicated consumer service cgroup")
    group = Path("/sys/fs/cgroup") / str(relative).lstrip("/")
    expected = {
        "memory.max": str(14 * GIB),
        "memory.swap.max": "0",
        "pids.max": "512",
        "cpu.max": "400000 100000",
    }
    limits = {}
    for name in expected:
        try:
            limits[name] = (group / name).read_text().strip()
        except OSError as exc:
            limits[name] = {"errno": exc.errno}
    try:
        events = dict(
            line.split() for line in (group / "memory.events").read_text().splitlines()
        )
    except OSError as exc:
        events = {"errno": exc.errno}
    print(
        json.dumps(
            {
                "schema": "qa3-worker-cgroup-v1",
                "scope": str(relative),
                "expected": expected,
                "actual": limits,
                "events": events,
                "nativeExecutionObservation": "NOT_CHECKED",
                "publicationAuthorized": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    require(limits == expected, "consumer limits differ")
    require(events.get("oom") == events.get("oom_kill") == "0", "consumer OOM")
    return {"scope": str(relative), "limits": expected, "namespaces": namespaces}


def probe_boundary(args):
    require(os.geteuid() == 0, "root boundary probe preparation required")
    recipe = args.recipe.resolve(strict=True)
    output = args.output.absolute()
    require(
        not output.parent.resolve(strict=True).is_relative_to(recipe),
        "boundary probe output must be outside the original recipe",
    )
    account = "qa3-boundary-probe"
    try:
        pwd.getpwnam(account)
    except KeyError:
        pass
    else:
        raise ValueError("dedicated boundary probe account already exists")
    require(not PROBE_ROOT.exists(), "boundary probe root already exists")
    head = raw_git(recipe, "rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", head), "invalid boundary probe recipe")
    output.mkdir(mode=0o755)
    make_directory(PROBE_ROOT)
    root = PROBE_ROOT / (head[:12] + "-" + str(os.getpid()))
    make_directory(root)
    created_account = False
    result = None
    reason = None
    spec = None
    clean = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}

    def cancelled(signum, frame):
        raise KeyboardInterrupt

    handlers = {s: signal.signal(s, cancelled) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        for name in (
            "recipe",
            "recipe/.github",
            "recipe/.github/workflows",
            "recipe/.github/workflows/scripts",
            "evidence",
            "controller-inputs",
        ):
            make_directory(root / name)
        for name in FILES:
            relative = ".github/workflows/scripts/" + name
            raw = raw_git(recipe, "cat-file", "blob", head + ":" + relative)
            require(
                raw == (recipe / relative).read_bytes(),
                "boundary probe code differs from original raw Runtime recipe",
            )
            path = root / "recipe" / relative
            path.write_bytes(raw)
            path.chmod(0o444)
        marker = root / "controller-inputs/credential-marker"
        marker.write_text("QA3_BOUNDARY_CONTROLLED_MARKER\n")
        marker.chmod(0o644)
        subprocess.run(
            [
                "/usr/sbin/useradd",
                "--system",
                "--user-group",
                "--no-log-init",
                "--home-dir",
                str(root / "state/home"),
                "--shell",
                "/usr/sbin/nologin",
                account,
            ],
            check=True,
            timeout=15,
            env=clean,
        )
        created_account = True
        native = pwd.getpwnam(account)
        state = root / "state"
        state.mkdir(mode=0o700)
        os.chown(state, native.pw_uid, native.pw_gid)
        spec = {
            "profile": PROFILE,
            "boundaryProbe": True,
            "root": str(root),
            "state": str(state),
            "account": account,
            "uid": native.pw_uid,
            "gid": native.pw_gid,
            "unit": "qa3-boundary-probe-" + str(os.getpid()) + ".service",
            "controllerPID": os.getpid(),
            "controllerNamespaces": {
                name: os.readlink("/proc/self/ns/" + name)
                for name in ("mnt", "net", "user")
            },
            "controllerUidMap": Path("/proc/self/uid_map").read_text()[:4096],
            "controllerGidMap": Path("/proc/self/gid_map").read_text()[:4096],
            "controllerPaths": [
                str(recipe),
                str(output.parent.resolve()),
                str(root / "controller-inputs"),
            ],
        }
        require(
            all(not re.search(r"\s", path) for path in spec["controllerPaths"]),
            "unsafe boundary probe controller path",
        )
        write_json(root / "spec.json", spec)
        (root / "spec.json").chmod(0o444)
        result = subprocess.run(
            service_command(spec, "probe-worker"),
            env=clean,
            timeout=120,
            check=False,
        )
        if result.returncode:
            reason = "original boundary probe service failed"
    except BaseException as exc:
        reason = "boundary probe failed: " + type(exc).__name__
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        if spec is not None:
            for action in (["kill", "--kill-whom=all", "--signal=KILL"], ["stop"]):
                try:
                    subprocess.run(
                        ["/usr/bin/systemctl", *action, spec["unit"]],
                        env=clean,
                        timeout=15,
                        check=False,
                        capture_output=True,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    reason = reason or "boundary probe service cleanup failed"
            try:
                group = Path("/sys/fs/cgroup/system.slice") / spec["unit"]
                require(
                    not group.exists()
                    or "populated 0"
                    in (group / "cgroup.events").read_text().splitlines(),
                    "boundary probe service retained children",
                )
                for entry in Path("/proc").iterdir():
                    if entry.name.isdecimal():
                        try:
                            require(
                                entry.stat().st_uid != spec["uid"],
                                "boundary probe account retained processes",
                            )
                        except FileNotFoundError:
                            pass
            except (OSError, ValueError) as exc:
                reason = (
                    reason or "boundary probe cleanup rejected: " + type(exc).__name__
                )
        try:
            for name in ("native.stdout", "native.stderr"):
                path = root / "evidence" / name
                if path.exists():
                    info = path.lstat()
                    require(
                        stat.S_ISREG(info.st_mode)
                        and info.st_uid == 0
                        and info.st_nlink == 1
                        and info.st_size <= 65536,
                        "unsafe or oversized boundary probe diagnostic",
                    )
                    shutil.copyfile(path, output / name)
                    (output / name).chmod(0o644)
            if result is not None and result.returncode == 0 and reason is None:
                worker = read_json(root / "state/probe-result.json", maximum=65536)
                require(
                    worker.get("schema") == "qa3-boundary-probe-worker-v1"
                    and worker.get("status") == "PASS_BOUNDARY_ONLY"
                    and worker.get("nativeProductExecuted") is False
                    and worker.get("publicationAuthorized") is False,
                    "boundary probe worker result is incomplete",
                )
                write_json(output / "worker-result.json", worker)
                (output / "worker-result.json").chmod(0o644)
        except (OSError, ValueError) as exc:
            reason = reason or "boundary probe evidence rejected: " + type(exc).__name__
        if created_account:
            try:
                deleted = subprocess.run(
                    ["/usr/sbin/userdel", account],
                    env=clean,
                    timeout=15,
                    check=False,
                    capture_output=True,
                )
                if deleted.returncode:
                    reason = reason or "boundary probe account cleanup failed"
            except (OSError, subprocess.TimeoutExpired):
                reason = reason or "boundary probe account cleanup failed"
        try:
            require(
                root.resolve().parent == PROBE_ROOT.resolve(), "unsafe probe cleanup"
            )
            shutil.rmtree(root)
            PROBE_ROOT.rmdir()
        except (OSError, ValueError):
            reason = reason or "boundary probe directory cleanup failed"
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    write_json(
        output / "result.json",
        {
            "schema": "qa3-boundary-probe-v1",
            "runtimeRecipe": head,
            "status": "FAIL" if reason else "PASS_BOUNDARY_ONLY",
            "reason": reason,
            "serviceExit": None if result is None else result.returncode,
            "nativeProductExecuted": False,
            "publicationAuthorized": False,
        },
    )
    (output / "result.json").chmod(0o644)
    require(reason is None, "original boundary-only probe failed")


def export_after_stop(root, complete, context):
    destination = root / "export"
    make_directory(destination)
    make_directory(destination / "logs")
    output = root / "state/output"
    schedule = native_schedule(read_json(root / "recipe" / PLAN_PATH))
    phases = [
        "cold-venv",
        "offline-install",
        "pip-check",
        *(name for name, _, _ in schedule),
    ]
    allowed = (
        {"consumer.json", "worker-failure.json"}
        | {
            f"logs/{phase}.{suffix}"
            for phase in phases
            for suffix in ("stdout", "stderr", "process.json")
        }
        | {f"logs/{phase}.mozlog" for phase, _, _ in schedule}
    )
    rows = []
    total = 0
    if output.exists():
        for path in output.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                continue
            name = path.relative_to(output).as_posix()
            info = path.lstat()
            require(
                name in allowed
                and stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and not info.st_mode & 0o6111
                and info.st_size <= 16 * 1024**2,
                "arbitrary or oversized native output",
            )
            total += info.st_size
            require(total <= MAX_EXPORT, "consumer export budget exceeded")
            target = destination / name
            with path.open("rb") as source, target.open("xb") as sink:
                shutil.copyfileobj(source, sink, 1024**2)
            target.chmod(0o644)
            rows.append({
                "path": name,
                "bytes": target.stat().st_size,
                "sha256": file_digest(target),
            })
    if complete:
        require(
            not (destination / "worker-failure.json").exists(),
            "worker originally failed",
        )
        verify_consumer(
            destination,
            root / "state/support",
            read_json(root / "inputs/producer.json"),
            context,
        )
    write_json(
        destination / "export.json", {"schema": "qa3-hosted-export-v1", "files": rows}
    )
    (destination / "export.json").chmod(0o644)
    return rows


def launch(args):
    require(os.geteuid() == 0, "root disposable-consumer preparation required")
    inputs = args.inputs.resolve(strict=True)
    context = validate_context(read_json(inputs / "context.json"))
    require(
        {p.name for p in inputs.iterdir()}
        == {
            "context.json",
            "transport.json",
            "producer.json",
            "runtime.tar.xz",
            "test-support.tar.gz",
        },
        "arbitrary source/HOME/OBJDIR in controller inputs",
    )
    producer = validate_producer(read_json(inputs / "producer.json"), context)
    verify_recipe_metadata(args.recipe, producer)
    require(
        Path("/run/systemd/system").is_dir()
        and Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "fresh systemd cgroup-v2 VM required",
    )
    for name in ("/usr/bin/python3.12", "/usr/bin/xvfb-run", "/usr/bin/prlimit"):
        protected(Path(name).resolve(strict=True))
    try:
        pwd.getpwnam("qa3-native")
    except KeyError:
        pass
    else:
        raise ValueError("dedicated native account already exists")
    require(not ROOT.exists() and not ROOT.is_symlink(), "consumer root already exists")
    protected(ROOT.parent)
    make_directory(ROOT)
    root = ROOT / f"{context['run']}-1"
    make_directory(root)
    for name in (
        "recipe",
        "recipe/.github",
        "recipe/.github/qa",
        "recipe/.github/workflows",
        "recipe/.github/workflows/scripts",
        "evidence",
    ):
        make_directory(root / name)
    for name in FILES:
        relative = ".github/workflows/scripts/" + name
        raw = raw_git(
            args.recipe, "cat-file", "blob", context["runtimeRecipe"] + ":" + relative
        )
        require(
            raw == (args.recipe / relative).read_bytes(),
            "consumer code differs from raw R",
        )
        path = root / "recipe" / relative
        path.write_bytes(raw)
        path.chmod(0o444)
    for relative in METADATA:
        raw = raw_git(
            args.recipe, "cat-file", "blob", context["runtimeRecipe"] + ":" + relative
        )
        require(
            raw == (args.recipe / relative).read_bytes(), "metadata differs from raw R"
        )
        path = root / "recipe" / relative
        path.write_bytes(raw)
        path.chmod(0o444)
    stage_inputs(inputs, root / "inputs")
    subprocess.run(
        [
            "/usr/sbin/useradd",
            "--system",
            "--user-group",
            "--no-log-init",
            "--home-dir",
            str(root / "state/home"),
            "--shell",
            "/usr/sbin/nologin",
            "qa3-native",
        ],
        check=True,
        timeout=15,
        env={"PATH": "/usr/bin:/bin"},
    )
    native = pwd.getpwnam("qa3-native")
    state = root / "state"
    state.mkdir(mode=0o700)
    os.chown(state, native.pw_uid, native.pw_gid)
    spec = {
        "profile": PROFILE,
        "root": str(root),
        "state": str(state),
        "context": context,
        "uid": native.pw_uid,
        "gid": native.pw_gid,
        "unit": f"qa3-hosted-{context['run']}-1-consumer.service",
        "inputSnapshot": capture_material_tree(root / "inputs"),
        "controllerPID": os.getpid(),
        "controllerNamespaces": {
            name: os.readlink("/proc/self/ns/" + name)
            for name in ("mnt", "net", "user")
        },
        "controllerUidMap": Path("/proc/self/uid_map").read_text()[:4096],
        "controllerGidMap": Path("/proc/self/gid_map").read_text()[:4096],
        "controllerPaths": [str(args.recipe.resolve()), str(inputs.parent)],
    }
    require(
        all(
            path.startswith("/") and not re.search(r"\s", path)
            for path in spec["controllerPaths"]
        ),
        "unsafe controller path in service policy",
    )
    write_json(root / "spec.json", spec)
    (root / "spec.json").chmod(0o444)
    result = None
    first_failure = None
    clean = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    rows = []
    scope_empty = False

    def cancelled(signum, frame):
        raise KeyboardInterrupt

    handlers = {s: signal.signal(s, cancelled) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = subprocess.run(
            service_command(spec), env=clean, timeout=1560, check=False
        )
        if result.returncode:
            first_failure = "native service failed"
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        first_failure = "controller timeout or cancellation"
    finally:
        for action in (["kill", "--kill-whom=all", "--signal=KILL"], ["stop"]):
            try:
                subprocess.run(
                    ["/usr/bin/systemctl", *action, spec["unit"]],
                    env=clean,
                    timeout=15,
                    check=False,
                    capture_output=True,
                )
            except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
                first_failure = first_failure or "consumer cleanup failed"
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    try:
        group = Path("/sys/fs/cgroup/system.slice") / spec["unit"]
        require(
            not group.exists()
            or dict(
                line.split()
                for line in (group / "cgroup.events").read_text().splitlines()
            ).get("populated")
            == "0",
            "native children survived in service cgroup",
        )
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal():
                try:
                    require(
                        entry.stat().st_uid != spec["uid"],
                        "native account process survived",
                    )
                except FileNotFoundError:
                    pass
        scope_empty = True
        require(
            capture_material_tree(root / "inputs") == spec["inputSnapshot"],
            "readonly inputs changed",
        )
        rows = export_after_stop(root, first_failure is None, context)
        for path in (root / "evidence").iterdir():
            require(
                path.is_file()
                and not path.is_symlink()
                and path.stat().st_size <= 16 * 1024**2,
                "unsafe service raw log",
            )
            path.chmod(0o644)
    except (ValueError, OSError, KeyboardInterrupt) as exc:
        first_failure = (
            first_failure
            or "consumer evidence or cleanup rejected: " + type(exc).__name__
        )
    write_json(
        root / "evidence/final.json",
        {
            "schema": "qa3-hosted-root-supervision-v1",
            "context": context,
            "status": "FAIL" if first_failure else "PASS",
            "reason": first_failure,
            "scopeEmpty": scope_empty,
            "serviceExit": None if result is None else result.returncode,
            "export": rows,
            "publicationAuthorized": False,
        },
    )
    (root / "evidence/final.json").chmod(0o644)
    require(first_failure is None, "original native consumer failed")


def collect(args):
    destination = args.output
    destination.mkdir(mode=0o700)
    context = context_from_environment(args.build_id)
    root = ROOT / f"{context['run']}-1"
    write_json(
        destination / "collection.json",
        {
            "schema": "qa3-hosted-collection-v1",
            "context": context,
            "status": "COLLECTION_STARTED",
            "acquireOutcome": os.environ.get("QA3_ACQUIRE_OUTCOME"),
            "launchOutcome": os.environ.get("QA3_LAUNCH_OUTCOME"),
            "publicationAuthorized": False,
        },
    )
    protected(root / "evidence")
    for folder in ("evidence", "export"):
        source = root / folder
        if not source.exists():
            continue
        total = 0
        for path in source.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                continue
            protected(path)
            info = path.stat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_size <= 16 * 1024**2,
                "unsafe controller export",
            )
            total += info.st_size
            require(total <= MAX_EXPORT, "controller evidence budget exceeded")
            target = destination / folder / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    final = read_json(destination / "evidence/final.json")
    require(
        final.get("schema") == "qa3-hosted-root-supervision-v1"
        and final.get("context") == context
        and final.get("status") == "PASS"
        and final.get("reason") is None
        and final.get("scopeEmpty") is True
        and final.get("serviceExit") == 0
        and final.get("publicationAuthorized") is False
        and os.environ.get("QA3_LAUNCH_OUTCOME") == "success",
        "original consumer job failed",
    )
    require(
        os.environ.get("QA3_ACQUIRE_OUTCOME") == "success",
        "original artifact acquisition failed",
    )
    rows = read_json(destination / "export/export.json")["files"]
    require(rows == final["export"], "root export receipt differs")
    for row in rows:
        path = destination / "export" / row["path"]
        require(
            path.stat().st_size == row["bytes"] and file_digest(path) == row["sha256"],
            "root evidence bytes changed",
        )
    write_json(
        destination / "collection-result.json",
        {
            "schema": "qa3-hosted-collection-result-v1",
            "context": context,
            "status": "PASS_DEBUG_HARNESS_ONLY",
            "publicationAuthorized": False,
        },
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write("verdict=PASS_DEBUG_HARNESS_ONLY\n")
    consumer = read_json(destination / "export/consumer.json")
    print(
        json.dumps(
            {
                "schema": "qa3-hosted-verified-summary-v1",
                "context": context,
                "status": "PASS_DEBUG_HARNESS_ONLY",
                "scopeEmpty": final["scopeEmpty"],
                "serviceExit": final["serviceExit"],
                "consumerSha256": file_digest(destination / "export/consumer.json"),
                "rootReceiptSha256": file_digest(destination / "evidence/final.json"),
                "producerBootSha256": consumer["producerBootSha256"],
                "consumerBootSha256": consumer["consumerBootSha256"],
                "cases": [
                    {
                        "name": case["name"],
                        "suite": case["suite"],
                        "canary": case["canary"],
                        "exit": case["process"]["exit"],
                        "ownedCleanupComplete": case["process"]["ownedCleanupComplete"],
                        "rawLog": case["rawLog"],
                        "mozlog": case["mozlog"],
                    }
                    for case in consumer["cases"]
                ],
                "nativeProductQualification": "UNVERIFIED",
                "publicationAuthorized": False,
            },
            sort_keys=True,
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation", choices=("launch", "worker", "collect", "probe", "probe-worker")
    )
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build-id")
    args = parser.parse_args()
    if args.operation == "launch":
        launch(args)
    elif args.operation == "probe":
        probe_boundary(args)
    elif args.operation == "collect":
        try:
            collect(args)
        except BaseException as exc:
            if args.output.is_dir() and not args.output.is_symlink():
                write_json(
                    args.output / "collection-result.json",
                    {
                        "schema": "qa3-hosted-collection-result-v1",
                        "status": "INCOMPLETE",
                        "type": type(exc).__name__,
                        "publicationAuthorized": False,
                    },
                )
            raise
    else:
        spec = read_json(protected(args.spec))
        if args.operation == "probe-worker":
            require(spec.get("boundaryProbe") is True, "foreign boundary probe spec")
        observation = verify_worker(spec)
        state = Path(spec["state"])
        (state / "home").mkdir(mode=0o700)
        if args.operation == "probe-worker":
            write_json(
                state / "probe-result.json",
                {
                    "schema": "qa3-boundary-probe-worker-v1",
                    "status": "PASS_BOUNDARY_ONLY",
                    "observation": observation,
                    "nativeProductExecuted": False,
                    "publicationAuthorized": False,
                },
            )
            return
        try:
            result = consume(
                Path(spec["root"]) / "inputs",
                state,
                Path(spec["root"]) / "recipe",
                spec["context"],
            )
            require(
                verify_worker(spec) == observation, "native resource boundary changed"
            )
            require(result["context"] == spec["context"], "native context changed")
        except BaseException as exc:
            if (state / "output").is_dir():
                write_json(
                    state / "output/worker-failure.json",
                    {
                        "schema": "qa3-hosted-failure-v1",
                        "phase": "consumer",
                        "type": type(exc).__name__,
                        "status": "FAIL",
                        "publicationAuthorized": False,
                    },
                )
            raise


if __name__ == "__main__":
    main()
