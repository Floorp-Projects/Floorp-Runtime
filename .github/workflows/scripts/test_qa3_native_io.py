# SPDX-License-Identifier: MPL-2.0

import io
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from qa3_native_io import (
    GIB,
    ExpansionBudget,
    IOBudget,
    _descendants,
    child_environment,
    copy_file,
    elf_identity,
    extract_archive,
    owned_alive,
    pack_tree,
    read_json,
    run_owned,
    verify_group_limits,
    write_json,
)


def elf(path, machine=62, buildid=b"fixture-id"):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 18, machine)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    notes = struct.pack("<III", 4, len(buildid), 3) + b"GNU\0" + buildid
    notes += bytes((-len(buildid)) % 4)
    program = bytearray(56)
    struct.pack_into("<I", program, 0, 4)
    struct.pack_into("<Q", program, 8, 120)
    struct.pack_into("<Q", program, 32, len(notes))
    path.write_bytes(header + program + notes)
    path.chmod(0o755)
    return path


def archive(path, entries):
    with tarfile.open(path, "w:gz") as out:
        for name, content, kind in entries:
            item = tarfile.TarInfo(name)
            if kind == "file":
                item.size = len(content)
                out.addfile(item, io.BytesIO(content))
            else:
                item.type = {
                    "symlink": tarfile.SYMTYPE,
                    "hardlink": tarfile.LNKTYPE,
                    "device": tarfile.CHRTYPE,
                }[kind]
                item.linkname = content
                out.addfile(item)
    return path


class NativeIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def tar(self, entries, name="input.tar.gz"):
        return archive(self.root / name, entries)

    def test_archive_roundtrip_and_native_elf_identity(self):
        source = self.root / "source"
        source.mkdir()
        elf(source / "helper")
        (source / "data").write_bytes(b"complete")
        packed = self.root / "bundle.tar.gz"
        pack_tree(source, packed, IOBudget(self.root, 4096))
        destination = self.root / "expanded"
        result = extract_archive(packed, destination, budget=IOBudget(self.root, 4096))
        self.assertEqual(result["members"], 2)
        self.assertEqual(
            elf_identity(source / "helper"), elf_identity(destination / "helper")
        )

    def test_archive_traversal_and_duplicate_names(self):
        for i, entries in enumerate((
            [("../outside", b"bad", "file")],
            [("/absolute", b"bad", "file")],
            [("a//b", b"bad", "file")],
            [("a", b"one", "file"), ("a", b"two", "file")],
        )):
            with self.subTest(i=i), self.assertRaises(ValueError):
                extract_archive(
                    self.tar(entries, str(i) + ".tar.gz"), self.root / str(i)
                )

    def test_archive_special_hardlink_and_external_symlink(self):
        for i, entries in enumerate((
            [("a", "target", "hardlink")],
            [("a", "", "device")],
            [("a", "../outside", "symlink")],
            [("a", "absent", "symlink")],
            [
                ("a", "payload", "symlink"),
                ("a/b", b"bad", "file"),
                ("payload", b"x", "file"),
            ],
        )):
            with self.subTest(i=i), self.assertRaises((OSError, ValueError)):
                extract_archive(
                    self.tar(entries, str(i) + ".tar.gz"), self.root / str(i)
                )

    def test_archive_member_and_expanded_limits(self):
        source = self.tar([("a", b"1234", "file"), ("b", b"1234", "file")])
        for i, kwargs in enumerate(({"expanded": 7}, {"max_files": 1})):
            with self.subTest(i=i), self.assertRaises(ValueError):
                extract_archive(source, self.root / str(i), **kwargs)

    def test_archive_expansion_cumulative_across_inputs(self):
        expansion = ExpansionBudget(maximum=7)
        for i in range(2):
            source = self.tar([(str(i), b"1234", "file")], str(i) + ".tar.gz")
            if i == 0:
                extract_archive(source, self.root / str(i), expansion=expansion)
            else:
                with self.assertRaises(ValueError):
                    extract_archive(source, self.root / str(i), expansion=expansion)

    def test_stage_merge_peak_is_not_just_final_size(self):
        budget = IOBudget(self.root, 7)
        stage = self.root / "stage"
        extract_archive(self.tar([("a", b"1234", "file")]), stage, budget=budget)
        with self.assertRaises(ValueError):
            copy_file(stage / "a", self.root / "copy", budget)
        self.assertEqual(budget.used, 4)
        budget.release_tree(stage)
        self.assertEqual(budget.used, 0)

    def test_copy_pack_and_extract_keep_free_reserve(self):
        source = self.root / "source"
        source.mkdir()
        (source / "file").write_bytes(b"1234")
        budget = IOBudget(self.root, 4096, minimum_free=10)
        with mock.patch(
            "qa3_native_io.shutil.disk_usage",
            return_value=shutil._ntuple_diskusage(100, 90, 10),
        ):
            for operation in (
                lambda: copy_file(source / "file", self.root / "copy", budget),
                lambda: pack_tree(source, self.root / "packed", budget),
                lambda: extract_archive(
                    self.tar([("x", b"1234", "file")]),
                    self.root / "expanded",
                    budget=budget,
                ),
            ):
                with self.assertRaises(ValueError):
                    operation()

    def test_zip_symlink_and_traversal(self):
        for i, name in enumerate(("link", "../outside")):
            path = self.root / (str(i) + ".zip")
            with zipfile.ZipFile(path, "w") as out:
                member = zipfile.ZipInfo(name)
                if i == 0:
                    member.external_attr = 0o120777 << 16
                out.writestr(member, "payload")
            with self.assertRaises(ValueError):
                extract_archive(path, self.root / str(i))

    def test_json_duplicate_keys_and_overwrite(self):
        path = self.root / "data.json"
        path.write_bytes(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            read_json(path)
        with self.assertRaises(FileExistsError):
            write_json(path, {})

    def test_wrong_architecture_and_missing_elf_identity(self):
        for i, (machine, buildid) in enumerate(((183, b"x"), (62, b""))):
            with self.subTest(i=i), self.assertRaises(ValueError):
                elf_identity(elf(self.root / str(i), machine, buildid))

    def command(self, code, name="fixture", **kwargs):
        return run_owned(
            [sys.executable, "-B", "-c", code],
            self.root,
            child_environment(self.root / "state"),
            self.root / "logs",
            name,
            kwargs.pop("timeout", 2),
            **kwargs,
        )

    def test_process_preserves_complete_streams(self):
        result = self.command('print("fixture complete")')
        self.assertEqual(result["exit"], 0)
        self.assertTrue(result["ownedCleanupComplete"])
        self.assertEqual(
            (self.root / "logs/fixture.stdout").read_text(), "fixture complete\n"
        )

    def test_burst_log_hard_cap_and_cumulative_budget(self):
        self.command('print("a" * 31)', name="first", log_limit=40)
        with self.assertRaises(ValueError):
            self.command(
                'import os; os.write(1,b"x" * 100000)', name="second", log_limit=40
            )
        self.assertLessEqual(
            sum(p.stat().st_size for p in (self.root / "logs").glob("*.stdout")), 40
        )
        receipt = read_json(self.root / "logs/second.process.json")
        self.assertEqual(receipt["stop"], "LOG_LIMIT")

    def test_data_stdout_has_distinct_budget(self):
        with self.assertRaises(ValueError):
            self.command(
                'import os; os.write(1,b"x" * 100000)',
                data_stdout=True,
                data_limit=10,
                log_limit=5,
            )
        self.assertEqual((self.root / "logs/fixture.stdout").stat().st_size, 10)
        self.assertEqual(
            read_json(self.root / "logs/fixture.process.json")["stop"], "DATA_LIMIT"
        )

    def test_closed_pipes_do_not_stop_timeout_or_disk_monitoring(self):
        with mock.patch(
            "qa3_native_io.shutil.disk_usage",
            side_effect=[
                shutil._ntuple_diskusage(100, 0, 100),
                shutil._ntuple_diskusage(100, 95, 5),
                *[shutil._ntuple_diskusage(100, 95, 5) for _ in range(1000)],
            ],
        ), self.assertRaises(ValueError):
            self.command(
                "import os,time; os.close(1); os.close(2); time.sleep(30)",
                minimum_free=10,
            )
        self.assertEqual(
            read_json(self.root / "logs/fixture.process.json")["stop"], "DISK_LIMIT"
        )

    def test_daemon_cleanup_does_not_kill_unowned_process(self):
        unowned = subprocess.Popen([
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
        ])
        self.addCleanup(lambda: unowned.kill() if unowned.poll() is None else None)
        self.addCleanup(unowned.wait)
        code = (
            "import os,time; p=os.fork(); "
            "os._exit(0) if p else None; os.setsid(); "
            'open("daemon.pid","w").write(str(os.getpid())); time.sleep(30)'
        )
        result = self.command(code)
        self.assertTrue(result["ownedCleanupComplete"])
        self.assertIsNone(unowned.poll())
        pid = int((self.root / "daemon.pid").read_text())
        self.assertFalse(Path(f"/proc/{pid}").exists())
        unowned.terminate()
        unowned.wait(timeout=2)

    def test_group_memory_pids_and_oom_preconditions(self):
        proc = self.root / "cgroup"
        proc.write_text("0::/qa3-7-2-builder.scope\n")
        group = self.root / "groups/qa3-7-2-builder.scope"
        group.mkdir(parents=True)
        (group / "memory.max").write_text(str(28 * GIB))
        (group / "pids.max").write_text("512")
        (group / "cpu.max").write_text("800000 100000")
        (group / "memory.events").write_text("oom 0\noom_kill 0\n")
        value = verify_group_limits(
            "builder", {"run": 7, "attempt": 2}, self.root / "groups", proc
        )
        self.assertEqual(value["memoryMaxBytes"], 28 * GIB)
        for name, text in (
            ("cpu.max", "max 100000"),
            ("cpu.max", "900000 100000"),
            ("memory.max", "max"),
            ("memory.max", str(29 * GIB)),
            ("pids.max", "max"),
            ("pids.max", "513"),
            ("memory.events", "oom 1\noom_kill 0\n"),
        ):
            old = (group / name).read_text()
            (group / name).write_text(text)
            with self.subTest(name=name, text=text), self.assertRaises(ValueError):
                verify_group_limits(
                    "builder", {"run": 7, "attempt": 2}, self.root / "groups", proc
                )
            (group / name).write_text(old)
        with self.assertRaises(ValueError):
            verify_group_limits(
                "builder", {"run": 7, "attempt": 3}, self.root / "groups", proc
            )

    def test_pid_birth_snapshot_handles_exit_between_reads(self):
        calls = []

        def proc(pid):
            calls.append(pid)
            if pid == 20:
                return (10, "S", 9)
            return (1, "S", 5) if calls.count(10) == 1 else None

        owned = {10: 5}
        with mock.patch(
            "qa3_native_io.Path.iterdir", return_value=iter([Path("20")])
        ), mock.patch("qa3_native_io._proc", side_effect=proc):
            _descendants(owned, set())
            self.assertEqual(owned[20], 9)
            self.assertEqual(calls.count(10), 1)
            self.assertEqual(set(owned_alive(owned)), {20})

    def test_environment_has_no_controller_or_agent_tokens(self):
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN": "fixture-token",
                "OPENAI_API_KEY": "fixture-key",
                "MOZCONFIG": "/untrusted",
                "PYTHONPATH": "/untrusted",
            },
        ):
            env = child_environment(self.root / "state")
        self.assertFalse(
            {"GITHUB_TOKEN", "OPENAI_API_KEY", "PYTHONPATH", "MOZCONFIG"} & set(env)
        )
        with self.assertRaises(ValueError):
            child_environment(self.root / "state2", {"GITHUB_TOKEN": "fixture"})


if __name__ == "__main__":
    unittest.main()
