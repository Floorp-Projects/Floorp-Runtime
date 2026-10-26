#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import copy
import gzip
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import download_mac_pgo_stage1 as subject


HEAD = "a" * 40
DIGEST = "b" * 64
PACKAGE = "floorp-mac-x86_64-moz-artifact.tar.gz"
PIN = {"upstream": {"version": "159.0"}, "floorp_patch": {"sha256": DIGEST}}


def make_zip(package=None, provenance=None, extra=None):
    stream = io.BytesIO()
    proof = provenance or {"schema_version": 1, "runtime_commit": HEAD, **PIN}
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as output:
        with output.open(PACKAGE, "w", force_zip64=True) as member:
            member.write(package if package is not None else gzip.compress(b"owned package"))
        output.writestr("runtime-source-provenance.json", json.dumps(proof))
        if extra:
            output.writestr(*extra)
    return stream.getvalue()


class Response(io.BytesIO):
    status = 200


class Opener:
    def __init__(self, body, transfers=None):
        self.run = {"id": 7, "run_attempt": 1, "head_sha": HEAD,
                    "created_at": "2026-10-25T22:06:32Z",
                    "repository": {"full_name": "Floorp-Projects/Floorp-Runtime"}}
        self.artifact = {"id": 9, "name": "floorp-mac-x86_64-moz-artifact",
                         "expired": False, "size_in_bytes": len(body),
                         "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                         "workflow_run": {"id": 7, "head_sha": HEAD}}
        self.body, self.transfers = body, list(transfers or [])
        self.downloads = self.run_reads = 0
        self.requests = []
        self.change_run_after = None
        self.storage_url = "https://owned.blob.core.windows.net/file?sig=private"

    def open(self, request, timeout):
        self.requests.append(request)
        url = request.full_url
        if url.endswith("/actions/runs/7"):
            self.run_reads += 1
            value = copy.deepcopy(self.run)
            if self.change_run_after == self.run_reads:
                value["run_attempt"] = 2
            return Response(json.dumps(value).encode())
        if url.endswith("/actions/artifacts/9"):
            return Response(json.dumps(self.artifact).encode())
        if url.endswith("/actions/artifacts/9/zip"):
            raise urllib.error.HTTPError(url, 302, "redirect", {
                "Location": self.storage_url
            }, None)
        if url.startswith("https://owned.blob.core.windows.net/"):
            if request.has_header("Authorization"):
                raise AssertionError("Credential forwarded to storage")
            self.downloads += 1
            return Response(self.transfers.pop(0) if self.transfers else self.body)
        raise AssertionError("Unexpected network request: " + url)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".github").mkdir()
        (self.root / ".github/runtime-upstream.json").write_text(json.dumps(PIN))
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.env = patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "Floorp-Projects/Floorp-Runtime", "GITHUB_RUN_ID": "7",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": HEAD,
            "GITHUB_API_URL": subject.API, "GITHUB_TOKEN": "private-token",
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def args(self, opener, suffix="result"):
        return SimpleNamespace(arch="x86_64", artifact_id="9",
                               artifact_sha256=hashlib.sha256(opener.body).hexdigest(),
                               expected_build_id="20261025220632", output=self.root / suffix)

    def acquire(self, opener, args=None):
        return subject.acquire(args or self.args(opener), opener=opener, sleeper=lambda _: None)

    def test_verified_zip64_member_source_and_gzip(self):
        opener = Opener(make_zip(extra=("dist-host/mar", b"host")))
        final = self.acquire(opener)
        self.assertEqual(gzip.decompress(final.read_bytes()), b"owned package")
        receipt = json.loads((final.parent / "verified-package.json").read_bytes())
        self.assertTrue(receipt["success"])
        self.assertEqual(receipt["package"]["compiledSource"]["runtime_commit"], HEAD)
        self.assertEqual(opener.downloads, 1)

    def test_silent_partial_transfer_retries_without_publishing(self):
        body = make_zip()
        opener = Opener(body, [body[:len(body) // 2], body])
        final = self.acquire(opener)
        failure = json.loads((final.parent / "attempt-1.json").read_bytes())
        self.assertFalse(failure["success"])
        self.assertEqual(failure["bytes"], len(body) // 2)
        self.assertTrue(failure["retryable"])
        self.assertFalse((final.parent / "attempt-1.zip").exists())
        self.assertEqual(failure["sha256"], hashlib.sha256(body[:len(body) // 2]).hexdigest())
        self.assertTrue(failure["partialZipRemoved"])
        self.assertFalse((final.parent / "attempt-1.tar.gz.partial").exists())
        self.assertEqual(opener.downloads, 2)

    def test_same_size_wrong_digest_retries(self):
        body = make_zip()
        changed = bytes([body[0] ^ 1]) + body[1:]
        opener = Opener(body, [changed, body])
        self.acquire(opener)
        self.assertEqual(opener.downloads, 2)

    def test_retry_budget_preserves_all_failures_and_no_final(self):
        body = make_zip()
        opener = Opener(body, [body[:30]] * subject.ATTEMPTS)
        with self.assertRaisesRegex(ValueError, "acquisition failed"):
            self.acquire(opener)
        output = self.root / "result"
        self.assertEqual(opener.downloads, 3)
        self.assertEqual(len(list(output.glob("attempt-*.json"))), 3)
        self.assertFalse((output / PACKAGE).exists())
        self.assertFalse((output / "verified-package.json").exists())
        self.assertFalse(list(output.glob("*.zip")))
        self.assertNotIn("private-token", "".join(p.read_text() for p in output.glob("*.json")))

    def test_metadata_id_name_expiry_size_digest_run_head_fail_before_writes(self):
        changes = [("id", True), ("name", "wrong"), ("expired", True),
                   ("size_in_bytes", 0), ("size_in_bytes", subject.MAX_ARCHIVE + 1),
                   ("digest", "sha256:" + "c" * 64),
                   ("workflow_run", None),
                   ("workflow_run", {"id": 8, "head_sha": HEAD}),
                   ("workflow_run", {"id": 7, "head_sha": "d" * 40})]
        for index, (key, value) in enumerate(changes):
            with self.subTest(field=key, value=value):
                opener = Opener(make_zip()); opener.artifact[key] = value
                args = self.args(opener, "invalid-" + str(index))
                with self.assertRaises(ValueError): self.acquire(opener, args)
                self.assertFalse(args.output.exists())
                self.assertEqual(opener.downloads, 0)

    def test_run_attempt_head_repository_buildid_fail_before_writes(self):
        for key, value in [("run_attempt", 2), ("head_sha", "e" * 40),
                           ("repository", {"full_name": "other/runtime"}),
                           ("created_at", "2026-10-25T22:06:33Z")]:
            with self.subTest(field=key):
                opener = Opener(make_zip()); opener.run[key] = value
                args = self.args(opener, key)
                with self.assertRaises(ValueError): self.acquire(opener, args)
                self.assertFalse(args.output.exists())

    def test_changed_attempt_before_publish_keeps_final_absent(self):
        opener = Opener(make_zip()); opener.change_run_after = 3
        with self.assertRaises(ValueError): self.acquire(opener)
        self.assertFalse((self.root / "result" / PACKAGE).exists())
        self.assertEqual(opener.downloads, 1)

    def reject_package(self, body):
        opener = Opener(body)
        with self.assertRaisesRegex(ValueError, "package/source integrity"):
            self.acquire(opener)
        self.assertEqual(opener.downloads, 1)
        self.assertFalse((self.root / "result" / PACKAGE).exists())
        self.assertFalse(json.loads((self.root / "result/attempt-1.json").read_bytes())["retryable"])

    def test_authenticated_non_zip_is_rejected(self):
        self.reject_package(b"not zip")

    def test_authenticated_truncated_gzip_is_rejected(self):
        self.reject_package(make_zip(package=gzip.compress(b"owned")[:-6]))

    def test_authenticated_wrong_source_is_rejected(self):
        self.reject_package(make_zip(provenance={"schema_version": 1,
                                                "runtime_commit": "e" * 40, **PIN}))

    def test_zip_member_crc_is_checked(self):
        body = bytearray(make_zip())
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            offset = archive.getinfo(PACKAGE).header_offset
        name, extra = struct.unpack_from("<HH", body, offset + 26)
        body[offset + 30 + name + extra] ^= 1
        self.reject_package(bytes(body))

    def test_unsafe_zip_entry_is_rejected(self):
        self.reject_package(make_zip(extra=("../escape", b"outside")))

    def test_duplicate_package_entry_is_rejected(self):
        self.reject_package(make_zip(extra=(PACKAGE, b"ambiguous")))

    def test_zip_symlink_is_rejected(self):
        link = zipfile.ZipInfo("alias"); link.create_system = 3
        link.external_attr = 0o120777 << 16
        self.reject_package(make_zip(extra=(link, b"elsewhere")))

    def test_oversized_transfer_never_exposes_final(self):
        body = make_zip()
        opener = Opener(body, [body + b"unexpected"] * subject.ATTEMPTS)
        with self.assertRaises(ValueError): self.acquire(opener)
        self.assertFalse((self.root / "result" / PACKAGE).exists())

    def test_network_read_failure_retries_without_logging_credentials(self):
        opener = Opener(make_zip())
        original = opener.open
        failed = False
        def open_request(request, timeout):
            nonlocal failed
            if request.full_url.endswith("/zip") and not failed:
                failed = True
                raise OSError("sensitive failure URL must not be logged")
            return original(request, timeout)
        opener.open = open_request
        final = self.acquire(opener)
        receipt = (final.parent / "attempt-1.json").read_text()
        self.assertIn('"error": "OSError"', receipt)
        self.assertNotIn("sensitive", receipt)

    def test_bearer_only_on_api_never_on_signed_storage(self):
        opener = Opener(make_zip())
        self.acquire(opener)
        self.assertTrue(all(request.get_header("Authorization") == "Bearer private-token"
                            for request in opener.requests if request.full_url.startswith(subject.API)))
        self.assertTrue(all(not request.has_header("Authorization") for request in opener.requests
                            if request.full_url.startswith("https://owned.blob.core.windows.net/")))

    def test_unapproved_signed_redirect_never_requested(self):
        opener = Opener(make_zip()); opener.storage_url = "https://unapproved.invalid/file?sig=private"
        with self.assertRaises(ValueError): self.acquire(opener)
        self.assertFalse(any("unapproved.invalid" in r.full_url for r in opener.requests))
        self.assertFalse((self.root / "result" / PACKAGE).exists())

    def test_insufficient_staging_space_refuses_before_download(self):
        opener = Opener(make_zip())
        with patch.object(subject.shutil, "disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(ValueError, "Insufficient free space"):
                self.acquire(opener)
        self.assertEqual(opener.downloads, 0)
        self.assertFalse((self.root / "result").exists())


if __name__ == "__main__":
    unittest.main()
