# SPDX-License-Identifier: MPL-2.0

import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from qa3_native_transport import (
    API,
    WORKFLOW,
    authenticated_context,
    download_artifact,
    load_native_context,
    same_execution,
    validate_context,
    verify_artifact_metadata,
)
from qa3_source_cohort import file_digest


def context():
    return {
        "schemaVersion": 1,
        "executionRepository": "fixture-private/qa",
        "controllerHead": "a" * 40,
        "controllerWorkflow": "b" * 40,
        "runtimeRecipe": "c" * 40,
        "run": 7,
        "attempt": 2,
        "createdAt": "2026-10-09T01:02:03Z",
        "buildID": "20261009010203",
        "privateExecution": True,
        "controllerUid": 123,
        "publicationAuthorized": False,
    }


def metadata(digest, size=3):
    return {
        "id": 42,
        "name": "qa3-primary-7-2",
        "digest": "sha256:" + digest,
        "expired": False,
        "size_in_bytes": size,
        "workflow_run": {"id": 7, "head_sha": "a" * 40},
    }


class Response(io.BytesIO):
    status = 200


class TransportContracts(unittest.TestCase):
    def test_context_binds_actual_private_run_w_r_attempt_created_time(self):
        env = {
            "GITHUB_REPOSITORY": "fixture-private/qa",
            "GITHUB_RUN_ID": "7",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_WORKFLOW_SHA": "b" * 40,
            "GITHUB_API_URL": API,
            "GITHUB_TOKEN": "fixture-token",
        }
        payload = {
            "id": 7,
            "run_attempt": 2,
            "head_sha": "a" * 40,
            "created_at": "2026-10-09T01:02:03Z",
            "repository": {"full_name": "fixture-private/qa", "private": True},
            "referenced_workflows": [
                {"path": WORKFLOW + "@" + "c" * 40, "sha": "c" * 40}
            ],
        }
        with mock.patch.dict(os.environ, env, clear=True):
            actual = authenticated_context("c" * 40, "b" * 40, lambda **kw: payload)
            self.assertEqual(actual["buildID"], "20261009010203")
            for key, value in (
                ("run_attempt", 1),
                ("head_sha", "d" * 40),
                ("referenced_workflows", []),
                ("repository", {"full_name": "fixture-private/qa", "private": False}),
            ):
                changed = {**payload, key: value}
                with self.subTest(key=key), self.assertRaises(ValueError):
                    authenticated_context("c" * 40, "b" * 40, lambda **kw: changed)

    def test_artifact_wrong_id_name_attempt_digest_expired_run_head_and_size(self):
        good = metadata("f" * 64)
        self.assertEqual(
            verify_artifact_metadata(good, context(), 42, "primary", "f" * 64), 3
        )
        for key, value in (
            ("id", 43),
            ("name", "qa3-primary-7-1"),
            ("digest", "sha256:" + "e" * 64),
            ("expired", True),
            ("size_in_bytes", 0),
            ("size_in_bytes", True),
            ("workflow_run", {"id": 8, "head_sha": "a" * 40}),
            ("workflow_run", {"id": 7, "head_sha": "e" * 40}),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_artifact_metadata(
                    {**good, key: value}, context(), 42, "primary", "f" * 64
                )

    def test_cross_attempt_and_controller_recipe_mismatch(self):
        same_execution(context(), context())
        for key, value in (
            ("runtimeRecipe", "d" * 40),
            ("controllerWorkflow", "d" * 40),
            ("attempt", 3),
            ("controllerHead", "d" * 40),
            ("run", 8),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                same_execution({**context(), key: value}, context())
        same_execution({**context(), "controllerUid": 999}, context())

    def test_invalid_context_schema_time_uid_or_authority(self):
        for key, value in (
            ("privateExecution", False),
            ("buildID", "20261009010204"),
            ("controllerUid", True),
            ("publicationAuthorized", True),
            ("run", True),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_context({**context(), key: value})
        with self.assertRaises(ValueError):
            validate_context({**context(), "unknown": True})

    def transfer(self, location, payload=b"abc", expected=b"abc", size=None):
        requests = []
        digest = hashlib.sha256(expected).hexdigest()

        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                if len(requests) == 1:
                    return Response(
                        json.dumps(
                            metadata(digest, len(expected) if size is None else size)
                        ).encode()
                    )
                if len(requests) == 2:
                    raise urllib.error.HTTPError(
                        request.full_url, 302, "", {"Location": location}, None
                    )
                return Response(payload)

        with tempfile.TemporaryDirectory() as name, mock.patch.dict(
            os.environ, {"GITHUB_TOKEN": "fixture-token"}
        ):
            download_artifact(
                context(), 42, "primary", digest, Path(name) / "input.zip", Opener()
            )
        return requests

    def test_signed_storage_redirect_strips_authentication(self):
        requests = self.transfer(
            "https://fixture.blob.core.windows.net/input?sig=fixture"
        )
        self.assertEqual(
            requests[1].get_header("Authorization"), "Bearer fixture-token"
        )
        self.assertIsNone(requests[2].get_header("Authorization"))

    def test_storage_redirect_rejects_foreign_host_plaintext_and_userinfo(self):
        for location in (
            "https://evil.example/input",
            "http://fixture.blob.core.windows.net/input",
            "https://user@fixture.blob.core.windows.net/input",
            "https://fixture.blob.core.windows.net:8443/input",
        ):
            with self.subTest(location=location), self.assertRaises(ValueError):
                self.transfer(location)

    def test_transfer_rejects_truncation_excess_and_hash_difference(self):
        for payload in (b"ab", b"abcd", b"xyz"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.transfer("https://fixture.blob.core.windows.net/input", payload)

    def test_native_rejects_same_uid_root_wrong_service_user_tokens_and_changed_receipt(
        self,
    ):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "context.json"
            path.write_text(json.dumps(context()))
            digest = file_digest(path)
            for uid, user in ((0, "qa3-native"), (123, "qa3-native"), (456, "other")):
                with mock.patch("os.geteuid", return_value=uid), mock.patch(
                    "pwd.getpwuid", return_value=mock.Mock(pw_name=user)
                ), self.assertRaises(ValueError):
                    load_native_context(path, digest, "c" * 40, "b" * 40)
            with mock.patch("os.geteuid", return_value=456), mock.patch(
                "pwd.getpwuid", return_value=mock.Mock(pw_name="qa3-native")
            ), mock.patch.dict(
                os.environ, {"GITHUB_TOKEN": "fixture-token"}
            ), self.assertRaises(ValueError):
                load_native_context(path, digest, "c" * 40, "b" * 40)
            path.write_text(json.dumps({**context(), "attempt": 3}))
            with self.assertRaises(ValueError):
                load_native_context(path, digest, "c" * 40, "b" * 40)


if __name__ == "__main__":
    unittest.main()
