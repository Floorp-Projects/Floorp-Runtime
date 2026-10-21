#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import runtime_build_context as build_context

REPOSITORY = "Floorp-Projects/Floorp-Runtime"
HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"
WORKFLOW_RUN_ID = "123456789"
CREATED_AT = "2026-07-23T01:02:03Z"
EXPECTED_BUILD_ID = "20260723010203"


def run_payload(
    *,
    repository: object = REPOSITORY,
    run_id: object = 123456789,
    head_sha: object = HEAD_SHA,
    created_at: object = CREATED_AT,
    run_attempt: object = 2,
) -> dict[str, object]:
    return {
        "id": run_id,
        "repository": {"full_name": repository},
        "head_sha": head_sha,
        "created_at": created_at,
        "run_attempt": run_attempt,
    }


def resolve(**overrides: object) -> build_context.BuildContext:
    arguments: dict[str, object] = {
        "resolved_moz_build_date": "",
        "requested_moz_build_date": "",
        "require_run_metadata": False,
        "repository": REPOSITORY,
        "head_sha": HEAD_SHA,
        "workflow_run_id": WORKFLOW_RUN_ID,
        "run_attempt": "2",
        "github_token": "token",
        "api_url": "https://api.github.com",
        "fetcher": lambda **_kwargs: run_payload(),
    }
    arguments.update(overrides)
    return build_context.resolve_build_context(**arguments)


class ValidationTests(unittest.TestCase):
    def test_build_id_accepts_valid_leap_day(self) -> None:
        self.assertEqual(
            build_context.validate_build_id("20240229235959", "value"),
            "20240229235959",
        )

    def test_build_id_rejects_noncanonical_or_invalid_values(self) -> None:
        invalid_values = (
            "",
            "2026072301020",
            "202607230102030",
            "２０２６０７２３０１０２０３",
            "20260229010203",
            "20261301010203",
            "20260723240203",
            "20260723016003",
            "20260723010260",
            " 20260723010203",
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.validate_build_id(value, "value")

    def test_created_at_is_strict_utc_and_derives_build_id(self) -> None:
        self.assertEqual(build_context.derive_build_id(CREATED_AT), EXPECTED_BUILD_ID)
        invalid_values = (
            "2026-07-23T01:02:03+00:00",
            "2026-07-23T01:02:03.000Z",
            "2026-07-23 01:02:03Z",
            "2026-07-23T24:02:03Z",
            "2026-02-29T01:02:03Z",
            "２０２６-07-23T01:02:03Z",
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.derive_build_id(value)

    def test_context_identifiers_are_strict(self) -> None:
        for repository in (
            "Floorp-Projects",
            "Floorp-Projects/Floorp-Runtime/extra",
            "Floorp--Projects/Floorp-Runtime",
            "Floorp-Projects-/Floorp-Runtime",
            "Floorp Projects/Floorp-Runtime",
            "Floorp-Projects/..",
        ):
            with self.subTest(repository=repository), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.validate_repository(repository)
        for sha in (HEAD_SHA.upper(), HEAD_SHA[:-1], f"g{HEAD_SHA[1:]}"):
            with self.subTest(sha=sha), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.validate_head_sha(sha)
        for number in ("", "0", "01", "+1", "-1", "1 ", "1" * 21):
            with self.subTest(number=number), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.validate_positive_decimal(number, "number")

    def test_boolean_is_not_truthy_coerced(self) -> None:
        self.assertTrue(build_context.parse_boolean("true", "flag"))
        self.assertFalse(build_context.parse_boolean("false", "flag"))
        for value in ("True", "FALSE", "1", "", " true"):
            with self.subTest(value=value), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.parse_boolean(value, "flag")


class ResolutionTests(unittest.TestCase):
    def test_trusted_resolved_value_avoids_rest(self) -> None:
        def forbidden_fetcher(**_kwargs: object) -> dict[str, object]:
            self.fail("trusted resolution must not call REST")

        context = resolve(
            resolved_moz_build_date=EXPECTED_BUILD_ID,
            requested_moz_build_date=EXPECTED_BUILD_ID,
            github_token="",
            fetcher=forbidden_fetcher,
        )
        self.assertEqual(
            context.as_outputs(),
            {
                "expected-build-id": EXPECTED_BUILD_ID,
                "repository": REPOSITORY,
                "head-sha": HEAD_SHA,
                "workflow-run-id": WORKFLOW_RUN_ID,
                "run-created-at": "",
                "run-attempt": "2",
            },
        )

    def test_conflicting_trusted_and_requested_values_fail_before_rest(self) -> None:
        def forbidden_fetcher(**_kwargs: object) -> dict[str, object]:
            self.fail("conflicting assertions must fail before REST")

        with self.assertRaisesRegex(build_context.BuildContextError, "conflicts with"):
            resolve(
                resolved_moz_build_date=EXPECTED_BUILD_ID,
                requested_moz_build_date="20260723010204",
                require_run_metadata=True,
                fetcher=forbidden_fetcher,
            )

    def test_missing_resolved_value_uses_rest(self) -> None:
        observed: list[dict[str, object]] = []

        def fetcher(**kwargs: object) -> dict[str, object]:
            observed.append(kwargs)
            return run_payload()

        context = resolve(fetcher=fetcher)
        self.assertEqual(context.expected_build_id, EXPECTED_BUILD_ID)
        self.assertEqual(context.run_created_at, CREATED_AT)
        self.assertEqual(context.run_attempt, "2")
        self.assertEqual(
            observed,
            [
                {
                    "api_url": "https://api.github.com",
                    "repository": REPOSITORY,
                    "workflow_run_id": WORKFLOW_RUN_ID,
                    "github_token": "token",
                }
            ],
        )

    def test_require_metadata_forces_rest_and_checks_resolved_assertion(self) -> None:
        context = resolve(
            resolved_moz_build_date=EXPECTED_BUILD_ID,
            require_run_metadata=True,
        )
        self.assertEqual(context.run_created_at, CREATED_AT)
        with self.assertRaisesRegex(
            build_context.BuildContextError, "resolved_moz_build_date does not match"
        ):
            resolve(
                resolved_moz_build_date="20260723010204",
                require_run_metadata=True,
            )

    def test_requested_value_is_only_an_assertion(self) -> None:
        self.assertEqual(
            resolve(requested_moz_build_date=EXPECTED_BUILD_ID).expected_build_id,
            EXPECTED_BUILD_ID,
        )
        with self.assertRaisesRegex(
            build_context.BuildContextError, "requested_moz_build_date does not match"
        ):
            resolve(requested_moz_build_date="20260723010204")

    def test_run_attempt_is_observed_but_does_not_change_identity(self) -> None:
        first = resolve(
            run_attempt="1", fetcher=lambda **_kwargs: run_payload(run_attempt=1)
        )
        second = resolve(
            run_attempt="2", fetcher=lambda **_kwargs: run_payload(run_attempt=2)
        )
        self.assertEqual(first.expected_build_id, second.expected_build_id)
        self.assertEqual(first.run_attempt, "1")
        self.assertEqual(second.run_attempt, "2")

    def test_daily_manifest_uses_aggregate_attempt_on_rerun(self) -> None:
        preserved_resolver = resolve(
            run_attempt="1", fetcher=lambda **_kwargs: run_payload(run_attempt=1)
        )
        aggregate_attempt = "2"
        self.assertEqual(preserved_resolver.run_attempt, "1")
        self.assertEqual(preserved_resolver.expected_build_id, EXPECTED_BUILD_ID)
        self.assertEqual(aggregate_attempt, "2")

        workflow = (
            Path(__file__).resolve().parents[1] / "daily-build.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "MANIFEST_RUN_ATTEMPT: ${{ github.run_attempt }}",
            workflow,
        )
        self.assertNotIn(
            "needs.resolve-build-context.outputs.run-attempt",
            workflow,
        )

    def test_daily_validation_only_runs_manifest_without_publish_side_effects(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1] / "daily-build.yml"
        ).read_text(encoding="utf-8")
        aggregate = workflow.split("  aggregate-runtime-manifest-v2:", 1)[1].split(
            "  publish-debug-to-core-ftp:", 1
        )[0]
        debug_publish = workflow.split("  publish-debug-to-core-ftp:", 1)[1].split(
            "  publish-release:", 1
        )[0]
        release_publish = workflow.split("  publish-release:", 1)[1]

        validation_input = workflow.split("      validation_only:", 1)[1].split(
            "      requested_MOZ_BUILD_DATE:", 1
        )[0]
        self.assertIn("type: boolean", validation_input)
        self.assertIn("default: false", validation_input)
        self.assertEqual(workflow.count("inputs.validation_only != true"), 3)
        self.assertIn("  # android:", workflow)
        self.assertNotIn("\n  android:\n", workflow)
        self.assertIn("inputs.validation_only == true", aggregate)
        self.assertIn("github.event.inputs.debug != 'true'", aggregate)
        self.assertNotIn("aggregate-runtime-manifest-v2", debug_publish)
        self.assertIn("inputs.validation_only != true", debug_publish)
        self.assertIn("vars.RUNTIME_FTP_DELIVERY_ENABLED == 'true' &&", debug_publish)
        self.assertIn("needs:\n      - aggregate-runtime-manifest-v2", release_publish)
        self.assertIn("# - android", release_publish)
        self.assertIn("# artifacts/android/floorp-android-all-artifacts.zip", release_publish)
        self.assertIn("inputs.validation_only != true", release_publish)

    def test_daily_runtime_verifier_matrix_and_publish_gates(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1] / "daily-build.yml"
        ).read_text(encoding="utf-8")
        verifier_specs = [
            (
                "verify-windows-x86_64",
                "windows-x86_64",
                "Windows",
                "x86_64",
                "windows-2025",
            ),
            (
                "verify-linux-x86_64",
                "linux-x86_64",
                "Linux",
                "x86_64",
                "ubuntu-24.04",
            ),
            (
                "verify-linux-aarch64",
                "linux-aarch64",
                "Linux",
                "aarch64",
                "ubuntu-24.04-arm",
            ),
            (
                "verify-mac-x86_64",
                "mac",
                "Darwin",
                "x86_64",
                "macos-15-intel",
            ),
            (
                "verify-mac-aarch64",
                "mac",
                "Darwin",
                "aarch64",
                "macos-14",
            ),
        ]

        def job_block(job: str) -> str:
            marker = f"  {job}:"
            self.assertEqual(workflow.count(marker), 1)
            lines = workflow.split(marker, 1)[1].splitlines()[1:]
            block_lines = []
            for line in lines:
                if line.startswith("  ") and not line.startswith("    "):
                    break
                block_lines.append(line)
            return "\n".join(block_lines)

        def setting(block: str, name: str) -> str:
            prefix = f"{name}:"
            values = [
                line.strip().removeprefix(prefix).strip()
                for line in block.splitlines()
                if line.strip().startswith(prefix)
            ]
            self.assertEqual(len(values), 1, name)
            return values[0]

        actual_specs = []

        for job, build, platform, arch, runner in verifier_specs:
            block = job_block(job)
            actual_specs.append(
                (
                    job,
                    setting(block, "needs"),
                    setting(block, "platform"),
                    setting(block, "arch"),
                    setting(block, "runner"),
                )
            )
            self.assertIn(f"needs: {build}", block)
            self.assertIn("uses: ./.github/workflows/verify-runtime-artifact.yml", block)
            for input_name, output_name in (
                ("artifact-id", "artifact-id"),
                ("artifact-name", "artifact-name"),
                ("expected-build-id", "expected-build-id"),
            ):
                self.assertIn(
                    f"{input_name}: ${{{{ needs.{build}.outputs.{output_name} }}}}",
                    block,
                )
            self.assertIn(f"platform: {platform}", block)
            self.assertIn(f"arch: {arch}", block)
            self.assertIn(f"runner: {runner}", block)

        self.assertEqual(actual_specs, verifier_specs)

        def list_needs(block: str) -> list[str]:
            lines = block.splitlines()
            start = lines.index("    needs:") + 1
            needs = []
            for line in lines[start:]:
                if line.startswith("      # "):
                    continue
                if not line.startswith("      - "):
                    break
                needs.append(line.removeprefix("      - "))
            return needs

        verifier_jobs = [job for job, *_rest in verifier_specs]
        self.assertEqual(
            list_needs(job_block("aggregate-runtime-manifest-v2")),
            [
                "resolve-build-context",
                "windows-x86_64",
                "linux-x86_64",
                "linux-aarch64",
                "mac",
                *verifier_jobs,
            ],
        )
        self.assertEqual(
            list_needs(job_block("publish-debug-to-core-ftp")),
            [
                "windows-x86_64",
                "linux-x86_64",
                "linux-aarch64",
                "mac",
                *verifier_jobs,
            ],
        )

    def test_linux_stage2_uses_retained_profile_generation_artifact(self) -> None:
        workflows = Path(__file__).resolve().parents[1]
        common = (workflows / "common-build.yml").read_text(encoding="utf-8")
        wrapper = (workflows / "wrapper-build-linux.yml").read_text(
            encoding="utf-8"
        )
        artifact_name = "floorp-linux-x86_64-profile-generate-mode-package"
        self.assertIn("Upload PGO profile generation package (Linux)", common)
        self.assertIn(f"name: {artifact_name}", common)
        self.assertIn(f"browser-artifact-name: >-\n        {artifact_name}", wrapper)

    def test_rest_payload_must_match_all_trusted_context_fields(self) -> None:
        mismatches = {
            "repository": run_payload(repository="Floorp-Projects/Other"),
            "id": run_payload(run_id=123456788),
            "head_sha": run_payload(head_sha="f" * 40),
            "run_attempt": run_payload(run_attempt=1),
        }
        for field, payload in mismatches.items():
            with self.subTest(field=field), self.assertRaises(
                build_context.BuildContextError
            ):
                resolve(fetcher=lambda **_kwargs: payload)

    def test_rest_payload_rejects_missing_and_wrong_field_types(self) -> None:
        fields = ("repository", "id", "head_sha", "created_at", "run_attempt")
        for field in fields:
            payload = run_payload()
            del payload[field]
            with self.subTest(missing=field), self.assertRaises(
                build_context.BuildContextError
            ):
                resolve(fetcher=lambda **_kwargs: payload)

        wrong_values = {
            "repository": {"full_name": 123},
            "id": True,
            "head_sha": 123,
            "created_at": 123,
            "run_attempt": True,
        }
        for field, value in wrong_values.items():
            payload = run_payload()
            payload[field] = value
            with self.subTest(wrong_type=field), self.assertRaises(
                build_context.BuildContextError
            ):
                resolve(fetcher=lambda **_kwargs: payload)

    def test_trusted_path_still_validates_github_context(self) -> None:
        invalid_cases = {
            "repository": "Floorp-Projects",
            "head_sha": HEAD_SHA.upper(),
            "workflow_run_id": "0",
            "run_attempt": "01",
        }
        for field, value in invalid_cases.items():
            with self.subTest(field=field), self.assertRaises(
                build_context.BuildContextError
            ):
                resolve(resolved_moz_build_date=EXPECTED_BUILD_ID, **{field: value})


class RestClientTests(unittest.TestCase):
    def test_json_parser_rejects_duplicates_constants_and_non_objects(self) -> None:
        invalid_documents = (
            b'{"id": 1, "id": 2}',
            b'{"id": NaN}',
            b"[]",
            b"\xff",
            b"not-json",
        )
        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.parse_rest_json(document)

    def test_run_url_supports_github_enterprise_api_base(self) -> None:
        self.assertEqual(
            build_context.build_run_url(
                "https://github.example/api/v3/", REPOSITORY, WORKFLOW_RUN_ID
            ),
            "https://github.example/api/v3/repos/"
            "Floorp-Projects/Floorp-Runtime/actions/runs/123456789",
        )
        for url in (
            "",
            "http://api.github.com",
            "https://user@example.com",
            "https://api.github.com?query=1",
            "https://api.github.com/#fragment",
            " https://api.github.com",
        ):
            with self.subTest(url=url), self.assertRaises(
                build_context.BuildContextError
            ):
                build_context.build_run_url(url, REPOSITORY, WORKFLOW_RUN_ID)

    def test_fetch_uses_authenticated_versioned_get_and_parses_json(self) -> None:
        response_body = json.dumps(run_payload()).encode("utf-8")

        class Response:
            status = 200

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, _size: int) -> bytes:
                return response_body

        with mock.patch.object(
            build_context.urllib.request, "urlopen", return_value=Response()
        ) as urlopen:
            payload = build_context.fetch_actions_run(
                api_url="https://api.github.com",
                repository=REPOSITORY,
                workflow_run_id=WORKFLOW_RUN_ID,
                github_token="secret-token",
            )
        self.assertEqual(payload["created_at"], CREATED_AT)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")
        self.assertEqual(urlopen.call_args.kwargs, {"timeout": 30.0})

    def test_fetch_fails_closed_without_token_or_on_http_error(self) -> None:
        with self.assertRaisesRegex(
            build_context.BuildContextError, "TOKEN is required"
        ):
            build_context.fetch_actions_run(
                api_url="https://api.github.com",
                repository=REPOSITORY,
                workflow_run_id=WORKFLOW_RUN_ID,
                github_token="",
            )
        error = urllib.error.HTTPError(
            "https://api.github.com", 403, "Forbidden", {}, None
        )
        with mock.patch.object(
            build_context.urllib.request, "urlopen", side_effect=error
        ):
            with self.assertRaisesRegex(build_context.BuildContextError, "HTTP 403"):
                build_context.fetch_actions_run(
                    api_url="https://api.github.com",
                    repository=REPOSITORY,
                    workflow_run_id=WORKFLOW_RUN_ID,
                    github_token="token",
                )


class CliTests(unittest.TestCase):
    def test_trusted_cli_writes_exact_github_outputs_without_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "github-output"
            with mock.patch.dict(os.environ, {}, clear=True):
                result = build_context.main([
                    "--resolved-moz-build-date",
                    EXPECTED_BUILD_ID,
                    "--requested-moz-build-date",
                    EXPECTED_BUILD_ID,
                    "--require-run-metadata",
                    "false",
                    "--repository",
                    REPOSITORY,
                    "--head-sha",
                    HEAD_SHA,
                    "--workflow-run-id",
                    WORKFLOW_RUN_ID,
                    "--run-attempt",
                    "2",
                    "--github-output",
                    str(output_path),
                ])
            self.assertEqual(result, 0)
            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                f"expected-build-id={EXPECTED_BUILD_ID}\n"
                f"repository={REPOSITORY}\n"
                f"head-sha={HEAD_SHA}\n"
                f"workflow-run-id={WORKFLOW_RUN_ID}\n"
                "run-created-at=\n"
                "run-attempt=2\n",
            )

    def test_cli_failure_does_not_write_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "github-output"
            with mock.patch.dict(os.environ, {}, clear=True):
                result = build_context.main([
                    "--resolved-moz-build-date",
                    "invalid",
                    "--repository",
                    REPOSITORY,
                    "--head-sha",
                    HEAD_SHA,
                    "--workflow-run-id",
                    WORKFLOW_RUN_ID,
                    "--run-attempt",
                    "2",
                    "--github-output",
                    str(output_path),
                ])
            self.assertEqual(result, 1)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
