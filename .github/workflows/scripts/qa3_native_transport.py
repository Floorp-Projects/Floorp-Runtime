# SPDX-License-Identifier: MPL-2.0

import argparse
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from qa3_native_io import (
    GIB,
    MAX_COMPRESSED,
    ExpansionBudget,
    IOBudget,
    extract_archive,
    fresh,
    read_json,
    write_json,
)
from qa3_source_cohort import file_digest, hash_value
from runtime_build_context import (
    derive_build_id,
    fetch_actions_run,
    parse_rest_json,
    validate_positive_decimal,
    validate_repository,
    validate_run_payload,
)

API = "https://api.github.com"
WORKFLOW = "Floorp-Projects/Floorp-Runtime/.github/workflows/qa3-linux-debug-proof.yml"


def authenticated_context(runtime, controller, fetcher=None):
    hash_value(runtime, 40)
    hash_value(controller, 40)
    repo = validate_repository(os.environ["GITHUB_REPOSITORY"])
    run = validate_positive_decimal(os.environ["GITHUB_RUN_ID"], "run")
    attempt = validate_positive_decimal(os.environ["GITHUB_RUN_ATTEMPT"], "attempt")
    if (
        os.environ.get("GITHUB_API_URL") != API
        or os.environ.get("GITHUB_WORKFLOW_SHA") != controller
    ):
        raise ValueError("unverified controller workflow origin")
    payload = (fetcher or fetch_actions_run)(
        api_url=API,
        repository=repo,
        workflow_run_id=run,
        github_token=os.environ["GITHUB_TOKEN"],
    )
    created, observed = validate_run_payload(
        payload,
        repository=repo,
        workflow_run_id=run,
        head_sha=os.environ["GITHUB_SHA"],
        run_attempt=attempt,
    )
    if payload["repository"].get("private") is not True:
        raise ValueError(
            "native proof requires authenticated private execution repository"
        )
    matches = [
        w
        for w in payload.get("referenced_workflows", [])
        if w.get("path") == WORKFLOW + "@" + runtime and w.get("sha") == runtime
    ]
    if len(matches) != 1:
        raise ValueError("REST metadata does not bind the pinned reusable recipe")
    return {
        "schemaVersion": 1,
        "executionRepository": repo,
        "controllerHead": os.environ["GITHUB_SHA"],
        "controllerWorkflow": controller,
        "runtimeRecipe": runtime,
        "run": int(run),
        "attempt": int(observed),
        "createdAt": created,
        "buildID": derive_build_id(created),
        "privateExecution": True,
        "controllerUid": os.geteuid(),
        "publicationAuthorized": False,
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def request_json(url, token, opener=None):
    if not url.startswith(API + "/repos/"):
        raise ValueError("unapproved authenticated REST origin")
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "floorp-qa3-native",
        },
    )
    try:
        with (opener or urllib.request.build_opener(NoRedirect())).open(
            request, timeout=30
        ) as response:
            if response.status != 200:
                raise ValueError("authenticated metadata request failed")
            data = response.read(1024**2 + 1)
    except urllib.error.URLError as exc:
        raise ValueError("authenticated metadata request failed") from exc
    if len(data) > 1024**2:
        raise ValueError("oversized authenticated metadata")
    return dict(parse_rest_json(data))


def verify_artifact_metadata(metadata, context, artifact_id, kind, digest):
    hash_value(digest)
    if (
        type(artifact_id) is not int
        or artifact_id <= 0
        or kind not in {"primary", "support"}
    ):
        raise ValueError("invalid expected artifact")
    name = f"qa3-{kind}-{context['run']}-{context['attempt']}"
    if metadata.get("id") != artifact_id or metadata.get("name") != name:
        raise ValueError("artifact ID/name/attempt mismatch")
    if (
        metadata.get("expired") is not False
        or metadata.get("digest") != "sha256:" + digest
    ):
        raise ValueError("expired artifact or digest mismatch")
    size = metadata.get("size_in_bytes")
    if type(size) is not int or not 0 < size <= MAX_COMPRESSED:
        raise ValueError("artifact compressed budget exceeded")
    subject = metadata.get("workflow_run", {})
    if (
        subject.get("id") != context["run"]
        or subject.get("head_sha") != context["controllerHead"]
    ):
        raise ValueError("artifact producer run or controller mismatch")
    return size


def download_artifact(
    context, artifact_id, kind, digest, destination, opener=None, budget=None
):
    if (
        type(artifact_id) is not int
        or artifact_id <= 0
        or kind not in {"primary", "support"}
    ):
        raise ValueError("invalid transfer artifact ID or kind")
    hash_value(digest)
    repo = validate_repository(context["executionRepository"])
    token = os.environ["GITHUB_TOKEN"]
    active = opener or urllib.request.build_opener(NoRedirect())
    endpoint = API + f"/repos/{repo}/actions/artifacts/{artifact_id}"
    metadata = request_json(endpoint, token, active)
    size = verify_artifact_metadata(metadata, context, artifact_id, kind, digest)
    request = urllib.request.Request(
        endpoint + "/zip",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "User-Agent": "floorp-qa3-native",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        try:
            response = active.open(request, timeout=30)
        except urllib.error.HTTPError as redirect:
            if redirect.code != 302:
                raise ValueError("authenticated artifact transfer failed") from None
            location = redirect.headers.get("Location", "")
            parsed = urllib.parse.urlsplit(location)
            if (
                parsed.scheme != "https"
                or parsed.username
                or parsed.password
                or parsed.port not in {None, 443}
                or not parsed.hostname
                or not (
                    parsed.hostname.endswith(".blob.core.windows.net")
                    or parsed.hostname.endswith(".githubusercontent.com")
                )
            ):
                raise ValueError("unapproved artifact storage redirect")
            response = active.open(
                urllib.request.Request(
                    location, headers={"User-Agent": "floorp-qa3-native"}
                ),
                timeout=30,
            )
        with response, destination.open("xb") as output:
            if response.status != 200:
                raise ValueError("private artifact transfer failed")
            transferred = 0
            while block := response.read(1024**2):
                transferred += len(block)
                if transferred > size or transferred > MAX_COMPRESSED:
                    raise ValueError("artifact transfer size limit exceeded")
                if budget is not None:
                    budget.consume(len(block))
                output.write(block)
    except urllib.error.URLError:
        raise ValueError("private artifact transfer failed") from None
    if transferred != size or file_digest(destination) != digest:
        raise ValueError("artifact transfer bytes do not match authenticated digest")
    return metadata


def worker_boot_identity():
    return file_digest(Path("/proc/sys/kernel/random/boot_id"))


def validate_context(value):
    fields = {
        "schemaVersion",
        "executionRepository",
        "controllerHead",
        "controllerWorkflow",
        "runtimeRecipe",
        "run",
        "attempt",
        "createdAt",
        "buildID",
        "privateExecution",
        "controllerUid",
        "publicationAuthorized",
    }
    if (
        set(value) != fields
        or value["schemaVersion"] != 1
        or value["privateExecution"] is not True
    ):
        raise ValueError("invalid producer context")
    validate_repository(value["executionRepository"])
    for field in ("controllerHead", "controllerWorkflow", "runtimeRecipe"):
        hash_value(value[field], 40)
    for field in ("run", "attempt"):
        if type(value[field]) is not int or value[field] <= 0:
            raise ValueError("invalid producer run/attempt")
    if type(value["controllerUid"]) is not int or value["controllerUid"] < 0:
        raise ValueError("invalid controller process identity")
    if (
        value["buildID"] != derive_build_id(value["createdAt"])
        or value["publicationAuthorized"] is not False
    ):
        raise ValueError("producer authority or BuildID mismatch")
    return value


def load_native_context(path, expected_digest, runtime, controller):
    import pwd

    if file_digest(path) != hash_value(expected_digest):
        raise ValueError("controller-authenticated context bytes changed")
    value = validate_context(read_json(path))
    if value["runtimeRecipe"] != runtime or value["controllerWorkflow"] != controller:
        raise ValueError("controller context does not match pinned W/R")
    if (
        os.geteuid() == 0
        or os.geteuid() == value["controllerUid"]
        or pwd.getpwuid(os.geteuid()).pw_name != "qa3-native"
    ):
        raise ValueError(
            "native execution requires a distinct preconfigured unprivileged UID"
        )
    credential_keys = (
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    )
    if any(os.environ.get(k) for k in credential_keys):
        raise ValueError("native process inherited a controller/Agent credential")
    allowed_env = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "TZ",
        "USER",
        "LOGNAME",
        "TERM",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
    }
    if (
        set(os.environ) - allowed_env
        or os.environ.get("HOME") != pwd.getpwuid(os.geteuid()).pw_dir
    ):
        raise ValueError(
            "native entry environment/home is not scrubbed by the pinned launcher"
        )
    if os.access(path, os.W_OK) or any(
        os.access(p, os.W_OK) for p in path.parents if p != Path("/")
    ):
        raise ValueError("native UID can replace the authenticated controller context")
    for name in (".ssh", ".aws", ".netrc", ".git-credentials", ".mozilla"):
        if (Path.home() / name).exists():
            raise ValueError(
                "native home contains credentials or real browser profiles"
            )
    return value


def same_execution(actual, expected):
    validate_context(actual)
    validate_context(expected)
    if {k: v for k, v in actual.items() if k != "controllerUid"} != {
        k: v for k, v in expected.items() if k != "controllerUid"
    }:
        raise ValueError(
            "producer and consumer authenticated execution context differs"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("context", "download"))
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--output", type=Path, required=True)
    for kind in ("primary", "support"):
        parser.add_argument("--" + kind + "-id", type=int)
        parser.add_argument("--" + kind + "-sha256")
    args = parser.parse_args()
    try:
        context = authenticated_context(args.runtime, args.controller)
        fresh(args.output)
        if args.operation == "download":
            sizes = 0
            budget = IOBudget(args.output, 40 * GIB, 10 * GIB)
            expansion = ExpansionBudget(maximum=MAX_COMPRESSED)
            for kind, allowed in (
                ("primary", {"runtime.tar.xz", "primary.json"}),
                (
                    "support",
                    {
                        "test-support.tar.gz",
                        "proof.json",
                        "baseline.json",
                        "final.json",
                    },
                ),
            ):
                archive = args.output / (kind + ".zip")
                identifier = getattr(args, kind + "_id")
                wanted = getattr(args, kind + "_sha256")
                metadata = download_artifact(
                    context, identifier, kind, wanted, archive, budget=budget
                )
                sizes += metadata["size_in_bytes"]
                if sizes > MAX_COMPRESSED:
                    raise ValueError(
                        "combined transferred native input budget exceeded"
                    )
                stage = args.output / kind
                extract_archive(
                    archive,
                    stage,
                    expanded=MAX_COMPRESSED,
                    budget=budget,
                    expansion=expansion,
                )
                if {
                    p.relative_to(stage).as_posix() for p in stage.rglob("*")
                } != allowed:
                    raise ValueError("unexpected native artifact wrapper member")
                write_json(
                    args.output / (kind + "-transport.json"),
                    {
                        "artifactId": identifier,
                        "archiveSha256": wanted,
                        "metadata": metadata,
                        "authenticatedRepository": context["executionRepository"],
                    },
                )
                budget.release_tree(archive)
        path = args.output / "context.json"
        write_json(path, context)
        for item in sorted(
            args.output.rglob("*"), key=lambda p: len(p.parts), reverse=True
        ):
            item.chmod(0o555 if item.is_dir() else 0o444)
        args.output.chmod(0o555)
        if os.environ.get("GITHUB_OUTPUT"):
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as out:
                out.write("context-sha256=" + file_digest(path) + "\n")
    except (ValueError, OSError, KeyError):
        print(
            "Private context/artifact verification failed; native execution is blocked.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
