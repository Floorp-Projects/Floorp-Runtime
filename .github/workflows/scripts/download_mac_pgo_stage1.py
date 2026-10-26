#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import argparse
import gzip
import hashlib
import http.client
import json
import os
import re
import shutil
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from runtime_build_context import (
    derive_build_id,
    parse_rest_json,
    validate_build_id,
    validate_head_sha,
    validate_positive_decimal,
    validate_repository,
    validate_run_payload,
)

API = "https://api.github.com"
MAX_ARCHIVE = 16 * 1024**3
MAX_EXPANDED = 128 * 1024**3
ATTEMPTS = 3
TRANSFER_SECONDS = 900
BLOCK = 1024**2


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class AcquisitionError(ValueError):
    pass


class TransferError(AcquisitionError):
    pass


def require(condition, message):
    if not condition:
        raise AcquisitionError(message)


def write_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def remove_owned_attempt(path, output):
    if not path.exists() and not path.is_symlink():
        return
    require(not output.is_symlink() and not path.is_symlink() and path.is_file() and
            path.resolve(strict=True).parent == output.resolve(strict=True) and
            re.fullmatch(r"attempt-[1-3]\.(zip|tar\.gz\.partial)", path.name),
            "Refusing unexpected attempt cleanup path")
    path.unlink()


def api_request(url, token):
    return urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "floorp-mac-pgo-stage1",
    })


def metadata(opener, url, token):
    with opener.open(api_request(url, token), timeout=60) as response:
        require(response.status == 200, "Authenticated metadata request failed")
        data = response.read(BLOCK + 1)
    require(len(data) <= BLOCK, "Oversized artifact metadata")
    return parse_rest_json(data)


def validate_artifact(value, *, artifact_id, digest, arch, run_id, head):
    require(type(value.get("id")) is int and value["id"] == artifact_id,
            "Artifact ID mismatch")
    require(value.get("name") == f"floorp-mac-{arch}-moz-artifact",
            "Artifact name mismatch")
    require(value.get("expired") is False and value.get("digest") == "sha256:" + digest,
            "Artifact expired or digest mismatch")
    size = value.get("size_in_bytes")
    require(type(size) is int and 0 < size <= MAX_ARCHIVE, "Invalid artifact size")
    subject = value.get("workflow_run", {})
    require(isinstance(subject, dict) and type(subject.get("id")) is int and subject["id"] == run_id and
            subject.get("head_sha") == head, "Artifact run/head mismatch")
    return size


def stream_zip(opener, endpoint, token, path, size, digest, receipt):
    started = time.monotonic()
    try:
        response = opener.open(api_request(endpoint + "/zip", token), timeout=60)
    except urllib.error.HTTPError as redirect:
        require(redirect.code == 302, "Artifact request did not return a download")
        location = redirect.headers.get("Location", "")
        target = urllib.parse.urlsplit(location)
        require(target.scheme == "https" and not target.username and not target.password
                and target.port in (None, 443) and not target.fragment and target.hostname
                and (target.hostname.endswith(".blob.core.windows.net") or
                     target.hostname.endswith(".githubusercontent.com")),
                "Unexpected artifact storage redirect")
        response = opener.open(urllib.request.Request(location, headers={
            "User-Agent": "floorp-mac-pgo-stage1",
        }), timeout=60)
    observed = hashlib.sha256()
    receipt.update(bytes=0, sha256=observed.hexdigest())
    with response, path.open("xb") as output:
        require(response.status == 200, "Artifact download failed")
        while block := response.read(BLOCK):
            receipt["bytes"] += len(block)
            observed.update(block)
            receipt["sha256"] = observed.hexdigest()
            output.write(block)
            if receipt["bytes"] > size or time.monotonic() - started > TRANSFER_SECONDS:
                raise TransferError("Artifact download exceeded size/time limit")
    if receipt["bytes"] != size or observed.hexdigest() != digest:
        raise TransferError("Artifact ZIP size/digest mismatch (incomplete download)")


def verify_member(archive, destination, *, arch, head, pin):
    expected = f"floorp-mac-{arch}-moz-artifact.tar.gz"
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        require(0 < len(entries) <= 128 and
                len({entry.filename for entry in entries}) == len(entries),
                "Ambiguous artifact ZIP entries")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            kind = stat.S_IFMT(entry.external_attr >> 16)
            require(not path.is_absolute() and ".." not in path.parts and
                    "\\" not in entry.filename and ":" not in entry.filename and
                    kind in (0, stat.S_IFREG, stat.S_IFDIR) and not entry.flag_bits & 1,
                    "Unsafe artifact ZIP member")
        matches = [entry for entry in entries if entry.filename == expected]
        proofs = [entry for entry in entries if entry.filename == "runtime-source-provenance.json"]
        require(len(matches) == len(proofs) == 1 and not matches[0].is_dir() and
                stat.S_IFMT(matches[0].external_attr >> 16) in (0, stat.S_IFREG) and
                stat.S_IFMT(proofs[0].external_attr >> 16) in (0, stat.S_IFREG) and
                0 < matches[0].file_size <= MAX_ARCHIVE and
                0 < proofs[0].file_size <= BLOCK,
                "Missing or invalid exact package/source member")
        provenance = parse_rest_json(source.read(proofs[0]))
        require(provenance.get("schema_version") == 1 and
                provenance.get("runtime_commit") == head and
                provenance.get("upstream") == pin["upstream"] and
                provenance.get("floorp_patch") == pin["floorp_patch"],
                "Compiled source provenance mismatch")
        observed = hashlib.sha256()
        count = 0
        with source.open(matches[0]) as stream, destination.open("xb") as output:
            while block := stream.read(BLOCK):
                count += len(block)
                require(count <= matches[0].file_size, "Package member size exceeded")
                observed.update(block)
                output.write(block)
        require(count == matches[0].file_size, "Truncated package ZIP member")
    expanded = 0
    with gzip.open(destination, "rb") as stream:
        while block := stream.read(BLOCK):
            expanded += len(block)
            require(expanded <= MAX_EXPANDED, "Package gzip expansion exceeded limit")
    require(expanded > 0, "Empty package gzip")
    return {"name": expected, "bytes": count, "sha256": observed.hexdigest(),
            "gzipBytes": expanded, "compiledSource": provenance}


def acquire(args, *, opener=None, sleeper=time.sleep):
    arch = args.arch
    require(arch in {"x86_64", "aarch64"}, "Unsupported Mac architecture")
    artifact_id = int(validate_positive_decimal(args.artifact_id, "artifact ID"))
    digest = args.artifact_sha256.removeprefix("sha256:")
    require(re.fullmatch("[0-9a-f]{64}", digest), "Invalid producer artifact digest")
    repo = validate_repository(os.environ["GITHUB_REPOSITORY"])
    run_id = validate_positive_decimal(os.environ["GITHUB_RUN_ID"], "run")
    attempt = validate_positive_decimal(os.environ["GITHUB_RUN_ATTEMPT"], "attempt")
    head = validate_head_sha(os.environ["GITHUB_SHA"])
    expected = validate_build_id(args.expected_build_id, "expected BuildID")
    require(os.environ.get("GITHUB_API_URL") == API, "Unexpected GitHub API origin")
    token = os.environ["GITHUB_TOKEN"]
    require(token and not any(c.isspace() or ord(c) < 32 for c in token),
            "Invalid GitHub credential")
    opener = opener or urllib.request.build_opener(NoRedirect())
    run_url = API + f"/repos/{repo}/actions/runs/{run_id}"
    def check_run():
        run = metadata(opener, run_url, token)
        created, _ = validate_run_payload(run, repository=repo, workflow_run_id=run_id,
                                         head_sha=head, run_attempt=attempt)
        require(derive_build_id(created) == expected, "BuildID differs from source run")
        return run
    run = check_run()
    endpoint = API + f"/repos/{repo}/actions/artifacts/{artifact_id}"
    artifact = metadata(opener, endpoint, token)
    size = validate_artifact(artifact, artifact_id=artifact_id, digest=digest, arch=arch,
                             run_id=int(run_id), head=head)
    pin = json.loads(Path(".github/runtime-upstream.json").read_text(encoding="utf-8"))
    output = args.output
    require(not output.exists() and not output.is_symlink(), "Output must be fresh")
    require(shutil.disk_usage(output.parent).free >= 2 * size + 512 * BLOCK,
            "Insufficient free space for verified ZIP and package staging")
    output.mkdir()
    write_json(output / "source-run.json", run)
    write_json(output / "artifact-metadata.json", artifact)
    failures = []
    for index in range(1, ATTEMPTS + 1):
        receipt = {"attempt": index, "expectedZipBytes": size,
                   "expectedZipSha256": digest, "artifactId": artifact_id,
                   "runId": int(run_id), "runAttempt": int(attempt), "head": head,
                   "sha256Kind": "downloaded bytes written to owned attempt ZIP"}
        archive = output / f"attempt-{index}.zip"
        member = output / f"attempt-{index}.tar.gz.partial"
        try:
            check_run()
            stream_zip(opener, endpoint, token, archive, size, digest, receipt)
        except (OSError, http.client.HTTPException, TransferError) as exc:
            receipt.update(success=False, error=type(exc).__name__, retryable=True)
            receipt["retainedZipBytes"] = archive.stat().st_size if archive.exists() else 0
            if isinstance(exc, TransferError):
                receipt["reason"] = str(exc)
            failures.append(receipt)
            remove_owned_attempt(archive, output)
            receipt["partialZipRemoved"] = True
            write_json(output / f"attempt-{index}.json", receipt)
            if index < ATTEMPTS:
                sleeper(2 * index)
            continue
        except ValueError as exc:
            receipt.update(success=False, error=type(exc).__name__, retryable=False)
            if isinstance(exc, AcquisitionError):
                receipt["reason"] = str(exc)
            remove_owned_attempt(archive, output)
            write_json(output / f"attempt-{index}.json", receipt)
            raise
        try:
            package = verify_member(archive, member, arch=arch, head=head, pin=pin)
            check_run()
        except (OSError, ValueError, EOFError, zipfile.BadZipFile, zlib.error) as exc:
            receipt.update(success=False, error=type(exc).__name__, retryable=False)
            if isinstance(exc, AcquisitionError):
                receipt["reason"] = str(exc)
            remove_owned_attempt(member, output)
            remove_owned_attempt(archive, output)
            receipt["attemptFilesRemoved"] = True
            write_json(output / f"attempt-{index}.json", receipt)
            raise AcquisitionError("Authenticated package/source integrity failed") from None
        final = output / package["name"]
        member.rename(final)
        remove_owned_attempt(archive, output)
        receipt.update(success=True, package=package, previousFailures=failures)
        receipt["outerZipRemovedAfterVerification"] = True
        write_json(output / f"attempt-{index}.json", receipt)
        write_json(output / "verified-package.json", receipt)
        print(f"Verified Mac {arch} Stage1 artifact {artifact_id}: ZIP {size} bytes {digest}")
        return final
    raise AcquisitionError("Mac Stage1 artifact acquisition failed; retained attempt receipts")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--expected-build-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    try:
        acquire(parser.parse_args())
    except (ValueError, OSError, KeyError, EOFError, zipfile.BadZipFile,
            http.client.HTTPException, zlib.error) as exc:
        print(f"Mac Stage1 acquisition rejected: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
