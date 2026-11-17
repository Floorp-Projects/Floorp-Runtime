# SPDX-License-Identifier: MPL-2.0
import argparse
import os
import re
from pathlib import Path

REPOSITORY = "Floorp-Projects/Floorp-Runtime"
BRANCH = "nora-0.2.0"
PROFILE = "runtime-native-debug-artifact-v1"
VALIDATION_PROFILE = "runtime-native-debug-validation-v1"
VALIDATION_BRANCH = "codex/debug-native-artifacts"
WORKFLOWS = {".github/workflows/daily-build.yml", ".github/workflows/wrapper-build-linux.yml"}
PATCH = ".github/patches/native-debug/noraneko-chrome-csp-allowlist.patch"
PRODUCT_PROFILE = {
    "schema": "floorp-native-debug-product-profile-v1",
    "target": "x86_64-pc-linux-gnu",
    "role": "canonical-debug",
    "sourceRepository": "Floorp-Projects/Floorp",
    "sourceCommit": "ea85c9274d6959e87d3bf3bfa9bc0d0c13971ef5",
    "patches": [{"path": PATCH, "sha256": "1d5c76d89966cefc4e51cd077e20c1a5cd8ca6094bc9ae8ae9635c13b4adba62"}],
    "productTestsExecuted": False,
}


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_context(value):
    require(set(value) == {"schema", "profile", "executionRepository", "controllerHead", "runtimeRecipe", "run", "attempt", "buildID", "publicationAuthorized"}, "invalid native Debug context fields")
    require(value["schema"] == "qa3-hosted-context-v1" and value["profile"] in {PROFILE, VALIDATION_PROFILE} and value["executionRepository"] == REPOSITORY, "foreign native Debug context")
    require(isinstance(value["runtimeRecipe"], str) and re.fullmatch(r"[0-9a-f]{40}", value["runtimeRecipe"]) and value["controllerHead"] == value["runtimeRecipe"], "native Debug source mismatch")
    require(all(type(value[k]) is int and value[k] > 0 for k in ("run", "attempt")), "invalid native Debug run")
    require(isinstance(value["buildID"], str) and re.fullmatch(r"[0-9]{14}", value["buildID"]) and value["publicationAuthorized"] is False, "invalid native Debug identity")
    return value


def context_from_environment(build_id):
    env = os.environ
    sha = env.get("GITHUB_SHA", "")
    validation = env.get("RUNTIME_NATIVE_DEBUG_VALIDATION") == "true"
    ref = "refs/heads/" + (VALIDATION_BRANCH if validation else BRANCH)
    workflow = env.get("GITHUB_WORKFLOW_REF", "")
    require(env.get("GITHUB_REPOSITORY") == REPOSITORY and env.get("GITHUB_REF") == ref and env.get("GITHUB_WORKFLOW_SHA") == sha, "foreign native Debug source/ref")
    workflows = {".github/workflows/wrapper-build-linux.yml"} if validation else WORKFLOWS
    require(workflow in {REPOSITORY + "/" + name + "@" + ref for name in workflows}, "foreign native Debug workflow")
    event = env.get("GITHUB_EVENT_NAME")
    require(event == "workflow_dispatch" or (not validation and event == "schedule" and "/daily-build.yml@" in workflow), "native Debug requires trusted dispatch/schedule")
    require(all(re.fullmatch(r"[1-9][0-9]*", env.get(k, "")) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "invalid native Debug run metadata")
    return validate_context({"schema": "qa3-hosted-context-v1", "profile": VALIDATION_PROFILE if validation else PROFILE, "executionRepository": REPOSITORY, "controllerHead": sha, "runtimeRecipe": sha, "run": int(env["GITHUB_RUN_ID"]), "attempt": int(env["GITHUB_RUN_ATTEMPT"]), "buildID": build_id, "publicationAuthorized": False})


def verify_product_profile(source):
    from qa3_hosted import raw_git
    from qa3_source_cohort import file_digest
    patch = source / PATCH
    require(file_digest(patch) == PRODUCT_PROFILE["patches"][0]["sha256"], "native Debug patch differs")
    raw_git(source, "apply", "--reverse", "--check", str(patch.resolve()))
    return PRODUCT_PROFILE


def prepare(source):
    from qa3_hosted import raw_git
    from qa3_build_profile import profile, verify_config
    from qa3_source_cohort import file_digest
    require(os.environ.get("RUNTIME_NATIVE_DEBUG_ARTIFACTS") == "true", "native Debug profile not selected")
    context_from_environment(os.environ["MOZ_BUILD_DATE"])
    verify_config((source / "mozconfig").read_text(), profile("linux", "x86_64", True, False))
    patch = source / PATCH
    require(file_digest(patch) == PRODUCT_PROFILE["patches"][0]["sha256"], "native Debug patch differs")
    raw_git(source, "apply", "--check", str(patch.resolve()))
    raw_git(source, "apply", str(patch.resolve()))
    verify_product_profile(source)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare"])
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    prepare(args.source)


if __name__ == "__main__":
    main()