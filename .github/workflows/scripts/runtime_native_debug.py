# SPDX-License-Identifier: MPL-2.0
import argparse
import os
import re
from pathlib import Path

REPOSITORY = "Floorp-Projects/Floorp-Runtime"
BRANCH = "nora-0.2.0"
PROFILE = "runtime-native-debug-artifact-v2"
VALIDATION_PROFILE = "runtime-native-debug-validation-v2"
VALIDATION_BRANCH = "codex/debug-native-artifacts-strict"
WORKFLOWS = {".github/workflows/daily-build.yml", ".github/workflows/wrapper-build-linux.yml"}
EXCLUDED_DEBUG_PATCHES = {
    "dom-security-nsContentSecurityManager.patch": "53d6ce8c09a61dc45eb5cebbbd50eb49043a6b7e854a0d1ab8fe7869bd0fbadf",
    "dom-security-nsContentSecurityUtils.patch": "9dc5a92af923a5df56c5aea58a091298e27e0a7eca4037d05b380d2e55476a3b",
    "dom-security-nsCSPService.patch": "e481bd686e82279dfc125a67276dc9fa1095f73666e225193e540d09cd2a5992",
}
ASSERTION_SOURCE_FILES = (
    "dom/security/nsContentSecurityManager.cpp",
    "dom/security/nsContentSecurityUtils.cpp",
    "dom/security/nsCSPService.cpp",
)
PRODUCT_PROFILE = {
    "schema": "floorp-native-debug-strict-profile-v2",
    "target": "x86_64-pc-linux-gnu",
    "role": "canonical-debug",
    "activation": "validation-only-pending-independent-review",
    "assertionPolicy": "security-source-byte-identical-to-runtime-recipe",
    "excludedDebugPatches": EXCLUDED_DEBUG_PATCHES,
    "assertionSourceFiles": list(ASSERTION_SOURCE_FILES),
    "additionalPatches": [],
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


def assertion_source_identity(source, *, working_tree=True):
    import hashlib
    from qa3_hosted import raw_git
    identities = {}
    for relative in ASSERTION_SOURCE_FILES:
        expected = raw_git(source, "cat-file", "blob", "HEAD:" + relative)
        if working_tree:
            path = source / relative
            require(path.is_file() and not path.is_symlink() and path.read_bytes() == expected,
                    "security assertion/enforcement source differs: " + relative)
        identities[relative] = hashlib.sha256(expected).hexdigest()
    return identities


def verify_product_profile(source):
    from qa3_source_cohort import file_digest
    directory = source / ".github/patches/debug"
    require(directory.is_dir() and not directory.is_symlink(), "invalid Debug patch directory")
    patches = {path.name: file_digest(path) for path in directory.glob("*.patch") if path.is_file() and not path.is_symlink()}
    require(patches == EXCLUDED_DEBUG_PATCHES and len(list(directory.glob("*.patch"))) == len(patches),
            "unknown or changed Debug patch policy")
    require(not (source / ".github/patches/native-debug/noraneko-chrome-csp-allowlist.patch").exists(),
            "removed validator allowance is present")
    assertion_source_identity(source)
    return PRODUCT_PROFILE


def strict_setup(source, platform, arch, debug, pgo, mode):
    from qa3_hosted import raw_git, validate_mode
    validate_mode(platform, arch, debug == "true", pgo == "true", mode)
    require(debug == "true" and pgo == "false", "invalid strict build mode")
    require(os.environ.get("RUNTIME_NATIVE_DEBUG_ARTIFACTS") == "true" and
            os.environ.get("RUNTIME_NATIVE_DEBUG_VALIDATION") == "true", "strict profile is validation-only")
    context = context_from_environment(os.environ["MOZ_BUILD_DATE"])
    require(raw_git(source, "rev-parse", "HEAD").decode().strip() == context["runtimeRecipe"], "strict source revision differs before configure")
    verify_product_profile(source)


def prepare(source):
    from qa3_build_profile import profile, verify_config
    strict_setup(source, "linux", "x86_64", "true", "false", "")
    verify_config((source / "mozconfig").read_text(), profile("linux", "x86_64", True, False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["verify", "strict-setup"])
    parser.add_argument("--source", required=True, type=Path)
    for name in ("platform", "arch", "debug", "pgo", "mode"):
        parser.add_argument("--" + name, default="")
    args = parser.parse_args()
    if args.action == "verify": prepare(args.source)
    else: strict_setup(args.source, args.platform, args.arch, args.debug, args.pgo, args.mode)


if __name__ == "__main__":
    main()
