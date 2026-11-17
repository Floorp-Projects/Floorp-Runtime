# Native Debug artifact contract v2: strict validation candidate

This revision is VALIDATION-ONLY pending independent security and functionality
review and a real product proof. It does not activate normal Debug artifacts yet.
Ordinary Debug (including nora-0.2.0), Release, PGO, Windows/macOS, Linux arm64,
existing QA3 proof, publication/FTPS routing and credentials retain prior behavior.
Eventual normal Linux x64 Debug integration requires a separate activation review.

## Why v1 cannot qualify

The superseded candidate added a Noraneko internal-page CSP validator allowlist.
It also inherited three development Debug patches that bypassed assertions or
security enforcement. Neither the prior validation run nor an old v1 artifact
qualifies as strict product evidence. Removing only the added allowlist would not
have restored the pre-patch security source.

The new candidate deletes the added allowlist file and application machinery.
Within the explicit native validation route only, setup-floorp.sh excludes exactly:

- dom-security-nsContentSecurityManager.patch (privileged-load early success)
- dom-security-nsContentSecurityUtils.patch (CSP visitor assertion bypasses)
- dom-security-nsCSPService.patch (HTTP(S) CSP enforcement early success)

The original development patch files remain unchanged for unrelated Debug calls.
Their exact hashes are bound in runtime_native_debug.EXCLUDED_DEBUG_PATCHES. A
missing, changed, symlinked or unknown Debug patch fails the strict policy. No new
allowance, preference shortcut, assertion suppression or expectation override is
introduced.

Before configure and immediately before compile, strict validation checks that:

- the route is Linux x64, Debug, non-PGO, explicit validation-only;
- all three dom/security/nsContentSecurityManager.cpp,
  nsContentSecurityUtils.cpp and nsCSPService.cpp working files are byte-identical
  to their corresponding immutable Runtime recipe Git blobs;
- the recorded mozconfig enables Debug and native tests and contains no PGO mode.

Packaging rechecks those source bytes, plus the existing before/after source delta,
configure state and compiled binary identities. This proves equality to the reviewed
Runtime recipe for these three files; it is not a claim of whole-browser security
or native product functionality. Changes anywhere outside that scope need their own
review. Existing setup/profile regressions cover non-test routes.

## Producer and receipt

The existing common-build compile is reused once, followed by same-OBJDIR
package-tests-common/mochitest/xpcshell. No second product compile is added.
The ZIP still contains runtime.tar.xz, test-support.tar.gz and producer.json.
Producer schema remains qa3-hosted-debug-producer-v1, status PACKAGED_NOT_CONSUMED,
consumerVerdict UNVERIFIED and publicationAuthorized=false.

Validation context profile is runtime-native-debug-validation-v2. The reserved
normal profile runtime-native-debug-artifact-v2 is not enabled by the wrapper.
The productProfile schema is floorp-native-debug-strict-profile-v2, with an exact
excluded-patch map, no additional patches, and explicit validation-only activation.
assertionSourceSha256 records the three original security source hashes.
verify_recipe_metadata compares those hashes to the trusted recipe Git blobs;
validate_producer checks the strict marker and complete hash inventory. Consumers
must reject old profiles, old namespaces and source hash mismatches. A marker alone
is not authentication and never substitutes for independently bound artifact bytes.

Existing support merges full common/mochitest/xpcshell archives and includes
same-build helpers/modules and pinned offline Python inputs. Embedded QA3 plan and
canaries cover only four finite tests, not Floorp P0/P1/P2 qualification. Product UI
assembly and exact native cohort execution remain separate unverified work.

## Nonpublishing proof route (not dispatched for this revision)

Manual wrapper-build-linux.yml on exact candidate branch codex/debug-native-artifacts-strict:

    debug=true
    pgo=false
    arch=x86_64
    native_validation_only=true

Only this branch/manual wrapper route selects strict source policy. Invalid target
or mode fails before build; PGO jobs are excluded. The wrapper has no publication
jobs. No daily or scheduled strict validation is enabled. Namespace:

    native-debug-validation-linux-x86_64-v2-<SHA>-<BuildID>-<run>-<attempt>

All validation artifacts retain for one day. Normal consumers must reject this
validation namespace/profile. No new workflow dispatch, push or merge occurred in
preparing the strict follow-up. The already-running v1 proof is superseded for
qualification, not silently treated as v2.

## Review and access boundaries

First-party consumers need trusted read-only Actions retrieval, pinned repository,
source/run/attempt/artifact ID/name/ZIP digest and strict inner receipt/material
checks. Missing/expired/inaccessible artifacts fail closed, without alternate FTPS
aliases or credentials in PR-controlled code. Source equality and host fixtures do
not prove test/STG/production functionality; activation awaits independent review
of those environments and genuine native results.

Host checks:

    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest test_runtime_native_debug test_qa3_hosted test_qa3_build_profile -v

Run from .github/workflows/scripts. Current WSL result:137 tests pass, including
exact excluded-patch hashes, changed/unknown policy rejection, source byte mutation,
Debug/tests/PGO flag checks, bounded validation routing and preserved original
Release/PGO build-step regressions. No assertion or native-test expectation is
relaxed to obtain these results.
