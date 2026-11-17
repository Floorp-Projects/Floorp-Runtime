# Native Debug artifact contract v1

Only native Linux x64 canonical Debug (debug=true, pgo=false) is enabled.
Windows/macOS, Linux arm64 and ordinary Debug dispatches on other branches retain existing behavior. Release and PGO builds,
FTPS aliases, publication jobs, credentials and workflow permissions are unchanged.

## Producer

The normal Linux wrapper selects the existing common-build QA3 preparation and
same-OBJDIR test packaging. There is one normal compile, followed by the existing
package-tests-common/mochitest/xpcshell targets, not a second product build.
Original source delta, configure state and binary identities are compared before
and after packaging. The normal route does not launch the old four-case cold proof.

Normal context profile: runtime-native-debug-artifact-v1. Allowed source is
Floorp-Projects/Floorp-Runtime, refs/heads/nora-0.2.0, matching controller/source SHA,
manual daily-build or wrapper-build-linux workflow, or scheduled daily-build.
Receipt context keeps schema qa3-hosted-context-v1 and its exact key shape.

Artifact name:

    native-debug-linux-x86_64-v1-<sourceSHA>-<BuildID>-<run>-<attempt>

Retention is 90 days (repository policy may cap it). Artifact ID and ZIP digest
are exposed as reusable workflow outputs. No overwrite or mutable release alias
is used. Expired/missing artifacts must fail closed, never silently rebuild or
substitute a different run.

The artifact ZIP contains exactly runtime.tar.xz, test-support.tar.gz and
producer.json. Producer receipt schema remains qa3-hosted-debug-producer-v1;
status PACKAGED_NOT_CONSUMED, consumerVerdict UNVERIFIED and
publicationAuthorized=false are intentional. These fields never authorize or
certify product publication. Full common/mochitest/xpcshell archive contents are
merged into support, along with same-build helpers/modules and pinned offline
Python material. The embedded QA3 plan covers four finite tests only. Its canary
transforms affect browser-performance and xpcom unit manifests and are recorded;
they do not establish Floorp P0/P1/P2 results. A consumer must independently bind
and resolve its approved selection, product UI resources and manifest inventory.

## Explicit product compatibility component

The separately identified floorp-native-debug-product-profile-v1 carries exactly
the previously reviewed Floorp ea85c9274d6959e87d3bf3bfa9bc0d0c13971ef5 Noraneko
Debug CSP internal-page allowlist patch. Its SHA256 is
1d5c76d89966cefc4e51cd077e20c1a5cd8ca6094bc9ae8ae9635c13b4adba62.
No new URI is added, no assertion is disabled, and the patch is not applied to
Release, PGO, other platforms, or the original QA3 proof route. It is applied before
the normal Debug compile with strict apply-check, then reverse-checked before
recording productProfile. The trusted workflow order and original source/binary
cohort checks bind that receipt. Real Floorp overlay execution remains required;
a successful patch application is not product proof.

## Cross-repository handoff

Use a trusted first-party download job with read-only Actions access. Pin repository,
source SHA, run ID, attempt, artifact ID, artifact name and ZIP SHA256. Independently
check API run branch/event/workflow/conclusion and artifact ownership/expiry/digest,
then safely unpack the exact wrapper and verify inner hashes, producer context,
recipe metadata, productProfile, build identities and support inventory. Existing
qa3_hosted.validate_producer/verify_recipe_metadata/verify_support implement deep
receipt checks; old acquire is proof-specific and must not be repurposed by
bypassing its guards. The consumer must explicitly require the normal profile.

GitHub Actions artifacts require authenticated download; this change adds no
cross-repository credential. If the first-party job token cannot read the producer
artifact, report the access blocker. Do not expose credentials to PR-controlled
code or public forks, use FTPS aliases as fallback, or weaken provenance checks.

## Nonpublishing premerge validation

The existing manual Linux wrapper has no release/FTP publication jobs. One
explicit native_validation_only=true dispatch is supported only on the exact
codex/debug-native-artifacts candidate branch, with debug=true, pgo=false,
arch=x86_64. Invalid target/mode combinations fail before build and PGO jobs are
excluded. No schedule, daily workflow or arbitrary branch can use this route.

Validation profile: runtime-native-debug-validation-v1.
Validation artifact: native-debug-validation-linux-x86_64-v1-<SHA>-<BuildID>-<run>-<attempt>.
Retention: one day, including generic primary/dist-host/application.ini artifacts. Normal consumers must reject this profile and namespace.
Deep receipt validation recognizes it for proof diagnostics, not normal intake.
No workflow dispatch is performed by adding this candidate.

## Host checks

    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .github/workflows/scripts -p test_runtime_native_debug.py -v

Also run test_qa3_hosted and test_qa3_build_profile from that scripts directory.
On Windows WSL Ubuntu, the combined suites pass 133 tests. The exact CSP patch
passes forward/reverse apply-check against the b72ff4d base in an isolated source
snapshot. Host checks are not a substitute for a successful real build and native
consumer run. Existing tests verify unchanged Release/PGO setup behavior and hash
all original build steps after normalizing only opt-in artifact-retention policy.