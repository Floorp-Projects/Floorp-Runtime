# Validating an upstream Runtime candidate

A successful **Pull Upstream** run establishes source integration and required
patch compatibility. It does not establish that the resulting Runtime builds,
runs, is correctly signed, or is ready to publish.

## Source and contract checks

Record the candidate commit SHA and the upstream commit/version in
`.github/runtime-upstream.json`. Keep the patch inventory, order and SHA-256
checks in `.github/qa/source-policy.json` intact. A changed patch must be reviewed
and have its policy digest updated; never ignore an application failure.

Run **QA3 Runtime contracts (shadow)** on the candidate. Inspect the actual test
and preflight steps and the uploaded `contracts.exit-code`, `contracts.log` and
`preflight.json`, rather than relying only on the workflow's overall status:
this is a shadow job with `continue-on-error`. A preflight PASS is not native
qualification or publication authorization.

## Native source validation without publication

Use **Validate Runtime Source** (`validate-runtime-source.yml`) against the
candidate ref. The workflow supports manual dispatch and pushes under
`codex/runtime-build/**` when its configured source/policy/workflow paths change.
Keep a validation branch bound to the exact candidate SHA and verify that the
run's `head_sha` matches before interpreting its results.

The existing matrix builds optimized, non-PGO Runtime artifacts for Windows
x86_64, Linux x86_64/aarch64 and macOS universal, and verifies the Windows, Linux,
macOS Intel and macOS ARM artifacts on their respective runners. Preserve the
resolved build ID and record each run, attempt, artifact ID and digest.

This workflow does not publish a release. Its success does not replace PGO,
debug, signing, final Floorp package or behavioral regression validation. Keep
those results separate, and do not update a release lock to unrelated or
unverified artifacts. After a candidate change, obtain fresh evidence for the
new SHA rather than reusing qualification from the previous source cohort.
