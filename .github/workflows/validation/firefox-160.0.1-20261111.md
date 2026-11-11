# Firefox 160.0.1 native source validation — 2026-11-11

## Immutable candidate

- Candidate PR: https://github.com/Floorp-Projects/Floorp-Runtime/pull/100
- Candidate commit: `7ddb453558c064f33252d286e5fa75a3a61779d0`
- Upstream version: `160.0.1`
- Upstream commit: `b59ea98ffcd5707003e24c773f7a81eaca13a625`
- Candidate QA3 run: `42956604822` — contracts job passed, 358 tests,
  policy preflight PASS; native qualification remains UNVERIFIED.

## Execution

This documentation-only commit requests the existing `Validate Runtime Source`
push workflow on `codex/runtime-build/firefox-160.0.1-20261111`. The executable
source, patches, proof plans and workflow code are unchanged from the candidate.
Record the actual validation commit SHA and the workflow run/attempt rather than
claiming the run was executed at the parent candidate SHA.

Build optimized, non-PGO Windows x86_64, Linux x86_64, Linux aarch64 and macOS
universal artifacts. Require their existing native artifact verifiers, including
both macOS architectures, to pass. Inspect individual jobs and logs. Preserve
actual BuildID, artifact IDs, digests, provenance and failure diagnostics.

This is validation only: no release publication, no updater distribution, no
production Runtime lock change, no bypass of existing checks, and no reuse of
older native qualification. Successful source builds do not replace PGO/Debug,
macOS behavioral regressions or signed final Floorp package QA. Any subsequent
source fix requires fresh validation of its new immutable revision.
