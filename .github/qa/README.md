# QA3 Runtime foundation and limited Debug proof

The foundation implements QA3-01 configuration and source/profdata contracts.
The shadow workflow checks those contracts without native execution. The
separate hosted campaign now has one successful Linux x64 Debug producer and
cold-consumer run at an immutable code revision; see the
[2026-10-13 evidence record](hosted-debug-evidence-20261013.md).
Its result is `PASS_DEBUG_HARNESS_ONLY`, with
`nativeProductQualification=UNVERIFIED` and `publicationAuthorized=false`.
Production qualification and the publisher remain separate work.
The [fixed hosted selection expansion](hosted-debug-expansion.md) describes the
next limited campaign; its native verification remains pending at this revision.

## Canonical Debug and existing profiles

`setup-floorp.sh` now explicitly enables tests only when `debug=true,pgo=false`.
The helper removes the active `--disable-tests` from the selected template and
adds exactly one `--enable-tests`; this covers both Mac templates. PGO
generate/use, Linux ARM production-opt and legacy Debug+PGO retain their
existing tests flags. Existing diagnostic patches and the Mac sandbox override
remain declared differences; this is not strict identical final source or
production security qualification.

The five-target tests execute the real setup script in temporary workspaces with
package manager/bootstrap commands stubbed. They inspect generated target,
debug/tests/profiling/LTO/profdata flags and invalid combinations. They prove
generation only. The recorded Linux x64 campaign additionally verifies effective
Debug/tests/native configuration, same-OBJDIR support generation and two Mozilla
harness cases with assertion canaries. Other OS configurations, SDK behavior,
PGO builds and final product artifacts are not qualified by that run.

## Common source and variant contracts

`source-policy.json` pins all 28 common patches and the three Debug diagnostic
patches in UTF-8 path order. The current 28-patch source cohort includes the
macOS helper trust requirement patch and is distinct from the earlier 27-patch
cohort. Previously recorded native evidence remains bound to its original
immutable revision and does not qualify this new cohort; native product
qualification remains UNVERIFIED and publication is not authorized.
Policy preflight checks complete membership, order,
bytes and expected Runtime HEAD. It records the upstream canonical Git
repository and full revision separately from Runtime R. It does not prove that
patches were applied or that the resulting source was compiled.

The verifier requires U `{vcs,repository,fullRevision}`, R, ordered P, common
transforms and nonempty B with a versioned inventory scope. A trusted producer
must prepare the common patches **and** branding/update URL transformations
before capturing B, then derive the exact approved diagnostic expectation and
capture final F before configure. The private full-native recipe describes that
ordered preparation. The hosted campaign uses the existing common-build path
and records its declared source delta, compiled-source metadata and effective
configuration before and after test packaging. Those receipts do not complete
the reusable Debug/PGO source-qualification model in QA3-08. Existing legacy
metadata is not silently upgraded.

The inventory covers regular bytes, executable mode and symlink targets,
including untracked/ignored consumed inputs. Only root `.git`, `.hg` and the
separately recorded `mozconfig` are excluded. Keep OBJDIR, profile files and QA
output outside the checkout. Symlinks must resolve to inventoried inputs inside
the tree; external, missing and excluded targets are rejected. An empty
diagnostic delta requires `F == B`. Source additions/changes outside the exact
patch expectation fail. The diagnostic helper computes expected patch results in
a temporary workspace; a changed path allowlist is insufficient.

`verify_upstream_ancestor` must establish the actual canonical Git ingestion
relation and expected checkout before accepting producer evidence; absent
history/objects is unverified. `same_cohort` compares all U/R/P/transforms/B,
while `verify_build_subject` additionally matches the trusted expected role,
target, D/F, config/toolchain/artifact and producer run/attempt, and checks
final source bytes. Supply trusted expectations, not candidate
self-declarations. Authentication/issuance is QA3-08; these functions alone do
not attest a build.

PGO verification binds actual profdata/jarlog bytes, workload, generating
subject/artifact/run/attempt, same cohort, target, toolchain and final source.
Stage configs may differ and have separate digests. Wrong or missing profile
evidence is rejected. Linux ARM remains production-opt with no invented PGO
producer. Source-preserving repack/recovery must retain the original compile
subject and record the new packager separately.

## Shadow evidence, observed hosted run and remaining validation

The standalone shadow workflow runs only contract tests and policy preflight on
a sparse checkout containing `.github`, the pinned Mozilla harness files and
their Python dependencies. Preflight deliberately emits `B/F=null`, upstream
ingestion/native qualification **UNVERIFIED**, official Firefox match
`unverified/advisory`, and `publicationAuthorized=false`. Its nonblocking result
cannot replace existing native/build/source/packaging gates. Contract-test exit
codes/logs and failed preflight receipts are preserved even on failure. A
preflight object cannot satisfy the required common baseline schema.

The complete host contract suite requires Linux process supervision support.
Run the same command as shadow CI from the repository root on Ubuntu 24.04:

```sh
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=python/mozbuild:python/mozboot:testing/mozbase/mozfile:third_party/python/packaging:third_party/python/six \
python3 -B - <<'PY'
import sys
import unittest
suite = unittest.defaultTestLoader.discover(
    '.github/workflows/scripts', pattern='test_qa3_*.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() and result.testsRun > 0
         and not result.skipped else 1)
PY
python3 -B .github/workflows/scripts/qa3_source_cohort.py \
  --expected-runtime FULL_GIT_SHA --output /tmp/new-qa3-preflight.json
```

The [limited hosted proof](linux-debug-proof.md) records the first Linux x64
Debug build, separate test-support and cold harness execution. Its normal
browser-chrome case has one assertion and its xpcshell case has 49; each suite
also rejects one deliberately failing assertion canary. This is a fixed subset,
not broad Firefox coverage or Floorp overlay qualification.

Before promotion, use one pinned U/R/common preparation for Debug, PGO generate,
profile workload, PGO use and Linux ARM opt. Extend the verified subset and
separately demonstrate empty/skip/crash/OOM and cleanup failures on live workers,
then all five native targets and their final product artifacts. Verify each Mac
slice and universal transform. Do not add support files to the existing primary
archive or infer host-helper architecture. Record actual source snapshots,
toolchain/profile provenance and run/attempt edges without extending closed v2.

Official Firefox artifact URL/hash/platform/locale/format and internal source
stamp need independent proof. The observed official Linux artifact uses a
Mercurial namespace whereas the pin uses canonical Git; their mapping is still
unverified. Version/tag and equal-looking revision strings do not establish it.
The official match is advisory in this phase. The earlier Library transfer
failure is retained in the review history. The original kit's 114 host tests and
the repaired kit's 130 host tests are recorded in the
[separate kit review](https://github.com/Floorp-Projects/Floorp/blob/c6df42ba68074ea47b70be55980b426020a2641f/docs/qa/kit-v0.3.0-review-fixes/README.md).
Those counts are separate from the hosted run's 104 contracts and four native
cases, and do not establish production qualification.
