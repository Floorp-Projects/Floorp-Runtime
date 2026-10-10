# QA3 Runtime shadow foundation

This implements the QA3-01 configuration and source/profdata contracts for
review. It does not package test-support, run a Mozilla harness, compile a
native binary, issue qualification or change the publisher.

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
generation only. Effective configure, SDK/toolchain behavior, support files and
Mozilla harness execution remain **UNVERIFIED** until native CI is authorized.

## Common source and variant contracts

`source-policy.json` pins all 27 common patches and the three Debug diagnostic
patches in UTF-8 path order. Policy preflight checks complete membership, order,
bytes and expected Runtime HEAD. It records the upstream canonical Git
repository and full revision separately from Runtime R. It does not prove that
patches were applied or that the resulting source was compiled.

The verifier requires U `{vcs,repository,fullRevision}`, R, ordered P, common
transforms and nonempty B with a versioned inventory scope. A trusted producer
must prepare the common patches **and** branding/update URL transformations
before capturing B, then derive the exact approved diagnostic expectation and
capture final F before configure. Current setup applies Debug patches before
those common transforms; moving that boundary and connecting real producer
records is QA3-02 work. Existing legacy metadata is not silently upgraded.

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

## Shadow evidence and native validation plan

The standalone shadow workflow runs only contract tests and policy preflight on
a `.github` checkout. Preflight deliberately emits `B/F=null`, upstream
ingestion/native qualification **UNVERIFIED**, official Firefox match
`unverified/advisory`, and `publicationAuthorized=false`. Its nonblocking result
cannot replace existing native/build/source/packaging gates. Contract-test exit
codes/logs and failed preflight receipts are preserved even on failure. A
preflight object cannot satisfy the required common baseline schema.

```sh
python3 -B -m unittest discover -s .github/workflows/scripts -p 'test_qa3_*.py' -v
python3 -B .github/workflows/scripts/qa3_source_cohort.py \
  --expected-runtime FULL_GIT_SHA --output /tmp/new-qa3-preflight.json
```

Before promotion, use one pinned U/R/common preparation for Debug, PGO generate,
profile workload, PGO use and Linux ARM opt. Prove effective configure on Linux
x64 first, separately generated test-support with native helpers and Mozilla
FAIL/empty/skip/crash canaries, then all five native targets. Verify each Mac
slice and universal transform. Do not add support files to the existing primary
archive or infer host-helper architecture. Record actual source snapshots,
toolchain/profile provenance and run/attempt edges without extending closed v2.

Official Firefox artifact URL/hash/platform/locale/format and internal source
stamp need independent proof. The observed official Linux artifact uses a
Mercurial namespace whereas the pin uses canonical Git; their mapping is still
unverified. Version/tag and equal-looking revision strings do not establish it.
The official match is advisory in this phase. The implementation kit and its 114
tests remain unavailable after supported Library transfer returned HTTP 403,
including the new attachment. This code is an independent implementation.
