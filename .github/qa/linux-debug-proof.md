# Limited Linux Debug proof

This recipe implements the QA3-02/03 source producer and a clean, separately
booted test-bundle consumer. It is stacked on Runtime PR #83 and depends on the
source contracts in Floorp PR #2889. The recipe has only a `workflow_call` entry.
It is not connected to daily builds, release approval, signing, notarization or
publication.

The present evidence consists of source/Git fixtures, archive and process
fixtures, mock REST responses, mozlog fixtures, and static workflow checks.
No native build, packaged Mozilla harness, private launcher or offline dependency
environment has been executed or qualified. The original implementation-kit ZIP
has not been materialized; its reported 114 tests remain unverified.

Even a future successful limited consumer receipt keeps
`nativeQualification=UNVERIFIED`, `productArtifactQualification=UNVERIFIED` and
`publicationAuthorized=false`. This Linux x64 Debug proof cannot qualify a
signed production artifact, a PGO build, Linux ARM production-opt, or another OS.

## Pinned subjects and source preparation

The controller must pin the reusable workflow and Runtime checkout by full Git
SHA, together with the plan, both toolchain locks, offline Python environment
inventory and launcher by SHA256. Controller workflow revision W, Runtime recipe
revision R, canonical upstream Git revision U, run ID, attempt and the run-derived
BuildID are distinct subjects. The controller authenticates the real private run
and reusable-workflow references through GitHub REST before native execution.

The builder requires a complete, nonshallow, nonsparse raw Runtime checkout at R
with U in its history. It rejects skip-worktree, missing or changed bytes, Git
filters that hide raw differences, unexpected files and incorrect executable
modes. It independently applies the ordered common patches and branding/URL
transforms, captures baseline B, applies the exact diagnostic patches and checks
final F against an independently replayed transition. Root mozconfig is a
separately hashed generated input. Actual configure output must enable tests and
Debug, use Linux x64 and the pinned compiler, and exclude artifact/PGO modes.

The consumer independently replays every diagnostic patch from authenticated B
preimages and compares the complete expected F, including types and executable
bits. Source-only `.git`, `.hg` and root `mozconfig` exclusions are explicitly
rejected in primary, support and offline dependency inventories. Walk errors and
undeclared mutations fail closed.

## Required private worker boundary

The private controller, workers, launcher and locks are operator prerequisites.
This repository does not create credentials, users, sudo rules, cgroups or private
runner infrastructure. Launch remains No-Go until that boundary is provisioned
and separately reviewed, and a native run is explicitly authorized.

The existing `/var/lib/qa3-tools/bin/launch-native-proof` must be root owned, nonwritable by
controller and native users, and match the caller's SHA256. Its restricted
interface is `builder|consumer RUN ATTEMPT -- FIXED_COMMAND`. Before loading any
worker Python module, it must validate that command and provide:

- A fresh nonroot `qa3-native` UID boundary, credential-free environment and
  exact fresh HOME; no controller tokens, credential files or real user profiles.
- A fresh role/run/attempt cgroup v2 scope, with CPU quotas of 8/4 cores,
  `memory.max` of 28/14 GiB, numeric `pids.max` from 1 through 512, no prior OOM
  events, and permissions preventing the native UID from escaping those bounds.
- Controller-owned, immutable recipe, receipts, tool executables and offline
  wheels. All ancestors must prevent replacement by the native UID. Only the
  fresh native job root is writable.
- Separate ephemeral builder and consumer boots, with no builder source/OBJDIR
  on the consumer. Native execution must have no credential-bearing network
  access; allow the harness's required local connections and display service.
- Bounded termination and removal of the whole scope on failure, cancellation
  and timeout, including children created during cleanup.

The worker checks UID, environment/HOME, readonly inputs, raw R helper bytes,
scope names/limits and boot separation. These checks supplement the prelaunch
owner boundary; unit fixtures do not prove that the external launcher enforces it.

## Resource and dependency prerequisites

Use an 8-core/32-GiB builder with at least 200 GiB SSD and 180 GiB initially free;
after reserving/materializing source, the producer requires 140 GiB free. Use a
4-core/16-GiB consumer with at least 120 GiB SSD and 100 GiB initially free; after
compressed input transfer, it requires 80 GiB free. The builder job limit is
6 hours and the consumer limit is 1 hour. No automatic retry is permitted.

Each compressed artifact is limited to 20 GiB. Decoded archives share a 50-GiB,
200,000-member budget. Producer/consumer staging budgets are 30/50 GiB, retained
diagnostic logs are cumulatively capped at 2 GiB, and free-space reserves are
20/10 GiB. Decode data is budgeted separately from human-readable logs. Manual
extraction rejects traversal, duplicate paths, special files, unsafe links,
encrypted ZIP entries and truncated members. No generic `extractall` is used.

Tool locks bind executable bytes and version stdout. The builder requires Python,
Git, make, zstd, xvfb-run, clang, clang++, rustc, cargo, ld.lld and prlimit; the
consumer requires Python, Git, xvfb-run and prlimit. Git and prlimit must resolve
to the fixed system paths. The offline environment must contain only a fully
pinned, hashed `requirements.lock` and corresponding wheels, within 2 GiB.
Its contents and cold import completeness remain unmeasured prerequisites.

## Bundle, harness and failure evidence

The same Debug OBJDIR produces the primary package plus Mozilla common,
mochitest and xpcshell test archives. The producer preserves the primary bytes,
separately packages support and records source, configure, command order, ELF
GNU IDs, BuildID, source stamp, selected input hashes and support inventory.
Artifact names contain run and attempt. The consumer authenticates both artifact
IDs, origin, digest, expiry and exact wrapper contents; redirect requests never
carry the GitHub token.

The fixed selection contains one browser-chrome case and one xpcshell case,
each requiring execution and positive assertions. A parse-only probe checks the
actual packaged parsers before native launch. Paths explicitly bind the packaged
browser, xpcshell, XRE, utilities, certificates, modules and manifest. The
xpcshell API adapter sets `options.retry=False`, while preserving Mozilla's
ordinary exit mapping and automation behavior.

Each suite also runs one deliberately failing assertion canary. Only its exact
identity/reason, complete mozlog events and exit code 1 count as the expected
negative result. Skip, empty selection, retry exit 4, crash, recovered first
failure, extra test, missing event, truncation, OOM or cleanup failure cannot
produce PASS. Fresh profiles are used, and primary/support inventories are
rechecked after each command. Owned descendants are bounded, signalled and
reaped; pre-existing unrelated children are preserved.

Failures keep `INCOMPLETE` receipts and logs for the original attempt. Evidence
upload uses `always()` and excludes expanded bundles and decoded binary data.
The existing public QA and publication gates retain their independent role.
