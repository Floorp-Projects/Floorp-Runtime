# Fixed hosted Debug selection expansion

The creation-only campaign uses `codex/qa3-actions-native-proof-qa337-17` at
frozen revision `5416e40007a9605b68f2046690a27507b2253f33`.
The original successful campaign remains bound to its own revision and run in
[the earlier evidence record](hosted-debug-evidence-20261013.md).
Native evidence for this expanded selection must remain bound to that frozen revision.

`hosted-linux-debug-plan.json` selects four required Mozilla cases: hidden-window
existence, mutable arrays, pinned and hidden tabs, and INI parsing. Their minimum
assertion counts are respectively 1, 1, 3 and 100. Required skips, empty output,
missing cases, duplicate phases, retries and recovered first failures fail closed.
The original hidden-window and mutable-array cases each retain one assertion
canary. There is one canary transform per suite. All six executions share one
fixed schedule for execution, raw-result replay and the bounded export allowlist.

Source pins cover the added test bytes, tab manifest and its support files, the
tab head and testing module, and all 33 Linux INI fixtures. The INI case writes
temporary files inside the isolated native state and removes them on success.
The entire support inventory must still match after execution; any remaining
file or modified input fails. The private `linux-proof-plan.json` retains its
two-case selection and does not claim expanded qualification.

## Firefox 158 source compatibility

The current private and hosted plans follow the upstream rename from
`browser/base/content/test/performance` to `browser-performance`. The required
hidden-window test, manifest and head retain identical bytes. Its assertion
floor and the other required cases remain unchanged. Source pins additionally
track the current test-package targets, archive recipe, both Mozilla harnesses
and tab manifest.

The xpcshell adapter still calls the public `runTests` API. A contract executes
the current frozen wrapper and verifies the bound manifest, disabled retry,
ordinary exit mapping and cleanup of its owned temporary directory, including
an original failure. These source contracts do not execute native tests.
The Firefox 157 campaign above remains bound to its frozen revision; it is not
native evidence for the Firefox 158 source or subsequent integration commits.

## Firefox 159 source compatibility

Both proof plans now pin the Firefox 159 harness and selected manifest bytes.
The selected test bodies, manifest entries and defaults, assertion floors,
no-skip requirements and canaries are unchanged. Browser path normalization,
GMP staging, retry control, xpcshell assertion emission, selector identity and
owned temporary-directory cleanup retain their tested AST behavior.

The updated harnesses add assertion/UBSan parsing from same-build packaged
moztest, Android isolated-process options, and profiling and platform fixes.
Legacy reftest make targets were removed; test-package/archive handling remains.
These source-contract updates do not qualify a new native campaign: all native
readiness flags remain unverified, and prior campaign evidence retains its
original revision.

## Original campaign resource limits

The producer remains on a public standard GitHub-hosted Ubuntu runner, whose
compute is free under [GitHub's public repository billing policy](https://docs.github.com/en/actions/concepts/billing-and-usage). The
Blacksmith boundary probe is capped at five minutes and the consumer job at
30 minutes, with a 1500-second native service and 1560-second controller wait.
The remaining job time covers acquisition, teardown, export and diagnostic
upload. Existing memory, process, filesystem and credential isolation remain.
No rerun or automatic retry is permitted.

The campaign reserves at most $1 additional spend within the user's total $10
budget, retaining a separate $2 reserve for unconfirmed costs. The parent
observed a $0.36 month-to-date Blacksmith display; that observation is not an
invoice and does not establish other services' costs. At the [listed Blacksmith rate](https://www.blacksmith.sh/pricing) of $0.016 per
minute, a conservative 39 minutes for the two paid jobs is $0.624 before any
credits. Artifact/cache costs remain separately reserved and retention is one
day. A changed source or later attempt requires a new frozen campaign and review.

This proves only a limited Debug harness route when actual evidence passes.
Final signed product artifacts, other OS/native targets and Floorp product
behavior remain separate QA work. `nativeProductQualification=UNVERIFIED` and
`publicationAuthorized=false` remain mandatory.
