# Fluent branding regression

`LocalizationCpp.patch` and `localizeFfiLib.patch` replaced text after Fluent
inserted arguments. This changed page titles, filenames and other external data.
`fluent-brand-text.patch` installs a Fluent text-fragment transform instead;
ordinary arguments and select keys retain their exact value. Literal product
branding still applies, including before accented/bidi pseudo-localization.

The host check compiles the actual patched transform functions with Fluent
0.16.0 and fluent-pseudo 0.3.3, matching this Runtime's vendored versions:

```
git apply .github/patches/upstream/fluent-brand-text.patch
python .github/tests/test_fluent_branding.py --source intl/l10n/rust/fluent-ffi/src/bundle.rs
```

The host check covers resolver behavior, not Gecko's FFI. After applying the
maintained patches and rebuilding Runtime, run the registered integration test:

```
./mach xpcshell-test intl/l10n/test/test_floorp_branding.js
```

That test exercises all six sync/async Localization APIs, attributes, missing
values, repeated names, Unicode filenames, terms and select expressions. Also
compare actual `about:processes` tab text with its `data-l10n-args` and the page's
`document.title`. A source-only patch over prebuilt native artifacts cannot
deliver this change; a new native Runtime is required. No release is implied.
