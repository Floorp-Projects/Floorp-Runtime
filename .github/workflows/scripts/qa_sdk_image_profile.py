"""Select an immutable SDK archive profile from an observed runner image."""
from pathlib import Path

import qa_sdk_archive_probe as probe
import qa_sdk_exact_profile as exact

CONTEXT = {'ImageOS': 'macos26', 'machine': 'arm64', 'macOSVersion': '26.6.2',
           'pythonVersion': '3.9.6', 'xcodeVersion': '26.6', 'xcodeBuild': '17F113',
           'sdkVersion': '26.5'}
PROFILES = {
    '20261013.0424.1': ('qa-sdk-exact-legacy-image-20261030.json', '660193da5a1dc9b3ae7c52feb234e58881b2dedeea50ea0bdb0648e8d32cbd04'),
    '20261021.0445.8': ('qa-sdk-exact-20261030.json', '184d797d742f64c0beeb65dfe605b881f578a30a0b6b7a017c43cccac5fd2d1b'),
}


def select_profile(context, scripts):
    probe.need(type(context) is dict and set(context) == set(CONTEXT) | {'ImageVersion'}, 'image-context-shape')
    probe.need(all(type(value) is str for value in context.values()), 'image-context-shape')
    probe.need(all(context[key] == value for key, value in CONTEXT.items()), 'image-context')
    image = context['ImageVersion']
    probe.need(image in PROFILES, 'image-not-pinned')
    filename, expected = PROFILES[image]
    profile, actual = exact.load_profile(Path(scripts) / filename)
    probe.need(actual == expected, 'image-profile-sha256')
    return {'contract': 'sdk-image-profile-selection-v1', 'context': dict(context),
            'profileName': filename, 'profileSHA256': actual, 'loaderAdmitted': False}, profile
