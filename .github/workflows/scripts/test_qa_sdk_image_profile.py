import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import qa_sdk_archive_probe as probe
import qa_sdk_exact_profile as exact
import qa_sdk_image_profile as image


class SDKImageProfileTests(unittest.TestCase):
    def setUp(self):
        self.scripts = Path(__file__).parent
        self.context = {**image.CONTEXT, 'ImageVersion': '20261013.0424.1'}

    def select(self, context=None, scripts=None):
        return image.select_profile(self.context if context is None else context,
                                    self.scripts if scripts is None else scripts)

    def test_both_known_images_bind_distinct_complete_profiles(self):
        profiles = []
        for version in image.PROFILES:
            selection, profile = self.select({**self.context, 'ImageVersion': version})
            self.assertEqual(selection['profileSHA256'], image.PROFILES[version][1])
            self.assertEqual(selection['context']['ImageVersion'], version)
            self.assertFalse(selection['loaderAdmitted'])
            profiles.append(profile)
        self.assertEqual(profiles[0]['archive']['tree'], profiles[1]['archive']['tree'])
        self.assertNotEqual(profiles[0]['archive']['uncompressedTar'], profiles[1]['archive']['uncompressedTar'])

    def test_unknown_image_is_rejected_before_archive_or_profile_read(self):
        with patch.object(exact, 'load_profile') as load:
            with self.assertRaisesRegex(probe.ProbeError, '^image-not-pinned$'):
                self.select({**self.context, 'ImageVersion': 'unknown'})
            load.assert_not_called()

    def test_each_environment_field_is_required(self):
        for key in image.CONTEXT:
            with self.subTest(key=key):
                with self.assertRaisesRegex(probe.ProbeError, '^image-context$'):
                    self.select({**self.context, key: 'other'})

    def test_partial_extra_and_non_string_contexts_are_rejected(self):
        for mode in ('missing', 'extra', 'bool', 'none', 'not-dict'):
            with self.subTest(mode=mode):
                context = dict(self.context)
                if mode == 'missing':
                    del context['ImageOS']
                elif mode == 'extra':
                    context['allowFallback'] = 'yes'
                elif mode == 'bool':
                    context['ImageVersion'] = True
                elif mode == 'none':
                    context['ImageVersion'] = None
                else:
                    context = []
                with self.assertRaisesRegex(probe.ProbeError, '^image-context-shape$'):
                    self.select(context)

    def test_semantically_identical_profile_with_other_bytes_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            filename = image.PROFILES[self.context['ImageVersion']][0]
            original = self.scripts / filename
            (Path(folder) / filename).write_bytes(original.read_bytes() + b'\n')
            with self.assertRaisesRegex(probe.ProbeError, '^image-profile-sha256$'):
                self.select(scripts=folder)

    def test_other_image_profile_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as folder:
            filename = image.PROFILES[self.context['ImageVersion']][0]
            other = image.PROFILES['20261021.0445.8'][0]
            (Path(folder) / filename).write_bytes((self.scripts / other).read_bytes())
            with self.assertRaisesRegex(probe.ProbeError, '^image-profile-sha256$'):
                self.select(scripts=folder)

    def test_profile_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            filename = image.PROFILES[self.context['ImageVersion']][0]
            (Path(folder) / filename).symlink_to(self.scripts / filename)
            with self.assertRaisesRegex(probe.ProbeError, '^profile-file$'):
                self.select(scripts=folder)

    def test_matching_and_other_image_archives_are_distinguished(self):
        selected, profile = self.select()
        other, _ = exact.load_profile(self.scripts / image.PROFILES['20261021.0445.8'][0])
        report = {'contract': 'sdk-archive-diagnostic-v1', 'status': 'inspected',
                  'admission': 'NOT_ADMITTED', 'productQualification': False, **profile['archive']}
        self.assertEqual(exact.check_report(report, profile, selected['profileSHA256'])['status'], 'exact-match')
        report.update(other['archive'])
        self.assertEqual(exact.check_report(report, profile, selected['profileSHA256'])['status'], 'rejected')

    def test_mixed_identity_and_timestamp_are_rejected(self):
        selected, profile = self.select()
        other, _ = exact.load_profile(self.scripts / image.PROFILES['20261021.0445.8'][0])
        for key in ('uncompressedTar', 'headerFieldSHA256', 'compressed', 'sortedMetadataSHA256'):
            with self.subTest(key=key):
                report = {'contract': 'sdk-archive-diagnostic-v1', 'status': 'inspected',
                          'admission': 'NOT_ADMITTED', 'productQualification': False,
                          **copy.deepcopy(profile['archive'])}
                report[key] = other['archive'][key]
                self.assertEqual(exact.check_report(report, profile, selected['profileSHA256'])['mismatches'], [key])


if __name__ == '__main__':
    unittest.main()
