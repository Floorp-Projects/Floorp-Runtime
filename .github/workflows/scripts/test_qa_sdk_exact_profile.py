import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import plistlib
import tarfile
import tempfile
import unittest

import qa_sdk_archive_probe as probe
import qa_sdk_exact_profile as exact


class ExactSDKProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.make_archive('baseline.gz')
        self.report = probe.inspect_archive(self.archive)
        self.profile = {'contract': exact.CONTRACT, 'xcode': dict(exact.XCODE), 'containerEncoding': exact.ENCODING,
                        'archive': {key: copy.deepcopy(self.report[key]) for key in exact.ARCHIVE_KEYS}}
        self.profile_sha = hashlib.sha256(probe.encode(self.profile)).hexdigest()

    def make_archive(self, filename, *, mtime=1, reverse=False, content=b'int test;\n'):
        path = self.root / filename
        values = [('SDKSettings.plist', plistlib.dumps({'Version': '26.5'})), ('include/a.h', content)]
        with path.open('wb') as output, gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name, data in reversed(values) if reverse else values:
                    member = tarfile.TarInfo('./' + name)
                    member.size, member.mtime = len(data), mtime
                    archive.addfile(member, io.BytesIO(data))
        return path

    def check(self, report=None, profile=None):
        return exact.check_report(report or self.report, profile or self.profile, self.profile_sha)

    def test_exact_match_still_requires_api_reconciliation(self):
        result = self.check()
        self.assertEqual(result['status'], 'exact-match')
        self.assertEqual(result['admission'], 'PENDING_API_RECONCILIATION')
        self.assertFalse(result['loaderAdmitted'] or result['productQualification'] or result['freshFirefox45Executed'])

    def test_each_archive_identity_is_required(self):
        for key in exact.ARCHIVE_KEYS:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report)
                report[key] = None
                result = self.check(report)
                self.assertEqual(result['status'], 'rejected')
                self.assertEqual(result['mismatches'], [key])

    def test_every_header_field_is_compared(self):
        for key in probe.FIELDS:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report)
                report['headerFieldSHA256'][key] = '0' * 64
                self.assertEqual(self.check(report)['status'], 'rejected')

    def test_content_change_is_rejected(self):
        changed = probe.inspect_archive(self.make_archive('changed.gz', content=b'int changed;\n'))
        self.assertEqual(self.check(changed)['status'], 'rejected')
        self.assertIn('tree', self.check(changed)['mismatches'])

    def test_timestamp_change_is_rejected(self):
        changed = probe.inspect_archive(self.make_archive('changed.gz', mtime=2.5))
        self.assertEqual(self.report['tree'], changed['tree'])
        self.assertIn('uncompressedTar', self.check(changed)['mismatches'])
        self.assertIn('headerFieldSHA256', self.check(changed)['mismatches'])

    def test_reordering_is_rejected(self):
        changed = probe.inspect_archive(self.make_archive('changed.gz', reverse=True))
        self.assertEqual(self.report['tree'], changed['tree'])
        self.assertIn('memberOrderSHA256', self.check(changed)['mismatches'])

    def test_gzip_only_change_is_rejected(self):
        changed = self.make_archive('other-name.gz')
        data = changed.read_bytes()
        changed.write_bytes(data[:4] + (2).to_bytes(4, 'little') + data[8:])
        report = probe.inspect_archive(changed)
        self.assertEqual(self.report['uncompressedTar'], report['uncompressedTar'])
        self.assertIn('compressed', self.check(report)['mismatches'])

    def test_boolean_counts_are_rejected(self):
        for key in ('compressed', 'uncompressedTar', 'tree'):
            with self.subTest(key=key):
                profile = copy.deepcopy(self.profile)
                profile['archive'][key]['members' if key == 'tree' else 'bytes'] = True
                with self.assertRaises(probe.ProbeError):
                    self.check(profile=profile)

    def test_wrong_xcode_and_sdk_are_rejected(self):
        for key in exact.XCODE:
            with self.subTest(key=key):
                profile = copy.deepcopy(self.profile)
                profile['xcode'][key] = 'other'
                with self.assertRaisesRegex(probe.ProbeError, '^profile-version$'):
                    self.check(profile=profile)

    def test_missing_extra_and_foreign_contract_are_rejected(self):
        for mode in ('missing', 'extra', 'foreign'):
            with self.subTest(mode=mode):
                profile = copy.deepcopy(self.profile)
                if mode == 'missing':
                    del profile['archive']['memberOrderSHA256']
                elif mode == 'extra':
                    profile['archive']['allowTimestampDifference'] = True
                else:
                    profile['contract'] = 'sdk-exact-archive-profile-v1'
                with self.assertRaises(probe.ProbeError):
                    self.check(profile=profile)

    def test_bad_digest_is_rejected(self):
        profile = copy.deepcopy(self.profile)
        profile['archive']['compressed']['sha256'] = 'not-a-hash'
        with self.assertRaisesRegex(probe.ProbeError, '^profile-archive$'):
            self.check(profile=profile)

    def test_failed_or_admitted_diagnostic_is_rejected(self):
        for key, value in [('status', 'failed'), ('admission', 'ADMITTED'), ('productQualification', 0)]:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report)
                report[key] = value
                with self.assertRaisesRegex(probe.ProbeError, '^archive-report$'):
                    self.check(report)

    def test_duplicate_json_is_rejected(self):
        path = self.root / 'profile.json'
        path.write_text('{"contract": "a", "contract": "b"}')
        with self.assertRaisesRegex(probe.ProbeError, '^profile-json$'):
            exact.load_profile(path)

    def test_symlink_and_oversized_profile_are_rejected(self):
        path = self.root / 'profile.json'
        path.write_text(json.dumps(self.profile))
        link = self.root / 'link.json'
        link.symlink_to(path)
        with self.assertRaisesRegex(probe.ProbeError, '^profile-file$'):
            exact.load_profile(link)
        path.write_bytes(b' ' * 16385)
        with self.assertRaisesRegex(probe.ProbeError, '^profile-file$'):
            exact.load_profile(path)

    def test_profile_fd_and_bytes_are_bound(self):
        path = self.root / 'profile.json'
        path.write_bytes(probe.encode(self.profile))
        value, checksum = exact.load_profile(path)
        self.assertEqual(value, self.profile)
        self.assertEqual(checksum, self.profile_sha)

    def test_container_normalization_changes_only_outer_timestamp(self):
        data = self.archive.read_bytes()
        source = self.root / 'original.gz'
        source.write_bytes(bytes.fromhex('1f8b08001b62e36a0003') + data[10:])
        target = self.root / 'normalized.gz'
        result = exact.normalize_container(source, target)
        self.assertEqual(target.read_bytes(), exact.GZIP_HEADER + data[10:])
        self.assertEqual(result['originalCompressed']['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(probe.inspect_archive(source)['uncompressedTar'], probe.inspect_archive(target)['uncompressedTar'])

    def test_container_extensions_and_symlinks_are_rejected(self):
        source = self.root / 'original.gz'
        data = self.archive.read_bytes()
        source.write_bytes(bytes.fromhex('1f8b0804000000000003') + data[10:])
        with self.assertRaisesRegex(probe.ProbeError, '^container-header$'):
            exact.normalize_container(source, self.root / 'target.gz')
        link = self.root / 'link.gz'
        link.symlink_to(source)
        with self.assertRaisesRegex(probe.ProbeError, '^container-file$'):
            exact.normalize_container(link, self.root / 'target.gz')

    def test_normalization_refuses_existing_output(self):
        source = self.root / 'original.gz'
        source.write_bytes(exact.GZIP_HEADER + self.archive.read_bytes()[10:])
        output = self.root / 'existing.gz'
        output.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            exact.normalize_container(source, output)
        self.assertEqual(output.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
