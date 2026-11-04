import gzip
import io
from pathlib import Path
import plistlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import qa_sdk_archive_probe as probe


class ArchiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def archive(self, filename, *, order=('SDKSettings.plist', 'include/a.h'),
                uid=0, content=b'int test;\n', mtime=0, extra=None):
        path = self.root / filename
        with gzip.open(path, 'wb') as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
            for name in order:
                value = plistlib.dumps({'Version': '26.5'}) if name == 'SDKSettings.plist' else content
                member = tarfile.TarInfo('./' + name)
                member.size, member.uid, member.mtime = len(value), uid, mtime
                archive.addfile(member, io.BytesIO(value))
            if extra is not None:
                archive.addfile(extra)
        return path

    def inspect(self, filename='a.gz', **kwargs):
        return probe.inspect_archive(self.archive(filename, **kwargs))

    def test_metadata_change_keeps_content_and_order(self):
        first, second = self.inspect(), self.inspect('b.gz', uid=501, mtime=123)
        self.assertEqual(first['tree'], second['tree'])
        self.assertEqual(first['memberOrderSHA256'], second['memberOrderSHA256'])
        self.assertNotEqual(first['uncompressedTar'], second['uncompressedTar'])
        changed = [key for key in probe.FIELDS if first['headerFieldSHA256'][key] != second['headerFieldSHA256'][key]]
        self.assertEqual(changed, ['uid', 'mtime'])

    def test_order_change_keeps_sorted_metadata_and_content(self):
        first = self.inspect()
        second = self.inspect('b.gz', order=('include/a.h', 'SDKSettings.plist'))
        self.assertEqual(first['tree'], second['tree'])
        self.assertEqual(first['sortedMetadataSHA256'], second['sortedMetadataSHA256'])
        self.assertNotEqual(first['memberOrderSHA256'], second['memberOrderSHA256'])

    def test_file_content_change_is_visible(self):
        first, second = self.inspect(), self.inspect('b.gz', content=b'int different;\n')
        self.assertNotEqual(first['tree']['canonicalSHA256'], second['tree']['canonicalSHA256'])

    def test_exact_diagnostic_never_admits(self):
        first = self.inspect()
        with patch.object(probe, 'ORIGINAL_RAW', first['uncompressedTar']), patch.object(probe, 'ORIGINAL_TREE', first['tree']):
            result = probe.inspect_archive(self.root / 'a.gz')
        self.assertTrue(result['originalRawMatched'] and result['originalTreeMatched'])
        self.assertEqual(result['admission'], 'NOT_ADMITTED')
        self.assertFalse(result['productQualification'])

    def test_duplicate_path_is_rejected(self):
        with self.assertRaisesRegex(probe.ProbeError, '^members$'):
            self.inspect(order=('include/a.h', 'include/a.h'))

    def test_unsafe_path_is_rejected(self):
        with self.assertRaisesRegex(probe.ProbeError, '^member-path$'):
            self.inspect(order=('../a.h',))

    def test_link_outside_root_is_rejected(self):
        member = tarfile.TarInfo('link')
        member.type, member.linkname = tarfile.SYMTYPE, '../escape'
        with self.assertRaisesRegex(probe.ProbeError, '^link-target$'):
            self.inspect(extra=member)

    def test_device_is_rejected(self):
        member = tarfile.TarInfo('device')
        member.type = tarfile.CHRTYPE
        with self.assertRaisesRegex(probe.ProbeError, '^member-type$'):
            self.inspect(extra=member)

    def test_truncated_gzip_footer_is_rejected(self):
        path = self.archive('a.gz')
        path.write_bytes(path.read_bytes()[:-6])
        with self.assertRaises(EOFError):
            probe.inspect_archive(path)

    def test_trailing_bytes_are_included(self):
        path = self.archive('a.gz')
        first = probe.inspect_archive(path)
        with path.open('ab') as output:
            output.write(gzip.compress(b'additional complete gzip member'))
        second = probe.inspect_archive(path)
        self.assertEqual(first['tree'], second['tree'])
        self.assertGreater(second['uncompressedTar']['bytes'], first['uncompressedTar']['bytes'])
        self.assertNotEqual(first['uncompressedTar']['sha256'], second['uncompressedTar']['sha256'])

    def test_symlink_input_is_rejected(self):
        path = self.archive('a.gz')
        link = self.root / 'link.gz'
        link.symlink_to(path)
        with self.assertRaisesRegex(probe.ProbeError, '^archive-file$'):
            probe.inspect_archive(link)

    def test_resource_bounds_are_enforced(self):
        path = self.archive('a.gz')
        for key, maximum, code in [('MAX_ARCHIVE', 1, 'archive-file'), ('MAX_RAW', 1, 'raw-limit'),
                                   ('MAX_MEMBERS', 1, 'members'), ('MAX_SECONDS', -1, 'deadline')]:
            with self.subTest(key=key), patch.object(probe, key, maximum):
                with self.assertRaisesRegex(probe.ProbeError, '^' + code + '$'):
                    probe.inspect_archive(path)


if __name__ == '__main__':
    unittest.main()
