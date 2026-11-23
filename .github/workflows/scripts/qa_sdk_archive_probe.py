"""Bounded SDK archive diagnostics. This never admits an SDK to a build."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import stat
import tarfile
import time

CHUNK = 1024**2
MAX_ARCHIVE = 512 * CHUNK
MAX_RAW = 1024 * CHUNK
MAX_MEMBERS = 100000
MAX_SECONDS = 120
ORIGINAL_RAW = {'bytes': 760518144,
                'sha256': '57aeb200890ba97c382bf450f23f9dab3e0d4696fdf02323a705f82210b087e3'}
ORIGINAL_TREE = {'members': 49701, 'logicalBytes': 704719765,
                 'canonicalSHA256': 'c3c01387c82e9ce1436fd517ec19308416663cc526c39be15f66f6bab22c3a5f'}
FIELDS = ('mode', 'uid', 'gid', 'uname', 'gname', 'mtime', 'type', 'linkname',
          'devmajor', 'devminor', 'pax_headers')
IDENTITY = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size',
            'st_mtime_ns', 'st_ctime_ns')


class ProbeError(Exception):
    pass


def need(value, code):
    if not value:
        raise ProbeError(code)


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'),
                      sort_keys=True, allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(encode(value)).hexdigest()


def budget(deadline):
    need(time.monotonic() < deadline, 'deadline')


def identity(value):
    return tuple(getattr(value, name) for name in IDENTITY)


class RawReader:
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline
        self.count, self.digest = 0, hashlib.sha256()

    def read(self, size):
        need(type(size) is int and 0 <= size <= CHUNK, 'read-bound')
        budget(self.deadline)
        data = self.stream.read(size)
        self.count += len(data)
        need(self.count <= MAX_RAW, 'raw-limit')
        self.digest.update(data)
        budget(self.deadline)
        return data


def inspect_archive(path):
    deadline = time.monotonic() + MAX_SECONDS
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
         and before.st_nlink == 1 and 0 < before.st_size <= MAX_ARCHIVE, 'archive-file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    rows, order, headers, versions, seen, logical = [], [], [], [], set(), 0
    with os.fdopen(descriptor, 'rb') as compressed:
        need(identity(before) == identity(os.fstat(compressed.fileno())), 'archive-changed')

        def fingerprint():
            compressed.seek(0)
            digest, count = hashlib.sha256(), 0
            while block := compressed.read(CHUNK):
                budget(deadline)
                count += len(block)
                need(count <= before.st_size, 'archive-changed')
                digest.update(block)
            need(count == before.st_size, 'archive-changed')
            compressed.seek(0)
            return digest.hexdigest()

        compressed_sha = fingerprint()
        with gzip.GzipFile(fileobj=compressed, mode='rb') as inflated:
            raw = RawReader(inflated, deadline)
            with tarfile.open(fileobj=raw, mode='r|') as archive:
                for member in archive:
                    budget(deadline)
                    name = PurePosixPath(member.name)
                    need(not name.is_absolute() and '..' not in name.parts
                         and '\\' not in member.name and len(member.name.encode()) <= 4096
                         and all(ord(c) >= 32 for c in member.name), 'member-path')
                    normalized = str(name)
                    need(normalized not in seen and len(rows) < MAX_MEMBERS, 'members')
                    seen.add(normalized)
                    need(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'member-type')
                    if member.isfile():
                        logical += member.size
                        need(0 <= member.size <= MAX_RAW and logical <= MAX_RAW, 'logical-limit')
                        content, count, settings = hashlib.sha256(), 0, bytearray()
                        is_settings = name.name == 'SDKSettings.plist'
                        need(not is_settings or member.size <= CHUNK, 'settings-limit')
                        with archive.extractfile(member) as source:
                            while block := source.read(CHUNK):
                                budget(deadline)
                                count += len(block)
                                need(count <= member.size, 'member-size')
                                content.update(block)
                                if is_settings:
                                    settings.extend(block)
                        need(count == member.size, 'member-size')
                        kind, size, value = 'file', member.size, content.hexdigest()
                        if is_settings:
                            data = plistlib.loads(settings)
                            need(type(data) is dict and type(data.get('Version')) is str, 'settings')
                            versions.append(data['Version'])
                    elif member.isdir():
                        kind, size, value = 'dir', 0, ''
                    else:
                        target = PurePosixPath(member.linkname)
                        need(not target.is_absolute() and '\\' not in member.linkname
                             and len(member.linkname.encode()) <= 4096
                             and all(ord(c) >= 32 for c in member.linkname), 'link-target')
                        parts = list(name.parent.parts) if member.issym() else []
                        for part in target.parts:
                            if part == '..':
                                need(bool(parts), 'link-target')
                                parts.pop()
                            elif part != '.':
                                parts.append(part)
                        kind = 'symlink' if member.issym() else 'hardlink'
                        size, value = member.size, hashlib.sha256(member.linkname.encode()).hexdigest()
                    metadata = {key: getattr(member, key) for key in FIELDS}
                    metadata['type'] = member.type.hex()
                    rows.append([normalized, kind, size, value])
                    order.append([normalized, kind])
                    headers.append([normalized, metadata])
            while raw.read(CHUNK):
                pass
        need(identity(before) == identity(os.fstat(compressed.fileno())) == identity(path.lstat()), 'archive-changed')
        need(fingerprint() == compressed_sha, 'archive-changed')
        need(identity(before) == identity(os.fstat(compressed.fileno())) == identity(path.lstat()), 'archive-changed')
    canonical = encode(sorted(rows))
    need(len(canonical) <= 64 * CHUNK, 'canonical-limit')
    tree = {'members': len(rows), 'logicalBytes': logical,
            'canonicalSHA256': hashlib.sha256(canonical).hexdigest()}
    uncompressed = {'bytes': raw.count, 'sha256': raw.digest.hexdigest()}
    sorted_headers = sorted(headers)
    result = {'contract': 'sdk-archive-diagnostic-v1', 'status': 'inspected',
              'admission': 'NOT_ADMITTED', 'productQualification': False,
              'compressed': {'bytes': before.st_size, 'sha256': compressed_sha},
              'uncompressedTar': uncompressed, 'tree': tree, 'sdkVersions': versions,
              'memberOrderSHA256': sha(order), 'sortedMetadataSHA256': sha(sorted_headers),
              'headerFieldSHA256': {key: sha([[name, fields[key]] for name, fields in sorted_headers])
                                    for key in FIELDS},
              'originalRawMatched': uncompressed == ORIGINAL_RAW,
              'originalTreeMatched': tree == ORIGINAL_TREE,
              'sdkVersionMatched': versions == ['26.5']}
    budget(deadline)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = inspect_archive(args.archive)
    except Exception as error:
        report = {'contract': 'sdk-archive-diagnostic-v1', 'status': 'failed',
                  'admission': 'NOT_ADMITTED', 'productQualification': False,
                  'failureCode': str(error) if isinstance(error, ProbeError) else 'archive-read'}
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(encode(report) + b'\n')
    print(encode(report).decode(), flush=True)
    return 0 if report['status'] == 'inspected' else 1


if __name__ == '__main__':
    raise SystemExit(main())
