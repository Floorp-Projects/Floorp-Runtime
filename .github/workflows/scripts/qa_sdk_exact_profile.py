"""Check a complete SDK archive against an explicitly versioned exact profile."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import qa_sdk_archive_probe as probe

CONTRACT = 'sdk-exact-archive-profile-v2'
REPORT_CONTRACT = 'sdk-exact-producer-check-v2'
ARCHIVE_KEYS = frozenset(('compressed', 'uncompressedTar', 'tree', 'sdkVersions',
                          'memberOrderSHA256', 'sortedMetadataSHA256', 'headerFieldSHA256'))
XCODE = {'version': '26.6', 'build': '17F113', 'sdkVersion': '26.5'}
ENCODING = 'gzip-header-mtime-zero-v1'
GZIP_HEADER = bytes.fromhex('1f8b0800000000000003')


def same(value, expected):
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return set(value) == set(expected) and all(same(value[key], item) for key, item in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(same(a, b) for a, b in zip(value, expected))
    return value == expected


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _pairs(values):
    result = {}
    for key, value in values:
        probe.need(key not in result, 'profile-json')
        result[key] = value
    return result


def _constant(value):
    raise probe.ProbeError('profile-json')


def validate_profile(value):
    probe.need(type(value) is dict and set(value) == {'contract', 'xcode', 'archive', 'containerEncoding'}, 'profile-shape')
    probe.need(value['contract'] == CONTRACT and same(value['xcode'], XCODE)
               and value['containerEncoding'] == ENCODING, 'profile-version')
    archive = value['archive']
    probe.need(type(archive) is dict and set(archive) == ARCHIVE_KEYS, 'profile-shape')
    for key, maximum in [('compressed', probe.MAX_ARCHIVE), ('uncompressedTar', probe.MAX_RAW)]:
        part = archive[key]
        probe.need(type(part) is dict and set(part) == {'bytes', 'sha256'}
                   and type(part['bytes']) is int and 0 < part['bytes'] <= maximum
                   and digest(part['sha256']), 'profile-archive')
    tree = archive['tree']
    probe.need(type(tree) is dict and set(tree) == {'members', 'logicalBytes', 'canonicalSHA256'}
               and type(tree['members']) is int and 0 < tree['members'] <= probe.MAX_MEMBERS
               and type(tree['logicalBytes']) is int and 0 < tree['logicalBytes'] <= probe.MAX_RAW
               and digest(tree['canonicalSHA256']), 'profile-tree')
    probe.need(same(archive['sdkVersions'], ['26.5']), 'profile-sdk-version')
    probe.need(digest(archive['memberOrderSHA256']) and digest(archive['sortedMetadataSHA256']), 'profile-metadata')
    headers = archive['headerFieldSHA256']
    probe.need(type(headers) is dict and set(headers) == set(probe.FIELDS)
               and all(digest(item) for item in headers.values()), 'profile-metadata')
    return value


def load_profile(path):
    path = Path(path)
    before = path.lstat()
    probe.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
               and before.st_nlink == 1 and 0 < before.st_size <= 16384, 'profile-file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        probe.need(probe.identity(before) == probe.identity(os.fstat(stream.fileno())), 'profile-changed')
        raw = stream.read(16385)
        probe.need(len(raw) == before.st_size, 'profile-changed')
        probe.need(probe.identity(before) == probe.identity(os.fstat(stream.fileno()))
                   == probe.identity(path.lstat()), 'profile-changed')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
    return validate_profile(value), hashlib.sha256(raw).hexdigest()


def check_report(report, profile, profile_sha):
    validate_profile(profile)
    probe.need(digest(profile_sha), 'profile-sha256')
    probe.need(type(report) is dict and report.get('contract') == 'sdk-archive-diagnostic-v1'
               and report.get('status') == 'inspected' and report.get('admission') == 'NOT_ADMITTED'
               and report.get('productQualification') is False, 'archive-report')
    probe.need(ARCHIVE_KEYS <= set(report), 'archive-report')
    actual = {key: copy.deepcopy(report[key]) for key in sorted(ARCHIVE_KEYS)}
    mismatches = sorted(key for key in ARCHIVE_KEYS if not same(actual[key], profile['archive'][key]))
    return {'contract': REPORT_CONTRACT, 'status': 'rejected' if mismatches else 'exact-match',
            'admission': 'PENDING_API_RECONCILIATION', 'loaderAdmitted': False,
            'productQualification': False, 'freshFirefox45Executed': False,
            'profileSHA256': profile_sha, 'xcode': copy.deepcopy(profile['xcode']),
            'mismatches': mismatches, 'archive': actual}


def normalize_container(path, output):
    path, output = Path(path), Path(output)
    before = path.lstat()
    deadline = probe.time.monotonic() + probe.MAX_SECONDS
    probe.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
               and before.st_nlink == 1 and 10 < before.st_size <= probe.MAX_ARCHIVE, 'container-file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        probe.need(probe.identity(before) == probe.identity(os.fstat(source.fileno())), 'container-changed')
        header = source.read(10)
        probe.need(len(header) == 10 and header[:4] + b'\0' * 4 + header[8:] == GZIP_HEADER, 'container-header')
        destination = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        checksum, count = hashlib.sha256(header), 10
        with os.fdopen(destination, 'wb') as target:
            target.write(GZIP_HEADER)
            while block := source.read(probe.CHUNK):
                probe.budget(deadline)
                count += len(block)
                probe.need(count <= before.st_size, 'container-changed')
                checksum.update(block)
                target.write(block)
        probe.need(count == before.st_size and probe.identity(before) == probe.identity(os.fstat(source.fileno()))
                   == probe.identity(path.lstat()), 'container-changed')
        source.seek(0)
        second = hashlib.sha256()
        while block := source.read(probe.CHUNK):
            probe.budget(deadline)
            second.update(block)
        probe.need(second.hexdigest() == checksum.hexdigest()
                   and probe.identity(before) == probe.identity(os.fstat(source.fileno()))
                   == probe.identity(path.lstat()), 'container-changed')
    return {'encoding': ENCODING, 'originalCompressed': {'bytes': count, 'sha256': checksum.hexdigest()}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--normalized-output', required=True, type=Path)
    args = parser.parse_args()
    try:
        profile, profile_sha = load_profile(args.profile)
        container = normalize_container(args.archive, args.normalized_output)
        result = check_report(probe.inspect_archive(args.normalized_output), profile, profile_sha)
        result['container'] = container
    except Exception as error:
        result = {'contract': REPORT_CONTRACT, 'status': 'failed',
                  'admission': 'PENDING_API_RECONCILIATION', 'loaderAdmitted': False,
                  'productQualification': False, 'freshFirefox45Executed': False,
                  'failureCode': str(error) if isinstance(error, probe.ProbeError) else 'profile-or-archive-read'}
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(probe.encode(result) + b'\n')
    print(probe.encode(result).decode(), flush=True)
    return 0 if result['status'] == 'exact-match' else 1


if __name__ == '__main__':
    raise SystemExit(main())
