# SPDX-License-Identifier: MPL-2.0
import argparse
from contextlib import ExitStack
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
import time
import urllib.request

FIXTURE = '3c0a7345a47cc94953ceff21a116b9d0f32a8b95'
PARENT = 'd35a4f538b9e2f1942d8ea5749aa47de32cc61f5'
REPOSITORY = 'Floorp-Projects/Floorp-Runtime'
REF = 'refs/heads/b/qa-handoff-20261026'
PROFILE = 'mac-stack-binding-20261103-v1'
CERTIFICATE = '874ad391d20a7ed468eba7a8da6c5c63542650ca4c1378a98e6e978cf8a6b094'
MIB = 1024**2
CATALOG_SIZE = 830
RELATED_MODULES = ('test_nss_runtime', 'test_nss_dynamic_closure', 'test_diagnostic_archive',
                   'test_fresh45', 'test_mozilla_target_build')
RELATED_COUNT = 105
RELATED_IDS_SHA256 = 'e36e6d79240d8d97d16f2ed48f87f4cc931cd85a7b2621b645bb3320338c82fb'
FILES = (
    ('job-origin.json', 64*1024), ('started', 128), ('started-monotonic', 128),
    ('first-failure.json', MIB), ('monitor-preflight.json', 2*MIB),
    ('monitor-preflight-driver.private.log', 8*MIB),
    ('checkpoint-tests.private.log', 16*MIB),
    ('failure-recording-tests.private.log', 2*MIB),
    ('monitor-preflight.private.log', MIB), ('census-abi-compile.private.log', MIB),
)


def require(value, code):
    if not value:
        raise RuntimeError(code)


def binding(env):
    require(env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == REF and
            env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_RUN_ATTEMPT') == '1' and
            env.get('PUSH_CREATED') == 'false' and env.get('PUSH_BEFORE') == PARENT,
            'preflight-origin-scope')
    require(re.fullmatch('[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')) is not None and
            re.fullmatch('[0-9a-f]{40}', env.get('GITHUB_SHA', '')) is not None and
            env.get('FLOORP_FIXTURE_SHA') == FIXTURE, 'preflight-origin-binding')
    return {'repository': REPOSITORY, 'ref': REF, 'run': int(env['GITHUB_RUN_ID']),
            'attempt': 1, 'head': env['GITHUB_SHA'], 'fixture': FIXTURE, 'parent': PARENT}


def initialize(task, helper, env, *, opener=None, wall=time.time, mono=time.monotonic):
    from fresh_job_origin import NoRedirect, _decode
    expected = binding(env)
    token = env.get('JOB_READ_TOKEN')
    require(type(token) is str and 0 < len(token) <= 16384, 'preflight-api-token')
    client = urllib.request.build_opener(NoRedirect) if opener is None else opener
    deadline = mono()+60

    def api(suffix):
        require(mono() < deadline, 'preflight-api-deadline')
        request = urllib.request.Request('https://api.github.com/repos/'+REPOSITORY+'/actions/'+suffix,
            headers={'Authorization': 'Bearer '+token, 'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with client.open(request, timeout=15) as response:
                require(response.status == 200, 'preflight-api-status')
                raw = response.read(2*MIB+1)
        except OSError:
            raise RuntimeError('preflight-api-unavailable') from None
        require(len(raw) <= 2*MIB and mono() < deadline, 'preflight-api-bound')
        return _decode(raw)

    run = api('runs/'+str(expected['run']))
    require(type(run) is dict and type(run.get('id')) is int and run['id'] == expected['run'] and
            run.get('head_sha') == expected['head'] and run.get('head_branch') == REF.removeprefix('refs/heads/') and
            type(run.get('run_attempt')) is int and run['run_attempt'] == 1 and
            run.get('status') == 'in_progress' and run.get('event') == 'push' and
            run.get('path') == '.github/workflows/qa-mac-stack-binding-20261103.yml' and
            run.get('repository', {}).get('id') == 914860957, 'preflight-run-provenance')
    jobs = api('runs/'+str(expected['run'])+'/attempts/1/jobs?per_page=100')
    require(type(jobs) is dict and type(jobs.get('total_count')) is int and jobs['total_count'] == 1 and
            type(jobs.get('jobs')) is list and len(jobs['jobs']) == 1, 'preflight-job-count')
    job = jobs['jobs'][0]
    require(type(job.get('id')) is int and job['id'] > 0 and
            type(job.get('run_id')) is int and job['run_id'] == expected['run'] and type(job.get('run_attempt')) is int and
            job['run_attempt'] == 1 and job.get('head_sha') == expected['head'] and
            job.get('name') == 'preflight-evidence' and job.get('status') == 'in_progress' and
            job.get('labels') == ['macos-15-intel'], 'preflight-job-provenance')
    started = datetime.datetime.fromisoformat(job['started_at'].replace('Z', '+00:00')).timestamp()
    age = wall()-started
    require(-2 <= age < 600, 'preflight-job-age')
    origin = mono()-max(0, age)
    require(origin > 0 and not task.is_symlink(), 'preflight-clock-or-root')
    task.mkdir(mode=0o700, exist_ok=False)
    record = {'contract': PROFILE, **expected, 'job': job['id'], 'jobName': 'preflight-evidence',
              'startedAt': job['started_at'], 'jobMinutes': 20, 'workMinutes': 15,
              'clockResetAllowed': False, 'catalog': CATALOG_SIZE, 'executedCatalog': RELATED_COUNT,
              'relatedIDsSHA256': RELATED_IDS_SHA256, 'sourcePins': 157,
              'sourcePinsSHA256': hashlib.sha256(env['QA_SOURCE_PINS'].encode()).hexdigest(),
              'productQualification': False, 'native42Qualification': False}
    for name, raw in (('job-origin.json', (json.dumps(record, sort_keys=True)+'\n').encode()),
                      ('started', str(started).encode()), ('started-monotonic', str(origin).encode())):
        fd = os.open(task/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    return record


def run_preflight(task, helper, env):
    import unittest
    from support import Runner, clean_environment, require, write_json
    from darwin_activity import probe
    from unittest_receipt import receipt
    from process_census import BINDING_KEYS, prepare_abi, load_abi, snapshot
    plan = json.loads((helper/'plan.json').read_text())
    limits = dict(plan['limits'])
    require(limits['jobMinutes'] == 360, 'preflight-runner-contract')
    runner = Runner(task, float((task/'started').read_text()), limits)
    runner.phase_deadline_minutes = 15
    child_env = clean_environment(task)
    temporary = task/'monitor-tmp'
    temporary.mkdir(mode=0o700)
    child_env.update(TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE='1',
                     PYTHONWARNINGS='error::ResourceWarning')
    child_env['PATH'] += ':/usr/local/bin'
    result = {'status': 'failed', 'qualification': None, 'productQualification': False}
    phase = 'self-probe'
    try:
        own = probe().read(os.getpid(), os.getpgrp())
        require(own['status'] == 'measured' and own['rssMiB'] > 0, 'monitor-native-self-unavailable')
        result['self'] = {key: own[key] for key in ('status', 'rssMiB', 'cpuSeconds', 'state')}
        phase = 'abi'
        abi = prepare_abi(task, runner, child_env)
        os.environ['FLOORP_CENSUS_ABI'] = str(abi)
        child_env.update({key: env[key] for key in (*BINDING_KEYS, 'TASK_ROOT')})
        child_env['FLOORP_CENSUS_ABI'] = str(abi)
        phase = 'identity-snapshot'
        result['census'] = snapshot(load_abi(abi))['measurement']
        catalog = json.loads((helper/'fresh45_preflight_catalog.json').read_text())

        def ids(suite):
            return [name for child in suite for name in ids(child)] if isinstance(suite, unittest.TestSuite) else [suite.id()]

        actual = sorted(ids(unittest.defaultTestLoader.loadTestsFromNames(catalog['modules'])))
        require(actual == catalog['tests'] and len(actual) == len(set(actual)) == CATALOG_SIZE,
                'checkpoint-mac-test-catalog')
        selected = sorted(ids(unittest.defaultTestLoader.loadTestsFromNames(RELATED_MODULES)))
        require(len(selected) == len(set(selected)) == RELATED_COUNT and set(selected) <= set(actual) and
                hashlib.sha256(json.dumps(selected, separators=(',', ':')).encode()).hexdigest() ==
                RELATED_IDS_SHA256, 'checkpoint-selected-test-catalog')
        result.update(fullCatalogSize=CATALOG_SIZE, executedCatalogSize=RELATED_COUNT,
                      relatedIDsSHA256=RELATED_IDS_SHA256)
        suites = [('checkpoint-tests', [sys.executable, '-m', 'unittest', '-v', *RELATED_MODULES], RELATED_COUNT, False),
                  ('failure-recording-tests', [sys.executable, '-m', 'unittest', 'discover', '-v',
                   '-s', str(helper.parents[1]/'app-shim'), '-p', 'test_shim_failure_diagnostics.py'], 14, True)]
        for stage, command, expected, recording in suites:
            phase = stage
            try:
                runner.run(stage, command, helper, child_env, 360, phase_deadline_minutes=15)
            finally:
                result[stage] = receipt(task/(stage+'.private.log'), recording=recording)
            tests = result[stage]
            require(tests['complete'] and tests['status'] == 'passed' and
                    tests['total'] == expected and tests['skipped'] == 0, 'checkpoint-mac-tests')
        phase = 'owned-monitor-control'
        script = "import subprocess; [subprocess.run(['/bin/sh','-c','/bin/sleep 0.1'],check=True) for _ in range(20)]"
        runner.run('monitor-preflight', [sys.executable, '-c', script], task, child_env, 360,
                   phase_deadline_minutes=15)
        require(any(row['stage'] == 'monitor-preflight' and
                    (row['lastActivity'] or {}).get('sampleComplete') is True and
                    (row['lastActivity'] or {}).get('counterSource') == 'libproc-taskallinfo'
                    for row in runner.records), 'monitor-preflight-no-complete-sample')
        result['status'] = 'passed'
    except BaseException as error:
        from qa_core import Failure
        result['failurePhase'] = phase
        result['failureError'] = str(error) if isinstance(error, Failure) else type(error).__name__
        runner.fail('monitor-preflight', 'checkpoint-preflight-failure')
        raise
    finally:
        result.update(stages=runner.records, monitorFailure=runner.monitor_failure,
                      monitorDiagnostics=runner.monitor_diagnostics, firstFailure=runner.failure)
        write_json(task/'monitor-preflight.json', result)


def snapshot(task, env):
    from firefox_target_observer import _FixedRead, decode
    expected = binding(env)
    with ExitStack() as stack:
        reader = _FixedRead(task, stack, time.monotonic()+30)
        root = os.fstat(reader.root)
        require(stat.S_IMODE(root.st_mode) == 0o700, 'preflight-private-root')
        origin_raw, _ = reader.read('job-origin.json', 64*1024)
        require(origin_raw is not None, 'preflight-origin-missing')
        origin = decode(origin_raw)
        require(type(origin) is dict and all(type(origin.get(k)) is type(v) and origin[k] == v
                for k, v in expected.items()) and origin.get('contract') == PROFILE and
                type(origin.get('job')) is int and origin['job'] > 0 and
                origin.get('jobName') == 'preflight-evidence' and
                type(origin.get('jobMinutes')) is int and origin['jobMinutes'] == 20 and
                type(origin.get('workMinutes')) is int and origin['workMinutes'] == 15 and
                origin.get('clockResetAllowed') is False and
                type(origin.get('catalog')) is int and origin['catalog'] == CATALOG_SIZE and
                type(origin.get('executedCatalog')) is int and origin['executedCatalog'] == RELATED_COUNT and
                origin.get('relatedIDsSHA256') == RELATED_IDS_SHA256 and
                origin.get('sourcePinsSHA256') == hashlib.sha256(env['QA_SOURCE_PINS'].encode()).hexdigest(),
                'preflight-origin-mismatch')
        captured, records = {}, []
        for name, cap in FILES:
            raw, record = reader.read(name, cap)
            if raw is not None:
                captured[name] = raw
            records.append({'name': name, 'status': 'captured' if raw is not None else 'unavailable',
                            'reason': record['reason'], 'bytes': record['bytes'], 'sha256': record['sha256']})
        reader.verify()
    require(captured.get('job-origin.json') == origin_raw, 'preflight-origin-changed')
    manifest = {'contract': PROFILE, 'binding': expected, 'job': origin['job'], 'files': records,
                'catalog': CATALOG_SIZE, 'executedCatalog': RELATED_COUNT,
              'relatedIDsSHA256': RELATED_IDS_SHA256, 'sourcePins': 157, 'qualification': None,
                'productQualification': False, 'native42Qualification': False}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in {'manifest.json': (json.dumps(manifest, sort_keys=True)+'\n').encode(), **captured}.items():
            info = tarfile.TarInfo(name)
            info.mode, info.mtime, info.size = 0o600, 0, len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue(), manifest


def encrypt(task, helper, output, env, *, openssl):
    from diagnostic_archive import openssl_run
    from firefox_target_observer import _FixedRead, identity
    require(output.is_absolute() and output.parent.resolve() == output.parent and
            not output.exists() and not output.is_symlink(), 'preflight-output')
    certificate = helper/'diagnostic-recipient-20261029.pem'
    with ExitStack() as stack:
        reader = _FixedRead(helper, stack, time.monotonic()+5)
        certificate_raw, _ = reader.read(certificate.name, 16*1024)
        require(certificate_raw is not None and hashlib.sha256(certificate_raw).hexdigest() == CERTIFICATE,
                'preflight-recipient')
        reader.verify()
    require(re.match(rb'OpenSSL [3-9]\.[0-9]+\.', openssl_run(openssl, ['version'])) is not None,
            'preflight-openssl')
    payload, manifest = snapshot(task, env)
    with tempfile.TemporaryDirectory(prefix='.preflight-recipient-', dir=output.parent) as temporary:
        cert = Path(temporary)/'recipient.pem'
        cert.write_bytes(certificate_raw)
        cert.chmod(0o600)
        ciphertext = openssl_run(openssl, ['cms', '-encrypt', '-binary', '-aes-256-gcm', '-outform', 'DER',
            '-recip', str(cert), '-keyopt', 'rsa_padding_mode:oaep', '-keyopt', 'rsa_oaep_md:sha256',
            '-keyopt', 'rsa_mgf1_md:sha256'], payload=payload)
    require(0 < len(ciphertext) <= 66*MIB and
            b'\x06\x0b*\x86H\x86\xf7\r\x01\t\x10\x01\x17' in ciphertext[:128], 'preflight-ciphertext')
    fd = os.open(output, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w+b') as stream:
        stream.write(ciphertext)
        stream.flush()
        os.fsync(stream.fileno())
        written = identity(os.fstat(stream.fileno()))
        stream.seek(0)
        require(stream.read(len(ciphertext)+1) == ciphertext and
                identity(os.fstat(stream.fileno())) == written == identity(output.lstat()), 'preflight-write')
    return {**manifest, 'status': 'encrypted', 'ciphertextBytes': len(ciphertext),
            'ciphertextSHA256': hashlib.sha256(ciphertext).hexdigest(),
            'recipientSHA256': CERTIFICATE, 'rawContentPublished': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('origin', 'run', 'encrypt'))
    parser.add_argument('--task', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--openssl', type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.helper))
    if args.mode == 'origin':
        initialize(args.task, args.helper, os.environ)
    elif args.mode == 'run':
        run_preflight(args.task, args.helper, os.environ)
    else:
        print(json.dumps(encrypt(args.task, args.helper, args.output, os.environ,
                                 openssl=args.openssl), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
