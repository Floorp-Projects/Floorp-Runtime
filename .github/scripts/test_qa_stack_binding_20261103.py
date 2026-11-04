# SPDX-License-Identifier: MPL-2.0
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import qa_stack_binding_20261103 as subject


class Response:
    status = 200

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return json.dumps(self.value).encode()[:limit]


class Opener:
    def __init__(self, run, job):
        self.values = [run, {'total_count': 1, 'jobs': [job]}]

    def open(self, request, timeout):
        return Response(self.values.pop(0))


class PreflightEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/scratch')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {'GITHUB_REPOSITORY': subject.REPOSITORY, 'GITHUB_REF': subject.REF,
                    'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ATTEMPT': '1',
                    'PUSH_CREATED': 'false', 'PUSH_BEFORE': subject.PARENT,
                    'GITHUB_RUN_ID': '12345', 'GITHUB_SHA': 'a'*40,
                    'FLOORP_FIXTURE_SHA': subject.FIXTURE, 'QA_SOURCE_PINS': '{}',
                    'JOB_READ_TOKEN': 'synthetic-not-a-credential'}
        self.run = {'id': 12345, 'run_attempt': 1, 'head_sha': 'a'*40,
                    'head_branch': 'b/qa-handoff-20261026', 'event': 'push',
                    'status': 'in_progress', 'repository': {'id': 914860957},
                    'path': '.github/workflows/qa-mac-stack-binding-20261103.yml'}
        self.job = {'id': 67890, 'run_id': 12345, 'run_attempt': 1, 'head_sha': 'a'*40,
                    'name': 'preflight-evidence', 'status': 'in_progress',
                    'labels': ['macos-15-intel'], 'started_at': '1970-01-01T00:16:40Z'}

    def task(self, name='task'):
        path = self.root/name
        record = subject.initialize(path, Path('/work/tools/qa/native-nonpgo'), self.env,
            opener=Opener(self.run, self.job), wall=lambda: 1005, mono=lambda: 500)
        return path, record

    def test_job_clock_and_small_budget_are_bound_to_api(self):
        task, record = self.task()
        self.assertEqual(float((task/'started-monotonic').read_text()), 495)
        self.assertEqual((record['job'], record['jobMinutes'], record['workMinutes']), (67890, 20, 15))
        self.assertFalse(record['clockResetAllowed'])

    def test_origin_cannot_reset_existing_task(self):
        self.task()
        with self.assertRaises(FileExistsError):
            self.task()

    def test_origin_rejects_rerun_other_parent_ref_and_fixture(self):
        for key, value in [('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_REF', 'refs/heads/main'),
            ('PUSH_CREATED', 'true'), ('PUSH_BEFORE', 'b'*40), ('FLOORP_FIXTURE_SHA', 'c'*40),
            ('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_REPOSITORY', 'other/repo'),
            ('GITHUB_RUN_ID', '0'), ('GITHUB_SHA', 'bad')]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                subject.binding({**self.env, key: value})

    def test_origin_rejects_changed_api_run(self):
        for key, value in [('head_sha', 'b'*40), ('run_attempt', 2), ('status', 'completed'),
                           ('head_branch', 'main'), ('repository', {'id': 1}), ('path', 'other.yml')]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                subject.initialize(self.root/key, Path('/work'), self.env,
                    opener=Opener({**self.run, key: value}, self.job), wall=lambda: 1005, mono=lambda: 500)

    def test_origin_rejects_wrong_job_runner_and_attempt(self):
        for key, value in [('head_sha', 'b'*40), ('run_attempt', 2), ('name', 'fresh-firefox45'),
                           ('labels', ['macos-latest']), ('run_id', 1), ('id', True)]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                subject.initialize(self.root/key, Path('/work'), self.env,
                    opener=Opener(self.run, {**self.job, key: value}), wall=lambda: 1005, mono=lambda: 500)

    def test_archive_keeps_failure_log_and_hash_without_publishing_content(self):
        task, _ = self.task()
        content = b'FAIL: synthetic case\nprivate-example-sentinel\n'
        (task/'checkpoint-tests.private.log').write_bytes(content)
        payload, manifest = subject.snapshot(task, self.env)
        self.assertNotIn('private-example-sentinel', json.dumps(manifest))
        self.assertFalse(manifest['native42Qualification'])
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.assertEqual(archive.extractfile('checkpoint-tests.private.log').read(), content)
        row = next(r for r in manifest['files'] if r['name'] == 'checkpoint-tests.private.log')
        self.assertEqual(row['sha256'], hashlib.sha256(content).hexdigest())

    def test_archive_never_collects_unlisted_sdk_or_environment(self):
        task, _ = self.task()
        (task/'sdk.tar').write_bytes(b'synthetic-sdk-must-not-collect')
        with mock.patch.dict(os.environ, {'SYNTHETIC_SECRET_SENTINEL': 'must-not-collect'}):
            payload, manifest = subject.snapshot(task, self.env)
        self.assertNotIn(b'synthetic-sdk-must-not-collect', payload)
        self.assertNotIn(b'SYNTHETIC_SECRET_SENTINEL', payload)
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.assertEqual(set(archive.getnames()), {'manifest.json', 'job-origin.json', 'started', 'started-monotonic'})
        self.assertEqual(len(manifest['files']), 10)

    def test_missing_preflight_logs_remain_explicitly_unavailable(self):
        task, _ = self.task()
        _, manifest = subject.snapshot(task, self.env)
        row = next(r for r in manifest['files'] if r['name'] == 'checkpoint-tests.private.log')
        self.assertEqual((row['status'], row['reason']), ('unavailable', 'missing'))
        self.assertIsNone(manifest['qualification'])

    def test_archive_rejects_changed_origin_or_budget(self):
        task, record = self.task()
        for key, value in [('job', True), ('head', 'b'*40), ('run', 1), ('attempt', 2),
            ('contract', 'other'), ('workMinutes', 345), ('jobMinutes', 360),
            ('clockResetAllowed', True), ('sourcePinsSHA256', '0'*64),
            ('catalog', 824), ('executedCatalog', True), ('relatedIDsSHA256', '0'*64)]:
            with self.subTest(key=key):
                (task/'job-origin.json').write_text(json.dumps({**record, key: value}))
                with self.assertRaises(RuntimeError):
                    subject.snapshot(task, self.env)

    def test_link_fifo_hardlink_and_oversized_logs_are_not_read(self):
        for kind in ('symlink', 'hardlink', 'fifo', 'oversized'):
            with self.subTest(kind=kind):
                task, _ = self.task(kind)
                path = task/'checkpoint-tests.private.log'
                other = self.root/(kind+'-other')
                other.write_bytes(b'must-not-capture')
                if kind == 'symlink':
                    path.symlink_to(other)
                elif kind == 'hardlink':
                    os.link(other, path)
                elif kind == 'fifo':
                    os.mkfifo(path)
                else:
                    with path.open('wb') as stream:
                        stream.truncate(16*subject.MIB+1)
                payload, manifest = subject.snapshot(task, self.env)
                self.assertNotIn(b'must-not-capture', payload)
                row = next(r for r in manifest['files'] if r['name'] == path.name)
                self.assertEqual(row['status'], 'unavailable')

    def test_private_root_permission_is_required(self):
        task, _ = self.task()
        task.chmod(0o755)
        with self.assertRaises(RuntimeError):
            subject.snapshot(task, self.env)

    def test_encryption_authenticates_roundtrip_and_rejects_tampering(self):
        task, _ = self.task()
        (task/'checkpoint-tests.private.log').write_bytes(b'synthetic-private-test-log')
        helper = self.root/'helper'
        helper.mkdir(mode=0o700)
        cert, key = helper/'diagnostic-recipient-20261029.pem', self.root/'test.key'
        created = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', str(key), '-out', str(cert), '-nodes', '-subj', '/CN=synthetic-preflight-test', '-days', '1'],
            capture_output=True, timeout=15, env={'PATH': '/usr/bin:/bin', 'OPENSSL_CONF': '/dev/null'})
        self.assertEqual(created.returncode, 0)
        key.chmod(0o600)
        output = self.root/'encrypted.cms'
        with mock.patch.object(subject, 'CERTIFICATE', hashlib.sha256(cert.read_bytes()).hexdigest()):
            result = subject.encrypt(task, helper, output, self.env, openssl=Path('/usr/bin/openssl'))
        self.assertNotIn(b'synthetic-private-test-log', output.read_bytes())
        self.assertNotIn('synthetic-private-test-log', json.dumps(result))
        command = ['/usr/bin/openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                   '-recip', str(cert), '-inkey', str(key)]
        opened = subprocess.run(command, input=output.read_bytes(), capture_output=True, timeout=10)
        self.assertEqual(opened.returncode, 0)
        with tarfile.open(fileobj=io.BytesIO(opened.stdout)) as archive:
            self.assertEqual(archive.extractfile('checkpoint-tests.private.log').read(), b'synthetic-private-test-log')
        damaged = bytearray(output.read_bytes())
        damaged[-1] ^= 1
        self.assertNotEqual(subprocess.run(command, input=damaged, capture_output=True, timeout=10).returncode, 0)

    def native_boundary(self):
        from contextlib import ExitStack
        import process_census
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch('darwin_activity.probe', return_value=SimpleNamespace(
            read=lambda *args: {'status': 'measured', 'rssMiB': 1, 'cpuSeconds': 0.1, 'state': 'R'})))
        stack.enter_context(mock.patch.object(process_census, 'sys', SimpleNamespace(
            platform='darwin', byteorder='little')))
        stack.enter_context(mock.patch('support.time.monotonic', return_value=500))
        return stack

    def test_consumed_diagnostic_reproduces_real_runner_budget_rejection(self):
        import qa_preflight_evidence_20261102 as consumed
        from qa_core import Failure
        task, _ = self.task()
        self.native_boundary()
        with mock.patch('primary_anchor.PrimaryAnchor.spawn') as spawn:
            with self.assertRaisesRegex(Failure, '^platform-budget-binding$'):
                consumed.run_preflight(task, Path('/work/tools/qa/native-nonpgo'), self.env)
        spawn.assert_not_called()
        self.assertEqual(json.loads((task/'monitor-preflight.json').read_text())['stages'], [])

    def test_corrected_contract_reaches_compile_with_the_api_clock_unchanged(self):
        class CompileBoundary(Exception):
            pass
        task, _ = self.task()
        marker = (task/'started-monotonic').read_bytes()
        self.native_boundary()
        with mock.patch('primary_anchor.PrimaryAnchor.spawn', side_effect=CompileBoundary) as spawn:
            with self.assertRaises(CompileBoundary):
                subject.run_preflight(task, Path('/work/tools/qa/native-nonpgo'), self.env)
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(spawn.call_args.args[0][0], '/usr/bin/cc')
        self.assertEqual((task/'started-monotonic').read_bytes(), marker)
        result = json.loads((task/'monitor-preflight.json').read_text())
        self.assertEqual((result['failurePhase'], result['failureError']), ('abi', 'CompileBoundary'))
        self.assertFalse(result['productQualification'])

    def test_api_anchored_15_minute_work_limit_rejects_before_native_spawn(self):
        from qa_core import Failure
        task, _ = self.task()
        self.native_boundary()
        with mock.patch('support.time.monotonic', return_value=1395), \
             mock.patch('primary_anchor.PrimaryAnchor.spawn') as spawn:
            with self.assertRaisesRegex(Failure, '^phase-deadline-before-launch$'):
                subject.run_preflight(task, Path('/work/tools/qa/native-nonpgo'), self.env)
        spawn.assert_not_called()
        result = json.loads((task/'monitor-preflight.json').read_text())
        self.assertEqual(result['failureError'], 'phase-deadline-before-launch')

    def test_first_failure_survives_work_deadline_exception_and_snapshot(self):
        from qa_core import Failure
        task, _ = self.task()
        first = {'stage': 'checkpoint-tests', 'code': 'synthetic-first-failure', 'elapsedSeconds': 1}
        (task/'first-failure.json').write_text(json.dumps(first))
        self.native_boundary()
        with mock.patch('support.time.monotonic', return_value=1395):
            with self.assertRaises(Failure):
                subject.run_preflight(task, Path('/work/tools/qa/native-nonpgo'), self.env)
        result = json.loads((task/'monitor-preflight.json').read_text())
        self.assertEqual(result['firstFailure'], first)
        payload, manifest = subject.snapshot(task, self.env)
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.assertEqual(json.load(archive.extractfile('first-failure.json')), first)
        self.assertFalse(manifest['native42Qualification'])

    def selected_boundary(self):
        from contextlib import ExitStack
        from process_census import BINDING_KEYS
        task, _ = self.task()
        env = {**self.env, **{key: 'synthetic-binding' for key in BINDING_KEYS},
               'TASK_ROOT': str(task)}
        calls = []
        runner = SimpleNamespace(records=[], failure=None, monitor_failure=None,
                                 monitor_diagnostics=[])
        def run(stage, command, *args, **kwargs):
            calls.append((stage, command, args, kwargs))
            runner.records.append({'stage': stage, 'lastActivity': {
                'sampleComplete': True, 'counterSource': 'libproc-taskallinfo'}})
        runner.run = run
        runner.fail = lambda *args: None
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch('support.Runner', return_value=runner))
        stack.enter_context(mock.patch('darwin_activity.probe', return_value=SimpleNamespace(
            read=lambda *args: {'status': 'measured', 'rssMiB': 1, 'cpuSeconds': 0.1, 'state': 'R'})))
        stack.enter_context(mock.patch('process_census.prepare_abi', return_value=task/'abi.json'))
        stack.enter_context(mock.patch('process_census.load_abi', return_value=None))
        stack.enter_context(mock.patch('process_census.snapshot', return_value={'measurement': {}}))
        stack.enter_context(mock.patch('unittest_receipt.receipt', side_effect=[
            {'complete': True, 'status': 'passed', 'total': 105, 'skipped': 0},
            {'complete': True, 'status': 'passed', 'total': 14, 'skipped': 0}]))
        return task, env, calls

    def test_only_exact_related_ids_and_recording_controls_are_selected(self):
        task, env, calls = self.selected_boundary()
        subject.run_preflight(task, Path('/work/tools/qa/native-nonpgo'), env)
        self.assertEqual([call[0] for call in calls],
                         ['checkpoint-tests', 'failure-recording-tests', 'monitor-preflight'])
        self.assertEqual(tuple(calls[0][1][4:]), subject.RELATED_MODULES)
        self.assertTrue(all(call[2][-1] == 360 and call[3]['phase_deadline_minutes'] == 15
                            for call in calls))
        result = json.loads((task/'monitor-preflight.json').read_text())
        self.assertEqual((result['fullCatalogSize'], result['executedCatalogSize']), (830, 105))
        self.assertEqual(result['status'], 'passed')
        self.assertFalse(result['productQualification'])

    def test_selected_id_substitution_stops_before_test_spawn(self):
        from qa_core import Failure
        task, env, calls = self.selected_boundary()
        with mock.patch.object(subject, 'RELATED_IDS_SHA256', '0'*64):
            with self.assertRaisesRegex(Failure, '^checkpoint-selected-test-catalog$'):
                subject.run_preflight(task, Path('/work/tools/qa/native-nonpgo'), env)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
