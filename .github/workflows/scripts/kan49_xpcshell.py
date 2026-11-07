import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tomllib


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def summarize_events(events, expected_tests):
    ends = [event for event in events if event.get('action') == 'test_end']
    completed = {str(event.get('test', '')).replace('\\', '/').rsplit('/', 1)[-1]
                 for event in ends if event.get('status') == 'PASS'}
    unexpected = [event for event in events
                  if ('expected' in event and event.get('status') != event['expected'])
                  or event.get('action') == 'crash'
                  or (event.get('action') == 'test_end'
                      and event.get('status') not in ['PASS', 'SKIP'])]
    return {
        'testEnds': ends,
        'missingRunnableTests': sorted(set(expected_tests) - completed),
        'unexpected': unexpected,
        'shutdownTestRan': 'test_shutdown.js' in completed,
    }


def main():
    source = Path.cwd()
    output = Path(os.environ['RUNNER_TEMP']) / 'kan49-xpcshell'
    output.mkdir(exist_ok=False)
    result = {
        'scope': 'Same-build Linux x64 Debug native xpcshell timer manager suite; not signed complete Floorp acceptance',
        'productCodeBase': '4306e75d1c756449367ab2ab92efed004721bd31',
        'regressionTestHead': 'de03dfa95519def19f27ed809c61c91c7d6cdea0',
        'qaHead': os.environ['GITHUB_SHA'],
        'runId': os.environ['GITHUB_RUN_ID'],
        'runAttempt': os.environ['GITHUB_RUN_ATTEMPT'],
        'startedAt': time.time(),
    }
    try:
        binary = source / 'obj-x86_64-pc-linux-gnu/dist/bin'
        names = ['xpcshell', 'libxul.so', 'application.ini', 'platform.ini']
        before = {name: {'size': (binary / name).stat().st_size,
                         'sha256': digest(binary / name)} for name in names}
        result['binaryBefore'] = before
        manifest = source / 'toolkit/components/timermanager/tests/unit/xpcshell.toml'
        declared = tomllib.loads(manifest.read_text())
        assert 'test_shutdown.js' in declared
        result['declaredTests'] = sorted(k for k in declared if k != 'DEFAULT')
        skipped = [name for name in result['declaredTests'] if declared[name].get('run-if') == ['opt']]
        result['debugManifestSkipped'] = skipped
        result['expectedRunnableTests'] = [name for name in result['declaredTests'] if name not in skipped]
        paths = ['toolkit/components/timermanager/tests/unit/xpcshell.toml', 'toolkit/components/timermanager/tests/unit/test_shutdown.js',
                 'toolkit/components/timermanager/UpdateTimerManager.sys.mjs', 'mozconfig']
        result['sourceHashes'] = {name: digest(source / name) for name in paths}
        result['mozconfig'] = (source / 'mozconfig').read_text()
        raw = output / 'raw.jsonl'
        command = ['./mach', 'xpcshell-test', '--sequential', '--log-raw', str(raw), 'toolkit/components/timermanager/tests/unit']
        result['command'] = command
        with (output / 'stdout.log').open('wb') as stdout:
            process = subprocess.Popen(command, stdout=stdout, stderr=subprocess.STDOUT, start_new_session=True)
            result['pid'] = process.pid
            try:
                result['exitCode'] = process.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                result['timedOut'] = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=15)
                result['exitCode'] = process.returncode
        result['binaryAfter'] = {name: {'size': (binary / name).stat().st_size,
                                      'sha256': digest(binary / name)} for name in names}
        result['binariesUnchanged'] = result['binaryBefore'] == result['binaryAfter']
        events = [json.loads(line) for line in raw.read_text().splitlines() if line.strip()] if raw.exists() else []
        result.update(summarize_events(events, result['expectedRunnableTests']))
        result['passed'] = (result['exitCode'] == 0 and bool(result['testEnds'])
                            and result['shutdownTestRan'] and not result['unexpected']
                            and not result['missingRunnableTests']
                            and result['binariesUnchanged'])
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
        result['passed'] = False
    finally:
        result['finishedAt'] = time.time()
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
