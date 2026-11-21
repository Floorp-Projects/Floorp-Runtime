#!/usr/bin/env python3
"""Isolated target-verifier replay; reads authenticated diagnostic tar on stdin.

The input contains private diagnostics. Only fixed boolean results are printed;
neither the tar nor the summary is written to disk. This is an offline replay,
not a new workflow or qualification of the original failed run.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import io

import yaml
import consumer_time
import mozilla_target_build as target
import mozilla_upstream as upstream
import sdk_source


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


WORKFLOW = Path('/runtime/.github/workflows/mac-native-firefox45-nss-binding-20261103.yml')
PATCH = Path('/runtime/docs/qa/mac-native-target-order-20261104.patch')
SOURCE = Path('/work/tools/qa/native-nonpgo')
workflow = yaml.safe_load(WORKFLOW.read_text())
env = workflow['env']
pins = json.loads(env['QA_SOURCE_PINS'])
assert len(pins) == 157
assert all(sha((SOURCE / name).read_bytes()) == expected for name, expected in pins.items())
assert env['FLOORP_FIXTURE_SHA'] == '75fddcf00030d8d48fb707a201cb542aa3e0cf72'
os.environ.update({key: str(env[key]) for key in ('UPSTREAM_PLAN_SHA256', 'SDK_SOURCE_SHA256', 'FLOORP_FIXTURE_SHA')})
os.environ.update(GITHUB_REPOSITORY='Floorp-Projects/Floorp-Runtime', GITHUB_RUN_ID='41630387790',
                  GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='e3689d0afffca9af260ff59278c97cdfc9d72aee')
plan_raw = (SOURCE / 'plan.json').read_bytes()
expected_budget = consumer_time.select_fresh45_time(json.loads(plan_raw), sha(plan_raw), enabled=True)['evidence']
specification = sdk_source.load_sdk_source(SOURCE / 'plan.json', SOURCE / 'sdk_source-20261031.json')
sdk_pin = {key: specification['pin'].get(key) for key in ('artifact', 'run', 'zipSHA256', 'tarSHA256')}
sdk_pin.update({key: specification.get(key) for key in ('producerJob', 'producerRef', 'exactProfile')})

step = next(row for row in workflow['jobs']['fresh-firefox45']['steps']
            if row.get('name', '').startswith('Verify fresh origin'))
source = step['run'].split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]
lines = PATCH.read_text().splitlines()
old = next(line[1:].lstrip() for line in lines if line.startswith('-            required='))
new = next(line[1:].lstrip() for line in lines if line.startswith('+            required='))
assert source.count(old) == 1
assert old.replace('[:2]', '[:3]').replace('[2:]', '[3:]') == new
assert len([line for line in lines if line.startswith('-') and not line.startswith('---')]) == 1
assert len([line for line in lines if line.startswith('+') and not line.startswith('+++')]) == 1

def functions(text):
    tree = ast.parse(text)
    names = {'mapping', 'integer', 'case_ok', 'sdk_ok', 'preflight_ok', 'same_value',
             'time_budget_ok', 'nss_receipt_ok', 'nss_ok', 'final_ok', 'digest_safe',
             'upstream_ok', 'target_ok'}
    selected = [item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name in names]
    assert {item.name for item in selected} == names and len(selected) == len(names)
    constants = {'NSS_STAGES', 'NSS_GRAPH_PINS', 'NSS_FIXTURE_PINS', 'NSS_WRAPPER_PIN'}
    assignments = [item for item in tree.body if isinstance(item, ast.Assign) and
                   len(item.targets) == 1 and isinstance(item.targets[0], ast.Name) and
                   item.targets[0].id in constants]
    assert {item.targets[0].id for item in assignments} == constants and len(assignments) == len(constants)
    ns = {'os': os, 're': re, 'TARGET_STAGES': target.STAGES, 'UPSTREAM_STAGES': upstream.EXTRA_STAGES,
          'EXPECTED_BUDGET': expected_budget, 'SDK_PIN': sdk_pin}
    exec(compile(ast.Module(body=assignments, type_ignores=[]), '<verifier-constants>', 'exec'), ns)
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<verifier-functions>', 'exec'), ns)
    return ns


original = functions(source)
candidate = functions(source.replace(old, new))
target.upstream_api = upstream
raw_archive = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
assert len(raw_archive) <= 16 * 1024 * 1024
archive = tarfile.open(fileobj=io.BytesIO(raw_archive), mode='r:*')
members = archive.getmembers()
assert all(item.isfile() for item in members)
assert len({item.name for item in members}) == len(members)
manifest = json.load(archive.extractfile('manifest.json'))
assert (manifest['binding']['run'], manifest['binding']['attempt'], manifest['job'],
        manifest['binding']['head'], manifest['binding']['fixture']) == (
        41630387790, 1, 125898143523, 'e3689d0afffca9af260ff59278c97cdfc9d72aee',
        env['FLOORP_FIXTURE_SHA'])
record = next(row for row in manifest['files'] if row['name'] == 'summary.json')
raw = archive.extractfile('summary.json').read()
assert record['status'] == 'captured' and (len(raw), sha(raw)) == (record['bytes'], record['sha256'])
assert sha(raw) == '20e774f3a8d0133c459a2393c10316c7b78ebd21730a7762e774373e944b3de9'
summary = json.loads(raw)
rows = summary['stages']

checks = {
    'upstream_proof': candidate['upstream_ok'](summary, upstream),
    'target_graph_assets_and_smoke': target.proof_complete(summary['mozillaTargets'], summary['mozilla'], rows),
    'all_stages_complete': all(target.stage_complete(row) for row in rows),
    'old_order_rejected': not original['target_ok'](summary, target),
    'candidate_target_proof': candidate['target_ok'](summary, target),
    'final_summary_predicate': candidate['final_ok'](summary, target),
}
if not all(checks.values()):
    print(json.dumps({'phase': 'baseline', 'checks': checks, 'native_rerun': False}))
    raise SystemExit(1)

def stage(value, name):
    return next(row for row in value['stages'] if row['stage'] == name)


def mutate(kind):
    value = copy.deepcopy(summary)
    stages = value['stages']
    if kind == 'inventory_after_targets':
        row = stages.pop(next(i for i, row in enumerate(stages) if row['stage'] == 'mozilla-upstream-inventory'))
        stages.insert(next(i for i, row in enumerate(stages) if row['stage'] == 'mozilla-resources-build') + 1, row)
    elif kind == 'target_order':
        a = next(i for i, row in enumerate(stages) if row['stage'] == 'mozilla-shell-build')
        b = next(i for i, row in enumerate(stages) if row['stage'] == 'mozilla-http3-build')
        stages[a], stages[b] = stages[b], stages[a]
    elif kind == 'helper_order':
        a = next(i for i, row in enumerate(stages) if row['stage'] == 'mozilla-upstream-helpers-build')
        b = next(i for i, row in enumerate(stages) if row['stage'] == 'mozilla-upstream-helpers-install')
        stages[a], stages[b] = stages[b], stages[a]
    elif kind == 'duplicate_inventory':
        stages.append(copy.deepcopy(stage(value, 'mozilla-upstream-inventory')))
    elif kind == 'missing_inventory':
        stages.remove(stage(value, 'mozilla-upstream-inventory'))
    elif kind == 'missing_target':
        stages.remove(stage(value, 'mozilla-shell-build'))
    elif kind == 'unknown_cleanup':
        stage(value, 'mozilla-shell-build')['groupCleanup'] = 'unknown'
    elif kind == 'forged_anchor':
        stage(value, 'mozilla-shell-build')['primaryAnchor']['postReapAbsence']['signalAuthority'] = True
    elif kind == 'asset_identity':
        value['mozilla']['builtAssets']['XUL']['sha256'] = '0' * 64
    elif kind == 'graph_binding':
        value['mozillaTargets']['graph']['bindingsStable'] = False
    elif kind == 'inventory_receipt':
        value['mozillaUpstream']['inventoryReceipt']['sha256'] = '0' * 64
    elif kind == 'wrong_plan':
        value['mozillaUpstream']['planSHA256'] = '0' * 64
    elif kind == 'forbidden_stage':
        extra = copy.deepcopy(stage(value, 'mozilla-shell-build'))
        extra['stage'] = 'full-build'
        stages.append(extra)
    elif kind == 'checkpoint_stage':
        extra = copy.deepcopy(stage(value, 'mozilla-shell-build'))
        extra['stage'] = 'checkpoint-forged'
        stages.append(extra)
    else:
        raise AssertionError('unknown mutation')
    return value


names = ('inventory_after_targets', 'target_order', 'helper_order', 'duplicate_inventory',
         'missing_inventory', 'missing_target', 'unknown_cleanup', 'forged_anchor',
         'asset_identity', 'graph_binding', 'inventory_receipt', 'wrong_plan',
         'forbidden_stage', 'checkpoint_stage')
rejected = {name: not candidate['target_ok'](mutate(name), target) for name in names}
def mutate_final(kind):
    value = copy.deepcopy(summary)
    if kind == 'run_identity':
        value['run']['id'] = '0'
    elif kind == 'sdk_identity':
        value['sdk']['zipSHA256'] = '0' * 64
    elif kind == 'preflight_count':
        value['monitorPreflight']['checkpoint-tests']['total'] = 838
    elif kind == 'budget':
        value['executionTimeBudget']['sharedWorkDeadlineMinutes'] = 346
    elif kind == 'nss_assets':
        value['nssRuntime']['loadProbe']['assets']['XUL']['sha256'] = '0' * 64
    elif kind == 'smoke_outcome':
        value['mozilla']['cases'][1]['process']['exitCode'] = 0
    else:
        raise AssertionError('unknown final mutation')
    return value


final_names = ('run_identity', 'sdk_identity', 'preflight_count', 'budget', 'nss_assets', 'smoke_outcome')
final_rejected = {name: not candidate['final_ok'](mutate_final(name), target) for name in final_names}
print(json.dumps({'phase': 'complete', 'checks': checks, 'negative_controls': rejected,
                  'final_negative_controls': final_rejected,
                  'fixture_hashes_verified': len(pins), 'candidate_only': True,
                  'native_rerun': False, 'original_workflow_result': 'failure',
                  'product_qualification': False}, sort_keys=True))
assert all(rejected.values()) and all(final_rejected.values())
