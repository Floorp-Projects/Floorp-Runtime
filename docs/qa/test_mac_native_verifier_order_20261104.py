import ast
import hashlib
import json
from pathlib import Path

import yaml

root = Path('/runtime')
qa = Path('/work/tools/qa/native-nonpgo')
old_path = root / '.github/workflows/mac-native-firefox45-nss-binding-20261103.yml'
new_path = root / '.github/workflows/mac-native-firefox45-verifier-order-20261104.yml'
old = yaml.safe_load(old_path.read_text())
new = yaml.safe_load(new_path.read_text())
old_pins = json.loads(old['env']['QA_SOURCE_PINS'])
new_pins = json.loads(new['env']['QA_SOURCE_PINS'])
assert old_pins.keys() == new_pins.keys() and len(new_pins) == 157
assert all(hashlib.sha256((qa / n).read_bytes()).hexdigest() == h for n, h in new_pins.items())
changed = {name for name in old_pins if old_pins[name] != new_pins[name]}
assert changed == {'fresh_job_origin.py', 'diagnostic_archive.py', 'test_fresh_job_origin.py',
                   'test_diagnostic_archive.py', 'fresh45_preflight_catalog.json'}

def projection(workflow):
    step = next(s for s in workflow['jobs']['fresh-firefox45']['steps']
                if s.get('name', '').startswith('Verify fresh origin'))
    return step['run'].split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]

old_code, new_code = projection(old), projection(new)
old_required = "required=('configure','effective-config','fresh45-exports',*UPSTREAM_STAGES[:2],*TARGET_STAGES,*UPSTREAM_STAGES[2:])"
new_required = old_required.replace('[:2]', '[:3]').replace('[2:]', '[3:]')
assert old_code.count(old_required) == new_code.count(new_required) == 1

def functions(code):
    return {n.name: ast.dump(n) for n in ast.parse(code).body if isinstance(n, ast.FunctionDef)}

expected = old_code.replace(old_required, new_required).replace("('checkpoint-tests',839)", "('checkpoint-tests',848)")
expected = expected.replace('nss-binding-job-origin-20261103', 'verifier-order-job-origin-20261104')
expected = expected.replace('nss-binding-20261103', 'verifier-order-20261104')
assert functions(expected) == functions(new_code)
assert old['env']['SDK_SOURCE_SHA256'] == new['env']['SDK_SOURCE_SHA256']
for name in ('HARNESS_SHA', 'RUNTIME_SHA', 'PIPELINE_SHA256', 'TARGET_HELPER_SHA256',
             'UPSTREAM_HELPER_SHA256', 'UPSTREAM_PLAN_SHA256', 'FRESH_HELPER_SHA256',
             'DIAGNOSTIC_RECIPIENT_SHA256'):
    assert old['env'][name] == new['env'][name]
assert new['env']['LOCAL_CANDIDATE_QUALIFICATION'] == 'VERIFIER_ORDER_INITIAL_NATIVE_DIAGNOSTIC_ONLY'
assert new['on'] == {'push': {'branches': ['b/qa-fresh45-verifier-order-20261104']}}
assert old['permissions'] == new['permissions'] == {'contents': 'read', 'actions': 'read'}
assert old['concurrency'] == new['concurrency']
assert old['jobs'].keys() == new['jobs'].keys() == {'fresh-firefox45'}
old_job, new_job = old['jobs']['fresh-firefox45'], new['jobs']['fresh-firefox45']
assert {k: v for k, v in old_job.items() if k != 'steps'} == {k: v for k, v in new_job.items() if k != 'steps'}
assert len(old_job['steps']) == len(new_job['steps'])
for a, b in zip(old_job['steps'], new_job['steps']):
    expected = json.dumps(a, sort_keys=True).replace('nss-binding-20261103', 'verifier-order-20261104')
    expected = expected.replace('nss-binding-origin-20261103', 'verifier-order-origin-20261104')
    expected = expected.replace('nss-binding-job-origin-20261103', 'verifier-order-job-origin-20261104')
    expected = expected.replace('fresh45-nss-binding-', 'fresh45-verifier-order-')
    expected = expected.replace(',839,False)', ',848,False)').replace("('checkpoint-tests',839)", "('checkpoint-tests',848)")
    expected = expected.replace(old_required, new_required)
    assert json.loads(expected) == b, b.get('name')
result = {'contract': 'strict-new-verifier-workflow-comparison-v1',
          'allOtherPredicateASTsUnchanged': True, 'strictOrderCandidateWired': True,
          'onlyFiveSourcePinsChanged': sorted(changed), 'unmodifiedSourcePins': 152,
          'SDKCompileAndHarnessIdentitiesUnchanged': True,
          'allWorkflowStepsMatchAllowedOriginOrderAndCatalogChanges': True,
          'historicalWorkflowUnchanged': True, 'nativeExecuted': False, 'productQualification': False}
Path('/evidence/verifier-order-freeze-20261104/strict-workflow-comparison.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
