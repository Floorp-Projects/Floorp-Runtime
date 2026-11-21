#!/usr/bin/env python3
"""Run the existing failure-projection controls against the isolated candidate."""
from pathlib import Path

import yaml

workflow_path = Path('/runtime/.github/workflows/mac-native-firefox45-nss-binding-20261103.yml')
patch_path = Path('/runtime/docs/qa/mac-native-target-order-20261104.patch')
candidate_dir = Path('/evidence/target-order-20261104')
control_path = Path('/evidence/nss-binding-resume-20261103/public-controls.py')
workflow = yaml.safe_load(workflow_path.read_text())
step = next(row for row in workflow['jobs']['fresh-firefox45']['steps']
            if row.get('name', '').startswith('Verify fresh origin'))
projection = step['run'].split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]
lines = patch_path.read_text().splitlines()
old = next(line[1:].lstrip() for line in lines if line.startswith('-            required='))
new = next(line[1:].lstrip() for line in lines if line.startswith('+            required='))
assert projection.count(old) == 1
(candidate_dir / 'public-projection.py').write_text(projection.replace(old, new))

controls = control_path.read_text()
needle = "assert projection==Path('/evidence/nss-binding-resume-20261103/public-projection.py').read_text()+'\\n'"
assert controls.count(needle) == 1
controls = controls.replace(needle, "projection=projection.replace(" + repr(old) + "," + repr(new) + ")\n" + needle)
assert controls.count('/evidence/nss-binding-resume-20261103/') > 0
controls = controls.replace('/evidence/nss-binding-resume-20261103/', '/evidence/target-order-20261104/')
controls = controls.replace('/scratch/public-projection-nss-binding-839', '/scratch/public-projection-target-order-20261104')
exec(compile(controls, str(control_path), 'exec'), {'__name__': '__candidate_controls__'})
