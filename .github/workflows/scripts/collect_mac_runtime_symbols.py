#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import argparse
import hashlib
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path


def collect(archive, evidence, working_directory):
    identity = json.loads((evidence / 'native-symbol-input.json').read_text())
    working_directory.mkdir(parents=True, exist_ok=False)
    tar_path = working_directory / 'original-dist.tar.gz'
    expected = f'{identity["artifactName"]}.tar.gz'
    with zipfile.ZipFile(archive) as source:
        matches = [entry for entry in source.infolist() if entry.filename == expected]
        if len(matches) != 1:
            raise ValueError('Original dist archive has an unexpected layout')
        with source.open(matches[0]) as stream, tar_path.open('wb') as output:
            while block := stream.read(1024 * 1024):
                output.write(block)

    candidates = []
    inventory = []
    with tarfile.open(tar_path, 'r:gz') as source:
        for member in source:
            if not (member.name.endswith('/bin/XUL') or
                    member.name.endswith('/Contents/MacOS/XUL') or
                    member.name.endswith('/Contents/Resources/DWARF/XUL')):
                continue
            inventory.append({'member': member.name, 'size': member.size,
                              'link': member.linkname, 'regularFile': member.isfile()})
            if not member.isfile():
                continue
            if member.size <= 0 or member.size > 2 * 1024**3 or len(candidates) >= 8:
                raise ValueError('Unexpected native symbol candidate size/count')
            path = working_directory / f'XUL-{len(candidates)}'
            digest = hashlib.sha256()
            with source.extractfile(member) as stream, path.open('wb') as output:
                while block := stream.read(1024 * 1024):
                    output.write(block)
                    digest.update(block)
            result = subprocess.run(['xcrun', 'dwarfdump', '--uuid', str(path)],
                                    capture_output=True, text=True, check=True)
            candidates.append({'path': str(path), 'member': member.name,
                               'sha256': digest.hexdigest(), 'uuidOutput': result.stdout})
    (evidence / 'native-symbol-candidates.json').write_text(json.dumps({
        'input': identity, 'inventory': inventory, 'candidates': candidates,
    }, indent=2) + '\n')

    script = working_directory / 'lookup.py'
    script.write_text('''import json
from pathlib import Path
import lldb

root = Path(''' + repr(str(evidence)) + ''')
crash = json.loads((root / 'lldb-startup.json').read_text())
candidates = json.loads((root / 'native-symbol-candidates.json').read_text())['candidates']
results = []
for candidate in candidates:
    target = lldb.debugger.CreateTarget(candidate['path'])
    for thread in crash.get('threads', []):
        if thread['reason'] not in (lldb.eStopReasonSignal, lldb.eStopReasonException):
            continue
        for index, location in enumerate(thread.get('locations', [])):
            if not location['module'] or not location['module'].endswith('/XUL'):
                continue
            for module_index in range(target.GetNumModules()):
                module = target.GetModuleAtIndex(module_index)
                if module.GetUUIDString() != location['uuid']:
                    continue
                address = target.ResolveFileAddress(int(location['fileAddress'], 16))
                results.append({'frameIndex': index, 'originalFrame': thread['frames'][index],
                                'uuid': location['uuid'], 'fileAddress': location['fileAddress'],
                                'member': candidate['member'], 'symbol': str(address.GetSymbol()),
                                'symbolName': address.GetSymbol().GetName(),
                                'function': str(address.GetFunction()),
                                'lineEntry': str(address.GetLineEntry())})
(root / 'native-symbol-lookup.json').write_text(json.dumps(results, indent=2) + '\\n')
print(json.dumps(results[:25], indent=2))
''')
    command = f'script exec(compile(open({str(script)!r}).read(), {str(script)!r}, "exec"))'
    with (evidence / 'native-symbol-lookup.log').open('w') as output:
        subprocess.run(['xcrun', 'lldb', '--batch', '--no-lldbinit', '--one-line', command],
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    lookup = json.loads((evidence / 'native-symbol-lookup.json').read_text())
    named = sum(bool(item['symbolName']) and
                not item['symbolName'].startswith(('___lldb_unnamed', '__lldb_unnamed'))
                for item in lookup)
    (evidence / 'native-symbol-summary.json').write_text(json.dumps({
        'matchedFrames': len(lookup), 'namedFrames': named,
        'status': 'named-symbols' if named else 'no-named-symbols',
    }, indent=2) + '\n')
    print((evidence / 'native-symbol-candidates.json').read_text())
    print((evidence / 'native-symbol-lookup.log').read_text())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--working-directory', required=True, type=Path)
    args = parser.parse_args()
    collect(args.archive, args.evidence, args.working_directory)
