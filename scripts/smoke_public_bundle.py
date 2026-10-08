#!/usr/bin/env python3
"""Copy only manifested release files into a fresh workspace, then run reproduction."""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reviewer_revision.artifact_paths import artifact_path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); out=a.output.resolve()
    if out.exists(): raise FileExistsError(out)
    out.mkdir(parents=True); clone=out/'clean_bundle'; clone.mkdir()
    for line in (ROOT/'MANIFEST.sha256').read_text().splitlines():
        _, relative=line.split('  ',1)
        source=artifact_path(ROOT,relative); target=artifact_path(clone,relative)
        target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(source,target)
    shutil.copyfile(ROOT/'MANIFEST.sha256',clone/'MANIFEST.sha256')
    commands=[['scripts/verify_manifest.py'],['scripts/verify_portable_runtime.py'],
              ['-m','pytest','tests','-q'],
              ['scripts/run_reviewer_revision.py','--smoke','--output','results/controlled_smoke'],
              ['-m','reviewer_revision.verify','results/controlled_smoke']]
    env=os.environ.copy();env.pop('PYTHONPATH',None)
    started=time.perf_counter(); executions=[]
    for i,command in enumerate(commands):
        print('Running clean bundle:', ' '.join(command),flush=True)
        log=out/f'command_{i+1}.txt'
        with log.open('w',encoding='utf-8') as stream:
            result=subprocess.run([sys.executable,*command],cwd=clone,env=env,stdout=stream,stderr=subprocess.STDOUT)
        executions.append({'command':[sys.executable,*command],'exit_code':result.returncode,'log':log.name})
        if result.returncode:
            print(log.read_text(encoding='utf-8'))
            raise RuntimeError(f'Clean reproduction failed; see {log}')
    expected=['temporal_predictions.csv','policy_predictions.csv','verification_report.json','CHECKSUMS.sha256']
    for name in expected:
        if not (clone/'results/controlled_smoke'/name).is_file(): raise FileNotFoundError(name)
    report={'passed':True,'platform':platform.platform(),'python':platform.python_version(),
            'runtime_seconds':time.perf_counter()-started,'commands':executions,
            'scope':'Fresh manifested files and fresh generated outputs; installed interpreter/dependencies reused. No live OVS execution.'}
    (out/'smoke_report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()
