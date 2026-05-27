#!/usr/bin/env python3
"""Queue worker daemon: pops jobs from Redis list 'job_queue' and executes them by spawning
python_worker.py in the appropriate mode. It republishes PROGRESS lines to Redis pub/sub
channel 'job:{job_id}' and final JSON to 'job:{job_id}:result'.

Run:
  python backend/queue_worker.py

Requires redis server running and backend/requirements.txt installed.
"""
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

import redis

ROOT = Path(__file__).resolve().parents[1]
PY_WORKER = ROOT / 'backend' / 'python_worker.py'

REDIS_URL = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')

r = redis.Redis.from_url(REDIS_URL)

print('Queue worker starting, Redis:', REDIS_URL)

while True:
    try:
        item = r.brpop('job_queue', timeout=5)
        if not item:
            continue
        # brpop returns (list_name, value)
        raw = item[1]
        job = json.loads(raw.decode('utf-8'))
        job_id = job.get('id')
        mode = job.get('mode')
        args = job.get('args', {})
        print('Processing job', job_id, mode, args.get('orig_name') or args.get('domain') or args.get('target'))

        cmd = [sys.executable, str(PY_WORKER), mode]
        if mode == 'metadata':
            cmd.append(args.get('path'))
            cmd.append(args.get('orig_name'))
        elif mode == 'subdomains':
            cmd.append(args.get('domain'))
        elif mode == 'reputation':
            cmd.append(args.get('target'))
        else:
            r.publish(f'job:{job_id}', json.dumps({'type':'error','error':'unknown mode'}))
            continue

        # spawn and stream output
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_buf = b''
        # read stdout line by line
        if proc.stdout is None:
            r.publish(f'job:{job_id}', json.dumps({'type':'error','error':'worker stdout missing'}))
            continue
        for raw_line in proc.stdout:
            try:
                line = raw_line.decode('utf-8').strip()
            except Exception:
                line = ''
            if not line:
                continue
            if line.startswith('PROGRESS:'):
                msg = line.replace('PROGRESS:', '', 1)
                r.publish(f'job:{job_id}', json.dumps({'type':'progress','msg':msg}))
            else:
                out_buf += (raw_line)
        proc.wait(timeout=120)
        stderr = proc.stderr.read().decode('utf-8') if proc.stderr else ''
        if proc.returncode != 0:
            r.publish(f'job:{job_id}', json.dumps({'type':'error','error': stderr or 'worker failed'}))
            continue
        # final JSON output in out_buf
        try:
            final = json.loads(out_buf.decode('utf-8'))
        except Exception as e:
            r.publish(f'job:{job_id}', json.dumps({'type':'error','error': f'invalid output: {e}'}))
            continue
        r.set(f'job:{job_id}:result', json.dumps(final), ex=3600)
        r.publish(f'job:{job_id}', json.dumps({'type':'result','data': final}))

    except Exception as e:
        print('Worker loop error', e)
        time.sleep(1)
*** End Patch