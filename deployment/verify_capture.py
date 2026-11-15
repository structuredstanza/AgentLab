#!/usr/bin/env python3
"""Prove live guest capture without borrowing a credential and without changing policy.

Tier 2 of the authorized-verification design: the live guest only. The producer is
POST /api/tools/custom/test, which mints a short-lived session for the test run and
injects that run's proxy environment into the script it executes. Nothing here reads
a proxy credential, stages one in a file, or calls a policy or certificate endpoint.

Default run: the script requests a loopback origin. The gateway refuses loopback for
a research session, so the check asserts that refusal is recorded with the gateway
policy stage and a 403, and that the request leg is in the guest packet capture.

--task-id N: the operator names a task whose rules already authorize the fixture
origin (http://127.0.0.1:8790). The check then proves an allowed round trip. A
refusal there is reported as blocked, never verified.

An allowed live-guest round trip to a synthetic origin cannot be proven without an
operator-authorized task. That is a consequence of the policy model, not a defect.

Exit codes: 0 verified, 1 failed, 2 prerequisite missing.
"""
import argparse
import base64
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import select
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
TIER = 'tier 2: live guest'

# The fixture origin. A --task-id run needs the operator's task rules to authorize
# exactly this address and port; the default run never reaches it, because the
# gateway refuses loopback before it dials.
FIXTURE_PORT = 8790
FIXTURE_ORIGIN = 'http://127.0.0.1:%d' % FIXTURE_PORT

# The gateway names the stage of a refusal in this header, and the recorder copies
# it into the stored response head. netpolicy.StagePolicy.
STAGE_HEADER = 'X-M1nervac0nsole-Gateway'
POLICY_STAGE = 'policy'

# Runs inside the test run's own session, so it carries that run's proxy
# environment and nothing else. The credential stays in the environment: it is
# never put on a command line, so it cannot reach argv, an export or the report.
PRODUCER = '''
import base64, http.client, json, os, sys, urllib.parse
params = json.load(sys.stdin)
proxy = next((os.environ[n] for n in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY',
                                     'http_proxy', 'ALL_PROXY', 'all_proxy')
              if os.environ.get(n)), '')
parts = urllib.parse.urlsplit(proxy)
if not parts.hostname or not parts.username:
    raise SystemExit('the run carries no proxy credential, so nothing was sent')
conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=30)
conn.request('GET', 'http://127.0.0.1:%d/%s' % (int(params['port']), params['nonce']),
             headers={'Proxy-Authorization': 'Basic ' + base64.b64encode(
                 (parts.username + ':').encode()).decode()})
response = conn.getresponse()
print(json.dumps({'status': response.status,
                  'stage': response.getheader('X-M1nervac0nsole-Gateway'),
                  'body': response.read().decode('utf-8', 'replace')}))
'''

# The producer is a recorded API call, not a host command, so the host-event
# stdout/stderr correlation needs a command of its own. This one carries no proxy
# environment and makes no request.
MARKER = ("import sys; print('AGENTLAB_CAPTURE_SMOKE:' + sys.argv[1]); "
          "print('AGENTLAB_STDERR_SMOKE:' + sys.argv[1], file=sys.stderr)")

# The fixture origin for a --task-id run. It has to live in the guest root: the
# gateway dials origins from there, while a tool runs in its own network namespace.
ORIGIN = '''
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
body = b'AGENTLAB_CAPTURE_SMOKE\\n'
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), Handler)
print('ready', flush=True)
server.serve_forever()
'''


class Failed(Exception):
    """A check that ran and did not hold."""


def need(condition, message):
    if not condition:
        raise Failed(message)


def text(value):
    return value.decode('utf-8', 'replace') if isinstance(value, bytes) else value


def stop(report, code, result, detail):
    report['result'] = result
    report['detail'] = detail
    return code, report


def http_detail(err):
    try:
        raw = err.read()
    except (AttributeError, OSError):
        return str(err)
    return raw.decode('utf-8', 'replace')[:400]


class Lab:
    """The host side of the check: console API, guest commands and export.

    Imported lazily so the module can be exercised without a deployment.
    """
    root = ROOT

    def __init__(self):
        loader = importlib.machinery.SourceFileLoader('agentlab', str(ROOT / 'lab'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.module = importlib.util.module_from_spec(spec)
        loader.exec_module(self.module)
        self.name = self.module.NAME

    def login(self):
        return self.module.login()

    def api(self, path, data=None, token=None):
        return self.module.api(path, data, token=token)

    def guest(self, argv, stream=False):
        if stream:
            # Listing exits after the TOC; streaming the whole archive causes an msb stdin EPIPE.
            return subprocess.run([str(self.module.MSB), 'exec', '--stream', '--no-stdin',
                                   self.name, '--', *argv], capture_output=True, check=False)
        return subprocess.run([str(ROOT / 'lab'), 'exec', '--', *argv], capture_output=True, check=False)

    def export(self):
        result = subprocess.run([str(ROOT / 'lab'), 'export'], capture_output=True, text=True, check=False)
        need(result.returncode == 0, 'lab export failed: ' + result.stderr.strip()[-400:])
        return json.loads(result.stdout)

    def spawn(self, argv):
        return subprocess.Popen([str(ROOT / 'lab'), 'exec', '--', *argv],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)


def stop_origin(proc):
    proc.kill()
    proc.wait()
    proc.stdout.close()


def start_origin(transport):
    """Start the guest-root fixture origin and wait until it is listening."""
    proc = transport.spawn(['python3', '-c', ORIGIN, str(FIXTURE_PORT)])
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], 0.25)
            if ready:
                line = proc.stdout.readline()
                if not line:
                    break
                if 'ready' in line:
                    return proc
            elif proc.poll() is not None:
                break
    except BaseException:
        stop_origin(proc)
        raise
    stop_origin(proc)
    raise Failed('the fixture origin did not start on %s' % FIXTURE_ORIGIN)


def nonce_frames(captures, port, nonce):
    """Count the decoded frames carrying the nonce on the recorder port."""
    packets = 0
    for capture in captures.rglob('*.pcap*'):
        if not capture.is_file() or capture.is_symlink():
            continue
        decoded = subprocess.run(['tshark', '-r', str(capture), '-d', 'tcp.port==%d,http' % port,
            '-Y', 'frame contains "' + nonce + '"', '-T', 'fields', '-e', 'frame.number'],
            check=False, capture_output=True, text=True)
        # An online snapshot may end on a partial last packet; only decoded matching frames count.
        packets += len(decoded.stdout.splitlines())
    return packets


def check_export(transport, nonce, expected_status, task_id, recorder_port):
    """The export assertions: hashes, PostgreSQL backup, index, host events, capture."""
    root = transport.root
    exported = transport.export()
    output = Path(exported['export'])
    manifest = json.loads((output / 'manifest.json').read_text())
    for relative, expected in manifest['sha256'].items():
        with (output / relative).open('rb') as stream:
            need(hashlib.file_digest(stream, 'sha256').hexdigest() == expected,
                 'export hash mismatch: ' + relative)
    with tempfile.TemporaryDirectory(prefix='.verify-export-', dir=root / 'state') as staged:
        staged = Path(staged)
        (staged / 'postgres.dump').hardlink_to(output / 'raw/postgres.dump')
        listed = transport.guest(['pg_restore', '-l', '/state/' + staged.name + '/postgres.dump'],
                                 stream=True)
    need(b'TABLE DATA public llm_records' in listed.stdout,
         'the exported PostgreSQL backup has no llm_records table')
    with contextlib.closing(sqlite3.connect(output / 'raw/application/traffic/_index/index.sqlite')) as db:
        need(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok',
             'the exported traffic index is corrupt')
        rows = db.execute('SELECT id FROM exchanges WHERE url LIKE ?', ('%' + nonce + '%',)).fetchall()
        need(len(rows) == 1, 'the export holds %d exchanges for the fixture nonce' % len(rows))
        row_id = rows[0][0]
        status = db.execute('SELECT status FROM exchanges WHERE id=?', (row_id,)).fetchone()[0]
        need(status == expected_status,
             'the exported exchange status is %d, not %d' % (status, expected_status))
        if task_id:
            owner = db.execute('SELECT task_id FROM exchanges WHERE id=?', (row_id,)).fetchone()[0]
            need(owner == task_id,
                 'the exported exchange belongs to task %r, not %d' % (owner, task_id))
            body = db.execute('SELECT resp_body FROM exchange_bodies WHERE id=?',
                              (row_id,)).fetchone()[0] or b''
            need(b'AGENTLAB_CAPTURE_SMOKE' in body,
                 'the exported response body is not the fixture origin body')
        else:
            head = db.execute('SELECT resp_head FROM exchange_bodies WHERE id=?', (row_id,)).fetchone()[0]
            need(STAGE_HEADER + ': ' + POLICY_STAGE in head,
                 'the exported refusal carries no gateway policy stage')
    events_dir = output / 'raw/host-events'
    need(events_dir.is_dir(), 'the export has no host event segments: %s' % events_dir)
    events = [json.loads(line) for path in sorted(events_dir.glob('*.jsonl'))
              for line in path.read_text().splitlines()]
    command_ids = {e['command_id'] for e in events
                   if e['kind'] == 'command_start' and nonce in json.dumps(e['argv'])}
    need(len(command_ids) == 1,
         'the host event stream holds %d commands for the marker' % len(command_ids))
    command_events = [e for e in events if e['command_id'] in command_ids]
    need(any(e['kind'] == 'command_exit' and e['exit_code'] == 0 for e in command_events),
         'the marker command did not exit 0 in the host event stream')
    stderr = b''.join(base64.b64decode(e['data_base64']) for e in command_events if e['kind'] == 'stderr')
    need(('AGENTLAB_STDERR_SMOKE:' + nonce).encode() in stderr,
         'the marker command stderr is not in the host event stream')
    packets = nonce_frames(output / 'raw/captures', recorder_port, nonce)
    need(packets > 0, 'the fixture nonce is not in the guest packet capture')
    current = json.loads((root / 'state/current-capture.json').read_text())
    session = output / 'raw/captures' / Path(current['path']).name
    need(any(p.is_file() and 'execve(' in p.read_text(errors='replace')
             for p in (session / 'strace').glob('strace.*')),
         'no current-session process syscalls in the export')
    resource = json.loads((session / 'resources.jsonl').read_text().splitlines()[-1])
    need(resource['memory_kib']['MemTotal'] > 0 and resource['cpu_ticks'],
         'the current-session resource samples are empty')
    return {'packets': packets, 'export': str(output), 'training': exported.get('training')}


def verify(transport, task_id, nonce):
    """Run the check and return (exit code, report)."""
    report = {
        'tier': TIER,
        'task_id': task_id,
        'fixture_nonce': nonce,
        'fixture_origin': FIXTURE_ORIGIN + '/' + nonce,
        'model_run': False,
        'proven': [],
        'not_proven': [],
    }
    if shutil.which('tshark') is None:
        return stop(report, 2, 'prerequisite missing', 'tshark is not installed on the host')
    try:
        token = transport.login()
    except OSError as err:
        return stop(report, 2, 'prerequisite missing', 'the console login failed: %s' % err)
    try:
        settings = transport.api('/api/settings', token=token)
    except OSError as err:
        return stop(report, 2, 'prerequisite missing', 'the console is not reachable: %s' % err)
    off = [key for key in ('llm_record', 'traffic_capture', 'agent_traffic_binding')
           if not settings.get(key)]
    if off:
        return stop(report, 2, 'prerequisite missing', 'capture is disabled: ' + ', '.join(off))
    marker = transport.guest(['python3', '-c', MARKER, nonce])
    if marker.returncode != 0:
        return stop(report, 2, 'prerequisite missing',
                    'the guest did not run the marker command: ' + text(marker.stderr).strip()[-400:])
    try:
        need('AGENTLAB_CAPTURE_SMOKE:' + nonce in text(marker.stdout),
             'the marker command printed no stdout marker')
        need('AGENTLAB_STDERR_SMOKE:' + nonce in text(marker.stderr),
             'the marker command printed no stderr marker')
    except Failed as err:
        return stop(report, 1, 'failed', str(err))

    origin = None
    if task_id:
        try:
            origin = start_origin(transport)
        except Failed as err:
            return stop(report, 2, 'prerequisite missing', str(err))
    try:
        body = {'kind': 'script', 'exec': {'code': PRODUCER, 'timeout_ms': 60000},
                'params': {'nonce': nonce, 'port': FIXTURE_PORT}, 'task_id': task_id}
        try:
            result = transport.api('/api/tools/custom/test', body, token=token)
        except urllib.error.HTTPError as err:
            return stop(report, 2 if err.code in (401, 409) else 1,
                        'prerequisite missing' if err.code in (401, 409) else 'failed',
                        'the test run was refused with HTTP %d: %s' % (err.code, http_detail(err)))
        lines = text(result.get('output', '')).strip().splitlines()
        try:
            seen = json.loads(lines[0]) if lines else None
        except ValueError:
            seen = None
        if not isinstance(seen, dict):
            return stop(report, 1, 'failed',
                        'the producer returned no parseable result: ' + text(result.get('output', ''))[-400:])
        if task_id:
            if seen.get('status') == 403 and seen.get('stage') == POLICY_STAGE:
                return stop(report, 1, 'blocked',
                            'the gateway refused %s for task %d: its rules do not authorize that origin'
                            % (FIXTURE_ORIGIN, task_id))
            if seen.get('status') != 200 or 'AGENTLAB_CAPTURE_SMOKE' not in str(seen.get('body', '')):
                return stop(report, 1, 'failed',
                            'the fixture origin did not answer through the gateway: status=%r stage=%r'
                            % (seen.get('status'), seen.get('stage')))
        elif seen.get('status') != 403 or seen.get('stage') != POLICY_STAGE:
            return stop(report, 1, 'failed',
                        'the gateway did not refuse loopback for the research session: status=%r stage=%r'
                        % (seen.get('status'), seen.get('stage')))

        traffic = transport.api('/api/traffic?q=' + nonce + '&size=100', token=token)
        rows = [row for row in traffic.get('exchanges', []) if nonce in row['url']]
        if not rows:
            if task_id:
                return stop(report, 1, 'failed', 'the allowed exchange was not recorded')
            return stop(report, 1, 'refusal not recorded',
                        'the gateway refused the request but the recorder stored no exchange for it; '
                        'the check reports that instead of weakening the assertion')
        row = rows[0]
        expected = 200 if task_id else 403
        try:
            need(row['status'] == expected,
                 'the recorded exchange status is %r, not %d' % (row['status'], expected))
            if task_id:
                need(row.get('task_id') == task_id,
                     'the recorded exchange belongs to task %r, not %d' % (row.get('task_id'), task_id))
            detail = transport.api('/api/traffic/exchange?id=' + urllib.parse.quote(row['id']), token=token)
            if not task_id:
                need(STAGE_HEADER + ': ' + POLICY_STAGE in detail.get('resp', ''),
                     'the recorded refusal carries no gateway policy stage')
            recorder = urllib.parse.urlsplit(traffic.get('proxy') or '')
            need(recorder.port, 'the traffic API reported no recorder address')
            facts = check_export(transport, nonce, expected, task_id, recorder.port)
        except Failed as err:
            return stop(report, 1, 'failed', str(err))
    finally:
        if origin is not None:
            stop_origin(origin)

    report['result'] = 'verified'
    report['fixture_packets'] = facts['packets']
    report['export'] = facts['export']
    report['training'] = facts['training']
    report['proven'] = [
        'credential-free guest execution: marker stdout, stderr and host event correlation',
        'm1nervac0nsole HTTP recording through POST /api/tools/custom/test',
        'guest packet capture on the recorder port',
        'application syscall capture',
        'resource samples',
        'exported PostgreSQL backup',
        'exported SQLite integrity and fixture row',
        'artifact checksums',
    ]
    if task_id:
        report['proven'].insert(0, 'an allowed round trip to %s under task %d' % (FIXTURE_ORIGIN, task_id))
        report['not_proven'] = ['byte completeness of a large or streamed body (tier 1, verify_completeness.py)']
    else:
        report['proven'].insert(0, 'the gateway policy refusal of loopback for a research session, '
                                   'recorded with the policy stage and a 403')
        report['not_proven'] = [
            'an allowed live-guest round trip to a synthetic origin: it needs an operator-authorized '
            'task (--task-id), which is the policy model, not a defect of this check',
            'byte completeness of a large or streamed body (tier 1, verify_completeness.py)',
        ]
    return 0, report


def main(argv=None, transport=None):
    if not __debug__:
        raise SystemExit('refusing to run with asserts disabled (python -O); the checks are asserts')
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--task-id', type=int, default=0, metavar='N',
                        help='a task whose rules already authorize %s' % FIXTURE_ORIGIN)
    args = parser.parse_args(argv)
    if args.task_id < 0:
        print(json.dumps({'tier': TIER, 'result': 'prerequisite missing',
                          'detail': '--task-id must be positive'}, indent=2))
        return 2
    nonce = uuid.uuid4().hex
    try:
        code, report = verify(transport or Lab(), args.task_id, nonce)
    except (OSError, ValueError) as err:
        code, report = 1, {'tier': TIER, 'task_id': args.task_id, 'fixture_nonce': nonce,
                           'result': 'failed', 'detail': '%s: %s' % (type(err).__name__, err)}
    print(json.dumps(report, indent=2))
    return code


if __name__ == '__main__':
    sys.exit(main())
