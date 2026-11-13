#!/usr/bin/env python3
"""Exercise real VM capture and exported artifacts using a unique local fixture, never an LLM."""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('agentlab', str(ROOT / 'lab'))
spec = importlib.util.spec_from_loader(loader.name, loader)
lab = importlib.util.module_from_spec(spec)
loader.exec_module(lab)

FIXTURE = '''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess, threading
nonce = 'FIXTURE_NONCE'
body = ('AGENTLAB_CAPTURE_SMOKE:' + nonce + '\\n').encode()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    result = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--max-time', '15',
        '--noproxy', '', '--proxy', 'http://127.0.0.1:8788',
        'http://127.0.0.1:%d/agentlab-capture-smoke-%s' % (server.server_port, nonce)],
        check=True, capture_output=True)
    assert result.stdout == body, result.stdout
    print(result.stdout.decode(), end='')
    print('AGENTLAB_STDERR_SMOKE:' + nonce, file=__import__('sys').stderr)
finally:
    server.shutdown()
    server.server_close()
'''


def main():
    nonce = uuid.uuid4().hex
    token = lab.login()
    settings = lab.api('/api/settings', token=token)
    assert all(settings[key] for key in ('llm_record', 'traffic_capture', 'agent_traffic_binding'))
    proc = subprocess.run([str(ROOT / 'lab'), 'exec', '--', 'python3', '-c',
                           FIXTURE.replace('FIXTURE_NONCE', nonce)],
                          check=True, capture_output=True, text=True)
    assert 'AGENTLAB_CAPTURE_SMOKE:' + nonce in proc.stdout
    assert 'AGENTLAB_STDERR_SMOKE:' + nonce in proc.stderr
    traffic = lab.api('/api/traffic?q=' + nonce + '&size=100', token=token)
    assert any(nonce in row['url'] and row['status'] == 200 for row in traffic['exchanges']), traffic
    result = subprocess.run([str(ROOT / 'lab'), 'export'], check=True, capture_output=True, text=True)
    exported = json.loads(result.stdout)
    output = Path(exported['export'])
    manifest = json.loads((output / 'manifest.json').read_text())
    for relative, expected in manifest['sha256'].items():
        with (output / relative).open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected, relative
    # Listing exits after the TOC; streaming the whole archive causes an msb stdin EPIPE.
    with tempfile.TemporaryDirectory(prefix='.verify-export-', dir=ROOT / 'state') as staged:
        staged = Path(staged)
        (staged / 'postgres.dump').hardlink_to(output / 'raw/postgres.dump')
        listed = subprocess.run([str(lab.MSB), 'exec', '--stream', '--no-stdin', lab.NAME,
                                 '--', 'pg_restore', '-l', '/state/' + staged.name + '/postgres.dump'],
                                capture_output=True, check=True, text=False)
    assert b'TABLE DATA public llm_records' in listed.stdout
    with sqlite3.connect(output / 'raw/application/traffic/_index/index.sqlite') as db:
        assert db.execute('SELECT count(*) FROM exchanges WHERE url LIKE ? AND status=200',
                          ('%' + nonce + '%',)).fetchone()[0] > 0
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    events = [json.loads(line) for line in (output / 'raw/host-events.jsonl').read_text().splitlines()]
    command_ids = {e['command_id'] for e in events if e['kind'] == 'command_start' and nonce in json.dumps(e['argv'])}
    assert len(command_ids) == 1
    command_events = [e for e in events if e['command_id'] in command_ids]
    assert any(e['kind'] == 'command_exit' and e['exit_code'] == 0 for e in command_events)
    stderr = b''.join(base64.b64decode(e['data_base64']) for e in command_events if e['kind'] == 'stderr')
    assert ('AGENTLAB_STDERR_SMOKE:' + nonce).encode() in stderr
    packets = 0
    for capture in (output / 'raw/captures').rglob('*.pcap*'):
        if not capture.is_file() or capture.is_symlink():
            continue
        decoded = subprocess.run(['tshark', '-r', str(capture), '-d', 'tcp.port==8788,http',
            '-Y', 'frame contains "' + nonce + '"', '-T', 'fields', '-e', 'frame.number'],
            check=False, capture_output=True, text=True)
        # An online snapshot may end on a partial last packet; only decoded matching frames count.
        packets += len(decoded.stdout.splitlines())
    assert packets > 0, 'No unique fixture traffic in packet capture'
    current = json.loads((ROOT / 'state/current-capture.json').read_text())
    session = output / 'raw/captures' / Path(current['path']).name
    assert any(p.is_file() and 'execve(' in p.read_text(errors='replace')
               for p in (session / 'strace').glob('strace.*')), 'No current-session process syscalls'
    resource = json.loads((session / 'resources.jsonl').read_text().splitlines()[-1])
    assert resource['memory_kib']['MemTotal'] > 0 and resource['cpu_ticks']
    print(json.dumps({'verified': ['vm execution', 'stdout/stderr correlation', 'm1nervac0nsole HTTP recording',
          'guest packet capture', 'application syscall capture', 'resource samples',
          'exported PostgreSQL backup', 'exported SQLite integrity and fixture', 'artifact checksums'],
          'fixture_nonce': nonce, 'export': str(output), 'fixture_packets': packets,
          'training': exported['training'], 'model_run': False}, indent=2))


if __name__ == '__main__':
    main()
