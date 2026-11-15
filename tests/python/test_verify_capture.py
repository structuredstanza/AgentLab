"""Behavioral tests for verify_capture.

The console, the guest and the export are faked: nothing here reaches a live
server, a deployment or a credential. The export tree is built from scratch in a
temporary directory.

Run: python3 -m unittest discover -s tests/python -p 'test_*.py'  (from the repository root)
"""

import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'deployment'))
import verify_capture as vc  # noqa: E402

NONCE = '0123456789abcdef' * 2
TOKEN = 'ADMIN-TOKEN-SECRET'
CREDENTIAL = 'sesscred'
PROXY = 'http://' + CREDENTIAL + '@127.0.0.1:8788'
STAGE_HEAD = 'HTTP 403\r\nX-M1nervac0nsole-Gateway: policy\r\n\r\n'
MARKER_STDOUT = ('AGENTLAB_CAPTURE_SMOKE:' + NONCE).encode()
MARKER_STDERR = ('AGENTLAB_STDERR_SMOKE:' + NONCE).encode()


def build_export(root, status=403, task_id=0):
    """A minimal export tree with the pieces the verifier asserts on."""
    export = root / 'exports' / 'run'
    (export / 'raw/host-events').mkdir(parents=True)
    (export / 'raw/captures/session/strace').mkdir(parents=True)
    (export / 'raw/application/traffic/_index').mkdir(parents=True)
    (export / 'raw/postgres.dump').write_bytes(b'-- dump')
    (export / 'raw/captures/session/strace/strace.0').write_text('execve("/bin/sh", [], ...)\n')
    (export / 'raw/captures/session/resources.jsonl').write_text(
        json.dumps({'memory_kib': {'MemTotal': 2048}, 'cpu_ticks': 10}) + '\n')
    events = [
        {'command_id': 'c1', 'kind': 'command_start', 'argv': ['python3', '-c', 'marker', NONCE]},
        {'command_id': 'c1', 'kind': 'stdout', 'data_base64': base64.b64encode(MARKER_STDOUT).decode()},
        {'command_id': 'c1', 'kind': 'stderr', 'data_base64': base64.b64encode(MARKER_STDERR).decode()},
        {'command_id': 'c1', 'kind': 'command_exit', 'exit_code': 0},
    ]
    (export / 'raw/host-events/segment.jsonl').write_text(
        ''.join(json.dumps(event) + '\n' for event in events))
    with contextlib.closing(sqlite3.connect(export / 'raw/application/traffic/_index/index.sqlite')) as db:
        db.execute('CREATE TABLE exchanges (id TEXT PRIMARY KEY, url TEXT, status INTEGER, task_id INTEGER)')
        db.execute('CREATE TABLE exchange_bodies (id TEXT PRIMARY KEY, resp_head TEXT, resp_body BLOB)')
        db.execute('INSERT INTO exchanges VALUES (?,?,?,?)',
                   ('1-1', 'http://127.0.0.1:8790/' + NONCE, status, task_id or None))
        db.execute('INSERT INTO exchange_bodies VALUES (?,?,?)',
                   ('1-1', STAGE_HEAD, b'AGENTLAB_CAPTURE_SMOKE\n' if status == 200 else b'loopback address\n'))
        db.commit()
    digest = hashlib.sha256((export / 'raw/postgres.dump').read_bytes()).hexdigest()
    (export / 'manifest.json').write_text(json.dumps({'sha256': {'raw/postgres.dump': digest}}))
    (root / 'state').mkdir()
    (root / 'state/current-capture.json').write_text(json.dumps({'path': 'captures/session'}))
    return export


class Fake:
    """The console API, the guest and the export, recording every argv they see."""

    name = 'sandbox'

    def __init__(self, root, *, login=TOKEN, settings=None, marker=None, tool=None,
                 traffic=None, exchange=None, export=None):
        self.root = root
        self.argv = []
        self.api_calls = []
        self._login = login
        self._settings = settings if settings is not None else {
            'llm_record': True, 'traffic_capture': True, 'agent_traffic_binding': True}
        self._marker = marker if marker is not None else subprocess.CompletedProcess(
            [], 0, MARKER_STDOUT, MARKER_STDERR)
        self._tool = tool
        self._traffic = traffic
        self._exchange = exchange
        self._export = export

    def login(self):
        if isinstance(self._login, Exception):
            raise self._login
        return self._login

    def api(self, path, data=None, token=None):
        self.api_calls.append((path, data, token))
        if path == '/api/settings':
            return self._settings
        if path.startswith('/api/tools/custom/test'):
            if isinstance(self._tool, Exception):
                raise self._tool
            return self._tool
        if path.startswith('/api/traffic?'):
            return self._traffic
        if path.startswith('/api/traffic/exchange'):
            return self._exchange
        raise AssertionError('unexpected api call: ' + path)

    def guest(self, argv, stream=False):
        self.argv.append(list(argv))
        if argv[0] == 'pg_restore':
            return subprocess.CompletedProcess(argv, 0, b'TABLE DATA public llm_records\n', b'')
        return self._marker

    def export(self):
        return self._export

    def spawn(self, argv):
        self.argv.append(list(argv))
        return subprocess.Popen([sys.executable, '-c', "print('ready', flush=True)"],
                                stdout=subprocess.PIPE, text=True)


def tool_result(status, stage, body=''):
    return {'output': json.dumps({'status': status, 'stage': stage, 'body': body})
                      + '\n[script: /tmp/.tool-scripts/test-1.py]',
            'is_error': False}


def traffic_row(status=403, task_id=0):
    return {'exchanges': [{'id': '1-1', 'url': 'http://127.0.0.1:8790/' + NONCE,
                           'status': status, 'task_id': task_id}],
            'proxy': PROXY}


class VerifyCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        uuid = mock.patch.object(vc.uuid, 'uuid4', return_value=types.SimpleNamespace(hex=NONCE))
        uuid.start()
        self.addCleanup(uuid.stop)
        # Packet counting shells out to tshark over a live capture; it is the
        # unchanged original code and is exercised by a real run, not here.
        frames = mock.patch.object(vc, 'nonce_frames', return_value=1)
        frames.start()
        self.addCleanup(frames.stop)

    def run_main(self, fake, argv=()):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = vc.main(list(argv), transport=fake)
        return code, out.getvalue()

    def fake(self, **kwargs):
        export = kwargs.pop('export', None)
        if export is None:
            export = {'export': str(build_export(self.root)),
                      'training': {'rows': 0}}
        return Fake(self.root, export=export, **kwargs)

    # ---- exit-code mapping -------------------------------------------------

    def test_bad_task_id_is_a_missing_prerequisite(self):
        code, out = self.run_main(self.fake(), ['--task-id', '-1'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['result'], 'prerequisite missing')

    def test_missing_tshark_is_a_missing_prerequisite(self):
        with mock.patch.object(vc.shutil, 'which', return_value=None):
            code, out = self.run_main(self.fake())
        self.assertEqual(code, 2)
        self.assertIn('tshark', json.loads(out)['detail'])

    def test_login_failure_is_a_missing_prerequisite(self):
        code, out = self.run_main(self.fake(login=OSError('connection refused')))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['result'], 'prerequisite missing')

    def test_disabled_capture_is_a_missing_prerequisite(self):
        code, out = self.run_main(self.fake(settings={'llm_record': True}))
        self.assertEqual(code, 2)
        self.assertIn('traffic_capture', json.loads(out)['detail'])

    def test_guest_that_cannot_run_the_marker_is_a_missing_prerequisite(self):
        marker = subprocess.CompletedProcess([], 1, b'', b'no such sandbox')
        code, out = self.run_main(self.fake(marker=marker))
        self.assertEqual(code, 2)
        self.assertIn('no such sandbox', json.loads(out)['detail'])

    def test_marker_without_output_fails(self):
        marker = subprocess.CompletedProcess([], 0, b'', b'')
        code, out = self.run_main(self.fake(marker=marker))
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)['result'], 'failed')

    def test_unrefused_loopback_fails(self):
        code, out = self.run_main(self.fake(tool=tool_result(200, None, 'served')))
        self.assertEqual(code, 1)
        self.assertIn('did not refuse loopback', json.loads(out)['detail'])

    def test_refusal_not_recorded_is_non_zero(self):
        code, out = self.run_main(self.fake(
            tool=tool_result(403, 'policy'),
            traffic={'exchanges': [], 'proxy': PROXY}))
        report = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(report['result'], 'refusal not recorded')
        self.assertIn('weakening', report['detail'])

    def test_unauthorized_task_is_blocked_not_verified(self):
        code, out = self.run_main(self.fake(
            tool=tool_result(403, 'policy'),
            traffic=traffic_row(), exchange={'resp': STAGE_HEAD}), ['--task-id', '5'])
        report = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(report['result'], 'blocked')

    def test_verified_default_run(self):
        code, out = self.run_main(self.fake(
            tool=tool_result(403, 'policy'), traffic=traffic_row(),
            exchange={'resp': STAGE_HEAD}))
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report['result'], 'verified')
        self.assertEqual(report['tier'], vc.TIER)
        self.assertEqual(report['fixture_packets'], 1)
        self.assertTrue(any('policy refusal' in line for line in report['proven']))
        self.assertTrue(any('--task-id' in line for line in report['not_proven']))

    def test_verified_task_run(self):
        export = build_export(self.root, status=200, task_id=5)
        code, out = self.run_main(self.fake(
            tool=tool_result(200, None, 'AGENTLAB_CAPTURE_SMOKE\n'),
            traffic=traffic_row(status=200, task_id=5),
            exchange={'resp': 'HTTP 200\r\n\r\n'},
            export={'export': str(export), 'training': {'rows': 0}}), ['--task-id', '5'])
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report['result'], 'verified')
        self.assertTrue(any('allowed round trip' in line for line in report['proven']))

    def test_recorded_exchange_without_the_stage_fails(self):
        code, out = self.run_main(self.fake(
            tool=tool_result(403, 'policy'), traffic=traffic_row(),
            exchange={'resp': 'HTTP 403\r\n\r\n'}))
        self.assertEqual(code, 1)
        self.assertIn('policy stage', json.loads(out)['detail'])

    # ---- no credential, no proxy URL --------------------------------------

    def test_no_credential_or_proxy_url_reaches_argv_stdout_or_the_report(self):
        fake = self.fake(tool=tool_result(403, 'policy'), traffic=traffic_row(),
                         exchange={'resp': STAGE_HEAD})
        code, out = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertTrue(fake.argv, 'the run recorded no guest argv to check')
        # Everything the run touched: the report, every argv, every API body.
        haystack = [out] + [json.dumps(argv) for argv in fake.argv]
        haystack += [json.dumps(call[1]) for call in fake.api_calls]
        for secret in (CREDENTIAL, PROXY, 'http://127.0.0.1:8788', TOKEN):
            for value in haystack:
                self.assertNotIn(secret, value)

    def test_producer_script_keeps_the_credential_out_of_its_own_argv(self):
        # The producer reads the proxy URL from its environment and builds the
        # Proxy-Authorization header in-process; no shell or curl argv carries it.
        self.assertIn('os.environ', vc.PRODUCER)
        self.assertNotIn('subprocess', vc.PRODUCER)
        self.assertNotIn('--proxy', vc.PRODUCER)


if __name__ == '__main__':
    unittest.main()
