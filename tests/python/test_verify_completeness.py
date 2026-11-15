"""Behavioral tests for verify_completeness.

The tier-1 producer is faked: nothing here starts Go, a store, an origin or a
deployment. The measurements the real fixture reports are built from scratch, so
each verdict path is exercised directly.

Run: python3 -m unittest discover -s tests/python -p 'test_*.py'  (from the repository root)
"""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'deployment'))
import verify_completeness as vc  # noqa: E402

NONCE = '0123456789abcdef' * 2
DIGEST = 'a' * 64


def stage(size, digest=''):
    return {'bytes': size, 'sha256': digest}


def good_shape(path, size=64):
    return {'path': path, 'nonce': NONCE + '-' + path, 'status': 200,
            'sent': stage(size, DIGEST), 'collected': stage(size),
            'retained': stage(size, DIGEST), 'exported': stage(size, DIGEST),
            'consumed': stage(size, DIGEST), 'partial': False}


def good_ws(size=256):
    frames = [
        {'dir': 'c2s', 'type': 'text', 'len': 4, 'sha256': 'b' * 64},
        {'dir': 's2c', 'type': 'text', 'len': 4, 'sha256': 'b' * 64},
        {'dir': 'c2s', 'type': 'binary', 'len': 5, 'sha256': 'c' * 64},
        {'dir': 's2c', 'type': 'binary', 'len': 5, 'sha256': 'c' * 64},
    ]
    return {'path': 'ws', 'nonce': NONCE + '-ws', 'status': 101,
            'sent': stage(0), 'collected': stage(size),
            'retained': stage(size, DIGEST), 'exported': stage(size, DIGEST),
            'consumed': stage(size, DIGEST), 'frames': frames,
            'transcript': [dict(frame) for frame in frames],
            'closes': ['c2s', 's2c'], 'partial': False}


def good_report():
    return {'task_id': 1, 'imported': 5,
            'shapes': [good_shape('plain'), good_shape('sse'), good_shape('big'), good_ws()],
            'refused': {'port': 9999, 'status': 403, 'stage': 'policy', 'origin_hits': 0}}


class Fake:
    """The tier-1 producer, faked: it records the work directory it was given."""

    def __init__(self, report):
        self.report = report
        self.work = None

    def produce(self, work):
        self.work = work
        if isinstance(self.report, Exception):
            raise self.report
        return self.report


def report_of(out):
    lines = out.splitlines()
    return json.loads('\n'.join(lines[lines.index('{'):]))


class VerifyCompleteness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'm1nervac0nsole').mkdir()
        which = mock.patch.object(vc.shutil, 'which', return_value='/usr/bin/tool')
        which.start()
        self.addCleanup(which.stop)
        keylog = mock.patch.object(vc, 'keylog_fixture', return_value={'status': 'verified'})
        keylog.start()
        self.addCleanup(keylog.stop)

    def run_main(self, report=None):
        harness = Fake(good_report() if report is None else report)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = vc.main(harness=harness)
        return code, out.getvalue()

    # ---- exit-code mapping -------------------------------------------------

    def test_verified_run_exits_zero(self):
        code, out = self.run_main()
        report = report_of(out)
        self.assertEqual(code, 0)
        self.assertEqual(report['result'], 'verified')
        self.assertEqual(report['tier'], vc.TIER)
        self.assertTrue(report['proven'])
        self.assertTrue(any('verify_capture.py' in line for line in report['not_proven']))
        self.assertIn('plain', out)

    def test_missing_tool_is_a_missing_prerequisite(self):
        with mock.patch.object(vc.shutil, 'which', return_value=None):
            code, out = self.run_main()
        report = report_of(out)
        self.assertEqual(code, 2)
        self.assertEqual(report['result'], 'prerequisite missing')
        self.assertIn('go', report['detail'])

    def test_fixture_failure_is_a_failure(self):
        code, out = self.run_main(ValueError('the harness fixture failed: build error'))
        report = report_of(out)
        self.assertEqual(code, 1)
        self.assertEqual(report['result'], 'failed')
        self.assertIn('build error', report['detail'])

    def test_keylog_failure_fails(self):
        with mock.patch.object(vc, 'keylog_fixture',
                               return_value={'status': 'failed', 'reason': 'no handshake secret'}):
            code, out = self.run_main()
        report = report_of(out)
        self.assertEqual(code, 1)
        self.assertIn('keylog', [failure['shape'] for failure in report['failures']])

    def test_keylog_skip_is_a_missing_prerequisite(self):
        with mock.patch.object(vc, 'keylog_fixture',
                               return_value={'status': 'skipped', 'reason': 'not installed: tshark'}):
            code, out = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(report_of(out)['result'], 'prerequisite missing')

    # ---- byte completeness -------------------------------------------------

    def test_short_exported_body_fails(self):
        report = good_report()
        report['shapes'][2]['exported'] = stage(1024, DIGEST)
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual(failure['shape'], 'big')
        self.assertEqual(failure['stage'], 'exported')
        self.assertIn('1024', failure['detail'])

    def test_short_retained_body_fails(self):
        report = good_report()
        report['shapes'][0]['retained'] = stage(1, DIGEST)
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('plain', 'retained'))

    def test_collected_length_that_disagrees_with_the_origin_fails(self):
        report = good_report()
        report['shapes'][1]['collected'] = stage(3)
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('sse', 'collected'))

    def test_missing_shape_fails(self):
        report = good_report()
        report['shapes'] = [entry for entry in report['shapes'] if entry['path'] != 'sse']
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('sse', 'missing'))

    def test_partial_capture_fails(self):
        report = good_report()
        report['shapes'][3]['partial'] = True
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('ws', 'retained'))
        self.assertIn('partial', failure['detail'])

    def test_refused_status_cannot_pass(self):
        report = good_report()
        report['shapes'][0]['status'] = 403
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('plain', 'collected'))

    def test_shape_error_fails(self):
        report = good_report()
        report['shapes'][2]['error'] = 'no exchange was recorded'
        code, out = self.run_main(report)
        self.assertEqual(code, 1)
        self.assertEqual(report_of(out)['failures'][0]['stage'], 'error')

    # ---- the WebSocket transcript -----------------------------------------

    def test_ws_frame_payload_mismatch_fails(self):
        report = good_report()
        report['shapes'][3]['transcript'][1]['sha256'] = 'd' * 64
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('ws', 'transcript'))
        self.assertIn('s2c', failure['detail'])

    def test_ws_missing_frame_fails(self):
        report = good_report()
        report['shapes'][3]['transcript'] = report['shapes'][3]['transcript'][:3]
        code, out = self.run_main(report)
        self.assertEqual(code, 1)
        self.assertEqual(report_of(out)['failures'][0]['stage'], 'transcript')

    def test_ws_transcript_shorter_than_the_row_fails(self):
        report = good_report()
        report['shapes'][3]['retained'] = stage(10, DIGEST)
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('ws', 'retained'))

    def test_ws_without_a_close_line_fails(self):
        report = good_report()
        report['shapes'][3]['closes'] = ['c2s']
        code, out = self.run_main(report)
        self.assertEqual(code, 1)
        self.assertEqual(report_of(out)['failures'][0]['stage'], 'transcript')

    # ---- the grant is narrow ----------------------------------------------

    def test_ungranted_port_not_refused_fails(self):
        report = good_report()
        report['refused'] = {'port': 9999, 'status': 200, 'stage': '', 'origin_hits': 0}
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('refused', 'policy'))

    def test_gateway_dialed_the_ungranted_port_fails(self):
        report = good_report()
        report['refused']['origin_hits'] = 1
        code, out = self.run_main(report)
        failure = report_of(out)['failures'][0]
        self.assertEqual(code, 1)
        self.assertEqual((failure['shape'], failure['stage']), ('refused', 'dial'))

    # ---- no credential, no proxy URL, no policy write ----------------------

    def test_no_credential_or_proxy_url_reaches_stdout_or_the_report(self):
        code, out = self.run_main()
        self.assertEqual(code, 0)
        report = json.dumps(report_of(out))
        for rendered in (out, report):
            for secret in ('://', '@', 'AGENTLAB_PROXY_CREDENTIAL', 'Proxy-Authorization'):
                self.assertNotIn(secret, rendered)

    def test_fixture_argv_carries_only_directories(self):
        harness = vc.Harness(root=self.root)
        done = subprocess.CompletedProcess([], 0, json.dumps(good_report()), '')
        with mock.patch.object(vc.subprocess, 'run', return_value=done) as run:
            measured = harness.produce(self.root)
        argv = run.call_args[0][0]
        self.assertEqual(argv[:2], ['go', 'run'])
        self.assertEqual(len(argv), 6)
        for value in argv[2:]:
            self.assertNotIn('@', value)
            self.assertNotIn('credential', value.lower())
        self.assertEqual(measured, good_report())

    def test_the_script_keeps_no_credential_and_no_policy_call(self):
        source = Path(vc.__file__).read_text()
        self.assertFalse(hasattr(vc, 'authorize'))
        for banned in ('--credential', 'AGENTLAB_PROXY_CREDENTIAL', 'def authorize(', '/api/'):
            self.assertNotIn(banned, source)


if __name__ == '__main__':
    unittest.main()
