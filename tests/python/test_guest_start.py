"""Supervisor failures must stop owned processes even when diagnostics fail."""
import contextlib
import errno
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

loader = importlib.machinery.SourceFileLoader('guest_supervisor', str(Path(__file__).resolve().parents[2] / 'deployment' / 'guest-start.py'))
spec = importlib.util.spec_from_loader(loader.name, loader)
supervisor = importlib.util.module_from_spec(spec)
loader.exec_module(supervisor)

# Stands in for the m1nervac0nsole binary's execbox subcommands: serve creates the
# socket and waits for SIGTERM, probe prints a capability report and exits with
# its verdict. FAKE_SERVE_EXIT makes serve fail, FAKE_PROBE_OK=0 makes probe fail.
FAKE_BINARY = '''#!/usr/bin/env python3
import json, os, signal, sys, time
args = sys.argv[1:]
mode = args[1] if len(args) > 1 else ""
def opt(name):
    return args[args.index(name) + 1] if name in args else ""
if mode == "serve":
    if os.environ.get("FAKE_SERVE_EXIT"):
        sys.exit(1)
    socket = opt("-socket")
    open(socket, "w").close()
    def stop(*_):
        os.unlink(socket)
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    while True:
        time.sleep(0.05)
if mode == "probe":
    ok = os.environ.get("FAKE_PROBE_OK", "1") == "1"
    print(json.dumps({"isolation": ok, "checked": ["netns"], "missing": [] if ok else ["netns"]}))
    sys.exit(0 if ok else 1)
sys.exit(2)
'''


class SkillSyncTests(unittest.TestCase):
    """Skills come from the host build, but UI-created ones must survive."""

    def test_build_skills_replace_old_files_and_keep_operator_skills(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst = root / 'dist-skills', root / 'state-skills'
            (src / 'recon').mkdir(parents=True)
            (src / 'recon' / 'SKILL.md').write_text('v2')
            (dst / 'recon').mkdir(parents=True)
            (dst / 'recon' / 'SKILL.md').write_text('v1')
            (dst / 'operator').mkdir()
            (dst / 'operator' / 'SKILL.md').write_text('created in the UI')
            (dst / 'gone').mkdir()
            (dst / 'gone' / 'SKILL.md').write_text('removed upstream')
            manifest = dst / '.guest-dist.json'
            manifest.write_text(json.dumps(['recon/SKILL.md', 'gone/SKILL.md']))

            self.assertEqual(supervisor.sync_skills(str(src), str(dst), str(manifest)), 1)

            self.assertEqual((dst / 'recon' / 'SKILL.md').read_text(), 'v2')
            self.assertFalse((dst / 'gone').exists(), 'a skill deleted upstream must not linger')
            self.assertEqual((dst / 'operator' / 'SKILL.md').read_text(), 'created in the UI')
            self.assertEqual(json.loads(manifest.read_text()), ['recon/SKILL.md'])

    def test_absent_build_leaves_the_skill_directory_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / 'state-skills'
            self.assertEqual(supervisor.sync_skills(str(Path(tmp) / 'missing'), str(dst), str(dst / 'm.json')), 0)
            self.assertFalse(dst.exists())


class SupervisorCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name, value in {
            'CAPTURES': self.root / 'captures',
            'PGDATA': self.root / 'postgres',
            'RUNTIME': self.root / 'runtime',
            'STATUS_PATH': self.root / 'status.json',
            'SUPERVISOR_PID': self.root / 'supervisor.pid',
            'CURRENT_CAPTURE': self.root / 'current-capture.json',
            'LOCK_PATH': self.root / 'supervisor.lock',
            'STOP': {'signal': None},
        }.items():
            patch = mock.patch.object(supervisor, name, value if name == 'STOP' else str(value))
            patch.start()
            self.addCleanup(patch.stop)
        (self.root / 'runtime').mkdir()
        self.session = supervisor.Session()
        self.full = OSError(errno.ENOSPC, 'fixture capture storage full')

    def child(self, ignore_term=False):
        code = "import time; time.sleep(30)"
        if ignore_term:
            code = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(30)"
        p = subprocess.Popen([sys.executable, '-c', code], start_new_session=True,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        def reap():
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            p.stdout.close()
        self.addCleanup(reap)
        if ignore_term:
            self.assertEqual(p.stdout.readline(), b'ready\n')
        return p

    @contextlib.contextmanager
    def main_context(self):
        lock = supervisor.acquire_lock()
        try:
            with mock.patch.object(supervisor, 'acquire_lock', return_value=lock), \
                 mock.patch.object(supervisor.signal, 'signal'), \
                 mock.patch.object(supervisor, 'prepare_dirs'), \
                 mock.patch.object(supervisor, 'Session', return_value=self.session), \
                 mock.patch.object(supervisor, 'start_execbox',
                                   side_effect=lambda sess, binary: self.child()), \
                 mock.patch.object(supervisor, 'account_recorder_ca'), \
                 mock.patch.object(supervisor, 'log'):
                yield
        finally:
            os.close(lock)

    def test_disk_full_and_broken_log_do_not_skip_remaining_processes(self):
        app, tcpd = self.child(), self.child()
        stderr = Path(self.session.logs) / 'tcpdump.stderr.log'
        stderr.write_text('0 packets captured\n')
        self.session.m['capture']['stderr_log'] = str(stderr)
        with mock.patch.object(supervisor, 'write_file', side_effect=self.full), \
             mock.patch.object(supervisor, 'log', side_effect=BrokenPipeError('fixture stdout closed')), \
             mock.patch.object(supervisor, 'pg_stop', return_value=(0, 'stopped')):
            supervisor.shutdown(self.session, app, tcpd, '/fixture/postgres')
        self.assertIsNotNone(app.poll(), 'm1nervac0nsole group survived capture-storage failure')
        self.assertIsNotNone(tcpd.poll(), 'packet recorder survived capture-storage failure')
        self.assertEqual(self.session.m['postgres']['status'], 'stopped')
        self.assertEqual(self.session.m['exit_code'], 1)
        self.assertEqual(self.session.m['state'], 'failed')

    def test_sigkill_escalation_survives_broken_diagnostics(self):
        app = self.child(ignore_term=True)
        with mock.patch.object(supervisor, 'APP_STOP_TIMEOUT', 0.02), \
             mock.patch.object(supervisor, 'write_file', side_effect=self.full), \
             mock.patch.object(supervisor, 'log', side_effect=BrokenPipeError('fixture stdout closed')):
            supervisor.stop_app(self.session, app)
        self.assertEqual(app.returncode, -signal.SIGKILL)
        self.assertEqual(self.session.m['m1nervac0nsole']['exit_code_normalized'], 137)

    def test_post_spawn_metadata_failure_reaps_unreturned_child(self):
        real_popen = subprocess.Popen
        for start in ('capture', 'app'):
            with self.subTest(start=start):
                spawned = []
                def spawn(_argv, **kwargs):
                    p = real_popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
                    spawned.append(p)
                    return p
                try:
                    with mock.patch.object(supervisor.shutil, 'which', return_value='/fixture/tool'), \
                         mock.patch.object(supervisor.subprocess, 'Popen', side_effect=spawn), \
                         mock.patch.object(self.session, 'save', side_effect=self.full), \
                         mock.patch.object(supervisor, 'log'):
                        with self.assertRaises(OSError):
                            if start == 'capture':
                                supervisor.start_tcpdump(self.session)
                            else:
                                supervisor.start_app(self.session, '/fixture/app', {})
                    self.assertIsNotNone(spawned[0].poll(), 'failed start orphaned its child')
                finally:
                    for p in spawned:
                        if p.poll() is None:
                            os.killpg(p.pid, signal.SIGKILL)
                        p.wait()

    def test_bookkeeping_failure_still_cleans_owned_pid_and_marks_failure(self):
        write_file = supervisor.write_file
        def write(path, *args, **kwargs):
            if path == supervisor.CURRENT_CAPTURE:
                raise self.full
            return write_file(path, *args, **kwargs)
        with self.main_context(), \
             mock.patch.object(supervisor, 'write_file', side_effect=write):
            rc = supervisor.main()
        self.assertEqual(rc, 1)
        self.assertFalse(Path(supervisor.SUPERVISOR_PID).exists())
        self.assertEqual(self.session.m['state'], 'failed')
        self.assertEqual(self.session.m['exit_code'], 1)

    def test_postgres_pid_failure_does_not_lose_ownership_or_stop_preexisting_server(self):
        for preexisting in (False, True):
            with self.subTest(preexisting=preexisting):
                self.session = supervisor.Session()
                server = {'running': preexisting}
                def run(argv, **_kwargs):
                    if argv[-1] == 'status':
                        return subprocess.CompletedProcess(argv, 0 if server['running'] else 3, b'', b'')
                    server['running'] = True
                    return subprocess.CompletedProcess(argv, 0, b'', b'')
                def stop(_bindir):
                    server['running'] = False
                    return 0, ''
                with self.main_context(), \
                     mock.patch.object(supervisor, 'pg_bindir', return_value='/fixture/postgres'), \
                     mock.patch.object(supervisor, 'pg_init'), \
                     mock.patch.object(supervisor, 'pg_write_hba'), \
                     mock.patch.object(supervisor.subprocess, 'run', side_effect=run), \
                     mock.patch.object(supervisor, 'pg_stop', side_effect=stop):
                    self.assertEqual(supervisor.main(), 1)
                self.assertEqual(server['running'], preexisting)
                self.assertEqual(self.session.m['postgres']['status'],
                                 'not_started' if preexisting else 'stopped')

    def test_cleanup_does_not_remove_another_supervisors_pid_marker(self):
        def fail_start():
            Path(supervisor.SUPERVISOR_PID).write_text('424242\n')
            raise supervisor.Fatal('fixture startup failure')
        with self.main_context(), mock.patch.object(supervisor, 'pg_bindir', side_effect=fail_start):
            self.assertEqual(supervisor.main(), 1)
        self.assertEqual(Path(supervisor.SUPERVISOR_PID).read_text(), '424242\n')

    def test_final_io_failure_cannot_report_a_successful_run(self):
        for failure in ('manifest', 'stdout'):
            with self.subTest(failure=failure):
                self.session = supervisor.Session()
                err_path = Path(self.session.logs) / 'tcpdump.stderr.log'
                err_path.write_text('0 packets captured\n')
                tcpd = subprocess.Popen([
                    sys.executable, '-c',
                    "import signal,sys,time; signal.signal(signal.SIGINT,lambda *_:sys.exit(0)); print('ready',flush=True); time.sleep(30)",
                ], start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                app = subprocess.Popen(['/usr/bin/true'], start_new_session=True)
                app.wait()
                try:
                    self.assertEqual(tcpd.stdout.readline(), b'ready\n')
                    self.session.m['capture'].update(status='running', pid=tcpd.pid, stderr_log=str(err_path))
                    write_file = supervisor.write_file
                    def write(path, *args, **kwargs):
                        if failure == 'manifest' and self.session.m['ended_at'] is not None:
                            raise self.full
                        return write_file(path, *args, **kwargs)
                    def log(_message):
                        if failure == 'stdout' and self.session.m['ended_at'] is not None:
                            raise BrokenPipeError('fixture stdout closed')
                    with self.main_context(), \
                         mock.patch.object(supervisor, 'pg_bindir', return_value='/fixture/postgres'), \
                         mock.patch.object(supervisor, 'pg_init'), \
                         mock.patch.object(supervisor, 'pg_write_hba'), \
                         mock.patch.object(supervisor, 'pg_start', return_value=os.getpid()), \
                         mock.patch.object(supervisor, 'pg_provision', return_value='postgresql://fixture'), \
                         mock.patch.object(supervisor, 'pg_stop', return_value=(0, '')), \
                         mock.patch.object(supervisor, 'install_binary', return_value=('/fixture/app', 'fixture')), \
                         mock.patch.object(supervisor, 'app_env', return_value={}), \
                         mock.patch.object(supervisor, 'admin_password', return_value='fixture'), \
                         mock.patch.object(supervisor, 'start_tcpdump', return_value=tcpd), \
                         mock.patch.object(supervisor, 'start_app', return_value=app), \
                         mock.patch.object(supervisor, 'write_file', side_effect=write), \
                         mock.patch.object(supervisor, 'log', side_effect=log):
                        self.assertEqual(supervisor.main(), 1)
                    self.assertEqual(tcpd.returncode, 0)
                    self.assertEqual(self.session.m['state'], 'failed')
                    self.assertEqual(self.session.m['exit_code'], 1)
                    if failure == 'stdout':
                        saved = json.loads((Path(self.session.dir) / 'manifest.json').read_text())
                        self.assertEqual((saved['state'], saved['exit_code']), ('failed', 1))
                finally:
                    if tcpd.poll() is None:
                        os.killpg(tcpd.pid, signal.SIGKILL)
                    tcpd.wait()
                    tcpd.stdout.close()



class VpnSupervisionTests(unittest.TestCase):
    """A supplied OpenVPN profile must be proven up before capture starts, and a
    dropped tunnel must stop the engagement rather than let egress escape it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root / 'profile.ovpn'
        self.profile.write_text('client\nremote vpn.example 1194\n')
        self.vpn_log = self.root / 'openvpn.log'
        for name, value in {'VPN_PROFILE': str(self.profile), 'VPN_LOG': str(self.vpn_log),
                            'VPN_TIMEOUT': 5}.items():
            patch = mock.patch.object(supervisor, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.session = mock.Mock()
        self.session.m = {}

    def test_no_profile_means_no_tunnel(self):
        self.profile.unlink()
        self.assertIsNone(supervisor.start_vpn(self.session))
        self.session.save.assert_not_called()

    def test_missing_openvpn_is_fatal_not_silent(self):
        with mock.patch.object(supervisor.shutil, 'which', return_value=None):
            with self.assertRaises(supervisor.Fatal):
                supervisor.start_vpn(self.session)

    def test_tunnel_must_produce_an_address(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(supervisor.subprocess, 'Popen', return_value=proc), \
             mock.patch.object(supervisor, 'vpn_address', return_value=''), \
             mock.patch.object(supervisor, 'stop_vpn'):
            with self.assertRaises(supervisor.Fatal):
                supervisor.start_vpn(self.session)

    def test_address_selects_tun_interface_only(self):
        output = ('1: lo    inet 127.0.0.1/8 scope host lo\n'
                  '2: eth0    inet 10.0.0.5/24 scope global eth0\n'
                  '3: tun0    inet 10.8.0.6/24 scope global tun0\n')
        done = mock.Mock(returncode=0, stdout=output)
        with mock.patch.object(supervisor.subprocess, 'run', return_value=done):
            self.assertEqual(supervisor.vpn_address(), '10.8.0.6')
        done.stdout = output.replace('tun0    inet 10.8.0.6/24 scope global tun0\n', '')
        with mock.patch.object(supervisor.subprocess, 'run', return_value=done):
            self.assertEqual(supervisor.vpn_address(), '', 'a host address must not count as a tunnel')

    def test_exited_tunnel_is_fatal_while_running(self):
        """The kill switch: openvpn dying mid-run must stop the app, not fail open."""
        app = mock.Mock()
        app.poll.return_value = None
        vpn = mock.Mock()
        vpn.poll.return_value = 1
        vpn.returncode = 1
        tcpd = mock.Mock()
        tcpd.poll.return_value = None
        execbox = mock.Mock(**{'poll.return_value': None})
        sess = mock.Mock()
        sess.tls = '/state/captures/fixture/tls'
        sess.m = {'capture': {'status': 'running'}, 'm1nervac0nsole': {}, 'postgres': {'status': 'not_started'}}
        with mock.patch.object(supervisor, 'start_vpn', return_value=vpn), \
             mock.patch.object(supervisor, 'start_execbox', return_value=execbox), \
             mock.patch.object(supervisor, 'start_tcpdump', return_value=tcpd), \
             mock.patch.object(supervisor, 'start_app', return_value=app), \
             mock.patch.object(supervisor, 'account_recorder_ca') as account_ca, \
             mock.patch.object(supervisor, 'pg_bindir', return_value='/nonexistent'), \
             mock.patch.object(supervisor, 'pg_init'), \
             mock.patch.object(supervisor, 'pg_write_hba'), \
             mock.patch.object(supervisor, 'pg_start', return_value=1), \
             mock.patch.object(supervisor, 'pg_provision', return_value='dsn'), \
             mock.patch.object(supervisor, 'install_binary', return_value=('/bin/true', 'sha')), \
             mock.patch.object(supervisor, 'app_env', return_value={}), \
             mock.patch.object(supervisor, 'admin_password', return_value='pw'), \
             mock.patch.object(supervisor, 'shutdown') as shutdown, \
             mock.patch.object(supervisor, 'acquire_lock'), \
             mock.patch.object(supervisor, 'prepare_dirs'), \
             mock.patch.object(supervisor, 'Session', return_value=sess), \
             mock.patch.object(supervisor, 'write_file'), \
             mock.patch.object(supervisor, 'log'):
            supervisor.main()
        account_ca.assert_called_once_with(sess, app, watch=(vpn, tcpd, execbox))
        errors = [call.args[0] for call in sess.error.call_args_list]
        self.assertTrue(any('openvpn exited' in str(e) for e in errors), errors)
        self.assertTrue(shutdown.called, 'cleanup must still run after the kill switch fires')

class AppEnvTests(unittest.TestCase):
    """The tool environment no longer routes through a masking proxy: masking
    lives in the gateway, so no client stack may be pointed at a proxy or a CA
    that does not exist."""

    def test_no_proxy_or_egress_ca_variables(self):
        env = supervisor.app_env('postgresql://fixture', 'pw')
        for key in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'no_proxy', 'NO_PROXY',
                    'M1NERVAC0NSOLE_EGRESS_PROXY', 'M1NERVAC0NSOLE_EGRESS_CA',
                    'SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS',
                    'M1NERVAC0NSOLE_MAX_REQUESTS_PER_MINUTE'):
            self.assertNotIn(key, env)

    def test_scan_concurrency_defaults_to_sixteen(self):
        env = supervisor.app_env('postgresql://fixture', 'pw')
        for key in ('M1NERVAC0NSOLE_MAX_CONCURRENT_SCANS', 'M1NERVAC0NSOLE_MAX_SCANS_PER_TARGET'):
            self.assertEqual(env.get(key), '16')

    def test_there_is_no_egress_supervision(self):
        for name in ('start_egress', 'stop_egress', 'EGRESS_ADDR', 'EGRESS_RPM'):
            self.assertFalse(hasattr(supervisor, name), name)

    def test_tcpdump_excludes_the_session_veth_leg_once(self):
        seen = []

        def popen(cmd, **kwargs):
            seen.append(cmd)
            raise RuntimeError('stop after argv')

        sess = mock.Mock(pcap='/tmp/pcap', logs='/tmp/logs')
        sess.m = {'capture': {}}
        with mock.patch.object(supervisor.shutil, 'which', return_value='/usr/sbin/tcpdump'), \
             mock.patch.object(supervisor, 'ring_segments', return_value=4), \
             mock.patch.object(supervisor.subprocess, 'Popen', side_effect=popen), \
             mock.patch('builtins.open', mock.mock_open()):
            with self.assertRaises(RuntimeError):
                supervisor.start_tcpdump(sess)
        self.assertEqual(seen[0][-1], 'not net 10.98.0.0/16')
        self.assertEqual(seen[0][seen[0].index('-i') + 1], 'any')
        self.assertEqual(sess.m['capture']['limits']['filter'], 'not net 10.98.0.0/16')

    def test_the_capture_reserve_reaches_the_recorder(self):
        env = supervisor.app_env('postgresql://fixture', 'pw')
        self.assertEqual(env.get('M1NERVAC0NSOLE_CAPTURE_RESERVE_MB'),
                         str(supervisor.CAPTURE_RESERVE_MB),
                         'the recorder would fall back to its own default reserve')
        self.assertEqual(env.get('M1NERVAC0NSOLE_CAPTURE_RESERVE_PCT'),
                         str(supervisor.CAPTURE_RESERVE_PCT),
                         'the recorder would stop at a different floor than the ring')

    def test_the_gateway_keylog_is_inside_the_capture_session(self):
        env = supervisor.app_env('postgresql://fixture', 'pw', '/state/captures/x/tls/keys.log')
        self.assertEqual(env.get('SSLKEYLOGFILE'), '/state/captures/x/tls/keys.log',
                         'the captured pcap would stay ciphertext without the gateway keylog')
        self.assertNotIn('SSLKEYLOGFILE', supervisor.app_env('postgresql://fixture', 'pw'),
                         'a keylog must never be written outside a capture session')

class RingSizingTests(unittest.TestCase):
    """The pcap ring must never be able to fill the volume it writes to.

    A live engagement died this way: /state is a 4 GB quota, the ring was a fixed
    32 x 128 MB = 4 GB, and the disk reached 0 bytes free. tcpdump then could not
    write, Postgres shut down, and the stack went with it. The ceiling is now
    AGENTLAB_CAPTURE_RING_GB and the reserve a share of the volume, so a bigger
    /state buys more retention without ever eating the headroom.
    """

    def _statvfs(self, free_mb, total_mb=None):
        st = mock.Mock()
        st.f_bavail = free_mb
        st.f_blocks = free_mb if total_mb is None else total_mb
        st.f_frsize = 1024 * 1024
        return st

    def _segments(self, free_mb, total_mb=None, ceiling=None):
        st = self._statvfs(free_mb, total_mb)
        with mock.patch.object(supervisor.os, 'statvfs', return_value=st):
            if ceiling is None:
                return supervisor.ring_segments()
            with mock.patch.object(supervisor, 'MAX_SEGMENTS', ceiling):
                return supervisor.ring_segments()

    def _fresh_module(self):
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_ring_leaves_the_scaled_reserve_free(self):
        for free_mb, total_mb in ((2048, 4096), (4096, 4096), (8192, 8192),
                                  (65536, 65536), (200_000, 200_000)):
            n = self._segments(free_mb, total_mb)
            used = n * supervisor.SEGMENT_MB
            reserve = supervisor.ring_reserve_mb(self._statvfs(free_mb, total_mb))
            self.assertLessEqual(
                used, free_mb - reserve,
                f"{free_mb} MB free: ring of {n} segments ({used} MB) eats the {reserve} MB reserve")

    def test_reserve_is_a_share_of_the_volume_above_the_floor(self):
        small = supervisor.ring_reserve_mb(self._statvfs(2048, 4096))
        huge = supervisor.ring_reserve_mb(self._statvfs(140_000, 150_000))
        self.assertEqual(small, supervisor.CAPTURE_RESERVE_MB)
        self.assertEqual(huge, 150_000 // 5)
        self.assertGreater(huge, small,
                           'a big volume must keep more headroom for Postgres and exports')

    def test_env_reserve_reaches_the_ring_and_the_manifest(self):
        with mock.patch.dict(os.environ, {'AGENTLAB_CAPTURE_RESERVE_MB': '4096',
                                          'AGENTLAB_CAPTURE_RESERVE_PCT': '50'}):
            module = self._fresh_module()
            self.assertEqual(module.ring_reserve_mb(self._statvfs(8192, 8192)), 4096)
            self.assertEqual(module.ring_reserve_mb(self._statvfs(200_000, 200_000)), 100_000)
            self.assertEqual(module.CAPTURE_LIMITS['reserve_mb'], 4096)
            self.assertEqual(module.CAPTURE_LIMITS['reserve_pct'], 50)
            self.assertIn('50%', module.CAPTURE_LIMITS['reserve'])

    def test_bad_reserve_env_falls_back_and_logs(self):
        for raw in ('0', '-1', 'abc'):
            with mock.patch.dict(os.environ, {'AGENTLAB_CAPTURE_RESERVE_MB': raw}):
                with mock.patch.object(supervisor, 'log') as log:
                    self.assertEqual(supervisor.capture_reserve(),
                                     (supervisor.CAPTURE_RESERVE_MB_DEFAULT,
                                      supervisor.CAPTURE_RESERVE_PCT_DEFAULT), raw)
                    log.assert_called_once()
        for raw in ('0', '100', 'abc'):
            with mock.patch.dict(os.environ, {'AGENTLAB_CAPTURE_RESERVE_PCT': raw}):
                with mock.patch.object(supervisor, 'log') as log:
                    self.assertEqual(supervisor.capture_reserve()[1],
                                     supervisor.CAPTURE_RESERVE_PCT_DEFAULT, raw)
                    log.assert_called_once()

    def test_ring_never_exceeds_the_env_ceiling(self):
        # A 200 GB volume would fit 1250 segments, but the operator's ceiling wins.
        self.assertEqual(self._segments(200_000, 200_000, ceiling=500), 500)

    def test_the_old_4gb_ceiling_is_gone(self):
        n = self._segments(150_000, 153_600, ceiling=500)
        self.assertEqual(n, 500, 'a 150 GB volume must use the full 64 GB default ring')
        self.assertGreater(n * supervisor.SEGMENT_MB, 32 * supervisor.SEGMENT_MB)

    def test_ring_keeps_a_floor_when_the_volume_is_already_tight(self):
        # Nothing fits, but a zero-segment ring would mean no capture at all.
        self.assertEqual(self._segments(0, 4096), supervisor.MIN_SEGMENTS)
        self.assertEqual(self._segments(1536, 4096), supervisor.MIN_SEGMENTS)

    def test_the_4gb_quota_cannot_reproduce_the_crash(self):
        # The exact shape that failed: a 4 GB quota already holding ~700 MB.
        n = self._segments(4096 - 700, 4096, ceiling=500)
        reserve = supervisor.ring_reserve_mb(self._statvfs(4096 - 700, 4096))
        self.assertLess(n * supervisor.SEGMENT_MB, 4096 - 700)
        self.assertLessEqual(n, (4096 - 700 - reserve) // supervisor.SEGMENT_MB)

    def test_default_ceiling_is_64_gb(self):
        with mock.patch.dict(os.environ):
            os.environ.pop('AGENTLAB_CAPTURE_RING_GB', None)
            self.assertEqual(supervisor.ring_ceiling_segments(), 500)

    def test_declared_limits_follow_the_ceiling(self):
        limits = supervisor.CAPTURE_LIMITS
        self.assertEqual(limits['max_segments'], supervisor.MAX_SEGMENTS)
        self.assertEqual(limits['approx_max_bytes'],
                         supervisor.SEGMENT_MB * 1_000_000 * supervisor.MAX_SEGMENTS)
        self.assertIn(f'-W {supervisor.MAX_SEGMENTS}', limits['rotation'])

    def test_env_ceiling_reaches_the_module_cap(self):
        with mock.patch.dict(os.environ, {'AGENTLAB_CAPTURE_RING_GB': '8'}):
            self.assertEqual(self._fresh_module().MAX_SEGMENTS, 62,
                             'AGENTLAB_CAPTURE_RING_GB=8 is 8000 MB / 128 MB per segment')
        self.assertEqual(self._fresh_module().MAX_SEGMENTS, supervisor.ring_ceiling_segments())

    def test_bad_env_falls_back_to_the_default_and_logs_once(self):
        for raw in ('0', '-3', 'abc', '3.5'):
            with mock.patch.dict(os.environ, {'AGENTLAB_CAPTURE_RING_GB': raw}):
                with mock.patch.object(supervisor, 'log') as log:
                    self.assertEqual(supervisor.ring_ceiling_segments(), 500, raw)
                    log.assert_called_once()
        with mock.patch.dict(os.environ, {'AGENTLAB_CAPTURE_RING_GB': ''}):
            with mock.patch.object(supervisor, 'log') as log:
                self.assertEqual(supervisor.ring_ceiling_segments(), 500)
                log.assert_not_called()


class ExecboxSupervisorTests(unittest.TestCase):
    """The execution boundary is a gate: a start that cannot isolate must fail."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name, value in {
            'CAPTURES': self.root / 'captures',
            'RUNTIME': self.root / 'runtime',
            'STATUS_PATH': self.root / 'status.json',
            'EXECBOX_SOCKET_DIR': self.root / 'run',
            'EXECBOX_SOCKET': self.root / 'run' / 'execbox.sock',
            'EXECBOX_WORKSPACES': f'{self.root}/state/tasks,{self.root}/state/sessions',
            'RECORDER_CA': self.root / 'state' / 'traffic' / '_ca' / 'mitmproxy-ca-cert.pem',
            'EXECBOX_TIMEOUT': 5,
        }.items():
            patch = mock.patch.object(supervisor, name, value if name == 'EXECBOX_TIMEOUT' else str(value))
            patch.start()
            self.addCleanup(patch.stop)
        (self.root / 'runtime').mkdir()
        self.session = supervisor.Session()
        self.binary = self.root / 'm1nervac0nsole'
        self.binary.write_text(FAKE_BINARY)
        self.binary.chmod(0o755)

    def reap(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_start_gates_on_the_probe_and_stop_uses_sigterm(self):
        p = supervisor.start_execbox(self.session, str(self.binary))
        self.addCleanup(self.reap, p.pid)
        self.addCleanup(lambda: p.poll() is None and p.kill())
        box = self.session.m['execbox']
        self.assertEqual(box['status'], 'running', box)
        self.assertIn('"isolation": true', box['probe'])
        self.assertEqual(box['ca_cert'], supervisor.RECORDER_CA)
        self.assertEqual(box['argv'][box['argv'].index('-ca-cert') + 1], supervisor.RECORDER_CA,
                         'the supervisor must be told which single file to expose to sessions')
        self.assertTrue(Path(supervisor.EXECBOX_SOCKET).exists())
        self.assertTrue((Path(self.session.logs) / 'execbox.log').exists())
        for root in supervisor.EXECBOX_WORKSPACES.split(','):
            self.assertTrue(Path(root).is_dir(), f'{root} was not created for the session boundary')

        supervisor.stop_execbox(self.session, p)
        self.assertEqual(p.returncode, 0, 'the supervisor must exit cleanly on SIGTERM')
        self.assertEqual(self.session.m['execbox']['status'], 'stopped')
        self.assertFalse(Path(supervisor.EXECBOX_SOCKET).exists())

    def test_failed_probe_fails_the_start_and_leaves_no_supervisor(self):
        with mock.patch.dict(os.environ, {'FAKE_PROBE_OK': '0'}):
            with self.assertRaises(supervisor.Fatal) as caught:
                supervisor.start_execbox(self.session, str(self.binary))
        self.assertIn('execbox probe failed', str(caught.exception))
        pid = self.session.m['execbox']['pid']
        self.assertIsNone(proc_alive(pid), 'a refused start left the supervisor running')
        self.assertEqual(self.session.m['execbox']['status'], 'stopped')

    def test_supervisor_that_exits_during_start_fails_loudly(self):
        with mock.patch.dict(os.environ, {'FAKE_SERVE_EXIT': '1'}):
            with self.assertRaises(supervisor.Fatal) as caught:
                supervisor.start_execbox(self.session, str(self.binary))
        self.assertIn('exited during start', str(caught.exception))
        self.assertIn('execbox.log', str(caught.exception))

    def test_shutdown_stops_the_boundary_after_the_app(self):
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)
        self.addCleanup(self.reap, app.pid)
        p = supervisor.start_execbox(self.session, str(self.binary))
        self.addCleanup(self.reap, p.pid)
        with mock.patch.object(supervisor, 'pg_stop', return_value=(0, 'stopped')):
            supervisor.shutdown(self.session, app, None, None, execbox=p)
        self.assertIsNotNone(app.poll(), 'the app survived shutdown')
        self.assertIsNotNone(p.poll(), 'the execution boundary survived shutdown')
        self.assertEqual(self.session.m['execbox']['status'], 'stopped')

    def write_ca(self, body):
        path = Path(supervisor.RECORDER_CA)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def live_app(self):
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)
        self.addCleanup(self.reap, app.pid)
        return app

    def test_recorder_ca_creation_and_rotation_are_recorded(self):
        app = self.live_app()
        self.write_ca('-----BEGIN CERTIFICATE-----\none\n-----END CERTIFICATE-----\n')
        supervisor.account_recorder_ca(self.session, app)
        first = self.session.m['recorder_ca']
        self.assertEqual(first['change'], 'created')
        self.assertIsNone(first['previous_sha256'])
        supervisor.account_recorder_ca(self.session, app)
        self.assertEqual(self.session.m['recorder_ca']['change'], 'unchanged')
        self.write_ca('-----BEGIN CERTIFICATE-----\ntwo\n-----END CERTIFICATE-----\n')
        supervisor.account_recorder_ca(self.session, app)
        rotated = self.session.m['recorder_ca']
        self.assertEqual(rotated['change'], 'rotated')
        self.assertEqual(rotated['previous_sha256'], first['sha256'])
        self.assertNotEqual(rotated['sha256'], first['sha256'])

    def test_missing_recorder_ca_is_reported_without_failing_the_start(self):
        # Recording can be off, and sessions already fail closed with a named
        # cause; killing the start would also stop the VPN kill switch running.
        supervisor.account_recorder_ca(self.session, self.live_app(), timeout=0.3)
        self.assertEqual(self.session.m['recorder_ca']['change'], 'missing')
        self.assertEqual(self.session.m['recorder_ca']['exposed'], 'nothing: no certificate to mount')
        self.assertNotEqual(self.session.m.get('state'), 'failed')

    def test_recorder_ca_wait_yields_on_shutdown_or_child_exit(self):
        for reason in ('SIGTERM', 'child exit'):
            with self.subTest(reason=reason):
                app = mock.Mock(**{'poll.return_value': None})
                child = mock.Mock(**{'poll.return_value': None})
                sess = mock.Mock(m={})

                def interrupt(_delay):
                    if reason == 'SIGTERM':
                        supervisor.on_signal(signal.SIGTERM, None)
                    else:
                        child.poll.return_value = 1

                with mock.patch.object(supervisor, 'STOP', {'signal': None}), \
                     mock.patch.object(supervisor.time, 'monotonic', side_effect=(0, 0, 1)), \
                     mock.patch.object(supervisor.time, 'sleep', side_effect=interrupt):
                    supervisor.account_recorder_ca(sess, app, watch=(None, child), timeout=0)
                self.assertNotIn('recorder_ca', sess.m, 'startup must yield instead of timing out')

    def test_backend_that_exits_before_creating_the_ca_is_named(self):
        app = subprocess.Popen(['/usr/bin/true'])
        app.wait()
        with self.assertRaises(supervisor.Fatal) as caught:
            supervisor.account_recorder_ca(self.session, app, timeout=5)
        self.assertIn('before creating the recorder CA', str(caught.exception))

    def test_ca_file_with_a_private_key_or_no_certificate_is_refused(self):
        app = self.live_app()
        key = '-----BEGIN ' + 'PRIVATE KEY-----\nk\n-----END ' + 'PRIVATE KEY-----\n'
        for body in (key + '-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n', 'junk'):
            self.write_ca(body)
            with self.assertRaises(supervisor.Fatal) as caught:
                supervisor.account_recorder_ca(self.session, app)
            self.assertIn('public-certificate-only', str(caught.exception))


def proc_alive(pid):
    """True while pid exists and is not a reaped child, else None."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    try:
        reaped, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return None if reaped == pid else True


if __name__ == '__main__':
    unittest.main()

