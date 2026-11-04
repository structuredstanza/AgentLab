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

loader = importlib.machinery.SourceFileLoader('guest_supervisor', str(Path(__file__).with_name('guest-start.py')))
spec = importlib.util.spec_from_loader(loader.name, loader)
supervisor = importlib.util.module_from_spec(spec)
loader.exec_module(supervisor)


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
        self.assertIsNotNone(app.poll(), 'ARTEX group survived capture-storage failure')
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
        self.assertEqual(self.session.m['artex']['exit_code_normalized'], 137)

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
                         mock.patch.object(supervisor, 'start_egress', return_value=mock.Mock(**{'poll.return_value': None})), \
                         mock.patch.object(supervisor, 'start_egress', return_value=mock.Mock(**{'poll.return_value': None})), \
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
        """The kill switch: openvpn dying mid-run must stop ARTEX, not fail open."""
        app = mock.Mock()
        app.poll.return_value = None
        vpn = mock.Mock()
        vpn.poll.return_value = 1
        vpn.returncode = 1
        tcpd = mock.Mock()
        tcpd.poll.return_value = None
        sess = mock.Mock()
        sess.m = {'capture': {'status': 'running'}, 'artex': {}, 'postgres': {'status': 'not_started'},
                  'egress': {'status': 'starting'}}
        with mock.patch.object(supervisor, 'start_vpn', return_value=vpn), \
             mock.patch.object(supervisor, 'start_egress', return_value=mock.Mock(**{'poll.return_value': None})), \
             mock.patch.object(supervisor, 'start_tcpdump', return_value=tcpd), \
             mock.patch.object(supervisor, 'start_app', return_value=app), \
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
        errors = [call.args[0] for call in sess.error.call_args_list]
        self.assertTrue(any('openvpn exited' in str(e) for e in errors), errors)
        self.assertTrue(shutdown.called, 'cleanup must still run after the kill switch fires')

class AppEnvTests(unittest.TestCase):
    """The tool environment is what makes the identity proxy binding.

    A tool that does not inherit http_proxy reaches the target directly and
    presents its own User-Agent, which is the leak this whole mechanism exists to
    close. So the variables are asserted here rather than trusted.
    """

    def test_target_http_is_routed_through_the_identity_proxy(self):
        env = supervisor.app_env('postgresql://fixture', 'pw')
        proxy = 'http://' + supervisor.EGRESS_ADDR
        for key in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
            self.assertEqual(env.get(key), proxy, f'{key} missing: target HTTP would bypass the proxy')

    def test_the_host_native_proxy_is_excluded(self):
        env = supervisor.app_env('postgresql://fixture', 'pw')
        bypass = env.get('no_proxy', '') + env.get('NO_PROXY', '')
        self.assertIn('host.microsandbox.internal', bypass,
                      'model calls would be rewritten as if they were target traffic')

    def test_the_proxy_ca_is_trusted_by_every_client_stack(self):
        env = supervisor.app_env('postgresql://fixture', 'pw')
        for key in ('SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS'):
            self.assertEqual(env.get(key), supervisor.EGRESS_CA, f'{key} missing: TLS interception fails')

if __name__ == '__main__':
    unittest.main()
