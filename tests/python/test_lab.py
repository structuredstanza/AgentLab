"""Behavioral checks for untrusted guest artifact extraction."""
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

loader = importlib.machinery.SourceFileLoader('agentlab', str(Path(__file__).resolve().parents[2] / 'lab'))
spec = importlib.util.spec_from_loader(loader.name, loader)
lab = importlib.util.module_from_spec(spec)
loader.exec_module(lab)


class ArtifactSnapshotTests(unittest.TestCase):
    def archive(self, member, payload=b''):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as tar:
            tar.addfile(member, io.BytesIO(payload) if member.isfile() else None)
        stream.seek(0)
        return stream

    def test_guest_paths_cannot_escape_export_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'snapshot'
            target.mkdir()
            member = tarfile.TarInfo('../outside')
            member.size = 3
            with self.assertRaises(tarfile.FilterError):
                lab.extract_capture_archive(self.archive(member, b'bad'), target)
            self.assertFalse((Path(tmp) / 'outside').exists())

    def test_guest_links_are_rejected_without_reading_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / 'private-secret'
            private.write_text('not capture data')
            for linktype in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                with self.subTest(linktype=linktype):
                    member = tarfile.TarInfo('escape')
                    member.type = linktype
                    member.linkname = str(private)
                    with self.assertRaises(ValueError):
                        lab.extract_capture_archive(self.archive(member), Path(tmp) / 'snapshot')
            self.assertEqual(private.read_text(), 'not capture data')

    def test_regular_capture_preserves_bytes_and_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            member = tarfile.TarInfo('application/workspace/result.txt')
            member.size = 7
            member.mode = 0o777
            target = Path(tmp) / 'snapshot'
            lab.extract_capture_archive(self.archive(member, b'result\n'), target)
            output = target / member.name
            self.assertEqual(output.read_bytes(), b'result\n')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)



class ProviderProxyTrafficExportTests(unittest.TestCase):
    def test_exports_only_private_capture_artifact_and_manifest_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proxy_state = root / 'proxy-state'
            capture_dir = proxy_state / 'captures'
            capture_dir.mkdir(parents=True)
            source = capture_dir / 'native-sse.ndjson'
            records = [
                {'Direction': 'request', 'Provider': 'claude', 'Model': 'claude-test',
                 'Profile': '42', 'SessionID': 'opaque-session-id', 'Path': '/v1/messages',
                 'ContentType': 'application/json', 'ContentEncoding': '',
                 'Body': 'cHJpdmF0ZSByZXF1ZXN0', 'Complete': False, 'Truncated': False},
                {'Direction': 'response', 'Provider': 'claude', 'Model': 'claude-test',
                 'Profile': '42', 'SessionID': 'opaque-session-id', 'Path': '/v1/messages',
                 'ContentType': 'application/json', 'ContentEncoding': '',
                 'Body': 'cHJpdmF0ZSByZXNwb25zZQ==', 'Complete': True, 'Truncated': False},
            ]
            capture = ''.join(json.dumps(record) + '\n' for record in records).encode()
            source.write_bytes(capture)
            (capture_dir / 'native-sse.ndjson.secret').write_text('sibling-secret')
            (proxy_state / 'replay.key').write_text('replay-secret')
            (proxy_state / 'native-proxy-token').write_text('token-secret')
            profile_grant = proxy_state / 'profiles' / '42'
            profile_grant.mkdir(parents=True)
            (profile_grant / 'grant.json').write_text('grant-secret')
            raw = root / 'export' / 'raw'
            raw.mkdir(parents=True)
            existing_artifact = raw / 'postgres.dump'
            existing_artifact.write_bytes(b'preserved raw artifact')

            with mock.patch.object(lab, 'PROXY_STATE', proxy_state):
                manifest = lab.export_provider_proxy_traffic(raw)

            artifact = raw / 'provider-proxy-traffic' / 'native-sse.ndjson'
            self.assertEqual(artifact.read_bytes(), capture)
            self.assertEqual((artifact.parent.stat().st_mode & 0o777), 0o700)
            self.assertEqual((artifact.stat().st_mode & 0o777), 0o600)
            self.assertEqual(manifest['source'], 'proxy-state/captures/native-sse.ndjson')
            self.assertEqual(manifest['artifact'], 'raw/provider-proxy-traffic/native-sse.ndjson')
            self.assertEqual(manifest['sha256'], hashlib.sha256(capture).hexdigest())
            self.assertEqual(manifest['correlation_fields'],
                             ['Direction', 'Provider', 'Model', 'Profile', 'SessionID'])
            self.assertNotIn('opaque-session-id', json.dumps(manifest))
            self.assertEqual(
                sorted(path.relative_to(raw).as_posix() for path in raw.rglob('*')),
                ['postgres.dump', 'provider-proxy-traffic', 'provider-proxy-traffic/native-sse.ndjson'],
            )
            self.assertEqual(existing_artifact.read_bytes(), b'preserved raw artifact')



class ModelIdentityTests(unittest.TestCase):
    def check_runtime(self, root, runtime):
        key = root / 'model-key'
        key.write_text('fixture-only-key')
        with mock.patch.object(lab, 'ROOT', root), mock.patch.object(lab, 'PRIMARY_KEY', key):
            with mock.patch.object(lab.urllib.request, 'urlopen',
                                   return_value=io.BytesIO(json.dumps(runtime).encode())):
                return lab.primary_runtime()

    def identity(self, root):
        weights = root / 'model.gguf'
        weights.write_bytes(b'fixture weights')
        stamp = weights.stat()
        (root / 'deployment').mkdir()
        (root / 'deployment/provenance.json').write_text(json.dumps({'model_artifact': {
            'path': str(weights), 'size_bytes': stamp.st_size, 'mtime_ns': stamp.st_mtime_ns}}))
        return weights, {'model_alias': 'bonsai-2-27b', 'model_path': str(weights)}

    def test_fixed_alias_cannot_hide_different_weights(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            weights, runtime = self.identity(root)
            runtime['model_path'] = str(root / 'another-model.gguf')
            with self.assertRaisesRegex(RuntimeError, 'different model artifact'):
                self.check_runtime(root, runtime)

    def test_replaced_weights_cannot_keep_stale_dataset_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            weights, runtime = self.identity(root)
            weights.write_bytes(b'replaced fixture weights')
            with self.assertRaisesRegex(RuntimeError, 'weights changed'):
                self.check_runtime(root, runtime)


class NativeProxyBootstrapTests(unittest.TestCase):
    def prepare(self, root):
        (root / 'secrets').mkdir()
        (root / 'deployment').mkdir()
        (root / 'dist').mkdir()
        (root / 'dist/provider-proxy').write_text('binary\n')
        (root / 'deployment/artex-cliproxy.service').write_text('[Service]\n')
        return mock.patch.multiple(
            lab, ROOT=root, PROXY_BIN=root / 'dist/provider-proxy', PROXY_STATE=root / 'proxy-state',
            PROXY_TOKEN=root / 'secrets/native-proxy-token',
            PROXY_UNIT=root / 'deployment/artex-cliproxy.service',
        )

    def test_restart_preserves_private_proxy_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, home = Path(tmp) / 'lab', Path(tmp) / 'home'
            root.mkdir()
            with self.prepare(root), mock.patch.object(lab.Path, 'home', return_value=home):
                with mock.patch.object(lab.subprocess, 'run'), mock.patch.object(
                    lab.urllib.request, 'urlopen',
                    side_effect=lambda *args, **kwargs: io.BytesIO(b'{"status":"ok"}'),
                ):
                    lab.start_provider_proxy()
                    token = lab.PROXY_TOKEN.read_bytes()
                    lab.start_provider_proxy()
                    self.assertEqual(lab.PROXY_TOKEN.read_bytes(), token)
                    self.assertGreaterEqual(len(token.strip()), 32)
                    self.assertEqual(lab.PROXY_TOKEN.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(lab.PROXY_STATE.stat().st_mode & 0o777, 0o700)

    def test_unrelated_user_service_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, home = Path(tmp) / 'lab', Path(tmp) / 'home'
            root.mkdir()
            installed = home / '.config/systemd/user/artex-cliproxy.service'
            installed.parent.mkdir(parents=True)
            installed.write_text('user-owned service\n')
            with self.prepare(root), mock.patch.object(lab.Path, 'home', return_value=home):
                with mock.patch.object(lab.subprocess, 'run'):
                    with self.assertRaisesRegex(RuntimeError, 'unrelated service'):
                        lab.start_provider_proxy()
            self.assertEqual(installed.read_text(), 'user-owned service\n')





class SharedStateGuardTests(unittest.TestCase):
    def test_another_running_agentlab_vm_blocks_start(self):
        listing = mock.Mock(returncode=0,
                            stdout=f'{lab.NAME}\nartex-agentlab-old\nartex-htb-1\n',
                            stderr='')
        with mock.patch.object(lab, 'start_provider_proxy'), \
                mock.patch.object(lab.subprocess, 'run', return_value=listing):
            with self.assertRaisesRegex(RuntimeError, 'artex-agentlab-old'):
                lab.start()

    def test_own_and_unrelated_sandboxes_do_not_block(self):
        listing = mock.Mock(returncode=0,
                            stdout=f'{lab.NAME}\nartex-htb-20261104t2200z\n',
                            stderr='')
        with mock.patch.object(lab.subprocess, 'run', return_value=listing):
            self.assertEqual(lab.other_running_agentlab(), [])

    def test_unlistable_sandboxes_fail_closed(self):
        listing = mock.Mock(returncode=1, stdout='', stderr='engine down')
        with mock.patch.object(lab.subprocess, 'run', return_value=listing):
            with self.assertRaisesRegex(RuntimeError, 'Could not list'):
                lab.other_running_agentlab()


class BuildFreshnessTests(unittest.TestCase):
    """The guest runs the host build, so a stale check that never fires would
    silently serve the binary the image baked in."""

    def test_missing_binary_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(lab.guest_dist_stale(Path(tmp) / 'artex'))

    def check(self, source_time, binary_time):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'main.go'
            source.write_text('package main')
            binary = root / 'artex'
            binary.write_bytes(b'bin')
            os.utime(source, (source_time, source_time))
            os.utime(binary, (binary_time, binary_time))
            with mock.patch.object(lab, 'BUILD_INPUTS', [source]):
                return lab.guest_dist_stale(binary)

    def test_binary_newer_than_every_input_is_current(self):
        self.assertFalse(self.check(1000, 2000))

    def test_newer_input_makes_the_build_stale(self):
        self.assertTrue(self.check(3000, 2000))


class StateStorageTests(unittest.TestCase):
    def conf_text(self, quota_mb):
        path, temporary = lab.sandbox_conf(quota_mb)
        try:
            return path.read_text(), temporary
        finally:
            if temporary:
                path.unlink()

    def test_default_keeps_the_checked_in_spec(self):
        path, temporary = lab.sandbox_conf(None)
        self.assertEqual((path, temporary), (lab.SANDBOX_CONF, False))

    def test_quota_is_rewritten_only_on_the_state_mount(self):
        text, temporary = self.conf_text(409600)
        self.assertTrue(temporary)
        self.assertIn(':/state:quota=409600', text)
        self.assertEqual(text.count('quota='), 1)
        # Everything else in the spec is untouched.
        base = lab.SANDBOX_CONF.read_text().replace(
            ':/state:quota=' + lab.SANDBOX_CONF.read_text().split(':/state:quota=')[1].split()[0],
            ':/state:quota=409600')
        self.assertEqual(text, base)

    def test_zero_removes_the_quota(self):
        text, _ = self.conf_text(0)
        self.assertNotIn('quota=', text)
        self.assertIn(':/state', text)

    def test_quota_parsing_is_strict(self):
        self.assertEqual(lab.state_quota_mb(150), 150 * 1024)
        self.assertEqual(lab.state_quota_mb(0), 0)
        for bad in ('abc', '-1', '1.5'):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                lab.state_quota_mb(bad)

    def test_env_default_applies_when_no_flag(self):
        with mock.patch.dict(lab.os.environ, {'AGENTLAB_STATE_QUOTA_GB': '300'}):
            self.assertEqual(lab.state_quota_mb(), 300 * 1024)
        with mock.patch.dict(lab.os.environ, {}, clear=False):
            lab.os.environ.pop('AGENTLAB_STATE_QUOTA_GB', None)
            self.assertIsNone(lab.state_quota_mb())

    def test_low_host_space_refuses_to_create(self):
        usage = mock.Mock(free=5 * 2**30)
        with mock.patch.object(lab.shutil, 'disk_usage', return_value=usage), \
                mock.patch.object(lab, 'msb') as msb:
            with self.assertRaisesRegex(RuntimeError, 'GiB free'):
                lab.create_sandbox(None)
            msb.assert_not_called()

    def test_resize_refuses_a_running_vm(self):
        inspected = mock.Mock(returncode=0, stdout=json.dumps({'status': 'Running'}), stderr='')
        with mock.patch.object(lab.subprocess, 'run', return_value=inspected), \
                mock.patch.object(lab, 'msb') as msb:
            with self.assertRaisesRegex(RuntimeError, 'Stop the VM'):
                lab.resize_state(200, True)
            msb.assert_not_called()

    def test_resize_requires_confirmation_before_removing_anything(self):
        inspected = mock.Mock(returncode=0, stdout=json.dumps({'status': 'stopped'}), stderr='')
        with mock.patch.object(lab.subprocess, 'run', return_value=inspected), \
                mock.patch.object(lab, 'msb') as msb:
            with self.assertRaisesRegex(RuntimeError, '--yes'):
                lab.resize_state(200, False)
            msb.assert_not_called()

    def test_confirmed_resize_removes_then_recreates_with_the_new_quota(self):
        inspected = mock.Mock(returncode=0, stdout=json.dumps({'status': 'stopped'}), stderr='')
        created = []
        with mock.patch.object(lab.subprocess, 'run', return_value=inspected), \
                mock.patch.object(lab, 'create_sandbox', side_effect=lambda q=None: created.append(q)), \
                mock.patch.object(lab, 'msb') as msb:
            lab.resize_state(200, True)
        self.assertEqual(created, [200 * 1024])
        self.assertEqual([call.args[0] for call in msb.call_args_list], ['remove', 'stop'])


if __name__ == '__main__':
    unittest.main()
