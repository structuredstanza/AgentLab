"""Behavioral checks for untrusted guest artifact extraction."""
import hashlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

loader = importlib.machinery.SourceFileLoader('agentlab', str(Path(__file__).resolve().parents[1] / 'lab'))
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





if __name__ == '__main__':
    unittest.main()
