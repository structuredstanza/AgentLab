"""Behavioral checks for untrusted guest artifact extraction."""
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


class SDKBootstrapTests(unittest.TestCase):
    def prepare(self, root, home):
        (root / 'secrets').mkdir()
        (root / 'deployment').mkdir()
        (root / 'deployment/artex-sdk-bridge.service').write_text('[Service]\n')
        return mock.patch.multiple(
            lab, ROOT=root, SDK_STATE=root / 'sdk-state',
            SDK_TOKEN=root / 'secrets/sdk-bridge-token',
        )

    def test_restart_preserves_private_bridge_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, home = Path(tmp) / 'lab', Path(tmp) / 'home'
            root.mkdir()
            with self.prepare(root, home), mock.patch.object(lab.Path, 'home', return_value=home):
                with mock.patch.object(lab.subprocess, 'run'), mock.patch.object(
                    lab.urllib.request, 'urlopen',
                    side_effect=lambda *args, **kwargs: io.BytesIO(b'{"status":"ok"}'),
                ):
                    lab.start_sdk_bridge()
                    token = lab.SDK_TOKEN.read_bytes()
                    lab.start_sdk_bridge()
                    self.assertEqual(lab.SDK_TOKEN.read_bytes(), token)
                    self.assertGreaterEqual(len(token.strip()), 32)
                    self.assertEqual(lab.SDK_TOKEN.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(lab.SDK_STATE.stat().st_mode & 0o777, 0o700)

    def test_unrelated_user_service_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, home = Path(tmp) / 'lab', Path(tmp) / 'home'
            root.mkdir()
            installed = home / '.config/systemd/user/artex-sdk-bridge.service'
            installed.parent.mkdir(parents=True)
            installed.write_text('user-owned service\n')
            with self.prepare(root, home), mock.patch.object(lab.Path, 'home', return_value=home):
                with self.assertRaisesRegex(RuntimeError, 'unrelated service'):
                    lab.start_sdk_bridge()
            self.assertEqual(installed.read_text(), 'user-owned service\n')


if __name__ == '__main__':
    unittest.main()
