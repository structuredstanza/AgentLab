"""Behavioral checks for untrusted guest artifact extraction."""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
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
    def test_exports_every_segment_and_manifest_correlation(self):
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
            rotated = capture_dir / 'native-sse-1763.ndjson'
            rotated.write_bytes(b'{"Direction":"request"}\n')
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

            with mock.patch.object(lab, 'ROOT', root), \
                    mock.patch.object(lab, 'PROXY_STATE', proxy_state):
                manifest = lab.export_provider_proxy_traffic(raw)

            artifacts = raw / 'provider-proxy-traffic'
            self.assertEqual((artifacts / 'native-sse.ndjson').read_bytes(), capture)
            self.assertEqual((artifacts / 'native-sse-1763.ndjson').read_bytes(),
                             b'{"Direction":"request"}\n')
            self.assertEqual((artifacts.stat().st_mode & 0o777), 0o700)
            self.assertEqual(((artifacts / 'native-sse.ndjson').stat().st_mode & 0o777), 0o600)
            self.assertEqual([segment['source'] for segment in manifest['segments']],
                             ['proxy-state/captures/native-sse-1763.ndjson',
                              'proxy-state/captures/native-sse.ndjson'])
            self.assertEqual(manifest['segments'][1]['sha256'], hashlib.sha256(capture).hexdigest())
            self.assertEqual(manifest['correlation_fields'],
                             ['Direction', 'Provider', 'Model', 'Profile', 'SessionID'])
            self.assertNotIn('opaque-session-id', json.dumps(manifest))
            self.assertEqual(
                sorted(path.relative_to(raw).as_posix() for path in raw.rglob('*')),
                ['postgres.dump', 'provider-proxy-traffic',
                 'provider-proxy-traffic/native-sse-1763.ndjson',
                 'provider-proxy-traffic/native-sse.ndjson'],
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
        (root / 'deployment/m1nervac0nsole-cliproxy.service').write_text('[Service]\n')
        return mock.patch.multiple(
            lab, ROOT=root, PROXY_BIN=root / 'dist/provider-proxy', PROXY_STATE=root / 'proxy-state',
            PROXY_TOKEN=root / 'secrets/native-proxy-token',
            PROXY_UNIT=root / 'deployment/m1nervac0nsole-cliproxy.service',
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
            installed = home / '.config/systemd/user/m1nervac0nsole-cliproxy.service'
            installed.parent.mkdir(parents=True)
            installed.write_text('user-owned service\n')
            with self.prepare(root), mock.patch.object(lab.Path, 'home', return_value=home):
                with mock.patch.object(lab.subprocess, 'run'):
                    with self.assertRaisesRegex(RuntimeError, 'unrelated service'):
                        lab.start_provider_proxy()
            self.assertEqual(installed.read_text(), 'user-owned service\n')

    def test_checked_in_unit_symlink_is_replaced_by_a_rendered_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, home = Path(tmp) / 'lab', Path(tmp) / 'home'
            root.mkdir()
            installed = home / '.config/systemd/user/m1nervac0nsole-cliproxy.service'
            installed.parent.mkdir(parents=True)
            with self.prepare(root), mock.patch.object(lab.Path, 'home', return_value=home):
                lab.PROXY_UNIT.write_text('WorkingDirectory=@ROOT@/dist\n')
                installed.symlink_to(lab.PROXY_UNIT)
                with mock.patch.object(lab.subprocess, 'run'), mock.patch.object(
                    lab.urllib.request, 'urlopen',
                    side_effect=lambda *args, **kwargs: io.BytesIO(b'{"status":"ok"}'),
                ):
                    lab.start_provider_proxy()
                self.assertFalse(installed.is_symlink())
                self.assertEqual(installed.read_text(), lab.render_proxy_unit(root))
                self.assertIn(f'WorkingDirectory={root}/dist\n', installed.read_text())

    def test_stale_render_is_migrated_and_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, home = Path(tmp) / 'lab', Path(tmp) / 'home'
            root.mkdir()
            installed = home / '.config/systemd/user/m1nervac0nsole-cliproxy.service'
            installed.parent.mkdir(parents=True)
            with self.prepare(root), mock.patch.object(lab.Path, 'home', return_value=home):
                lab.PROXY_UNIT.write_text('WorkingDirectory=@ROOT@/dist\n')
                installed.write_text(f'{lab.UNIT_MARKER}\nWorkingDirectory=/old/checkout/dist\n')
                output = io.StringIO()
                with mock.patch.object(lab.subprocess, 'run'), mock.patch.object(
                    lab.urllib.request, 'urlopen',
                    side_effect=lambda *args, **kwargs: io.BytesIO(b'{"status":"ok"}'),
                ), contextlib.redirect_stdout(output):
                    lab.start_provider_proxy()
                self.assertEqual(installed.read_text(), lab.render_proxy_unit(root))
                self.assertIn(f'Migrating {installed.name} to {root}', output.getvalue())





class SharedStateGuardTests(unittest.TestCase):
    def test_another_running_agentlab_vm_blocks_start(self):
        listing = mock.Mock(returncode=0,
                            stdout=f'{lab.NAME}\nm1nervac0nsole-agentlab-old\nm1nervac0nsole-htb-1\n',
                            stderr='')
        with mock.patch.object(lab, 'start_provider_proxy'), \
                mock.patch.object(lab.subprocess, 'run', return_value=listing):
            with self.assertRaisesRegex(RuntimeError, 'm1nervac0nsole-agentlab-old'):
                lab.start()

    def test_own_and_unrelated_sandboxes_do_not_block(self):
        listing = mock.Mock(returncode=0,
                            stdout=f'{lab.NAME}\nm1nervac0nsole-htb-20261104t2200z\n',
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
            self.assertTrue(lab.guest_dist_stale(Path(tmp) / 'm1nervac0nsole'))

    def check(self, source_age, binary_age, source_rel):
        """Staleness of a fake binary against one source file of a fake module tree.

        Times are anchored an hour ahead so the checkout's own mtimes can never
        decide the result."""
        base = time.time() + 3600
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module = root / 'm1nervac0nsole'
            source = module / source_rel
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text('package main')
            binary = root / 'built-m1nervac0nsole'
            binary.write_bytes(b'bin')
            os.utime(source, (base - source_age,) * 2)
            os.utime(binary, (base - binary_age,) * 2)
            with mock.patch.object(lab, 'ROOT', root), \
                    mock.patch.object(lab, 'M1NERVAC0NSOLE_SRC', module):
                return lab.guest_dist_stale(binary)

    def test_binary_newer_than_every_input_is_current(self):
        self.assertFalse(self.check(120, 60, 'main.go'))

    def test_newer_input_makes_the_build_stale(self):
        self.assertTrue(self.check(0, 60, 'main.go'))

    def test_newer_file_in_any_package_makes_the_build_stale(self):
        """A hand-picked list of packages missed linked ones such as execbox/."""
        self.assertTrue(self.check(0, 60, 'execbox/x.go'))


class ImageBuildTests(unittest.TestCase):
    """`image-build` builds a candidate; only --replace may move the configured tag.

    A failed build or a missing tool must leave the tag the sandbox boots exactly
    where it was, or the next `./lab start` boots an unverified image."""

    TAG = 'agentlab/m1nervac0nsole:deepseek-v1'

    def spec(self, tmp, text=None):
        spec = Path(tmp) / 'sandbox.yaml'
        spec.write_text(text if text is not None else f'image: {self.TAG}\npull_policy: never\n')
        return spec

    def run_image_build(self, ids=None, replace=False, **patches):
        """Run image_build with docker stubbed; return (summary, argv list, msb mock)."""
        ids = ids or {}
        self.calls = []

        def run(argv, **kwargs):
            self.calls.append(argv)
            if argv[:3] == ['docker', 'image', 'inspect']:
                reference = argv[-1]
                if reference not in ids:
                    return mock.Mock(returncode=1, stdout='', stderr='no such image')
                return mock.Mock(returncode=0, stdout=ids[reference] + '\n', stderr='')
            return mock.Mock(returncode=0, stdout='', stderr='')

        patches.setdefault('image_arch', mock.Mock(return_value='amd64'))
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(mock.patch.object(lab, 'image_tag', return_value=self.TAG))
            stack.enter_context(mock.patch.object(lab.subprocess, 'run', side_effect=run))
            msb = stack.enter_context(mock.patch.object(lab, 'msb'))
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(lab, name, value))
            summary = lab.image_build(replace)
        self.output = output.getvalue()
        return summary, self.calls, msb

    def test_tag_comes_from_the_sandbox_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(lab.image_tag(self.spec(tmp)), self.TAG)
            for text in ('pull_policy: never\n', 'image: a\nimage: b\n',
                         'image: two words\n', 'image:\n'):
                with self.subTest(text=text):
                    with self.assertRaises(RuntimeError):
                        lab.image_tag(self.spec(tmp, text))

    def test_candidate_build_leaves_the_tag_alone(self):
        summary, calls, msb = self.run_image_build(ids={self.TAG + '-candidate': 'sha256:candidate'})
        self.assertEqual(summary['candidate'], self.TAG + '-candidate')
        self.assertFalse(summary['tag_replaced'])
        self.assertNotIn('rollback', summary)
        self.assertFalse([argv for argv in calls if argv[:2] == ['docker', 'tag']])
        self.assertEqual([argv for argv in calls if argv[:2] == ['docker', 'build']][0][-1],
                         str(lab.ROOT))
        # The caveat is printed, not implied: a rebuild is not the historical image.
        self.assertIn('does not reproduce the historical image', self.output)
        # No sandbox is created, started, stopped or removed.
        msb.assert_not_called()

    def test_failed_capability_check_never_replaces_the_tag(self):
        with self.assertRaisesRegex(RuntimeError, 'missing: nmap'):
            self.run_image_build(ids={self.TAG: 'sha256:old'},
                                 check_image_capabilities=mock.Mock(
                                     side_effect=RuntimeError('missing: nmap')))
        self.assertFalse([argv for argv in self.calls if argv[:2] == ['docker', 'tag']])

    def test_failed_build_never_inspects_or_tags_the_configured_tag(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_image_build(ids={self.TAG: 'sha256:old'},
                                 build_image_candidate=mock.Mock(
                                     side_effect=subprocess.CalledProcessError(1, 'docker build')))
        self.assertFalse([argv for argv in self.calls if argv[:2] == ['docker', 'tag']])
        self.assertFalse([argv for argv in self.calls if argv[:3] == ['docker', 'image', 'inspect']])

    def test_replace_preserves_the_previous_image_first(self):
        summary, calls, msb = self.run_image_build(
            ids={self.TAG: 'sha256:oldimage0123456789',
                 self.TAG + '-candidate': 'sha256:candidate'},
            replace=True)
        rollback = self.TAG + '-prev-oldimage0123'
        self.assertEqual(summary['rollback'], rollback)
        self.assertTrue(summary['tag_replaced'])
        self.assertEqual([argv for argv in calls if argv[:2] == ['docker', 'tag']],
                         [['docker', 'tag', self.TAG, rollback],
                          ['docker', 'tag', self.TAG + '-candidate', self.TAG]])
        # Even the replacing path only moves docker tags: no sandbox is touched.
        msb.assert_not_called()

    def test_replace_without_a_local_image_just_moves_the_tag(self):
        summary, calls, _ = self.run_image_build(
            ids={self.TAG + '-candidate': 'sha256:candidate'}, replace=True)
        self.assertNotIn('rollback', summary)
        self.assertEqual([argv for argv in calls if argv[:2] == ['docker', 'tag']],
                         [['docker', 'tag', self.TAG + '-candidate', self.TAG]])

    def test_capability_check_passes_names_as_argv(self):
        with mock.patch.object(lab.subprocess, 'run',
                               return_value=mock.Mock(returncode=0, stdout='', stderr='')) as run:
            lab.check_image_capabilities('repo/img:tag')
        argv = run.call_args.args[0]
        self.assertEqual(argv[:7], ['docker', 'run', '--rm', '--entrypoint', 'sh', 'repo/img:tag', '-c'])
        self.assertIn('command -v', argv[7])
        self.assertEqual(argv[8], 'sh')
        self.assertIn('/opt/m1nervac0nsole/m1nervac0nsole', argv[9:])
        self.assertIn('/opt/agentlab/guest-start.py', argv[9:])
        # One argv entry per capability: no path is split or shell-quoted.
        self.assertFalse([name for name in argv[9:] if not name or ' ' in name])

    def test_capability_check_reports_the_missing_entry(self):
        failed = mock.Mock(returncode=1, stdout='missing: nmap\n', stderr='')
        with mock.patch.object(lab.subprocess, 'run', return_value=failed):
            with self.assertRaisesRegex(RuntimeError, 'missing: nmap'):
                lab.check_image_capabilities('repo/img:tag')

    def test_inventory_covers_the_runtime_entrypoints(self):
        entries = lab.image_capabilities()
        for name in ('nmap', 'tcpdump', 'strace', 'psql', 'gdb', 'r2', 'jadx', 'analyzeHeadless',
                     'searchsploit', 'sqlmap', 'playwright', '/opt/ms-playwright/current/chrome',
                     '/opt/m1nervac0nsole/m1nervac0nsole', '/opt/agentlab/guest-start.py'):
            with self.subTest(name=name):
                self.assertIn(name, entries)
        self.assertEqual(len(entries), len(set(entries)), 'capability inventory repeats an entry')

    def test_a_checkout_path_with_spaces_stays_one_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'check out'
            root.mkdir()
            calls = []

            def run(argv, **kwargs):
                calls.append((argv, kwargs))
                return mock.Mock(returncode=0, stdout='', stderr='')

            with mock.patch.object(lab, 'image_arch', return_value='amd64'), \
                    mock.patch.object(lab.subprocess, 'run', side_effect=run):
                candidate = lab.build_image_candidate('repo/img:tag', root)
        self.assertEqual(candidate, 'repo/img:tag-candidate')
        self.assertEqual(calls[0][0], [str(root / 'm1nervac0nsole/build.sh')])
        self.assertEqual(calls[0][1]['env']['M1NERVAC0NSOLE_TARGET_ARCH'], 'amd64')
        self.assertEqual(calls[0][1]['env']['M1NERVAC0NSOLE_TARGET_OS'], 'linux')
        build = calls[1][0]
        self.assertEqual(build[build.index('-f') + 1], str(root / 'deployment/Dockerfile'))
        self.assertEqual(build[build.index('-t') + 1], 'repo/img:tag-candidate')
        self.assertEqual(build[-1], str(root))

    def test_other_architectures_are_refused(self):
        with mock.patch.object(lab.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(RuntimeError, 'amd64-only'):
                lab.image_arch()

    def test_load_command_is_printed_not_run(self):
        command = lab.image_load_command(self.TAG)
        self.assertIn('docker save', command)
        self.assertIn('MSB_HOME=', command)
        self.assertIn('load -i', command)
        self.assertIn(self.TAG, command)


class StateStorageTests(unittest.TestCase):
    def spec_root(self):
        """The checkout root the checked-in spec's mount lines name."""
        for line in lab.SANDBOX_CONF.read_text().splitlines():
            line = line.strip()
            if line.startswith('- ') and '/state:' in line:
                return line[2:].split('/state:')[0]
        raise AssertionError('no /state mount in the sandbox spec')

    def relocated_spec(self, tmp):
        """A copy of the checked-in spec whose mounts name tmp as the root."""
        spec = Path(tmp) / 'sandbox.yaml'
        spec.write_text(lab.SANDBOX_CONF.read_text().replace(self.spec_root() + '/', tmp + '/'))
        return spec

    def conf_text(self, quota_mb):
        path, temporary = lab.sandbox_conf(quota_mb)
        try:
            return path.read_text(), temporary
        finally:
            if temporary:
                path.unlink()

    def test_default_keeps_the_checked_in_spec(self):
        # The spec is used as is only at the path its mounts name; a relocated
        # checkout gets a rewritten copy (see the relocation test below). The
        # spec is relocated too, so the test never needs the checked-in path to
        # exist on the runner.
        with tempfile.TemporaryDirectory() as tmp:
            spec = self.relocated_spec(tmp)
            with mock.patch.object(lab, 'ROOT', Path(tmp)), mock.patch.object(lab, 'SANDBOX_CONF', spec):
                path, temporary = lab.sandbox_conf(None)
            self.assertEqual((path, temporary), (spec, False))

    def test_host_mounts_follow_a_relocated_checkout(self):
        # The spec mounts host paths under the repository root; a clone at
        # another path must rewrite them or /state, /dist and the secrets mount
        # empty or missing paths.
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(lab, 'ROOT', Path(tmp)):
                path, temporary = lab.sandbox_conf(None)
                self.assertTrue(temporary)
                text = path.read_text()
                path.unlink()
        self.assertIn(tmp + '/state:/state', text)
        self.assertNotIn(self.spec_root() + '/', text)

    def test_quota_is_rewritten_only_on_the_state_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = self.relocated_spec(tmp)
            with mock.patch.object(lab, 'ROOT', Path(tmp)), mock.patch.object(lab, 'SANDBOX_CONF', spec):
                text, temporary = self.conf_text(409600)
            self.assertTrue(temporary)
            self.assertIn(':/state:quota=409600', text)
            self.assertEqual(text.count('quota='), 1)
            # Everything else in the spec is untouched.
            base = spec.read_text().replace(
                ':/state:quota=' + spec.read_text().split(':/state:quota=')[1].split()[0],
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


class StreamRotationTests(unittest.TestCase):
    """A bounded stream is what makes an export copy segments and `prune` safe."""

    def test_full_stream_becomes_an_immutable_segment(self):
        with tempfile.TemporaryDirectory() as tmp:
            stream = Path(tmp) / 'host-events.jsonl'
            stream.write_bytes(b'{"kind":"old"}\n')
            segment = lab.rotate_stream(stream, limit=1)
            self.assertTrue(segment.name.startswith('host-events-'))
            self.assertTrue(segment.name.endswith('.jsonl'))
            self.assertEqual(segment.read_bytes(), b'{"kind":"old"}\n')
            self.assertFalse(stream.exists())
            stream.write_bytes(b'{"kind":"new"}\n')
            self.assertEqual(segment.read_bytes(), b'{"kind":"old"}\n')

    def test_stream_below_the_limit_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            stream = Path(tmp) / 'host-events.jsonl'
            stream.write_bytes(b'{}\n')
            self.assertIsNone(lab.rotate_stream(stream, limit=1 << 20))
            self.assertEqual(stream.read_bytes(), b'{}\n')


class PruneTests(unittest.TestCase):
    """`prune` is the only deletion path, so it must refuse anything unverified."""

    EXPORT = '20260101T000000.000000Z'

    def prepare(self, root):
        """A verified export of two rotated segments, plus the live streams."""
        segments = [root / 'host-events-1.jsonl',
                    root / 'proxy-state/captures/native-sse-1.ndjson']
        for path in segments:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'{"segment":1}\n')
        for path in (root / 'host-events.jsonl',
                     root / 'proxy-state/captures/native-sse.ndjson'):
            path.write_bytes(b'{"live":true}\n')
        output = root / 'exports' / self.EXPORT
        raw = output / 'raw'
        raw.mkdir(parents=True)
        artifact = raw / 'host-events.jsonl'
        artifact.write_bytes(b'{"kind":"command_start"}\n')
        manifest = {
            'sha256': {'raw/host-events.jsonl': hashlib.sha256(artifact.read_bytes()).hexdigest()},
            'prunable': [{'source': str(path.relative_to(root)),
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in segments],
        }
        (output / 'manifest.json').write_text(json.dumps(manifest))
        return output, segments

    def test_missing_export_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(lab, 'ROOT', Path(tmp)):
                with self.assertRaisesRegex(RuntimeError, 'not found'):
                    lab.prune(self.EXPORT, dry_run=True)

    def test_export_without_a_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'exports' / self.EXPORT).mkdir(parents=True)
            with mock.patch.object(lab, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'no manifest'):
                    lab.prune(self.EXPORT)

    def test_artifact_that_does_not_match_the_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output, segments = self.prepare(root)
            (output / 'raw/host-events.jsonl').write_bytes(b'tampered\n')
            with mock.patch.object(lab, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'does not match'):
                    lab.prune(self.EXPORT)
            self.assertTrue(all(path.exists() for path in segments))

    def test_dry_run_lists_what_it_would_delete_and_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output, segments = self.prepare(root)
            with mock.patch.object(lab, 'ROOT', root), \
                    mock.patch('sys.stdout', new_callable=io.StringIO) as printed:
                targets = lab.prune(self.EXPORT, dry_run=True)
            self.assertEqual(sorted(targets), sorted(segments))
            self.assertTrue(all(path.exists() for path in segments))
            self.assertTrue((root / 'host-events.jsonl').exists())
            self.assertIn('"dry_run": true', printed.getvalue())

    def test_prune_deletes_only_the_exported_segments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output, segments = self.prepare(root)
            with mock.patch.object(lab, 'ROOT', root), \
                    mock.patch('sys.stdout', new_callable=io.StringIO):
                targets = lab.prune(self.EXPORT)
            self.assertEqual(sorted(targets), sorted(segments))
            self.assertFalse(any(path.exists() for path in segments))
            self.assertTrue((root / 'host-events.jsonl').exists())
            self.assertTrue((root / 'proxy-state/captures/native-sse.ndjson').exists())
            self.assertTrue((output / 'manifest.json').exists())

    def test_manifest_cannot_widen_what_prune_deletes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output, segments = self.prepare(root)
            live = root / 'host-events.jsonl'
            manifest = json.loads((output / 'manifest.json').read_text())
            manifest['prunable'].append({'source': 'host-events.jsonl',
                                         'sha256': hashlib.sha256(live.read_bytes()).hexdigest()})
            (output / 'manifest.json').write_text(json.dumps(manifest))
            with mock.patch.object(lab, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'unprunable source'):
                    lab.prune(self.EXPORT)
            self.assertTrue(live.exists())
            self.assertTrue(all(path.exists() for path in segments))

    def test_segment_that_grew_after_the_export_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, segments = self.prepare(root)
            segments[0].write_bytes(b'{"segment":1}\n{"segment":2}\n')
            with mock.patch.object(lab, 'ROOT', root), \
                    mock.patch('sys.stdout', new_callable=io.StringIO):
                lab.prune(self.EXPORT)
            self.assertTrue(segments[0].exists())
            self.assertFalse(segments[1].exists())


class FailedExportTests(unittest.TestCase):
    def test_failed_export_leaves_no_partial_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seen = []

            def die(*args, **kwargs):
                seen.extend(path.name for path in (root / 'exports').rglob('*'))
                raise RuntimeError('psql died')

            with mock.patch.object(lab, 'ROOT', root), \
                    mock.patch.object(lab, 'guest',
                                      return_value=mock.Mock(stdout='llm_records\n')), \
                    mock.patch.object(lab.subprocess, 'Popen', side_effect=die):
                with self.assertRaisesRegex(RuntimeError, 'psql died'):
                    lab.export()
            self.assertTrue(seen, 'the export failed before it wrote anything')
            self.assertEqual(list((root / 'exports').iterdir()), [])


class HostEventExportTests(unittest.TestCase):
    def test_exports_every_segment_and_only_rotated_ones_are_prunable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'host-events-1.jsonl').write_bytes(b'{"kind":"old"}\n')
            (root / 'host-events.jsonl').write_bytes(b'{"kind":"live"}\n')
            raw = root / 'export/raw'
            raw.mkdir(parents=True)
            with mock.patch.object(lab, 'ROOT', root):
                entry = lab.export_host_events(raw)
            self.assertEqual([segment['source'] for segment in entry['segments']],
                             ['host-events-1.jsonl', 'host-events.jsonl'])
            self.assertEqual((raw / 'host-events/host-events-1.jsonl').read_bytes(),
                             b'{"kind":"old"}\n')
            self.assertEqual(lab.prunable_segments((entry,)),
                             [{'source': 'host-events-1.jsonl',
                               'sha256': hashlib.sha256(b'{"kind":"old"}\n').hexdigest()}])


class GuestExportRootsTests(unittest.TestCase):
    def test_export_carries_both_runtime_logs_and_no_ca_material(self):
        path = Path(__file__).resolve().parents[2] / 'deployment/guest-export.py'
        loader = importlib.machinery.SourceFileLoader('guest_export', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        exported = [arcname for _, arcname in module.ROOTS + module.EXTRA_FILES]
        self.assertIn('logs/egress.log', exported)
        self.assertIn('logs/postgres.log', exported)
        for source, _ in module.ROOTS + module.EXTRA_FILES:
            self.assertNotIn('egress', source.parts[2:], source)
            self.assertNotIn(source.suffix, ('.key', '.pem'), source)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            for directory in ('m1nervac0nsole', 'captures', 'runtime/logs/postgres',
                              'runtime/egress'):
                (state / directory).mkdir(parents=True)
            (state / 'm1nervac0nsole/app.db').write_text('fixture')
            (state / 'runtime/logs/egress.log').write_text('egress\n')
            (state / 'runtime/logs/postgres/postgres.log').write_text('postgres\n')
            (state / 'runtime/egress/ca.key').write_text('private key')
            module.ROOTS = [(state / 'm1nervac0nsole', 'application'),
                            (state / 'captures', 'captures')]
            module.EXTRA_FILES = [(state / Path(*source.parts[2:]), arcname)
                                  for source, arcname in module.EXTRA_FILES]
            stream = io.BytesIO()
            with mock.patch.object(module.sys, 'stdout', mock.Mock(buffer=stream)):
                module.main()
            names = tarfile.open(fileobj=io.BytesIO(stream.getvalue())).getnames()
        self.assertIn('logs/egress.log', names)
        self.assertIn('logs/postgres.log', names)
        self.assertEqual([name for name in names if 'egress/' in name or name.endswith('.key')], [])


if __name__ == '__main__':
    unittest.main()
