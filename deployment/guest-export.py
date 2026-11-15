#!/usr/bin/python3
"""Stream task/capture files and the egress and PostgreSQL logs as tar.

Live SQLite is snapshotted in the writer's kernel.
"""
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tarfile
import tempfile
import time

STATE = Path('/state')
ROOTS = [(STATE / 'm1nervac0nsole', 'application'),
         (STATE / 'captures', 'captures')]
# Only these two logs are exported from the runtime tree. The egress CA directory
# beside them holds the CA private key, so /state/runtime is never copied whole.
EXTRA_FILES = [(STATE / 'runtime/logs/egress.log', 'logs/egress.log'),
               (STATE / 'runtime/logs/postgres/postgres.log', 'logs/postgres.log')]


def add_stream(archive, stream, arcname):
    """Add an already-open regular file with a private mode."""
    info = archive.gettarinfo(fileobj=stream, arcname=arcname)
    info.mode = 0o600
    archive.addfile(info, stream)


def main():
    skipped = []
    started = time.time_ns()
    with tempfile.TemporaryDirectory(prefix='agentlab-export-') as tmp:
        with tarfile.open(fileobj=sys.stdout.buffer, mode='w|', dereference=False) as archive:
            for root, prefix in ROOTS:
                for directory, dirs, files in os.walk(root, followlinks=False):
                    for name in list(dirs):
                        path = Path(directory) / name
                        if path.is_symlink():
                            skipped.append({'path': str(path), 'reason': 'symlink'})
                            dirs.remove(name)
                    for name in files:
                        path = Path(directory) / name
                        database = path.with_name(name[:-4]) if name.endswith(('-wal', '-shm')) else None
                        if database and database.is_file() and not database.is_symlink():
                            with database.open('rb') as stream:
                                if stream.read(16) == b'SQLite format 3\x00':
                                    skipped.append({'path': str(path), 'reason': 'SQLite sidecar; database backed up online'})
                                    continue
                        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                            skipped.append({'path': str(path), 'reason': 'non-regular file'})
                            continue
                        arcname = prefix + '/' + str(path.relative_to(root))
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, 'rb') as stream:
                            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                                raise RuntimeError(f'Capture changed file type: {path}')
                            sqlite = stream.read(16) == b'SQLite format 3\x00'
                            stream.seek(0)
                            if sqlite:
                                backup = Path(tmp) / 'snapshot.sqlite'
                                with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as source:
                                    with sqlite3.connect(backup) as target:
                                        source.backup(target)
                                archive.add(backup, arcname=arcname, recursive=False)
                                backup.unlink()
                            else:
                                add_stream(archive, stream, arcname)
            for path, arcname in EXTRA_FILES:
                if path.is_symlink():
                    skipped.append({'path': str(path), 'reason': 'symlink'})
                    continue
                if not path.exists():
                    skipped.append({'path': str(path), 'reason': 'missing'})
                    continue
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        skipped.append({'path': str(path), 'reason': 'non-regular file'})
                        continue
                    add_stream(archive, stream, arcname)
            body = json.dumps({'started_at_ns': started, 'finished_at_ns': time.time_ns(),
                               'skipped': skipped, 'sqlite': 'online backup inside guest',
                               'filesystem': 'online copy, not an atomic machine checkpoint'}).encode()
            info = tarfile.TarInfo('capture-export.json')
            info.size = len(body)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(body))


if __name__ == '__main__':
    main()
