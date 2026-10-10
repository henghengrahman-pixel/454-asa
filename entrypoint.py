"""Prepare only the application's volume files, then drop root privileges."""
import os
from pathlib import Path
import sys

UID = 10001
GID = 10001

def prepare_volume(directory):
    directory = Path(directory)
    if not directory.is_absolute() or directory == Path('/') or directory.is_symlink():
        raise RuntimeError('DATA_DIR harus direktori absolut khusus data, bukan / atau symlink')
    forbidden = ('/app', '/etc', '/usr', '/bin', '/sbin', '/proc', '/sys', '/dev', '/root')
    if any(directory == Path(p) or Path(p) in directory.parents for p in forbidden):
        raise RuntimeError('DATA_DIR tidak boleh menunjuk direktori sistem/aplikasi')
    directory.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(directory, UID, GID)
        os.chmod(directory, 0o700)
        for name in ('monitor.sqlite3', 'monitor.sqlite3-wal', 'monitor.sqlite3-shm', 'monitor.sqlite3-journal'):
            path = directory / name
            if path.is_symlink():
                raise RuntimeError('Database tidak boleh berupa symlink')
            if path.exists():
                if not path.is_file():
                    raise RuntimeError('Path database harus file biasa')
                os.chown(path, UID, GID)
                os.chmod(path, 0o600)

def main():
    try:
        prepare_volume(os.environ.get('DATA_DIR', '/data'))
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(GID)
            os.setuid(UID)
        os.umask(0o077)
        os.execv(sys.executable, [sys.executable, '/app/app.py'])
    except (OSError, RuntimeError) as exc:
        raise SystemExit('Startup volume gagal: ' + str(exc))

if __name__ == '__main__':
    main()
