import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from entrypoint import prepare_volume

class VolumeTests(unittest.TestCase):
    def test_reject_system_directory(self):
        for path in ('/', '/app', '/etc/db', 'relative'):
            with self.assertRaises(RuntimeError):
                prepare_volume(path)

    @unittest.skipUnless(os.geteuid() == 0, 'Root required to simulate mounted volume ownership')
    def test_volume_preparation_preserves_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            volume = Path(tmp) / 'data'
            volume.mkdir(mode=0o700)
            database = volume / 'monitor.sqlite3'
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE preserved(value TEXT)')
                db.execute("INSERT INTO preserved VALUES('original-data')")
            # Workspace filesystem cannot chown arbitrary UIDs; assert requested
            # ownership changes with a mock and inspect actual database contents.
            with patch('entrypoint.os.chown') as chown:
                prepare_volume(str(volume))
                self.assertEqual(chown.call_count, 2)
                chown.assert_any_call(volume, 10001, 10001)
                chown.assert_any_call(database, 10001, 10001)
            with sqlite3.connect(database) as db:
                self.assertEqual(db.execute('SELECT value FROM preserved').fetchone()[0], 'original-data')
            self.assertEqual(database.stat().st_mode & 0o777, 0o600)

if __name__ == '__main__':
    unittest.main(verbosity=2)
