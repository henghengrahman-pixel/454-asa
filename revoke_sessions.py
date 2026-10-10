import os, sqlite3
from pathlib import Path
path=Path(os.environ.get('DATA_DIR','./data'))/'monitor.sqlite3'
if not path.exists(): raise SystemExit('Database tidak ditemukan')
with sqlite3.connect(path) as db:
    db.execute('DELETE FROM sessions')
print('Semua session login dicabut.')
