import csv, html, io, json, os, re, secrets, sqlite3, threading, time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from security import cipher, verify_password, verify_totp

ROOT = Path(__file__).parent
LOCK = threading.RLock()
DB = None
ENV = None

def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def initialize():
    global DB, ENV
    ENV = {key: os.environ.get(key, '') for key in ('ADMIN_USERNAME','ADMIN_PASSWORD_HASH','ADMIN_TOTP_SECRET','ENCRYPTION_KEY','APP_URL')}
    if any(not value for value in ENV.values()):
        raise RuntimeError('ENV wajib: ADMIN_USERNAME, ADMIN_PASSWORD_HASH, ADMIN_TOTP_SECRET, ENCRYPTION_KEY, APP_URL')
    cipher(ENV['ENCRYPTION_KEY'])
    from security import totp
    totp(ENV['ADMIN_TOTP_SECRET'])
    if not verify_password('__configuration_check__', ENV['ADMIN_PASSWORD_HASH']):
        salt, digest = ENV['ADMIN_PASSWORD_HASH'].split(':')
        if len(bytes.fromhex(salt)) != 16 or len(bytes.fromhex(digest)) != 64:
            raise RuntimeError('ADMIN_PASSWORD_HASH tidak valid; gunakan setup_admin.py')
    url = urlsplit(ENV['APP_URL'])
    if url.scheme not in ('http','https') or not url.netloc:
        raise RuntimeError('APP_URL harus URL absolut')
    data = Path(os.environ.get('DATA_DIR', './data'))
    data.mkdir(parents=True, exist_ok=True)
    DB = str(data / 'monitor.sqlite3')
    with connect() as db:
        db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS websites(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, url TEXT NOT NULL, credential TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, website_id INTEGER NOT NULL REFERENCES websites(id), market TEXT NOT NULL, period TEXT NOT NULL, number TEXT NOT NULL, revenue INTEGER NOT NULL, payout INTEGER NOT NULL, invoices INTEGER NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, created TEXT NOT NULL, UNIQUE(website_id,market,period));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, event TEXT NOT NULL, detail TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, csrf TEXT NOT NULL, authenticated INTEGER NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS failures(id INTEGER PRIMARY KEY, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS used_totp(step INTEGER PRIMARY KEY);
        ''')
    os.chmod(DB, 0o600)

def audit(db, event, detail):
    db.execute('INSERT INTO audit(event,detail,created) VALUES(?,?,?)', (event,detail,time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())))

def escaped(value):
    return html.escape(str(value), quote=True)

def page(title, body, session=None):
    nav = ''
    if session and session['authenticated']:
        nav = '<nav><b>IDN MONITOR</b><a href="/">Dashboard</a><a href="/websites">Website</a><a href="/reports">Rekonsiliasi</a><a href="/audit">Audit log</a><a href="/export">Export CSV</a>' + form('/logout', session, '<button>Logout</button>') + '</nav>'
    return '<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + escaped(title) + '</title><link rel="stylesheet" href="/style.css">' + nav + '<main><h1>' + escaped(title) + '</h1>' + body + '</main></html>'

def form(action, session, content):
    return '<form method="post" action="'+action+'"><input type="hidden" name="csrf" value="'+escaped(session['csrf'])+'">'+content+'</form>'

def field(name, label, kind='text', value='', required=True):
    return '<label>'+label+'<input name="'+name+'" type="'+kind+'" value="'+escaped(value)+'" '+('required' if required else '')+' maxlength="2048"></label>'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, body='', content_type='text/html; charset=utf-8', cookie=None, location=None):
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        if os.environ.get('COOKIE_SECURE','true') == 'true':
            self.send_header('Strict-Transport-Security','max-age=31536000')
        if cookie:
            secure = '; Secure' if os.environ.get('COOKIE_SECURE','true') == 'true' else ''
            self.send_header('Set-Cookie','sid='+cookie+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800'+secure)
        if location:
            self.send_header('Location',location)
        raw = body.encode()
        self.send_header('Content-Length',str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def session(self, create=False):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie',''))
            token = cookies['sid'].value if 'sid' in cookies else ''
        except Exception:
            token = ''
        with connect() as db:
            db.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
            row = db.execute('SELECT * FROM sessions WHERE token=?',(token,)).fetchone()
            if row or not create:
                return row
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            db.execute('INSERT INTO sessions VALUES(?,?,0,?)',(token,csrf,time.time()+600))
            return db.execute('SELECT * FROM sessions WHERE token=?',(token,)).fetchone()

    def do_GET(self):
        try:
            self.get()
        except Exception:
            self.respond(500,page('Kesalahan','Permintaan gagal. Periksa konfigurasi atau coba kembali.'))

    def get(self):
        route = urlsplit(self.path).path
        if route == '/health':
            with connect() as db:
                db.execute('SELECT 1')
            return self.respond(200,'{"status":"ok"}','application/json')
        if route == '/style.css':
            return self.respond(200,(ROOT/'style.css').read_text(),'text/css')
        session = self.session(route == '/login')
        if route == '/login':
            body = form('/login',session,field('username','ID admin')+field('password','Password','password')+field('otp','Kode 2FA (6 digit)')+'<button>Masuk</button>')
            return self.respond(200,page('Login admin',body),cookie=session['token'])
        if not session or not session['authenticated']:
            return self.respond(303,location='/login')
        with connect() as db:
            websites = db.execute('SELECT id,code,name,url,updated FROM websites ORDER BY name').fetchall()
            reports = db.execute('SELECT r.*,w.name FROM reports r JOIN websites w ON w.id=r.website_id ORDER BY r.id DESC').fetchall()
            if route == '/':
                body = '<div class="cards"><section><h2>Website</h2><strong>'+str(len(websites))+'</strong></section><section><h2>Catatan result resmi</h2><strong>'+str(len(reports))+'</strong></section><section><h2>Koneksi agent</h2><strong>Belum diverifikasi</strong></section></div><section><h2>Monitoring & rekonsiliasi</h2><p>Catat result resmi dan nominal transaksi dari sumber yang dapat diverifikasi. Session tersimpan terenkripsi. Versi ini tidak mengambil data atau mengirim perubahan ke panel agent.</p></section><h2>Laporan gabungan</h2>'
                grouped = db.execute('SELECT market,period,number,COUNT(*) sites,SUM(revenue) revenue,SUM(payout) payout FROM reports GROUP BY market,period,number ORDER BY market,period').fetchall()
                body += '<div class="table"><table><tr><th>Pasaran</th><th>Periode</th><th>Result</th><th>Web tercatat / total</th><th>Omset</th><th>Pembayaran</th><th>Selisih</th></tr>'
                for r in grouped:
                    body += '<tr>'+''.join('<td>'+escaped(v)+'</td>' for v in (r['market'],r['period'],r['number'],f"{r['sites']} / {len(websites)}",r['revenue'],r['payout'],r['revenue']-r['payout']))+'</tr>'
                body += '</table></div><p>Jumlah website tercatat bukan bukti semua website selesai. Result berbeda dikelompokkan terpisah. Selisih = omset − pembayaran, belum termasuk biaya lainnya.</p>'
            elif route == '/websites':
                body = form('/websites/save',session,field('id','ID record untuk edit (kosong untuk tambah)',required=False)+field('code','Kode WEB')+field('name','Nama website')+field('url','Link agent HTTPS','url')+field('credential','Session agent (kosong saat edit = pertahankan)','password',required=False)+'<button>Simpan website</button>')
                body += '<div class="table"><table><tr><th>ID</th><th>Kode</th><th>Nama</th><th>Link agent</th><th>Status</th><th>Aksi</th></tr>'
                for r in websites:
                    body += '<tr>'+''.join('<td>'+escaped(r[k])+'</td>' for k in ('id','code','name','url'))+'<td>Belum diverifikasi</td><td>'+form('/websites/delete',session,'<input type="hidden" name="id" value="'+str(r['id'])+'"><button>Hapus jika tanpa laporan</button>')+'</td></tr>'
                body += '</table></div>'
            elif route == '/reports':
                options = ''.join('<option value="'+str(r['id'])+'">'+escaped(r['name'])+'</option>' for r in websites)
                body = form('/reports/save',session,'<label>Website<select name="website_id" required>'+options+'</select></label>'+field('market','Pasaran')+field('period','Periode')+field('number','Result resmi 4D')+field('revenue','Omset (rupiah bulat)','number')+field('payout','Total pembayaran (rupiah bulat)','number')+field('invoices','Jumlah invoice','number')+field('source','Link sumber result resmi','url')+'<label>Status verifikasi<select name="status"><option>PENDING</option><option>VERIFIED</option><option>DISPUTED</option></select></label><p>Satu catatan per website/pasaran/periode. Koreksi mengganti catatan dan masuk audit log.</p><button>Simpan catatan resmi</button>')
                body += '<div class="table"><table><tr><th>Web</th><th>Pasaran</th><th>Periode</th><th>Result</th><th>Omset</th><th>Pembayaran</th><th>Invoice</th><th>Status</th><th>Sumber</th></tr>'
                for r in reports:
                    body += '<tr>'+''.join('<td>'+escaped(r[k])+'</td>' for k in ('name','market','period','number','revenue','payout','invoices','status','source'))+'</tr>'
                body += '</table></div>'
            elif route == '/audit':
                rows = db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500').fetchall()
                body = '<div class="table"><table><tr><th>Waktu UTC</th><th>Aktivitas</th><th>Detail</th></tr>'+''.join('<tr>'+''.join('<td>'+escaped(r[k])+'</td>' for k in ('created','event','detail'))+'</tr>' for r in rows)+'</table></div><p>Log tidak dapat diedit melalui dashboard. Administrator database tetap memiliki akses.</p>'
            elif route == '/export':
                output = io.StringIO()
                writer = csv.writer(output)
                keys = ('name','market','period','number','revenue','payout','invoices','status','source','created')
                writer.writerow(keys)
                for r in reports:
                    writer.writerow([("'"+str(r[k])) if str(r[k]).startswith(('=','+','-','@','\t','\r')) else r[k] for k in keys])
                return self.respond(200,'\ufeff'+output.getvalue(),'text/csv; charset=utf-8')
            else:
                return self.respond(404,page('Tidak ditemukan','Halaman tidak tersedia.',session))
        self.respond(200,page({'/':'Dashboard','/websites':'Kelola website','/reports':'Result resmi & rekonsiliasi','/audit':'Audit log'}[route],body,session))

    def do_POST(self):
        with LOCK:
            try:
                self.post()
            except (ValueError, sqlite3.IntegrityError):
                self.respond(400,page('Data tidak valid','Periksa input, kode website unik, dan kaitan laporan. Kembali ke halaman sebelumnya.'))
            except Exception:
                self.respond(500,page('Kesalahan','Permintaan gagal. Tidak ada keberhasilan yang dikonfirmasi.'))

    def post(self):
        route = urlsplit(self.path).path
        length = int(self.headers.get('Content-Length','0'))
        if not 0 < length <= 16384:
            return self.respond(413,'Payload terlalu besar atau kosong')
        session = self.session()
        params = {k:v[0] for k,v in parse_qs(self.rfile.read(length).decode(),keep_blank_values=True).items()}
        if not session or not secrets.compare_digest(params.get('csrf',''),session['csrf']):
            return self.respond(403,'CSRF tidak valid')
        origin = self.headers.get('Origin')
        if origin and origin.rstrip('/') != ENV['APP_URL'].rstrip('/'):
            return self.respond(403,'Origin tidak valid')
        with connect() as db:
            if route == '/login':
                db.execute('DELETE FROM failures WHERE created<?',(time.time()-900,))
                if db.execute('SELECT COUNT(*) FROM failures').fetchone()[0] >= 10:
                    return self.respond(429,'Terlalu banyak percobaan. Tunggu 15 menit.')
                valid = secrets.compare_digest(params.get('username',''),ENV['ADMIN_USERNAME']) and verify_password(params.get('password',''),ENV['ADMIN_PASSWORD_HASH'])
                step = verify_totp(ENV['ADMIN_TOTP_SECRET'],params.get('otp','')) if valid else None
                if step is None or db.execute('SELECT 1 FROM used_totp WHERE step=?',(step,)).fetchone():
                    db.execute('INSERT INTO failures(created) VALUES(?)',(time.time(),))
                    audit(db,'LOGIN_FAILED','Kredensial atau 2FA tidak valid')
                    return self.respond(401,page('Login gagal','ID, password, atau 2FA tidak valid. Tunggu kode baru jika sudah digunakan. <a href="/login">Coba lagi</a>'))
                db.execute('INSERT INTO used_totp VALUES(?)',(step,))
                db.execute('DELETE FROM used_totp WHERE step<?',(step-5,))
                db.execute('DELETE FROM sessions WHERE token=?',(session['token'],))
                token = secrets.token_urlsafe(32)
                db.execute('INSERT INTO sessions VALUES(?,?,1,?)',(token,secrets.token_urlsafe(32),time.time()+28800))
                audit(db,'LOGIN_SUCCESS','Admin masuk')
                return self.respond(303,cookie=token,location='/')
            if not session['authenticated']:
                return self.respond(403,'Login diperlukan')
            if route == '/logout':
                db.execute('DELETE FROM sessions WHERE token=?',(session['token'],))
                audit(db,'LOGOUT','Admin keluar')
                return self.respond(303,cookie='deleted',location='/login')
            if route == '/websites/save':
                code,name,url = (params.get(k,'').strip() for k in ('code','name','url'))
                parsed = urlsplit(url)
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}',code) or not 1<=len(name)<=100 or parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError()
                credential = params.get('credential','')
                if len(credential)>4096 or '\r' in credential or '\n' in credential:
                    raise ValueError()
                identifier = params.get('id','')
                encrypted = cipher(ENV['ENCRYPTION_KEY']).encrypt(credential.encode()).decode() if credential else ''
                now = time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
                if identifier:
                    existing = db.execute('SELECT credential FROM websites WHERE id=?',(int(identifier),)).fetchone()
                    if not existing:
                        raise ValueError()
                    db.execute('UPDATE websites SET code=?,name=?,url=?,credential=?,updated=? WHERE id=?',(code,name,url,encrypted or existing['credential'],now,int(identifier)))
                else:
                    db.execute('INSERT INTO websites(code,name,url,credential,updated) VALUES(?,?,?,?,?)',(code,name,url,encrypted,now))
                audit(db,'WEBSITE_SAVED',code)
                destination = '/websites'
            elif route == '/websites/delete':
                identifier = int(params['id'])
                if db.execute('DELETE FROM websites WHERE id=?',(identifier,)).rowcount != 1:
                    raise ValueError()
                audit(db,'WEBSITE_DELETED',str(identifier))
                destination = '/websites'
            elif route == '/reports/save':
                website = int(params['website_id'])
                market,period,number,source,status = (params.get(k,'').strip() for k in ('market','period','number','source','status'))
                amounts = [int(params[k]) for k in ('revenue','payout','invoices')]
                if not 1<=len(market)<=80 or not 1<=len(period)<=40 or not re.fullmatch('[0-9]{4}',number) or urlsplit(source).scheme!='https' or not urlsplit(source).hostname or status not in ('PENDING','VERIFIED','DISPUTED') or any(v<0 or v>10**15 for v in amounts):
                    raise ValueError()
                prior = db.execute('SELECT number,revenue,payout,status FROM reports WHERE website_id=? AND market=? AND period=?',(website,market,period)).fetchone()
                db.execute('INSERT INTO reports(website_id,market,period,number,revenue,payout,invoices,source,status,created) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(website_id,market,period) DO UPDATE SET number=excluded.number,revenue=excluded.revenue,payout=excluded.payout,invoices=excluded.invoices,source=excluded.source,status=excluded.status,created=excluded.created',(website,market,period,number,*amounts,source,status,time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())))
                audit(db,'REPORT_SAVED',json.dumps({'website':website,'market':market,'period':period,'number':number,'previous':dict(prior) if prior else None,'revenue':amounts[0],'payout':amounts[1],'status':status}))
                destination='/reports'
            else:
                return self.respond(404,'Tidak ditemukan')
        self.respond(303,location=destination)

if __name__ == '__main__':
    initialize()
    server = ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('PORT','3000'))),Handler)
    server.daemon_threads = True
    print('IDN Monitor berjalan',flush=True)
    server.serve_forever()
