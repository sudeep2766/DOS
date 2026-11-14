#!/usr/bin/env python3
"""
SHA Ledger (multi-core): every TCP connection to port 8000 is stored in SQLite as
(client IP, SHA-512 hash of the raw request). The raw request text is never stored.
Rows are chained: each seal is SHA-512 over the previous seal plus the row's fields.

How it uses every CPU core:
  * N worker processes all listen on port 8000 (SO_REUSEPORT, Linux) and do the
    HTTP handling + SHA-512 hashing in parallel, so Python's GIL is not a limit.
  * One writer thread chains the hashes and inserts them in big batches
    (one commit per batch instead of one per request).
  * SQLite runs in WAL mode so the page can read while the writer writes.

Run:  python3 sha_ledger.py            (WORKERS=8 python3 sha_ledger.py to choose)
Open: http://localhost:8000
Test raw TCP:  echo "hello" | nc localhost 8000
Python 3.8+, standard library only, Linux recommended.
"""
import hashlib
import json
import multiprocessing as mp
import os
import queue
import signal
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_PORT = 8000
DB_FILE = "ledger.db"
MAX_BODY = 65536                                   # request body bytes included in the hash
WORKERS = int(os.environ.get("WORKERS", os.cpu_count() or 2))
BATCH_MAX = 2000                                   # rows per database commit
VERIFY_EVERY = int(os.environ.get("VERIFY_EVERY", 60))  # seconds between full chain checks
GENESIS = "0" * 128


def sha512(data):
    return hashlib.sha512(data).hexdigest()


def make_seal(prev, ts, ip, port, xff, req_hash):
    return sha512("|".join([prev, ts, ip, str(port), xff or "", req_hash]).encode())


def open_db():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    conn = open_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        forwarded_for TEXT,
        request_sha512 TEXT NOT NULL,
        prev_seal TEXT NOT NULL,
        seal TEXT NOT NULL)""")
    conn.commit()
    conn.close()


# ------------------------------------------------------------ writer process side
def writer_loop(q, stop):
    """Single writer: chains hashes in arrival order and inserts them in batches."""
    conn = open_db()
    row = conn.execute("SELECT seal FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
    prev = row[0] if row else GENESIS
    while True:
        try:
            batch = [q.get(timeout=0.2)]
        except queue.Empty:
            if stop.is_set():
                break
            continue
        while len(batch) < BATCH_MAX:
            try:
                batch.append(q.get_nowait())
            except queue.Empty:
                break
        rows = []
        for ts, ip, port, xff, rh in batch:
            seal = make_seal(prev, ts, ip, port, xff, rh)
            rows.append((ts, ip, port, xff, rh, prev, seal))
            prev = seal
        with conn:
            conn.executemany("INSERT INTO ledger (ts, ip, port, forwarded_for, request_sha512, "
                             "prev_seal, seal) VALUES (?,?,?,?,?,?,?)", rows)
    conn.close()


def verify_loop(stop, intact):
    """Re-checks the whole chain now and then; the result is shown on the page."""
    conn = open_db()
    while not stop.is_set():
        ok, prev = True, GENESIS
        for ts, ip, port, xff, rh, p, s in conn.execute(
                "SELECT ts, ip, port, forwarded_for, request_sha512, prev_seal, seal "
                "FROM ledger ORDER BY id"):
            if p != prev or make_seal(p, ts, ip, port, xff, rh) != s:
                ok = False
                break
            prev = s
        intact.value = 1 if ok else 0
        stop.wait(VERIFY_EVERY)
    conn.close()


# ------------------------------------------------------------ worker process side
def read_log(intact, limit=100):
    conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=30)
    try:
        rows = conn.execute("SELECT id, ts, ip, port, forwarded_for, request_sha512 "
                            "FROM ledger ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        total = conn.execute("SELECT MAX(id) FROM ledger").fetchone()[0] or 0  # fast, no scan
    finally:
        conn.close()
    keys = ["id", "ts", "ip", "port", "xff", "hash"]
    return {"total": total, "intact": bool(intact.value),
            "rows": [dict(zip(keys, r)) for r in rows]}


class Recorder:
    """Wraps the socket's read stream and keeps every byte the client sent."""
    def __init__(self, f):
        self._f = f
        self.buf = bytearray()

    def readline(self, *a):
        d = self._f.readline(*a)
        self.buf += d
        return d

    def read(self, *a):
        d = self._f.read(*a)
        self.buf += d
        return d

    def __getattr__(self, name):
        return getattr(self._f, name)


class Handler(BaseHTTPRequestHandler):
    server_version = "SHALedger/1.0"
    timeout = 10          # drop idle connections after 10 s
    queue = None          # set in each worker
    intact = None

    def log_message(self, *a):
        pass

    def record(self, raw, xff=None):
        ip, port = self.client_address[:2]
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.queue.put((ts, ip, port, xff, sha512(raw)))
        self._logged = True

    def setup(self):
        super().setup()
        self.rfile = Recorder(self.rfile)

    def handle_one_request(self):
        self._logged = False
        self.rfile.buf.clear()
        self.raw_requestline = b""
        super().handle_one_request()
        if not self._logged:  # connected, sent nothing (or too little to parse)
            self.record(bytes(self.rfile.buf))

    def send_error(self, code, message=None, explain=None):
        if not self._logged:  # not valid HTTP: hash whatever was received
            self.record(bytes(self.rfile.buf))
        super().send_error(code, message, explain)

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def handle_any(self):
        # The page's own polling is not logged, otherwise the ledger would fill with itself.
        if self.path.startswith("/api/log"):
            self._logged = True
            return self._send(200, json.dumps(read_log(self.intact)).encode(), "application/json")
        try:
            n = max(0, min(int(self.headers.get("Content-Length") or 0), MAX_BODY))
        except ValueError:
            n = 0
        if n:
            self.rfile.read(n)  # body joins the recorded raw request
        self.record(bytes(self.rfile.buf), self.headers.get("X-Forwarded-For"))
        if self.path.split("?")[0] in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        else:
            self._send(404, b"Not found, but it has been hashed.\n", "text/plain")

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = handle_any


class ReusePortServer(ThreadingHTTPServer):
    request_queue_size = 4096  # default is 5, which drops connections under load

    def server_bind(self):
        if hasattr(socket, "SO_REUSEPORT"):  # lets every worker share port 8000
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()


def worker(q, intact):
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # parent handles Ctrl-C
    Handler.queue, Handler.intact = q, intact
    srv = ReusePortServer(("0.0.0.0", HTTP_PORT), Handler)
    signal.signal(signal.SIGTERM,
                  lambda *a: threading.Thread(target=srv.shutdown, daemon=True).start())
    srv.serve_forever()
    srv.server_close()
    q.close()
    q.join_thread()  # make sure queued rows reach the writer before exiting


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SHA Ledger</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Fraunces:opsz,wght@9..144,600&display=swap">
<style>
:root{--bg:#e8eee9;--ink:#14213d;--mute:#5b6b7a;--line:#c5d0c8;--card:#f4f8f5;--ok:#1f7a4d;--bad:#c0392b}
@media (prefers-color-scheme:dark){:root{--bg:#0e1522;--ink:#e3eaf3;--mute:#8fa0b3;--line:#24324a;--card:#141f31;--ok:#5fd39a;--bad:#ff7a6b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Space Mono",ui-monospace,Menlo,Consolas,monospace}
main{max-width:1000px;margin:0 auto;padding:40px 20px 80px}
h1{font:600 clamp(36px,7vw,68px)/1 Fraunces,Georgia,serif;margin:0 0 12px;letter-spacing:-.02em}
.lead{max-width:60ch;color:var(--mute);margin:0 0 32px}
.hero{display:flex;gap:32px;align-items:center;flex-wrap:wrap;padding:24px;background:var(--card);border:1px solid var(--line);border-radius:6px}
.big{display:grid;grid-template-columns:repeat(16,1fr);width:320px;max-width:100%;height:160px;flex:none;border-radius:4px;overflow:hidden}
.big i,.mini i{display:block}
.hero-text{flex:1;min-width:240px}
.hash{word-break:break-all;font-size:13px;margin:6px 0 16px}
.stat{display:flex;gap:24px;flex-wrap:wrap;color:var(--mute);font-size:13px}
.stat b{color:var(--ink)}
.seal.ok{color:var(--ok)}.seal.bad{color:var(--bad)}
.how{margin:28px 0;padding:14px 16px;border-left:3px solid var(--ink);color:var(--mute);font-size:13px}
.how code{color:var(--ink)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px;background:var(--card)}
table{border-collapse:collapse;width:100%;min-width:700px;font-size:13px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-weight:700;color:var(--mute)}
tr:last-child td{border-bottom:0}
.mini{display:grid;grid-template-columns:repeat(16,1fr);width:64px;height:32px;border-radius:2px;overflow:hidden}
.empty{padding:28px;color:var(--mute)}
</style></head><body><main>
<h1>SHA Ledger</h1>
<p class="lead">Every connection to this server is turned into a SHA-512 hash of the raw request and stored with the IP address it came from. The request text itself is not kept.</p>

<section class="hero">
  <div class="big" id="big" aria-hidden="true"></div>
  <div class="hero-text">
    <div style="color:var(--mute)">Latest request hash (SHA-512)</div>
    <div class="hash" id="latest">Waiting for the first request…</div>
    <div class="stat">
      <span>Entries <b id="total">0</b></span>
      <span>Chain <b class="seal" id="seal">-</b></span>
    </div>
  </div>
</section>

<div class="how">Each hex digit of the 128-digit hash is one coloured cell. Anything that connects to this port is logged, even non-HTTP traffic: <code id="nc">nc HOST 8000</code></div>

<div class="wrap"><table>
<thead><tr><th>#</th><th>Pattern</th><th>Time (UTC)</th><th>From</th><th>SHA-512 of request</th></tr></thead>
<tbody id="rows"></tbody></table>
<div class="empty" id="empty">No entries yet. Open this page from another device or run the nc command above.</div></div>
</main>
<script>
function cells(hash){
  const f=document.createDocumentFragment();
  for(const ch of hash){const d=parseInt(ch,16);const i=document.createElement('i');
    i.style.background=`hsl(${d*22.5} 62% ${42+(d%4)*8}%)`;f.appendChild(i);}
  return f;
}
function td(txt){const t=document.createElement('td');t.textContent=txt;return t;}
async function load(){
  try{
    const r=await fetch('/api/log');const j=await r.json();
    document.getElementById('total').textContent=j.total;
    const s=document.getElementById('seal');
    s.textContent=j.intact?'intact':'BROKEN';s.className='seal '+(j.intact?'ok':'bad');
    document.getElementById('nc').textContent='nc '+location.hostname+' '+(location.port||80);
    const rows=document.getElementById('rows');rows.replaceChildren();
    document.getElementById('empty').style.display=j.rows.length?'none':'block';
    if(j.rows.length){
      const h=j.rows[0].hash;
      document.getElementById('latest').textContent=h;
      document.getElementById('big').replaceChildren(cells(h));
    }
    for(const r of j.rows){
      const tr=document.createElement('tr');
      tr.appendChild(td(r.id));
      const m=document.createElement('td');const mini=document.createElement('div');mini.className='mini';mini.appendChild(cells(r.hash));m.appendChild(mini);tr.appendChild(m);
      tr.appendChild(td(r.ts));
      tr.appendChild(td(r.ip+':'+r.port+(r.xff?' (xff '+r.xff+')':'')));
      const hh=td(r.hash.slice(0,32)+'…');hh.title=r.hash;tr.appendChild(hh);
      rows.appendChild(tr);
    }
  }catch(e){}
}
load();setInterval(load,3000);
</script></body></html>
"""


def main():
    init_db()
    q = mp.Queue(maxsize=200000)
    intact = mp.Value("b", 1)
    stop = threading.Event()
    threads = [threading.Thread(target=writer_loop, args=(q, stop)),
               threading.Thread(target=verify_loop, args=(stop, intact), daemon=True)]
    for t in threads:
        t.start()
    procs = [mp.Process(target=worker, args=(q, intact)) for _ in range(WORKERS)]
    for p in procs:
        p.start()
    print(f"{WORKERS} workers listening on :{HTTP_PORT}  ->  http://localhost:{HTTP_PORT}")
    try:
        while any(p.is_alive() for p in procs):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nshutting down, flushing queue...")
    for p in procs:
        p.terminate()
    for p in procs:
        p.join()
    stop.set()
    threads[0].join()


if __name__ == "__main__":
    main()
