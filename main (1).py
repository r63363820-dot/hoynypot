# main.py — облегчённый хонейпот (SQLi, XSS, сканеры)
import asyncio, json, time, sqlite3, re
from datetime import datetime
from pathlib import Path
from WAF import waf_middleware

HTTP_PORT = 8080
DB_PATH   = "honeypot.db"

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS hp_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ip TEXT NOT NULL,
            path TEXT,
            ua TEXT,
            detected TEXT,
            action TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_hp_ip ON hp_requests(ip);
    """)
    con.commit()
    con.close()
    print("[HP] DB initialized")

def log_hp(ip, path, ua, detected, action):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO hp_requests (ts, ip, path, ua, detected, action) VALUES (?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), ip, path, ua, detected, action)
    )
    con.commit()
    con.close()
    print(f"[HP] {ip} | {path} | {detected} → {action}")

SQLI_PATTERNS = [
    r"(?i)(\bunion\b.{0,30}\bselect\b)",
    r"(?i)(\bselect\b.{0,40}\bfrom\b)",
    r"(?i)(\bdrop\b\s+\btable\b)",
    r"(?i)(\binsert\b\s+into\b)",
    r"(?i)(\bupdate\b\s+\b\w+\b\s+set\b)",
    r"(?i)(\'|\"|`)\s*(?:or|and)\s*[\w\s'\"]*=[\w\s'\"]*)",
    r"(?i)(sleep\s*\(\s*\d+\))",
    r"(?i)(information_schema)",
    r"(?i)(xp_cmdshell)",
    r"(?i)(load_file\s*\()",
]

XSS_PATTERNS = [
    r"(?i)<\s*script[^>]*>",
    r"(?i)javascript\s*:",
    r"(?i)on(?:load|error|click|mouseover|focus|submit|input|change)\s*=",
    r"(?i)<\s*(?:img|svg|iframe|object|embed)[^>]+on\w+\s*=",
    r"(?i)vbscript\s*:",
    r"(?i)expression\s*\(",
]

SCANNER_PATTERNS = [
    r"(?i)nmap", r"(?i)masscan", r"(?i)nikto", r"(?i)nuclei",
    r"(?i)gobuster", r"(?i)dirb", r"(?i)dirbuster", r"(?i)sqlmap",
    r"(?i)burpsuite", r"(?i)acunetix", r"(?i)nessus", r"(?i)openvas",
    r"(?i)wfuzz", r"(?i)ffuf", r"(?i)hydra", r"(?i)zgrab",
]

SQLI_RE = [re.compile(p) for p in SQLI_PATTERNS]
XSS_RE  = [re.compile(p) for p in XSS_PATTERNS]
SCAN_RE = [re.compile(p) for p in SCANNER_PATTERNS]

def detect_attack(path: str, ua: str, body: str = "") -> list:
    detections = []
    payload = f"{path} {body}"
    for pat in SQLI_RE:
        if pat.search(payload):
            detections.append("sqli")
            break
    for pat in XSS_RE:
        if pat.search(payload):
            detections.append("xss")
            break
    for pat in SCAN_RE:
        if pat.search(ua):
            detections.append("scanner")
            break
    return detections

FAKE_PATHS = {
    "/admin": "<html><body><h1>Admin Panel</h1><form><input name=user><input name=pass type=password><button>Login</button></form><!-- debug: admin:admin123 --></body></html>",
    "/.env": "APP_ENV=production\nDB_HOST=10.0.0.5\nDB_PASS=Sup3rS3cr3t!\nAWS_KEY=AKIAFAKE123456",
    "/wp-login.php": "<html><body><h2>WordPress Login</h2><form><input name=log><input name=pwd type=password><button>Login</button></form></body></html>",
    "/phpinfo.php": "<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.4.33</h1><table><tr><td>System</td><td>Linux web01</td></tr></table></body></html>",
    "/.git/config": "[core]\nrepositoryformatversion=0\n[remote \"origin\"]\n\turl = git@github.com:internal/webapp.git\n",
    "/api/v1/users": '[{"id":1,"user":"admin","email":"admin@internal.corp","role":"superadmin"}]',
}

def fake_response(path: str):
    if path in FAKE_PATHS:
        return 200, "text/html", FAKE_PATHS[path]
    return 200, "text/html", "<html><body><h1>Internal System</h1><p>CVE-2026-15427 — RCE (unpatched)</p></body></html>"

async def http_handler(reader, writer):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "0.0.0.0"
    try:
        raw = await asyncio.wait_for(reader.read(8192), timeout=10)
        text = raw.decode(errors="ignore")
        lines = text.splitlines()
        if not lines:
            writer.close()
            return
        first = lines[0].split()
        method = first[0] if len(first) > 0 else "GET"
        path = first[1] if len(first) > 1 else "/"
        ua = ""
        for line in lines:
            if line.lower().startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
                break
        detections = detect_attack(path, ua)
        waf_result = waf_middleware(ip, method, path, {}, "")
        waf_action = waf_result.get("action", "allow")
        if detections or waf_action in ("block", "block_temp", "block_permanent"):
            log_hp(ip, path, ua, json.dumps(detections), "block")
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        code, ctype, body = fake_response(path)
        resp = f"HTTP/1.1 {code} OK\r\nServer: Apache/2.4.54\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n{body}"
        writer.write(resp.encode())
        await writer.drain()
        log_hp(ip, path, ua, json.dumps(detections), "allowed")
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[HP] error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def main():
    init_db()
    server = await asyncio.start_server(http_handler, "0.0.0.0", HTTP_PORT)
    print(f"[HP] Honeypot listening on :{HTTP_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[HP] shutdown")