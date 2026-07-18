# waf.py — самодостаточный WAF
import re, time, sqlite3, json, hashlib, threading
from datetime import datetime
from pathlib import Path

# ── конфиг ────────────────────────────────────────────────────────────────────
DB_PATH    = "waf.db"
TEMP_BAN   = 300          # секунд
PERM_SCORE = 100
RATE_LIMIT = 30           # запросов в секунду

# ── сигнатуры атак ────────────────────────────────────────────────────────────
SIGNATURES = {
    "sqli": [
        r"(?i)(\bunion\b.{0,50}\bselect\b)",
        r"(?i)(\bselect\b.{0,80}\bfrom\b)",
        r"(?i)(\bdrop\b\s+\btable\b|\btruncate\b\s+\btable\b)",
        r"(?i)(\'|\"|`)\s*(?:or|and)\s*[\w\s'\"]*=[\w\s'\"]*",
        r"(?i)(sleep\s*\(\s*\d+|benchmark\s*\(|waitfor\s+delay)",
        r"(?i)(information_schema|xp_cmdshell|sp_executesql|pg_sleep)",
        r"(?i)(load_file\s*\(|into\s+(?:out|dump)file\s)",
    ],
    "xss": [
        r"(?i)<\s*script[^>]*>",
        r"(?i)javascript\s*:",
        r"(?i)vbscript\s*:",
        r"(?i)on(?:load|error|click|mouseover|focus|submit|input|change)\s*=",
        r"(?i)<\s*(?:img|svg|iframe|object|embed)[^>]+on\w+\s*=",
        r"(?i)expression\s*\([^)]*\)",
    ],
    "rce": [
        r"(?i)(?:;|\||&&|`|\$\()\s*(?:ls|cat|whoami|id|uname|wget|curl|bash|sh|python3?|perl|ruby|nc|netcat)",
        r"(?i)(?:exec|system|passthru|shell_exec|popen|proc_open|eval)\s*\(",
        r"(?i)(?:/bin/(?:sh|bash|dash)|cmd\.exe|powershell(?:\.exe)?)\b",
    ],
    "lfi": [
        r"(?i)(?:\.\.[\\/]){2,}",
        r"(?i)(?:/etc/(?:passwd|shadow|hosts)|/proc/self/environ)",
        r"(?i)(?:boot\.ini|win\.ini|system32)",
        r"(?i)php://(?:filter|input|data)",
    ],
    "ssrf": [
        r"(?i)(?:http|ftp|file|dict|gopher)://(?:localhost|127\.|0\.0\.|169\.254\.|::1)",
        r"(?i)169\.254\.169\.254",
        r"(?i)metadata\.internal",
    ],
    "ssti": [
        r"\{\{.{0,50}\}\}",
        r"\{%.{0,50}%\}",
        r"(?i)<%=.{0,30}%>",
    ],
    "xxe": [
        r"(?i)<!ENTITY",
        r"(?i)SYSTEM\s+['\"](?:file|http|ftp|expect):",
        r"(?i)<!DOCTYPE[^>]+SYSTEM",
    ],
    "path_traversal": [
        r"(?i)(?:\.\.%2f|%2e%2e/|%2e%2e%5c){2,}",
        r"(?i)%252e%252e",
    ],
    "scanner": [
        r"(?i)(?:nmap|masscan|nikto|nuclei|gobuster|dirbuster|sqlmap|burpsuite|acunetix|nessus|openvas|wfuzz|ffuf|dirb|hydra)",
        r"(?i)(?:zgrab|python-requests/2\.[0-2]\.|go-http-client/1\.1$)",
    ],
}

SCANNER_PATHS = frozenset({
    "/.env", "/.env.local", "/.env.production",
    "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/phpmyadmin", "/.git/config", "/.git/HEAD",
    "/admin", "/actuator", "/actuator/env", "/actuator/beans",
    "/shell", "/.aws/credentials", "/config.php",
    "/backup.zip", "/db.sql", "/.htaccess",
    "/server-status", "/api/swagger", "/swagger.json",
    "/api/v1/users", "/debug", "/console", "/.DS_Store",
    "/web.config", "/app.config", "/settings.py",
})

# ── компилируем сигнатуры ──────────────────────────────────────────────────
COMPILED = {cat: [re.compile(p) for p in pats] for cat, pats in SIGNATURES.items()}

# ── база данных ──────────────────────────────────────────────────────────────
def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ip TEXT NOT NULL,
            method TEXT,
            path TEXT,
            ua TEXT,
            score INTEGER DEFAULT 0,
            action TEXT,
            detections TEXT
        );
        CREATE TABLE IF NOT EXISTS bans (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            score INTEGER,
            banned_at TEXT,
            ban_until TEXT,
            permanent INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip);
        CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
        CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
    """)
    con.commit()
    con.close()

def log_request(ip, method, path, ua, score, action, detections):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO requests (ts,ip,method,path,ua,score,action,detections) VALUES (?,?,?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), ip, method, path, ua, score, action, json.dumps(detections))
    )
    con.commit()
    con.close()

def get_bans():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT ip, ban_until, permanent FROM bans").fetchall()
    con.close()
    return {r[0]: (r[1], r[2]) for r in rows}

def add_ban(ip, reason, score, ban_until=None, permanent=0):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR REPLACE INTO bans (ip, reason, score, banned_at, ban_until, permanent) VALUES (?,?,?,?,?,?)",
        (ip, reason, score, datetime.utcnow().isoformat(), ban_until, permanent)
    )
    con.commit()
    con.close()

# ── ядро WAF ──────────────────────────────────────────────────────────────────
class WAF:
    def __init__(self):
        self.bans = {}
        self.records = {}
        self._lock = threading.Lock()
        init_db()
        self._load_bans()
        self._start_cleaner()

    def _load_bans(self):
        with self._lock:
            self.bans = get_bans()

    def _start_cleaner(self):
        def clean():
            while True:
                time.sleep(60)
                self._load_bans()
        threading.Thread(target=clean, daemon=True).start()

    def _is_banned(self, ip):
        if ip not in self.bans:
            return False
        until, perm = self.bans[ip]
        if perm:
            return True
        if until and datetime.utcnow().isoformat() < until:
            return True
        return False

    def _scan(self, text):
        hits = []
        for cat, patterns in COMPILED.items():
            for pat in patterns:
                if pat.search(text):
                    hits.append(cat)
                    break
        return hits

    def inspect(self, ip, method="GET", path="/", headers=None, body=""):
        headers = headers or {}
        ua = headers.get("User-Agent", "")

        if self._is_banned(ip):
            return {"action": "block", "reason": "banned", "ip": ip, "score": 0}

        with self._lock:
            if ip not in self.records:
                self.records[ip] = {"score": 0, "times": [], "attacks": []}
            rec = self.records[ip]

        now = time.time()
        rec["times"] = [t for t in rec["times"] if now - t < 1.0]
        rec["times"].append(now)

        detections = []
        score = rec["score"]

        # rate limit
        if len(rec["times"]) > RATE_LIMIT:
            detections.append("rate_limit")
            score += 10

        # scanner paths
        if path in SCANNER_PATHS:
            detections.append("scanner_path")
            score += 20

        # signature scan
        payload = f"{path} {body} {ua}"
        for hit in self._scan(payload):
            if hit not in detections:
                detections.append(hit)
                score += 25

        # action
        if score >= PERM_SCORE:
            action = "block_permanent"
            add_ban(ip, json.dumps(detections), score, permanent=1)
        elif score >= 75:
            action = "block_temp"
            until = (datetime.utcnow().timestamp() + TEMP_BAN).isoformat()
            add_ban(ip, json.dumps(detections), score, ban_until=until)
        elif score >= 40 or detections:
            action = "honeypot"
        else:
            action = "allow"

        rec["score"] = score

        if detections:
            log_request(ip, method, path, ua, score, action, detections)
            print(f"[WAF] {ip} score={score} {detections} → {action}")

        return {"action": action, "score": score, "detections": detections, "ip": ip}

# ── Singleton ─────────────────────────────────────────────────────────────────
waf = WAF()

# ── middleware для FastAPI / Flask ──────────────────────────────────────────
def waf_middleware(ip, method="GET", path="/", headers=None, body=""):
    """Вызов из вашего приложения: result = waf_middleware(request.ip, request.method, request.path, request.headers, request.body)"""
    return waf.inspect(ip, method, path, headers, body)