HONEYWALL FREE — DOCUMENTATION

Version: 1.0
License: MIT
Author: [N]

WHAT IT IS:
Lightweight WAF + HTTP honeypot against SQLi, XSS, scanners.

FILES:
WAF.py        - core WAF (signatures, bans, DB)
main.py       - honeypot (port 8080)
Aegis.py      - Flask + WAF
WAFFIESKm.py  - FastAPI + WAF

RUN:
FastAPI: uvicorn WAFFIESKm:app --reload
Flask:   python Aegis.py
Honeypot: python main.py

CONFIG (in WAF.py):
TEMP_BAN=300, PERM_SCORE=100, RATE_LIMIT=30

TEST:
curl "http://localhost:8000/?id=1 UNION SELECT * FROM users"
curl "http://localhost:8000/?q=<script>alert(1)</script>"
curl -A "nmap" http://localhost:8000/

HONEYPOT TEST:
curl http://localhost:8080/.env
curl -A "gobuster" http://localhost:8080/

FREE VERSION HAS:
- WAF (SQLi, XSS, RCE, LFI, SSRF, SSTI, XXE, scanners)
- HTTP honeypot
- SQLite logging
- IP blocking
- Flask/FastAPI integration

FREE VERSION DOES NOT HAVE:
- Honeytokens
- AI
- GeoIP
- UBA
- Alerts
- Dashboard
- Shodan
- MITRE
- Docker
by: Mirnov is a cybersecurity engineer t.me/xoxuzo
:D
