# PhishingAnalyzer

A modular email phishing analysis toolkit that examines `.eml` files across **10 analysis vectors** and produces a unified risk score with exportable reports.

Built for SOC analysts, security researchers, and anyone who needs to quickly triage suspicious emails.

---

## Features

| Module | What it does |
|---|---|
| **Header Analysis** | Parses SPF, DKIM, DMARC authentication; detects From/Return-Path/Reply-To mismatches; traces the full Received chain; extracts originating IP |
| **URL Analysis** | Extracts all URLs from text + HTML parts; checks for suspicious TLDs, IP-based URLs, typosquatting, URL shorteners, excessive subdomains, `@` tricks |
| **Body Content Analysis** | Scans email body against 15 social engineering patterns — urgency, threats, prize bait, credential harvesting, artificial deadlines, generic greetings |
| **HTML Analysis** | Detects external form actions, hidden inputs/elements, `<script>` tags, inline event handlers, iframes, base64 obfuscation, link text/href mismatches, meta refresh redirects |
| **Attachment Analysis** | Identifies suspicious file types (.exe, .scr, macros), double extension tricks, extension/content-type mismatches, password-protected ZIPs; hashes files (SHA256 + MD5) and checks hashes on VirusTotal |
| **WHOIS / Domain Age** | Performs raw WHOIS lookups via socket; flags domains registered < 30 days ago |
| **VirusTotal Integration** | Scans extracted URLs and originating IP against 70+ antivirus engines |
| **AbuseIPDB Integration** | Checks originating IP reputation — abuse score, ISP, report count |
| **Risk Scoring** | Aggregates all findings into a 0–100 risk score with verdict: `LOW RISK`, `CAUTION`, `SUSPICIOUS`, `HIGH RISK` |
| **Report Export** | Generates JSON (machine-readable) and HTML (dark-themed, human-readable) reports |

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/phisingAnalyzer.git
cd phisingAnalyzer

# Install dependencies
pip install -r requirements.txt

# Set up API keys
cp .env.example .env
# Edit .env and add your keys (see API Keys section below)

# Analyze a single email
python3 header_analyzer.py samples_phising/phishing-test.eml

# Analyze a whole folder
python3 header_analyzer.py samples_phising/

# Analyze multiple files
python3 header_analyzer.py mail1.eml mail2.eml mail3.eml

# Use CLI flags
python3 header_analyzer.py --no-export samples_phising/phishing-test.eml
python3 header_analyzer.py --format json samples_phising/phishing-test.eml
python3 header_analyzer.py --format html samples_phising/phishing-test.eml
```

## API Keys

The tool integrates with two external threat intelligence APIs. Both are **free** for limited use.

| Service | Free tier | Get key at |
|---|---|---|
| VirusTotal | 4 req/min, 500 req/day | https://www.virustotal.com/gui/join |
| AbuseIPDB | 1000 req/day | https://www.abuseipdb.com/register |

Create a `.env` file in the project root:

```
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

The tool works without API keys — VirusTotal and AbuseIPDB checks will be skipped gracefully.

## Example Output

```
============================================================
       EMAIL HEADER ANALYSIS REPORT
============================================================

--- Basic Info ---
  From:        "PayPal Security" <security@paypa1-support.xyz>
  Subject:     Urgent: Your account has been limited
  ...

--- Authentication ---
  SPF:   FAIL
  DKIM:  FAIL
  DMARC: FAIL

--- RED FLAGS ---
  [!] SPF FAIL — sender not authorized
  [!] DKIM FAIL — message may be tampered
  [!] FROM/RETURN-PATH MISMATCH: paypa1-support.xyz vs mail-server.ru

--- Body Content Analysis ---
  Social engineering patterns found: 6
    - Account threat: "account will be suspended"
    - Urgency language: "immediately"
    - Verification request: "verify your account"
    ...

============================================================
       RISK SCORE: 87/100 — PHISHING — HIGH RISK
============================================================
```

## Project Structure

```
phisingAnalyzer/
├── header_analyzer.py       # Main entry point + header parsing
├── url_analyzer.py          # URL extraction + pattern analysis
├── body_analyzer.py         # Social engineering detection
├── html_analyzer.py         # Suspicious HTML element detection
├── attachment_analyzer.py   # Attachment analysis + VT hash lookup
├── whois_checker.py         # Domain age via raw WHOIS
├── virustotal_scanner.py    # VirusTotal API integration
├── abuseipdb_checker.py     # AbuseIPDB API integration
├── scoring.py               # Risk score calculation (0-100)
├── report_export.py         # JSON + HTML report generation
├── tests/
│   ├── test_url_analyzer.py
│   ├── test_body_analyzer.py
│   ├── test_html_analyzer.py
│   └── test_scoring.py
├── samples_phising/         # Sample .eml files for testing
├── requirements.txt
├── .env.example
└── .gitignore
```

## Running Tests

```bash
pytest tests/ -v
```

## How the Scoring Works

Each module contributes points to the risk score (max 100):

| Category | Max points | Examples |
|---|---|---|
| Email authentication | 48 | SPF/DKIM/DMARC failures (+16 each), header mismatches (+10 each, max 20) |
| Suspicious URLs | 40 | Bad TLDs, IP URLs, typosquatting, shorteners (+6 per flag) |
| Social engineering | 30 | Urgency, threats, credential requests (+30 for 4+ patterns) |
| HTML tricks | 30 | Hidden forms, scripts, link mismatches (+8 per issue) |
| Malicious attachments | 50 | Bad extensions (+10/flag, max 20), **VT malware = +50** |
| Domain age | 20 | Domains < 30 days = +20, < 90 days = +10 |
| VirusTotal detections | 50 | **5+ engines = +50**, 1-4 = +24, suspicious = +10 |
| AbuseIPDB score | 30 | Score >= 80% = +30, >= 25% = +14 |

**Verdicts:**
- **0–24:** `LOW RISK` — probably legitimate
- **25–49:** `CAUTION` — some red flags
- **50–74:** `SUSPICIOUS` — likely phishing
- **75–100:** `PHISHING — HIGH RISK`

## License

MIT
