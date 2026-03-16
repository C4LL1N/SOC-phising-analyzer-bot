# HOW IT WORKS - STEP BY STEP

This document explains exactly what each module does, in what order, and why.

---

## GENERAL FLOW

When you run `python3 header_analyzer.py email.eml`, here's what happens:

```
email.eml (raw email file)
    |
    v
[1] HEADER ANALYZER --- reads email headers (From, To, SPF, DKIM...)
    |
    v
[2] URL ANALYZER --- extracts all links from the email body
    |
    v
[3] BODY ANALYZER --- scans content for manipulation patterns ("urgent!", "click here!")
    |
    v
[4] HTML ANALYZER --- checks HTML for hidden forms, scripts, iframes
    |
    v
[5] ATTACHMENT ANALYZER --- analyzes attachments (extensions, hashes, VT lookup)
    |
    v
[6] WHOIS CHECKER --- checks domain age from URLs (fresh domain = suspicious)
    |
    v
[7] VIRUSTOTAL --- scans URLs and IPs against 70+ antivirus engines
    |
    v
[8] ABUSEIPDB --- checks sender IP reputation
    |
    v
[9] SCORING --- collects all red flags and calculates score 0-100
    |
    v
[10] EXPORT --- saves report to JSON and HTML
```

---

## MODULE 1: header_analyzer.py (HEADERS)

### What it does:
Opens a .eml file and reads email headers — these are metadata that mail servers add to every email.

### How exactly:
1. Opens the .eml file using Python's built-in `email` library
2. Extracts fields: From, To, Subject, Date, Return-Path, Reply-To, Message-ID
3. Reads the "Received" chain — these are stamps from every server that relayed the email. Last on the list = first server (sender), first = last server (your server)
4. Extracts the sender IP from the first Received header (regex searches for `[123.45.67.89]`)
5. Reads "Authentication-Results" and checks:
   - **SPF** (Sender Policy Framework) — whether the sender's server is authorized to send emails from that domain. FAIL = someone is impersonating that domain
   - **DKIM** (DomainKeys Identified Mail) — digital signature of the email. FAIL = content may have been altered in transit
   - **DMARC** (Domain-based Message Authentication) — combines SPF + DKIM and specifies what to do with emails that don't pass. FAIL = domain doesn't confirm this email
6. Compares domains:
   - From vs Return-Path — if they differ, someone may be pretending to be another sender
   - From vs Reply-To — if they differ, the reply will go to a different address than what the recipient sees

### Why it matters:
Phishing emails almost always fail SPF/DKIM/DMARC because they're sent from unauthorized servers. Domain mismatches are a classic red flag.

---

## MODULE 2: url_analyzer.py (LINKS)

### What it does:
Extracts all URLs from the email and checks if they look suspicious.

### How exactly:
1. Iterates through all email parts (text/plain and text/html)
2. Regex searches for the pattern `https?://...` (every link)
3. Additionally searches for `href="..."` in HTML (links can be hidden in tags)
4. For each URL checks:
   - **IP instead of domain** — `http://192.168.1.1/login` instead of `http://bank.com/login` = suspicious
   - **Suspicious TLDs** — `.xyz`, `.top`, `.tk` etc. are cheap/free and frequently used for phishing
   - **Typosquatting** — whether the domain contains a known brand name but IS NOT that brand (e.g. `paypa1-login.com` contains "paypal" but it's not PayPal)
   - **URL shorteners** — `bit.ly`, `tinyurl.com` etc. hide the real destination
   - **Excessive subdomains** — `login.secure.paypal.verify.evil.com` looks suspicious
   - **@ in URL** — `http://google.com@evil.com` — the browser ignores "google.com" and goes to evil.com!
   - **Non-standard port** — `http://site.com:8080` might be a phishing server

---

## MODULE 3: body_analyzer.py (EMAIL CONTENT)

### What it does:
Scans the email text for 15 psychological manipulation patterns typical of phishing.

### Patterns it detects:
1. **Urgency** — "immediately", "urgent", "ASAP", "time sensitive"
2. **Pressure** — "act now", "action required", "must verify"
3. **Threats** — "account will be suspended/closed/terminated"
4. **Verification** — "verify your account/identity/email"
5. **Credentials** — "confirm your password/credentials"
6. **Payments** — "update your payment/billing/credit card"
7. **Suspicious activity** — "unusual activity/sign-in/transaction"
8. **Rewards** — "won", "prize", "congratulations", "lottery"
9. **Untraceable payments** — "wire transfer", "bitcoin", "gift card"
10. **Directives** — "click here", "click below", "open the attachment"
11. **Password** — "password expiring", "reset your password"
12. **Isolation** — "do not share", "confidential", "do not forward"
13. **Generic greeting** — "Dear valued customer" (instead of a name)
14. **Artificial deadline** — "within 24 hours", "in the next 48 hours"
15. **Delivery** — "invoice", "receipt", "shipment", "tracking"

Additionally checks:
- Exclamation mark count (>5 = pressure tactic)
- Words in ALL CAPS
- Unusual phrasing typical of phishing ("kindly", "do the needful")

---

## MODULE 4: html_analyzer.py (HTML)

### What it does:
Analyzes the email's HTML code for suspicious technical elements.

### What it checks:
1. **Forms with external action** — `<form action="http://evil.com/steal">` — a form that sends your data to an external server
2. **Hidden inputs** — `<input type="hidden">` — fields that submit data without your knowledge
3. **display:none** — CSS-hidden elements that may contain additional code
4. **Tracking pixels** — 0x0 or 1x1 px elements used to track whether you opened the email
5. **JavaScript** — `<script>` in an email is a MAJOR red flag, legitimate emails don't contain JS
6. **Event handlers** — `onclick`, `onload` etc. — inline JS that fires on events
7. **Base64** — encoded content that may hide malicious code
8. **iframe** — embedded pages within the email
9. **Link mismatch** — link text says "http://paypal.com" but href points to "http://evil.com"
10. **Meta refresh** — automatic redirect to another page

---

## MODULE 5: attachment_analyzer.py (ATTACHMENTS)

### What it does:
Checks every attachment in the email for potential threats.

### How:
1. Iterates through MIME parts of the email and finds those with `Content-Disposition: attachment`
2. For each attachment:
   - Checks the extension — there's a list of ~35 suspicious ones (.exe, .scr, .bat, .js, .vbs, .docm, .xlsm...)
   - Checks for **macro files** (.docm, .xlsm) — macros can execute malicious code
   - Detects **double extensions** — `invoice.pdf.exe` looks like a PDF but it's an .exe
   - Compares extension with Content-Type (e.g. .exe file with Content-Type: application/pdf = suspicious)
   - Checks if a ZIP is password-protected (common phishing trick — the password is in the email, AV can't scan it)
   - Calculates **SHA256 and MD5** hashes of the file
   - Checks the hash on **VirusTotal** — if someone already uploaded this file, VT has scan results

---

## MODULE 6: whois_checker.py (DOMAIN AGE)

### What it does:
Checks when the domain from the email's URLs was registered.

### Why it matters:
Phishers register new domains for every campaign. A domain registered 2 days ago that claims to be "PayPal" = obvious phishing.

### How:
1. Connects via socket to `whois.iana.org` (port 43) and queries the domain
2. IANA returns which WHOIS server handles that domain (e.g. `whois.verisign-grs.com` for .com)
3. Connects to the proper WHOIS server and retrieves registration data
4. Parses the registration date (various formats — WHOIS has no single standard)
5. Calculates how many days ago it was registered:
   - **< 30 days** — VERY NEW, major red flag
   - **< 90 days** — relatively new, warning

---

## MODULE 7: virustotal_scanner.py

### What it does:
Sends URLs and IPs to VirusTotal — a service that scans suspicious files/URLs against 70+ antivirus engines.

### How:
1. Takes a URL, encodes it in base64 (required by VT API)
2. First checks if VT already has a report for that URL (`GET /urls/{id}`)
3. If not — submits the URL for scanning (`POST /urls`) and waits 3 seconds for results
4. Extracts from the report: how many engines flagged it as `malicious`, `suspicious`, `harmless`
5. Does the same for the sender IP (`GET /ip_addresses/{ip}`)

### API:
- Free account: 4 requests/minute, 500/day
- Key stored in `.env` as `VT_API_KEY`

---

## MODULE 8: abuseipdb_checker.py

### What it does:
Checks the sender IP in AbuseIPDB — a database of reported malicious IPs.

### How:
1. Sends a request to `api.abuseipdb.com/api/v2/check` with the sender IP
2. Receives: abuse score (0-100%), country, ISP, number of reports, date of last report
3. Score >= 80% = HIGH RISK (many people reported this IP)
4. Score >= 25% = SUSPICIOUS

---

## MODULE 9: scoring.py (SCORING)

### What it does:
Collects results from ALL modules and calculates a final score of 0-100.

### Point sources:
```
SPF FAIL                      +16 pts
SPF SOFTFAIL                  +8 pts
DKIM FAIL                     +16 pts
DMARC FAIL                    +16 pts
Header mismatches             +10 per mismatch (max 20)
Suspicious URLs               +6 per flag (max 40)
Social engineering 4+ patterns +30 pts
Social engineering 2-3         +16 pts
Social engineering 1           +6 pts
ALL CAPS                       +6 pts
Exclamation marks              +4 pts
Suspicious HTML                +8 per issue (max 30)
Suspicious attachment          +10 per flag (max 20)
VT: malicious attachment       +50 pts   <<<< MALWARE = half the scale
Domain < 30 days               +20 pts
Domain < 90 days               +10 pts
VT: 5+ engines flag            +50 pts   <<<< MALWARE = half the scale
VT: 1-4 engines                +24 pts
VT: suspicious                 +10 pts
AbuseIPDB >= 80%               +30 pts
AbuseIPDB >= 25%               +14 pts
```

### Verdicts:
- **0-24** = LOW RISK — probably legitimate
- **25-49** = CAUTION — some red flags present
- **50-74** = SUSPICIOUS — likely phishing
- **75-100** = PHISHING HIGH RISK

---

## MODULE 10: report_export.py (EXPORT)

### What it does:
Generates reports in two formats:

1. **JSON** — file `name_report.json` with a full dump of all results. Machine-readable, can be parsed by other tools
2. **HTML** — file `name_report.html` with a dark theme, clean tables, and color-coded score. Can be opened in a browser and shared

---

## .eml FILE FORMAT

An `.eml` file is a raw email in text format (MIME). You can obtain one by:
- **Gmail**: Open the email -> three dots -> "Download message" / "Show original" -> Download
- **Outlook**: Open the email -> File -> Save As -> type "Outlook Message Format - Unicode" or drag to desktop
- **Thunderbird**: Open the email -> File -> Save As -> .eml file

---

## HOW TO RUN

### Step 1: Install Python
```bash
python3 --version
# Should show 3.8 or newer. If you don't have it:
# Ubuntu/Debian: sudo apt install python3 python3-pip
# Mac: brew install python3
# Windows: https://python.org/downloads
```

### Step 2: Install dependencies
```bash
cd phisingAnalyzer
pip install -r requirements.txt
```

### Step 3: Set API keys (optional)
```bash
cp .env.example .env
nano .env  # paste your keys
```
Without keys the tool still works — it simply skips VT and AbuseIPDB checks.

### Step 4: Run
```bash
# Single file
python3 header_analyzer.py samples_phising/phishing-test.eml

# Entire folder
python3 header_analyzer.py samples_phising/

# Without report export
python3 header_analyzer.py --no-export samples_phising/phishing-test.eml

# JSON only
python3 header_analyzer.py --format json samples_phising/phishing-test.eml
```

### Step 5: View the HTML report
```bash
# After analysis, open in browser:
xdg-open samples_phising/phishing-test_report.html    # Linux
open samples_phising/phishing-test_report.html         # Mac
start samples_phising/phishing-test_report.html        # Windows
```
