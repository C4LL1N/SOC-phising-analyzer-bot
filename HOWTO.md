HOW IT WORKS - STEP BY STEP
This document explains exactly what each module does, in what order, and why.

GENERAL FLOW
When you run python3 header_analyzer.py email.eml, this happens:
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

MODULE 1: header_analyzer.py (HEADERS)
What it does:
Opens the .eml file and reads email headers — metadata that mail servers add to every email.
How exactly:

Opens the .eml file using Python's built-in email library
Extracts fields: From, To, Subject, Date, Return-Path, Reply-To, Message-ID
Reads the "Received" chain — these are stamps from every server that relayed the email. Last in the list = first server (sender), first = last server (your server)
Extracts the sender's IP from the first Received header (regex looks for [123.45.67.89])
Reads "Authentication-Results" and checks:

SPF (Sender Policy Framework) — is the sender's server authorized to send emails from this domain? FAIL = someone is spoofing this domain
DKIM (DomainKeys Identified Mail) — digital signature of the email. FAIL = content may have been altered in transit
DMARC (Domain-based Message Authentication) — combines SPF + DKIM and specifies what to do with emails that fail. FAIL = the domain does not authenticate this email


Compares domains:

From vs Return-Path — if they differ, someone may be impersonating a different sender
From vs Reply-To — if they differ, the reply will go to a different address than the recipient sees



Why it matters:
Phishing emails almost always fail SPF/DKIM/DMARC because they are sent from unauthorized servers. Domain mismatches are a classic red flag.

MODULE 2: url_analyzer.py (LINKS)
What it does:
Extracts all URLs from the email and checks if they look suspicious.
How exactly:

Iterates through all parts of the email (text/plain and text/html)
Regex searches for https?://... pattern (every link)
Additionally searches for href="..." in HTML (links can be hidden in tags)
For each URL, checks:

IP instead of domain — http://192.168.1.1/login instead of http://bank.com/login = suspicious
Suspicious TLDs — .xyz, .top, .tk etc. are cheap/free and frequently used for phishing
Typosquatting — does the domain contain a known brand name but ISN'T that brand (e.g. paypa1-login.com contains "paypal" but it's not PayPal)
URL shorteners — bit.ly, tinyurl.com etc. hide the real destination
Excessive subdomains — login.secure.paypal.verify.evil.com looks suspicious
@ in URL — http://google.com@evil.com — the browser ignores "google.com" and goes to evil.com!
Non-standard port — http://site.com:8080 could be a phishing server




MODULE 3: body_analyzer.py (EMAIL BODY)
What it does:
Scans the email text for 15 psychological manipulation patterns typical of phishing.
Patterns it detects:

Urgency — "immediately", "urgent", "ASAP", "time sensitive"
Pressure — "act now", "action required", "must verify"
Threats — "account will be suspended/closed/terminated"
Verification — "verify your account/identity/email"
Credentials — "confirm your password/credentials"
Payments — "update your payment/billing/credit card"
Suspicious activity — "unusual activity/sign-in/transaction"
Rewards — "won", "prize", "congratulations", "lottery"
Untraceable payments — "wire transfer", "bitcoin", "gift card"
Directives — "click here", "click below", "open the attachment"
Password — "password expiring", "reset your password"
Isolation — "do not share", "confidential", "do not forward"
Generic greeting — "Dear valued customer" (instead of a name)
Artificial deadline — "within 24 hours", "in the next 48 hours"
Shipping — "invoice", "receipt", "shipment", "tracking"

Additionally checks:

Exclamation mark count (>5 = pressure tactic)
Words written in ALL CAPS
Unusual phrasing typical of phishing ("kindly", "do the needful")


MODULE 4: html_analyzer.py (HTML)
What it does:
Analyzes the email's HTML code for suspicious technical elements.
What it checks:

Forms with external action — <form action="http://evil.com/steal"> — a form that sends your data to an external server
Hidden inputs — <input type="hidden"> — fields that submit data without your knowledge
display:none — CSS-hidden elements that may contain additional code
Tracking pixels — 0x0 or 1x1 px elements used to track whether you opened the email
JavaScript — <script> in an email is a MAJOR red flag, legitimate emails don't have JS
Event handlers — onclick, onload etc. — inline JS that fires on events
Base64 — encoded content that may hide malicious code
iframe — embedded pages inside the email
Link mismatch — link text says "http://paypal.com" but href points to "http://evil.com"
Meta refresh — automatic redirect to another page


MODULE 5: attachment_analyzer.py (ATTACHMENTS)
What it does:
Checks every attachment in the email for threats.
How:

Iterates through MIME parts of the email and finds those with Content-Disposition: attachment
For each attachment:

Checks the extension — there's a list of ~35 suspicious ones (.exe, .scr, .bat, .js, .vbs, .docm, .xlsm...)
Checks if it's a macro-enabled file (.docm, .xlsm) — macros can execute malicious code
Detects double extensions — invoice.pdf.exe looks like a PDF but it's an .exe
Compares extension with Content-Type (e.g. .exe file with Content-Type: application/pdf = suspicious)
Checks if ZIP is password-protected (common phishing trick — password is in the email body, AV can't scan it)
Calculates SHA256 and MD5 hashes
Looks up the hash on VirusTotal — if someone already uploaded this file, VT has scan results




MODULE 6: whois_checker.py (DOMAIN AGE)
What it does:
Checks when the domain from the email's URLs was registered.
Why it matters:
Phishers register new domains for every campaign. A domain registered 2 days ago claiming to be "PayPal" = obvious phishing.
How:

Connects via socket to whois.iana.org (port 43) and queries the domain
IANA returns which WHOIS server handles that domain (e.g. whois.verisign-grs.com for .com)
Connects to the proper WHOIS server and retrieves registration data
Parses the registration date (various formats — WHOIS has no single standard)
Calculates how many days ago it was registered:

< 30 days — VERY NEW, major red flag
< 90 days — relatively new, warning




MODULE 7: virustotal_scanner.py
What it does:
Sends URLs and IPs to VirusTotal — a service that scans suspicious files/URLs against 70+ antivirus engines.
How:

Takes the URL, encodes it in base64 (required by the VT API)
First checks if VT already has a report for this URL (GET /urls/{id})
If not — submits the URL for scanning (POST /urls) and waits 3 seconds for results
Extracts from the report: how many engines flagged it as malicious, suspicious, harmless
Does the same for the sender's IP (GET /ip_addresses/{ip})

API:

Free account: 4 requests/minute, 500/day
Key stored in .env as VT_API_KEY


MODULE 8: abuseipdb_checker.py
What it does:
Checks the sender's IP in AbuseIPDB — a database of reported malicious IPs.
How:

Sends a request to api.abuseipdb.com/api/v2/check with the sender's IP
Receives: abuse score (0-100%), country, ISP, number of reports, date of last report
Score >= 80% = HIGH RISK (many people reported this IP)
Score >= 25% = SUSPICIOUS


MODULE 9: scoring.py (RISK SCORING)
What it does:
Collects results from ALL modules and calculates a final score from 0-100.
Point breakdown:
SPF FAIL                      +16 pts
SPF SOFTFAIL                  +8 pts
DKIM FAIL                     +16 pts
DMARC FAIL                    +16 pts
Header mismatches             +10 per mismatch (max 20)
Suspicious URLs               +6 per flag (max 40)
Social engineering 4+ patterns +30 pts
Social engineering 2-3         +16 pts
Social engineering 1           +6 pts
ALL CAPS abuse                +6 pts
Excessive exclamation marks   +4 pts
Suspicious HTML               +8 per issue (max 30)
Suspicious attachment         +10 per flag (max 20)
VT: malicious attachment      +50 pts   <<<< MALWARE = half the scale
Domain < 30 days              +20 pts
Domain < 90 days              +10 pts
VT: 5+ engines flag URL       +50 pts   <<<< MALWARE = half the scale
VT: 1-4 engines flag URL      +24 pts
VT: suspicious                +10 pts
AbuseIPDB >= 80%              +30 pts
AbuseIPDB >= 25%              +14 pts
Verdicts:

0-24 = LOW RISK — probably legitimate
25-49 = CAUTION — some red flags present
50-74 = SUSPICIOUS — likely phishing
75-100 = PHISHING — HIGH RISK


MODULE 10: report_export.py (EXPORT)
What it does:
Generates reports in two formats:

JSON — file name_report.json with a full dump of all results. Machine-readable, can be parsed by other tools
HTML — file name_report.html with a dark theme, clean tables, color-coded score. Can be opened in a browser and shared


.eml FILE FORMAT
An .eml file is a raw email in text format (MIME). You can obtain it from:

Gmail: Open the email -> three dots -> "Download message" / "Show original" -> Download
Outlook: Open the email -> File -> Save As -> type "Outlook Message Format - Unicode" or drag to desktop
Thunderbird: Open the email -> File -> Save As -> .eml file


HOW TO RUN
Step 1: Install Python
bashpython3 --version
# Should show 3.8 or newer. If not installed:
# Ubuntu/Debian: sudo apt install python3 python3-pip
# Mac: brew install python3
# Windows: https://python.org/downloads
Step 2: Install dependencies
bashcd phisingAnalyzer
pip install -r requirements.txt
Step 3: Set up API keys (optional)
bashcp .env.example .env
nano .env  # paste your keys
Without keys the tool still works — it just skips VT and AbuseIPDB checks.
Step 4: Run
bash# Single file
python3 header_analyzer.py samples_phishing/phishing-test.eml

# Entire folder
python3 header_analyzer.py samples_phishing/

# Without report export
python3 header_analyzer.py --no-export samples_phishing/phishing-test.eml

# JSON only
python3 header_analyzer.py --format json samples_phishing/phishing-test.eml
Step 5: View the HTML report
bash# After analysis, open in browser:
xdg-open samples_phishing/phishing-test_report.html    # Linux
open samples_phishing/phishing-test_report.html         # Mac
start samples_phishing/phishing-test_report.html        # Windows
