# JAK TO DZIALA - KROK PO KROKU

Ten dokument tlumaczy dokladnie co robi kazdy modul, w jakiej kolejnosci i dlaczego.

---

## OGOLNY PRZEPLYW

Kiedy odpalasz `python3 header_analyzer.py email.eml`, dzieje sie to:

```
email.eml (plik z mailem)
    |
    v
[1] HEADER ANALYZER --- czyta naglowki maila (From, To, SPF, DKIM...)
    |
    v
[2] URL ANALYZER --- wyciaga wszystkie linki z tresci maila
    |
    v
[3] BODY ANALYZER --- skanuje tresc pod katem manipulacji ("pilne!", "kliknij tu!")
    |
    v
[4] HTML ANALYZER --- sprawdza HTML pod katem ukrytych formularzy, skryptow, iframe
    |
    v
[5] ATTACHMENT ANALYZER --- analizuje zalaczniki (rozszerzenia, hashe, VT lookup)
    |
    v
[6] WHOIS CHECKER --- sprawdza wiek domen z linkow (swieza domena = podejrzana)
    |
    v
[7] VIRUSTOTAL --- skanuje URL-e i IP na 70+ silnikach antywirusowych
    |
    v
[8] ABUSEIPDB --- sprawdza reputacje IP nadawcy
    |
    v
[9] SCORING --- zbiera wszystkie red flagi i liczy score 0-100
    |
    v
[10] EXPORT --- zapisuje raport do JSON i HTML
```

---

## MODUL 1: header_analyzer.py (NAGLOWKI)

### Co robi:
Otwiera plik .eml i czyta naglowki emaila — to sa metadane ktore serwery pocztowe dodaja do kazdego maila.

### Jak dokladnie:
1. Otwiera plik .eml uzywajac biblioteki `email` (wbudowana w Pythona)
2. Wyciaga pola: From, To, Subject, Date, Return-Path, Reply-To, Message-ID
3. Czyta lancuch "Received" — to sa stempelki od kazdego serwera ktory przekazal maila. Ostatni na liscie = pierwszy serwer (nadawca), pierwszy = ostatni (Twoj serwer)
4. Z pierwszego Received wyciaga IP nadawcy (regex szuka `[123.45.67.89]`)
5. Czyta "Authentication-Results" i sprawdza:
   - **SPF** (Sender Policy Framework) — czy serwer nadawcy jest upowazniony do wysylania maili z tej domeny. FAIL = ktos podszywa sie pod te domene
   - **DKIM** (DomainKeys Identified Mail) — podpis cyfrowy maila. FAIL = tresc mogla byc zmieniona po drodze
   - **DMARC** (Domain-based Message Authentication) — laczy SPF + DKIM i mowi co robic z mailem ktory nie przechodzi. FAIL = domena nie potwierdza tego maila
6. Porownuje domeny:
   - From vs Return-Path — jesli sie roznia, ktos moze udawac innego nadawce
   - From vs Reply-To — jesli sie roznia, odpowiedz poleci na inny adres niz widzi odbiorca

### Czemu to wazne:
Phishingowe maile prawie zawsze failuja SPF/DKIM/DMARC bo sa wysylane z serwerow ktore nie sa autoryzowane. Mismatch domen to klasyczny red flag.

---

## MODUL 2: url_analyzer.py (LINKI)

### Co robi:
Wyciaga wszystkie URL-e z maila i sprawdza czy wygladaja podejrzanie.

### Jak dokladnie:
1. Przechodzi przez wszystkie czesci maila (text/plain i text/html)
2. Regex szuka wzorca `https?://...` (kazdy link)
3. Dodatkowo szuka `href="..."` w HTML-u (linki moga byc ukryte w tagach)
4. Dla kazdego URL-a sprawdza:
   - **IP zamiast domeny** — `http://192.168.1.1/login` zamiast `http://bank.com/login` = podejrzane
   - **Podejrzane TLD** — `.xyz`, `.top`, `.tk` itp. sa tanie/darmowe i czesto uzywane do phishingu
   - **Typosquatting** — czy domena zawiera nazwe znanej marki ale nie JEST ta marka (np. `paypa1-login.com` zawiera "paypal" ale to nie PayPal)
   - **Skracacze URL** — `bit.ly`, `tinyurl.com` itp. ukrywaja prawdziwy cel
   - **Duzo subdomen** — `login.secure.paypal.verify.evil.com` wyglada podejrzanie
   - **@ w URL** — `http://google.com@evil.com` — przegladarka zignoruje "google.com" i przejdzie na evil.com!
   - **Niestandardowy port** — `http://site.com:8080` moze byc serwer phishingowy

---

## MODUL 3: body_analyzer.py (TRESC MAILA)

### Co robi:
Skanuje tekst maila pod katem 15 wzorcow manipulacji psychologicznej typowych dla phishingu.

### Wzorce ktore wykrywa:
1. **Pilnosc** — "immediately", "urgent", "ASAP", "time sensitive"
2. **Pressure** — "act now", "action required", "must verify"
3. **Grozby** — "account will be suspended/closed/terminated"
4. **Weryfikacja** — "verify your account/identity/email"
5. **Dane logowania** — "confirm your password/credentials"
6. **Platnosci** — "update your payment/billing/credit card"
7. **Podejrzana aktywnosc** — "unusual activity/sign-in/transaction"
8. **Nagrody** — "won", "prize", "congratulations", "lottery"
9. **Nieprosledzalne platnosci** — "wire transfer", "bitcoin", "gift card"
10. **Dyrektywy** — "click here", "click below", "open the attachment"
11. **Haslo** — "password expiring", "reset your password"
12. **Izolacja** — "do not share", "confidential", "do not forward"
13. **Generyczne powitanie** — "Dear valued customer" (zamiast imienia)
14. **Sztuczny deadline** — "within 24 hours", "in the next 48 hours"
15. **Przesylka** — "invoice", "receipt", "shipment", "tracking"

Dodatkowo sprawdza:
- Ilosc wykrzyknikow (>5 = nacisk)
- Slowa pisane CAPS LOCKIEM
- Dziwne sformulowania typowe dla phishingu ("kindly", "do the needful")

---

## MODUL 4: html_analyzer.py (HTML)

### Co robi:
Analizuje kod HTML maila pod katem podejrzanych elementow technicznych.

### Co sprawdza:
1. **Formularze z external action** — `<form action="http://evil.com/steal">` — formularz ktory wysyla Twoje dane na zewnetrzny serwer
2. **Ukryte inputy** — `<input type="hidden">` — pola ktore wysylaja dane bez Twojej wiedzy
3. **display:none** — elementy ukryte CSSem, moga zawierac dodatkowy kod
4. **Piksele sledzace** — elementy 0x0 lub 1x1 px, sluza do trackowania czy otworzyles maila
5. **JavaScript** — `<script>` w mailu to MEGA red flag, normalne maile nie maja JS
6. **Event handlery** — `onclick`, `onload` itp. — inline JS ktory odpala sie na zdarzenia
7. **Base64** — zakodowana tresc, moze ukrywac zlosliwy kod
8. **iframe** — osadzone strony wewnatrz maila
9. **Link mismatch** — tekst linku mowi "http://paypal.com" ale href prowadzi na "http://evil.com"
10. **Meta refresh** — automatyczne przekierowanie na inna strone

---

## MODUL 5: attachment_analyzer.py (ZALACZNIKI)

### Co robi:
Sprawdza kazdy zalacznik w mailu pod katem zagrozenia.

### Jak:
1. Przechodzi przez czesci MIME maila i znajduje te z `Content-Disposition: attachment`
2. Dla kazdego zalacznika:
   - Sprawdza rozszerzenie — jest lista ~35 podejrzanych (.exe, .scr, .bat, .js, .vbs, .docm, .xlsm...)
   - Sprawdza czy to **makro-plik** (.docm, .xlsm) — makra moga uruchomic zlosliwy kod
   - Wykrywa **podwojne rozszerzenie** — `faktura.pdf.exe` wyglada jak PDF ale to .exe
   - Porownuje rozszerzenie z Content-Type (np. plik .exe z Content-Type: application/pdf = podejrzane)
   - Sprawdza czy ZIP jest zaszyfrowany haslem (czesty trik phishingowy — haslo jest w mailu, AV nie moze skanowac)
   - Liczy **SHA256 i MD5** hash pliku
   - Sprawdza hash na **VirusTotal** — jesli ktos juz wgral ten plik, VT ma wyniki skanow

---

## MODUL 6: whois_checker.py (WIEK DOMENY)

### Co robi:
Sprawdza kiedy zostala zarejestrowana domena z URL-i w mailu.

### Dlaczego to wazne:
Phisherzy rejestruja nowe domeny na kazda kampanie. Domena zarejestrowana 2 dni temu ktora twierdzi ze jest "PayPal" = oczywisty phishing.

### Jak:
1. Laczy sie socketem z `whois.iana.org` (port 43) i pyta o domene
2. IANA zwraca ktory serwer WHOIS obsluguje ta domene (np. `whois.verisign-grs.com` dla .com)
3. Laczy sie z wlasciwym serwerem WHOIS i pobiera dane rejestracji
4. Parsuje date rejestracji (rozne formaty — WHOIS nie ma jednego standardu)
5. Liczy ile dni temu zarejestrowano:
   - **< 30 dni** — VERY NEW, duzy red flag
   - **< 90 dni** — relatywnie nowa, ostrzezenie

---

## MODUL 7: virustotal_scanner.py

### Co robi:
Wysyla URL-e i IP do VirusTotal — serwisu ktory skanuje podejrzane pliki/URL-e na 70+ silnikach antywirusowych.

### Jak:
1. Bierze URL, koduje go base64 (wymagane przez VT API)
2. Najpierw sprawdza czy VT ma juz raport dla tego URL-a (`GET /urls/{id}`)
3. Jesli nie ma — submituje URL do skanu (`POST /urls`) i czeka 3 sekundy na wynik
4. Z raportu wyciaga: ile silnikow oznaczylo jako `malicious`, `suspicious`, `harmless`
5. To samo robi dla IP nadawcy (`GET /ip_addresses/{ip}`)

### API:
- Darmowe konto: 4 requesty/minute, 500/dzien
- Klucz w `.env` jako `VT_API_KEY`

---

## MODUL 8: abuseipdb_checker.py

### Co robi:
Sprawdza IP nadawcy w AbuseIPDB — bazie danych zgloszonych zloslliwych IP.

### Jak:
1. Wysyla request do `api.abuseipdb.com/api/v2/check` z IP nadawcy
2. Dostaje: abuse score (0-100%), kraj, ISP, ilosc zgloszen, data ostatniego zgloszenia
3. Score >= 80% = HIGH RISK (duzo ludzi zglaszalo ten IP)
4. Score >= 25% = SUSPICIOUS

---

## MODUL 9: scoring.py (PUNKTACJA)

### Co robi:
Zbiera wyniki ze WSZYSTKICH modulow i liczy finalny score 0-100.

### Skad sa punkty:
```
SPF FAIL                      +16 pkt
SPF SOFTFAIL                  +8 pkt
DKIM FAIL                     +16 pkt
DMARC FAIL                    +16 pkt
Header mismatche              +10 za kazdy (max 20)
Podejrzane URL-e              +6 za flage (max 40)
Social engineering 4+ wzorcow +30 pkt
Social engineering 2-3        +16 pkt
Social engineering 1          +6 pkt
CAPS LOCK                     +6 pkt
Wykrzykniki                   +4 pkt
Podejrzany HTML               +8 za issue (max 30)
Podejrzany zalacznik          +10 za flage (max 20)
VT: zlosliwy zalacznik        +50 pkt   <<<< MALWARE = pol skali
Domena < 30 dni               +20 pkt
Domena < 90 dni               +10 pkt
VT: 5+ silnikow flaguje       +50 pkt   <<<< MALWARE = pol skali
VT: 1-4 silnikow              +24 pkt
VT: suspicious                +10 pkt
AbuseIPDB >= 80%              +30 pkt
AbuseIPDB >= 25%              +14 pkt
```

### Werdykty:
- **0-24** = LOW RISK — prawdopodobnie legit
- **25-49** = CAUTION — sa jakies red flagi
- **50-74** = SUSPICIOUS — pewnie phishing
- **75-100** = PHISHING HIGH RISK

---

## MODUL 10: report_export.py (EKSPORT)

### Co robi:
Generuje raporty do dwoch formatow:

1. **JSON** — plik `nazwa_report.json` z pelnym dumpem wszystkich wynikow. Czytelny maszynowo, mozna go parsowac w innych narzedziach
2. **HTML** — plik `nazwa_report.html` z ciemnym motywem, ladnymi tabelkami, kolorowanym score'em. Mozna otworzyc w przegladarce i wyslac komus

---

## FORMAT PLIKU .eml

Plik `.eml` to surowy email w formacie tekstowym (MIME). Mozesz go uzyskac:
- **Gmail**: Otworz maila -> trzy kropki -> "Pobierz wiadomosc" / "Show original" -> Download
- **Outlook**: Otworz maila -> File -> Save As -> typ "Outlook Message Format - Unicode" lub przeciagnij na pulpit
- **Thunderbird**: Otworz maila -> File -> Save As -> plik .eml

---

## JAK ODPALIC

### Krok 1: Zainstaluj Pythona
```bash
python3 --version
# Powinno pokazac 3.8 lub nowszy. Jesli nie masz:
# Ubuntu/Debian: sudo apt install python3 python3-pip
# Mac: brew install python3
# Windows: https://python.org/downloads
```

### Krok 2: Zainstaluj zaleznosci
```bash
cd phisingAnalyzer
pip install -r requirements.txt
```

### Krok 3: Ustaw klucze API (opcjonalnie)
```bash
cp .env.example .env
nano .env  # wklej swoje klucze
```
Bez kluczy narzedzie dalej dziala — po prostu pomija VT i AbuseIPDB.

### Krok 4: Odpal
```bash
# Jeden plik
python3 header_analyzer.py samples_phising/phishing-test.eml

# Caly folder
python3 header_analyzer.py samples_phising/

# Bez eksportu raportow
python3 header_analyzer.py --no-export samples_phising/phishing-test.eml

# Tylko JSON
python3 header_analyzer.py --format json samples_phising/phishing-test.eml
```

### Krok 5: Obejrzyj raport HTML
```bash
# Po analizie otworz w przegladarce:
xdg-open samples_phising/phishing-test_report.html    # Linux
open samples_phising/phishing-test_report.html         # Mac
start samples_phising/phishing-test_report.html        # Windows
```
