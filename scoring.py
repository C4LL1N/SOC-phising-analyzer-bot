def calculate_risk_score(header_results, url_results, body_results, html_results,
                         attachment_results, whois_results, vt_results, abuse_result):
    """Calculate overall phishing risk score (0-100) based on all analysis modules"""
    score = 0
    breakdown = []

    # --- Header red flags (max 25 pts) ---
    header_flags = len(header_results.get('red_flags', []))
    auth = header_results.get('auth', {})

    if auth.get('spf') == 'FAIL':
        score += 16
        breakdown.append(('SPF FAIL', 16))
    elif auth.get('spf') == 'SOFTFAIL':
        score += 8
        breakdown.append(('SPF SOFTFAIL', 8))

    if auth.get('dkim') == 'FAIL':
        score += 16
        breakdown.append(('DKIM FAIL', 16))

    if auth.get('dmarc') == 'FAIL':
        score += 16
        breakdown.append(('DMARC FAIL', 16))

    # From/Return-Path or Reply-To mismatch
    mismatch_flags = [f for f in header_results.get('red_flags', []) if 'MISMATCH' in f]
    if mismatch_flags:
        pts = min(len(mismatch_flags) * 10, 20)
        score += pts
        breakdown.append(('Header mismatches', pts))

    # --- URL analysis ---
    url_flag_count = sum(len(u.get('red_flags', [])) for u in url_results)
    if url_flag_count > 0:
        pts = min(url_flag_count * 6, 40)
        score += pts
        breakdown.append((f'Suspicious URLs ({url_flag_count} flags)', pts))

    # --- Body analysis ---
    body_matches = len(body_results.get('matches', []))
    if body_matches >= 4:
        score += 30
        breakdown.append((f'Heavy social engineering ({body_matches} patterns)', 30))
    elif body_matches >= 2:
        score += 16
        breakdown.append((f'Social engineering patterns ({body_matches})', 16))
    elif body_matches >= 1:
        score += 6
        breakdown.append(('Mild social engineering language', 6))

    body_flags = body_results.get('red_flags', [])
    for flag in body_flags:
        if 'ALL CAPS' in flag:
            score += 6
            breakdown.append(('ALL CAPS abuse', 6))
        if 'exclamation' in flag.lower():
            score += 4
            breakdown.append(('Excessive punctuation', 4))

    # --- HTML analysis ---
    html_flags = len(html_results.get('red_flags', []))
    if html_flags > 0:
        pts = min(html_flags * 8, 30)
        score += pts
        breakdown.append((f'Suspicious HTML ({html_flags} issues)', pts))

    # --- Attachments ---
    for att in attachment_results:
        att_flags = len(att.get('red_flags', []))
        if att_flags > 0:
            pts = min(att_flags * 10, 20)
            score += pts
            breakdown.append((f'Suspicious attachment: {att["filename"]}', pts))

        vt = att.get('vt_result', {})
        if vt and vt.get('malicious', 0) > 0:
            score += 50
            breakdown.append((f'VT: malicious attachment {att["filename"]}', 50))

    # --- WHOIS / Domain age ---
    for w in (whois_results or []):
        if not w:
            continue
        age = w.get('age_days')
        if age is not None and age < 30:
            score += 20
            breakdown.append((f'Very new domain: {w["domain"]} ({age}d)', 20))
        elif age is not None and age < 90:
            score += 10
            breakdown.append((f'New domain: {w["domain"]} ({age}d)', 10))

    # --- VirusTotal results ---
    for vt in (vt_results or []):
        if 'error' in vt:
            continue
        mal = vt.get('malicious', 0)
        sus = vt.get('suspicious', 0)
        if mal >= 5:
            score += 50
            breakdown.append((f'VT: {mal} engines flagged {vt.get("url") or vt.get("ip")}', 50))
        elif mal >= 1:
            score += 24
            breakdown.append((f'VT: {mal} engine(s) flagged {(vt.get("url") or vt.get("ip", ""))[:40]}', 24))
        elif sus >= 1:
            score += 10
            breakdown.append((f'VT: suspicious by {sus} engine(s)', 10))

    # --- AbuseIPDB ---
    if abuse_result and 'error' not in abuse_result:
        abuse_score = abuse_result.get('abuse_score', 0)
        if abuse_score >= 80:
            score += 30
            breakdown.append((f'AbuseIPDB score {abuse_score}%', 30))
        elif abuse_score >= 25:
            score += 14
            breakdown.append((f'AbuseIPDB score {abuse_score}%', 14))

    # Cap at 100
    score = min(score, 100)

    # Determine verdict
    if score >= 75:
        verdict = 'PHISHING — HIGH RISK'
    elif score >= 50:
        verdict = 'SUSPICIOUS — LIKELY PHISHING'
    elif score >= 25:
        verdict = 'CAUTION — SOME RED FLAGS'
    else:
        verdict = 'LOW RISK — PROBABLY LEGITIMATE'

    return {
        'score': score,
        'verdict': verdict,
        'breakdown': breakdown
    }


def print_score_report(result):
    """Print risk score report"""
    score = result['score']
    verdict = result['verdict']

    print(f"\n{'=' * 60}")
    print(f"       RISK SCORE: {score}/100 — {verdict}")
    print(f"{'=' * 60}")

    if result['breakdown']:
        print(f"\n  Score breakdown:")
        for reason, pts in sorted(result['breakdown'], key=lambda x: -x[1]):
            print(f"    +{pts:>2}  {reason}")
    else:
        print(f"\n  No risk indicators found")

    print()
