import json
import os
from datetime import datetime


def export_json(filepath, header_results, url_results, body_results, html_results,
                attachment_results, whois_results, vt_results, abuse_result, score_result):
    """Export full analysis report as JSON"""
    report = {
        'report_date': datetime.now().isoformat(),
        'source_file': filepath,
        'risk_score': score_result,
        'header_analysis': header_results,
        'url_analysis': url_results,
        'body_analysis': body_results,
        'html_analysis': html_results,
        'attachment_analysis': attachment_results,
        'whois_analysis': whois_results,
        'virustotal_results': vt_results,
        'abuseipdb_result': abuse_result
    }

    out_name = os.path.splitext(os.path.basename(filepath))[0] + '_report.json'
    out_path = os.path.join(os.path.dirname(filepath) or '.', out_name)

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)

    return out_path


def export_html(filepath, header_results, url_results, body_results, html_results,
                attachment_results, whois_results, vt_results, abuse_result, score_result):
    """Export full analysis report as HTML"""

    score = score_result['score']
    verdict = score_result['verdict']

    if score >= 75:
        color = '#dc3545'
    elif score >= 50:
        color = '#fd7e14'
    elif score >= 25:
        color = '#ffc107'
    else:
        color = '#28a745'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Phishing Analysis Report</title>
<style>
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
  h2 {{ color: #00d4ff; margin-top: 30px; }}
  .score-box {{ background: {color}; color: white; padding: 20px; border-radius: 10px;
               text-align: center; font-size: 24px; margin: 20px 0; }}
  .score-num {{ font-size: 48px; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #333; }}
  th {{ background: #16213e; color: #00d4ff; }}
  tr:hover {{ background: #16213e; }}
  .flag {{ color: #ff6b6b; font-weight: bold; }}
  .ok {{ color: #51cf66; }}
  .warn {{ color: #ffd43b; }}
  .section {{ background: #16213e; padding: 15px; border-radius: 8px; margin: 15px 0; }}
  .meta {{ color: #888; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>Phishing Analysis Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | File: {_esc(os.path.basename(filepath))}</p>

<div class="score-box">
  <div class="score-num">{score}/100</div>
  <div>{_esc(verdict)}</div>
</div>
"""

    # Score breakdown
    if score_result.get('breakdown'):
        html += '<h2>Score Breakdown</h2><div class="section"><table><tr><th>Factor</th><th>Points</th></tr>'
        for reason, pts in sorted(score_result['breakdown'], key=lambda x: -x[1]):
            html += f'<tr><td>{_esc(reason)}</td><td>+{pts}</td></tr>'
        html += '</table></div>'

    # Header info
    html += '<h2>Email Headers</h2><div class="section"><table>'
    for key in ['from', 'to', 'subject', 'date', 'return_path', 'reply_to', 'message_id']:
        val = header_results.get(key, 'N/A') or 'N/A'
        html += f'<tr><td><strong>{_esc(key.replace("_", " ").title())}</strong></td><td>{_esc(str(val))}</td></tr>'
    html += '</table>'

    # Auth
    auth = header_results.get('auth', {})
    html += '<table><tr><th>Auth</th><th>Status</th></tr>'
    for k in ['spf', 'dkim', 'dmarc']:
        val = auth.get(k, 'N/A')
        cls = 'ok' if val == 'PASS' else 'flag' if val in ('FAIL',) else 'warn'
        html += f'<tr><td>{k.upper()}</td><td class="{cls}">{_esc(val)}</td></tr>'
    html += '</table>'

    # Header red flags
    if header_results.get('red_flags'):
        html += '<br>'
        for flag in header_results['red_flags']:
            html += f'<div class="flag">[!] {_esc(flag)}</div>'
    html += '</div>'

    # URLs
    html += f'<h2>URL Analysis ({len(url_results)} URLs)</h2><div class="section">'
    if url_results:
        for entry in url_results:
            html += f'<p><strong>{_esc(entry["url"][:80])}</strong><br>Domain: {_esc(str(entry.get("domain")))}</p>'
            if entry.get('red_flags'):
                for flag in entry['red_flags']:
                    html += f'<div class="flag">[!] {_esc(flag)}</div>'
    else:
        html += '<p class="ok">No URLs found</p>'
    html += '</div>'

    # Body analysis
    html += '<h2>Body Content Analysis</h2><div class="section">'
    if body_results.get('matches'):
        html += '<table><tr><th>Pattern</th><th>Examples</th></tr>'
        for m in body_results['matches']:
            examples = ', '.join(f'"{e}"' for e in m['examples'][:2])
            html += f'<tr><td>{_esc(m["category"])}</td><td>{_esc(examples)}</td></tr>'
        html += '</table>'
    else:
        html += '<p class="ok">No social engineering patterns detected</p>'
    for flag in body_results.get('red_flags', []):
        html += f'<div class="flag">[!] {_esc(flag)}</div>'
    html += '</div>'

    # HTML analysis
    html += '<h2>HTML Analysis</h2><div class="section">'
    if html_results.get('has_html'):
        if html_results.get('findings'):
            for f in html_results['findings']:
                html += f'<p>{_esc(f)}</p>'
        for flag in html_results.get('red_flags', []):
            html += f'<div class="flag">[!] {_esc(flag)}</div>'
        if not html_results.get('findings') and not html_results.get('red_flags'):
            html += '<p class="ok">No suspicious HTML elements</p>'
    else:
        html += '<p>No HTML content</p>'
    html += '</div>'

    # Attachments
    html += f'<h2>Attachments ({len(attachment_results)})</h2><div class="section">'
    if attachment_results:
        for att in attachment_results:
            html += f'<p><strong>{_esc(att["filename"])}</strong> ({att["size"]} bytes)<br>'
            html += f'SHA256: <code>{att["sha256"]}</code></p>'
            for flag in att.get('red_flags', []):
                html += f'<div class="flag">[!] {_esc(flag)}</div>'
    else:
        html += '<p class="ok">No attachments</p>'
    html += '</div>'

    # WHOIS
    html += '<h2>Domain WHOIS</h2><div class="section">'
    if whois_results:
        for w in whois_results:
            if not w:
                continue
            html += f'<p><strong>{_esc(w["domain"])}</strong>'
            if w.get('creation_date'):
                html += f' — registered {_esc(w["creation_date"])} ({w["age_days"]}d ago)'
            html += '</p>'
            for flag in w.get('red_flags', []):
                html += f'<div class="flag">[!] {_esc(flag)}</div>'
    else:
        html += '<p>No domains checked</p>'
    html += '</div>'

    # VT results
    html += '<h2>VirusTotal</h2><div class="section">'
    if vt_results:
        html += '<table><tr><th>Target</th><th>Malicious</th><th>Suspicious</th><th>Harmless</th></tr>'
        for vt in vt_results:
            if 'error' in vt:
                html += f'<tr><td colspan="4">{_esc(vt["error"])}</td></tr>'
            else:
                target = vt.get('url') or vt.get('ip', '?')
                mal = vt.get('malicious', 0)
                cls = 'flag' if mal > 0 else ''
                html += f'<tr><td>{_esc(str(target)[:60])}</td><td class="{cls}">{mal}</td>'
                html += f'<td>{vt.get("suspicious", 0)}</td><td>{vt.get("harmless", 0)}</td></tr>'
        html += '</table>'
    else:
        html += '<p>No VT results</p>'
    html += '</div>'

    # AbuseIPDB
    html += '<h2>AbuseIPDB</h2><div class="section">'
    if abuse_result and 'error' not in abuse_result:
        abuse_s = abuse_result.get('abuse_score', 0)
        cls = 'flag' if abuse_s >= 50 else 'warn' if abuse_s >= 25 else 'ok'
        html += f'<p>IP: <strong>{_esc(abuse_result["ip"])}</strong></p>'
        html += f'<p class="{cls}">Abuse Score: {abuse_s}%</p>'
        html += f'<p>ISP: {_esc(abuse_result.get("isp", "N/A"))} | Country: {_esc(abuse_result.get("country", "N/A"))}</p>'
        html += f'<p>Reports: {abuse_result.get("total_reports", 0)}</p>'
    elif abuse_result and 'error' in abuse_result:
        html += f'<p>{_esc(abuse_result["error"])}</p>'
    else:
        html += '<p>No IP to check</p>'
    html += '</div>'

    html += '</div></body></html>'

    out_name = os.path.splitext(os.path.basename(filepath))[0] + '_report.html'
    out_path = os.path.join(os.path.dirname(filepath) or '.', out_name)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return out_path


def _esc(text):
    """Escape HTML special characters"""
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;'))
