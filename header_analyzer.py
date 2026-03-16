import email
from email import policy
import re
import socket


def analyze_headers(eml_path):
    """Analyze email headers from .eml file"""
    with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = email.message_from_file(f, policy=policy.default)

    results = {
        'from': msg['From'],
        'return_path': msg['Return-Path'],
        'reply_to': msg['Reply-To'],
        'to': msg['To'],
        'subject': msg['Subject'],
        'date': msg['Date'],
        'message_id': msg['Message-ID'],
        'received_chain': [],
        'auth': {
            'spf': 'NOT FOUND',
            'dkim': 'NOT FOUND',
            'dmarc': 'NOT FOUND'
        },
        'red_flags': [],
        'originating_ip': None
    }

    # Parse Received headers (bottom = first hop, top = last hop)
    received_headers = msg.get_all('Received', [])
    for i, header in enumerate(reversed(received_headers)):
        results['received_chain'].append({
            'hop': i + 1,
            'header': header.strip()
        })

    # Extract originating IP from first Received header
    if received_headers:
        first_received = received_headers[-1]  # bottom = origin
        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', first_received)
        if ip_match:
            results['originating_ip'] = ip_match.group(1)

    # Parse Authentication-Results
    auth_results = msg['Authentication-Results'] or ''
    if 'spf=pass' in auth_results.lower():
        results['auth']['spf'] = 'PASS'
    elif 'spf=fail' in auth_results.lower():
        results['auth']['spf'] = 'FAIL'
        results['red_flags'].append('SPF FAIL — sender not authorized')
    elif 'spf=softfail' in auth_results.lower():
        results['auth']['spf'] = 'SOFTFAIL'
        results['red_flags'].append('SPF SOFTFAIL — sender questionable')

    if 'dkim=pass' in auth_results.lower():
        results['auth']['dkim'] = 'PASS'
    elif 'dkim=fail' in auth_results.lower():
        results['auth']['dkim'] = 'FAIL'
        results['red_flags'].append('DKIM FAIL — message may be tampered')

    if 'dmarc=pass' in auth_results.lower():
        results['auth']['dmarc'] = 'PASS'
    elif 'dmarc=fail' in auth_results.lower():
        results['auth']['dmarc'] = 'FAIL'
        results['red_flags'].append('DMARC FAIL — domain alignment failed')

    # Check From vs Return-Path mismatch
    from_domain = extract_domain(results['from'])
    return_path_domain = extract_domain(results['return_path'])
    if from_domain and return_path_domain:
        if from_domain.lower() != return_path_domain.lower():
            results['red_flags'].append(
                f'FROM/RETURN-PATH MISMATCH: {from_domain} vs {return_path_domain}'
            )

    # Check Reply-To mismatch
    if results['reply_to']:
        reply_domain = extract_domain(results['reply_to'])
        if from_domain and reply_domain:
            if from_domain.lower() != reply_domain.lower():
                results['red_flags'].append(
                    f'FROM/REPLY-TO MISMATCH: {from_domain} vs {reply_domain}'
                )

    return results


def extract_domain(email_str):
    """Extract domain from email address string"""
    if not email_str:
        return None
    match = re.search(r'@([\w.-]+)', str(email_str))
    return match.group(1) if match else None


def resolve_ip(ip_address):
    """Reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except (socket.herror, socket.gaierror):
        return 'No PTR record'


def print_report(results):
    """Print formatted analysis report"""
    print("=" * 60)
    print("       EMAIL HEADER ANALYSIS REPORT")
    print("=" * 60)

    print(f"\n--- Basic Info ---")
    print(f"  From:        {results['from']}")
    print(f"  To:          {results['to']}")
    print(f"  Subject:     {results['subject']}")
    print(f"  Date:        {results['date']}")
    print(f"  Return-Path: {results['return_path']}")
    print(f"  Reply-To:    {results['reply_to']}")
    print(f"  Message-ID:  {results['message_id']}")

    print(f"\n--- Authentication ---")
    print(f"  SPF:   {results['auth']['spf']}")
    print(f"  DKIM:  {results['auth']['dkim']}")
    print(f"  DMARC: {results['auth']['dmarc']}")

    print(f"\n--- Originating IP ---")
    ip = results['originating_ip']
    if ip:
        ptr = resolve_ip(ip)
        print(f"  IP:       {ip}")
        print(f"  Reverse:  {ptr}")
    else:
        print(f"  Not found")

    print(f"\n--- Received Chain ({len(results['received_chain'])} hops) ---")
    for hop in results['received_chain']:
        print(f"  Hop {hop['hop']}: {hop['header'][:100]}...")

    print(f"\n--- RED FLAGS ---")
    if results['red_flags']:
        for flag in results['red_flags']:
            print(f"  [!] {flag}")
    else:
        print(f"  None detected")

    print("\n" + "=" * 60)


def analyze_single(eml_path, export=True, export_format='all'):
    """Run full analysis pipeline on a single .eml file"""
    from url_analyzer import extract_urls, print_url_report
    from virustotal_scanner import scan_url, scan_ip, print_vt_report
    from abuseipdb_checker import check_ip, print_abuse_report
    from attachment_analyzer import analyze_attachments, print_attachment_report
    from whois_checker import check_domains_from_urls, print_whois_report
    from body_analyzer import analyze_body, print_body_report
    from html_analyzer import analyze_html, print_html_report
    from scoring import calculate_risk_score, print_score_report
    from report_export import export_json, export_html

    # 1) Header analysis
    header_results = analyze_headers(eml_path)
    print_report(header_results)

    # 2) URL analysis
    url_results = extract_urls(eml_path)
    print_url_report(url_results)

    # 3) Body content analysis
    body_results = analyze_body(eml_path)
    print_body_report(body_results)

    # 4) HTML analysis
    html_results = analyze_html(eml_path)
    print_html_report(html_results)

    # 5) Attachment analysis
    attachment_results = analyze_attachments(eml_path)
    print_attachment_report(attachment_results)

    # 6) WHOIS / domain age
    whois_results = check_domains_from_urls(url_results)
    print_whois_report(whois_results)

    # 7) VirusTotal — scan URLs + originating IP
    vt_results = []
    for entry in url_results:
        vt_results.append(scan_url(entry['url']))
    if header_results['originating_ip']:
        vt_results.append(scan_ip(header_results['originating_ip']))
    print_vt_report(vt_results)

    # 8) AbuseIPDB — check originating IP
    if header_results['originating_ip']:
        abuse_result = check_ip(header_results['originating_ip'])
    else:
        abuse_result = None
    print_abuse_report(abuse_result)

    # 9) Risk score
    score_result = calculate_risk_score(
        header_results, url_results, body_results, html_results,
        attachment_results, whois_results, vt_results, abuse_result
    )
    print_score_report(score_result)

    # 10) Export reports
    if export:
        export_args = (eml_path, header_results, url_results, body_results,
                       html_results, attachment_results, whois_results,
                       vt_results, abuse_result, score_result)
        print(f"  Reports saved:")
        if export_format in ('all', 'json'):
            json_path = export_json(*export_args)
            print(f"    JSON: {json_path}")
        if export_format in ('all', 'html'):
            html_path = export_html(*export_args)
            print(f"    HTML: {html_path}")

    return score_result


if __name__ == "__main__":
    import sys
    import os
    import glob
    import argparse

    parser = argparse.ArgumentParser(
        description='PhishingAnalyzer — multi-vector email phishing analysis toolkit',
        epilog='Examples:\n'
               '  python3 header_analyzer.py email.eml\n'
               '  python3 header_analyzer.py samples_phising/\n'
               '  python3 header_analyzer.py --format json --no-export email.eml\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', nargs='+', help='.eml file(s) or folder(s) to analyze')
    parser.add_argument('--no-export', action='store_true', help='skip report export (JSON/HTML)')
    parser.add_argument('--format', choices=['all', 'json', 'html'], default='all',
                        help='export format (default: all)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='only show risk score, skip detailed output')

    args = parser.parse_args()

    # Resolve targets
    targets = []
    for arg in args.targets:
        if os.path.isdir(arg):
            targets.extend(sorted(glob.glob(os.path.join(arg, '*.eml'))))
        elif os.path.isfile(arg):
            targets.append(arg)
        else:
            # Try glob expansion
            expanded = sorted(glob.glob(arg))
            if expanded:
                targets.extend(expanded)
            else:
                print(f"Warning: '{arg}' not found, skipping")

    if not targets:
        print("No .eml files found")
        sys.exit(1)

    batch = len(targets) > 1
    summaries = []

    for i, eml_path in enumerate(targets):
        if batch:
            print(f"\n{'#' * 60}")
            print(f"  FILE {i+1}/{len(targets)}: {eml_path}")
            print(f"{'#' * 60}")

        export = not args.no_export
        score_result = analyze_single(eml_path, export=export, export_format=args.format)
        summaries.append((eml_path, score_result))

    # Batch summary
    if batch:
        print(f"\n{'=' * 60}")
        print(f"       BATCH SUMMARY — {len(summaries)} files analyzed")
        print(f"{'=' * 60}")
        summaries.sort(key=lambda x: -x[1]['score'])
        for path, sr in summaries:
            print(f"  [{sr['score']:>3}/100] {sr['verdict']:<35} {os.path.basename(path)}")
        print()