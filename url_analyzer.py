import re
import email
from email import policy
from urllib.parse import urlparse


def extract_urls(eml_path):
    """Extract all URLs from email body (text + HTML parts)"""
    with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = email.message_from_file(f, policy=policy.default)

    urls = set()
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]}>]+', re.IGNORECASE
    )

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ('text/plain', 'text/html'):
                body = part.get_content()
                urls.update(url_pattern.findall(body))
    else:
        body = msg.get_content()
        urls.update(url_pattern.findall(body))

    # Also extract href= values from HTML
    href_pattern = re.compile(r'href=["\']?(https?://[^\s"\'<>]+)', re.IGNORECASE)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                body = part.get_content()
                urls.update(href_pattern.findall(body))
    else:
        if msg.get_content_type() == 'text/html':
            body = msg.get_content()
            urls.update(href_pattern.findall(body))

    return analyze_urls(urls)


def analyze_urls(urls):
    """Analyze extracted URLs for suspicious patterns"""
    results = []
    for url in urls:
        parsed = urlparse(url)
        entry = {
            'url': url,
            'domain': parsed.hostname,
            'scheme': parsed.scheme,
            'red_flags': []
        }

        # Check for IP address instead of domain
        if parsed.hostname and re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname):
            entry['red_flags'].append('URL uses raw IP address instead of domain')

        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw']
        if parsed.hostname:
            for tld in suspicious_tlds:
                if parsed.hostname.endswith(tld):
                    entry['red_flags'].append(f'Suspicious TLD: {tld}')

        # Check for lookalike domains (homoglyph / typosquatting patterns)
        known_brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix', 'bank']
        if parsed.hostname:
            hostname_lower = parsed.hostname.lower()
            for brand in known_brands:
                if brand in hostname_lower and brand + '.' not in hostname_lower:
                    entry['red_flags'].append(f'Possible brand impersonation: {brand}')

        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly']
        if parsed.hostname and parsed.hostname.lower() in shorteners:
            entry['red_flags'].append('URL shortener detected — may hide real destination')

        # Check for excessive subdomains
        if parsed.hostname and parsed.hostname.count('.') >= 3:
            entry['red_flags'].append('Excessive subdomains — possible phishing pattern')

        # Check for @ in URL (credential trick)
        if '@' in url:
            entry['red_flags'].append('URL contains @ — browser may ignore text before it')

        # Check for non-standard port
        if parsed.port and parsed.port not in (80, 443):
            entry['red_flags'].append(f'Non-standard port: {parsed.port}')

        results.append(entry)

    return results


def print_url_report(url_results):
    """Print URL analysis report"""
    print(f"\n--- URL Analysis ({len(url_results)} URLs found) ---")
    if not url_results:
        print("  No URLs found in email body")
        return

    for i, entry in enumerate(url_results, 1):
        print(f"\n  [{i}] {entry['url'][:80]}")
        print(f"      Domain: {entry['domain']}")
        if entry['red_flags']:
            for flag in entry['red_flags']:
                print(f"      [!] {flag}")
        else:
            print(f"      No issues detected")
