import re
import email
from email import policy


def analyze_html(eml_path):
    """Analyze HTML content of email for suspicious elements"""
    with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = email.message_from_file(f, policy=policy.default)

    html_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                html_parts.append(part.get_content())
    elif msg.get_content_type() == 'text/html':
        html_parts.append(msg.get_content())

    if not html_parts:
        return {'has_html': False, 'findings': [], 'red_flags': []}

    html_full = '\n'.join(html_parts)
    findings = []
    red_flags = []

    # Check for external forms
    form_actions = re.findall(r'<form[^>]*action=["\']?(https?://[^"\'>\s]+)', html_full, re.IGNORECASE)
    if form_actions:
        for action in form_actions:
            findings.append(f'External form action: {action}')
            red_flags.append(f'Form submits data to external URL: {action[:60]}')

    # Check for hidden inputs
    hidden_inputs = re.findall(r'<input[^>]*type=["\']?hidden[^>]*>', html_full, re.IGNORECASE)
    if hidden_inputs:
        findings.append(f'{len(hidden_inputs)} hidden input field(s)')

    # Check for display:none elements (hidden content)
    hidden_elements = re.findall(r'display\s*:\s*none', html_full, re.IGNORECASE)
    if len(hidden_elements) > 2:
        findings.append(f'{len(hidden_elements)} hidden elements (display:none)')
        red_flags.append('Multiple hidden elements — possible content obfuscation')

    # Check for zero-size elements (tracking pixels, hidden content)
    zero_size = re.findall(r'(?:width|height)\s*[=:]\s*["\']?(?:0|1)(?:px)?["\']?', html_full, re.IGNORECASE)
    if zero_size:
        findings.append(f'{len(zero_size)} zero/1px sized elements (tracking pixels?)')

    # Check for JavaScript
    script_tags = re.findall(r'<script[^>]*>[\s\S]*?</script>', html_full, re.IGNORECASE)
    if script_tags:
        findings.append(f'{len(script_tags)} <script> tag(s)')
        red_flags.append('Email contains JavaScript — unusual and suspicious')

    # Check for event handlers (onclick, onload, onerror, etc.)
    event_handlers = re.findall(r'\bon\w+\s*=\s*["\'][^"\']*["\']', html_full, re.IGNORECASE)
    if event_handlers:
        findings.append(f'{len(event_handlers)} inline event handler(s)')
        red_flags.append('Inline JS event handlers found')

    # Check for obfuscated content (base64 encoded, excessive encoding)
    base64_chunks = re.findall(r'(?:data:[^;]+;base64,|atob\s*\()', html_full, re.IGNORECASE)
    if base64_chunks:
        findings.append(f'{len(base64_chunks)} base64 encoded element(s)')
        red_flags.append('Base64 encoded content — possible obfuscation')

    # Check for iframe
    iframes = re.findall(r'<iframe[^>]*>', html_full, re.IGNORECASE)
    if iframes:
        findings.append(f'{len(iframes)} iframe(s)')
        red_flags.append('Email contains iframe — possible content injection')

    # Check for link text vs href mismatch
    link_mismatches = _check_link_mismatches(html_full)
    if link_mismatches:
        for mismatch in link_mismatches:
            findings.append(f'Link mismatch: text="{mismatch["text"]}" href="{mismatch["href"]}"')
            red_flags.append(f'Link text shows different URL than actual destination')

    # Check for meta refresh redirect
    meta_refresh = re.findall(r'<meta[^>]*http-equiv=["\']?refresh[^>]*url=([^"\'>\s]+)', html_full, re.IGNORECASE)
    if meta_refresh:
        findings.append(f'Meta refresh redirect to: {meta_refresh[0]}')
        red_flags.append(f'Auto-redirect via meta refresh: {meta_refresh[0][:60]}')

    return {
        'has_html': True,
        'findings': findings,
        'red_flags': red_flags
    }


def _check_link_mismatches(html):
    """Check for links where displayed text looks like a URL different from href"""
    mismatches = []
    # Find <a href="url">text that looks like a url</a>
    pattern = re.compile(
        r'<a\s[^>]*href=["\']?(https?://[^"\'>\s]+)["\']?[^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL
    )
    for match in pattern.finditer(html):
        href = match.group(1).lower().rstrip('/')
        text = re.sub(r'<[^>]+>', '', match.group(2)).strip().lower().rstrip('/')

        # Only flag if the visible text itself looks like a URL
        if text.startswith(('http://', 'https://', 'www.')):
            # Normalize for comparison
            text_clean = re.sub(r'^https?://', '', text)
            href_clean = re.sub(r'^https?://', '', href)
            if text_clean != href_clean and text_clean.split('/')[0] != href_clean.split('/')[0]:
                mismatches.append({
                    'text': text[:50],
                    'href': href[:50]
                })

    return mismatches[:5]  # Limit to 5


def print_html_report(results):
    """Print HTML analysis report"""
    print(f"\n--- HTML Analysis ---")
    if not results['has_html']:
        print("  No HTML content in email")
        return

    if results['findings']:
        print(f"  Findings:")
        for f in results['findings']:
            print(f"    - {f}")
    else:
        print("  No suspicious HTML elements found")

    if results['red_flags']:
        for flag in results['red_flags']:
            print(f"  [!] {flag}")
