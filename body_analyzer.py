import re
import email
from email import policy


URGENCY_PATTERNS = [
    (r'(?i)\b(immediate(?:ly)?|urgent(?:ly)?|right\s+away|asap|time.sensitive)\b', 'Urgency language'),
    (r'(?i)\b(act\s+now|action\s+required|respond\s+immediately|must\s+verify)\b', 'Call to action pressure'),
    (r'(?i)\b(account\s+(?:will\s+be\s+)?(?:suspend|clos|deactivat|terminat|restrict|lock))', 'Account threat'),
    (r'(?i)\b(verify\s+your\s+(?:account|identity|information|email))\b', 'Verification request'),
    (r'(?i)\b(confirm\s+your\s+(?:password|credentials|details|payment|billing))\b', 'Credential harvesting language'),
    (r'(?i)\b(update\s+(?:your\s+)?(?:payment|billing|credit\s+card|bank))\b', 'Payment info request'),
    (r'(?i)\b(unusual\s+(?:activity|sign.?in|login|transaction))\b', 'Suspicious activity claim'),
    (r'(?i)\b(won|winner|congratulat|prize|reward|lottery|lucky)\b', 'Prize/reward bait'),
    (r'(?i)\b(wire\s+transfer|western\s+union|bitcoin|crypto(?:currency)?|gift\s+card)\b', 'Untraceable payment mention'),
    (r'(?i)\b(click\s+(?:here|below|the\s+link)|open\s+(?:the\s+)?attach)', 'Click/open directive'),
    (r'(?i)\b(password\s+expir|credentials?\s+expir|reset\s+your\s+password)\b', 'Password expiry scare'),
    (r'(?i)\b(do\s+not\s+(?:share|forward|ignore)|confidential|private)\b', 'Secrecy/isolation language'),
    (r'(?i)\b((?:dear\s+)?(?:valued\s+)?(?:customer|user|client|member|account\s+holder))\b', 'Generic greeting (not personalized)'),
    (r'(?i)\b(within\s+\d+\s+(?:hour|minute|day)|in\s+the\s+next\s+\d+)\b', 'Artificial deadline'),
    (r'(?i)\b(invoice|receipt|shipment|delivery|package|tracking)\b', 'Delivery/invoice lure'),
]


def analyze_body(eml_path):
    """Analyze email body text for social engineering patterns"""
    with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = email.message_from_file(f, policy=policy.default)

    body_text = _extract_text(msg)
    if not body_text:
        return {'body_length': 0, 'matches': [], 'red_flags': []}

    matches = []
    seen_categories = set()

    for pattern, category in URGENCY_PATTERNS:
        found = re.findall(pattern, body_text)
        if found and category not in seen_categories:
            seen_categories.add(category)
            matches.append({
                'category': category,
                'examples': list(set(found))[:3]
            })

    red_flags = []
    if len(matches) >= 4:
        red_flags.append(f'HIGH social engineering score — {len(matches)} manipulation patterns detected')
    elif len(matches) >= 2:
        red_flags.append(f'MODERATE social engineering indicators — {len(matches)} patterns detected')

    # Check for excessive exclamation marks
    excl_count = body_text.count('!')
    if excl_count > 5:
        red_flags.append(f'Excessive exclamation marks ({excl_count}) — pressure tactic')

    # Check for ALL CAPS words
    caps_words = re.findall(r'\b[A-Z]{4,}\b', body_text)
    caps_unique = set(caps_words) - {'HTML', 'HTTP', 'HTTPS', 'MIME', 'UTF', 'FROM', 'DATE', 'HREF'}
    if len(caps_unique) >= 3:
        red_flags.append(f'Multiple ALL CAPS words: {", ".join(list(caps_unique)[:5])}')

    # Check for spelling/grammar oddities (common in phishing)
    bad_patterns = re.findall(r'(?i)\b(kindly|do the needful|revert back|dear sir/madam)\b', body_text)
    if bad_patterns:
        red_flags.append(f'Unusual phrasing typical of phishing: {", ".join(set(bad_patterns))}')

    return {
        'body_length': len(body_text),
        'matches': matches,
        'red_flags': red_flags
    }


def _extract_text(msg):
    """Extract plain text from email message"""
    texts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                texts.append(part.get_content())
            elif ctype == 'text/html':
                html = part.get_content()
                # Strip HTML tags for text analysis
                clean = re.sub(r'<[^>]+>', ' ', html)
                clean = re.sub(r'\s+', ' ', clean)
                texts.append(clean)
    else:
        content = msg.get_content()
        if msg.get_content_type() == 'text/html':
            content = re.sub(r'<[^>]+>', ' ', content)
            content = re.sub(r'\s+', ' ', content)
        texts.append(content)

    return '\n'.join(texts)


def print_body_report(results):
    """Print body content analysis report"""
    print(f"\n--- Body Content Analysis ---")
    print(f"  Body length: {results['body_length']} chars")

    if results['matches']:
        print(f"  Social engineering patterns found: {len(results['matches'])}")
        for m in results['matches']:
            examples = ', '.join(f'"{e}"' for e in m['examples'][:2])
            print(f"    - {m['category']}: {examples}")
    else:
        print(f"  No social engineering patterns detected")

    if results['red_flags']:
        for flag in results['red_flags']:
            print(f"  [!] {flag}")
