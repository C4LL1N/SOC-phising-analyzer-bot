import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_domain_age(domain):
    """Check domain age via WHOIS using socket connection"""
    if not domain:
        return None

    # Strip to registrable domain (last two parts)
    parts = domain.split('.')
    if len(parts) > 2:
        domain = '.'.join(parts[-2:])

    result = {
        'domain': domain,
        'creation_date': None,
        'age_days': None,
        'registrar': None,
        'red_flags': []
    }

    try:
        whois_data = _raw_whois(domain)
        if not whois_data:
            result['red_flags'].append('WHOIS lookup failed — domain may be hidden')
            return result

        # Parse creation date
        for line in whois_data.splitlines():
            line_lower = line.lower().strip()
            if any(k in line_lower for k in ['creation date:', 'created:', 'registered on:', 'registration time:']):
                date_str = line.split(':', 1)[1].strip()
                creation = _parse_date(date_str)
                if creation:
                    result['creation_date'] = creation.strftime('%Y-%m-%d')
                    age = (datetime.now(timezone.utc) - creation).days
                    result['age_days'] = age
                    if age < 30:
                        result['red_flags'].append(f'Domain registered {age} days ago — VERY NEW')
                    elif age < 90:
                        result['red_flags'].append(f'Domain registered {age} days ago — relatively new')
                break

            if 'registrar:' in line_lower:
                result['registrar'] = line.split(':', 1)[1].strip()

        # Second pass for registrar if not found yet
        if not result['registrar']:
            for line in whois_data.splitlines():
                if 'registrar:' in line.lower():
                    result['registrar'] = line.split(':', 1)[1].strip()
                    break

    except Exception:
        result['red_flags'].append('WHOIS lookup failed')

    return result


def _raw_whois(domain):
    """Perform raw WHOIS query via socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('whois.iana.org', 43))
        sock.sendall((domain + '\r\n').encode())
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()

        iana_response = response.decode('utf-8', errors='ignore')

        # Find the right WHOIS server from IANA
        whois_server = None
        for line in iana_response.splitlines():
            if line.lower().startswith('refer:') or line.lower().startswith('whois:'):
                whois_server = line.split(':', 1)[1].strip()
                break

        if not whois_server:
            return iana_response

        # Query the actual WHOIS server
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(5)
        sock2.connect((whois_server, 43))
        sock2.sendall((domain + '\r\n').encode())
        response2 = b''
        while True:
            data = sock2.recv(4096)
            if not data:
                break
            response2 += data
        sock2.close()

        return response2.decode('utf-8', errors='ignore')

    except Exception:
        return None


def _parse_date(date_str):
    """Try to parse various WHOIS date formats"""
    formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
        '%d-%b-%Y',
        '%d/%m/%Y',
        '%Y/%m/%d',
        '%b %d %Y',
    ]
    date_str = date_str.strip().split('.')[0]  # Remove fractional seconds
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def check_domains_from_urls(url_results):
    """Check domain age for all unique domains from URL analysis"""
    seen = set()
    results = []
    for entry in url_results:
        domain = entry.get('domain')
        if domain and domain not in seen:
            seen.add(domain)
            results.append(check_domain_age(domain))
    return results


def print_whois_report(results):
    """Print WHOIS/domain age report"""
    print(f"\n--- Domain Age / WHOIS ({len(results)} domains) ---")
    if not results:
        print("  No domains to check")
        return

    for r in results:
        if not r:
            continue
        print(f"\n  Domain: {r['domain']}")
        if r['creation_date']:
            print(f"    Registered: {r['creation_date']} ({r['age_days']} days ago)")
        else:
            print(f"    Registration date: unknown")
        if r['registrar']:
            print(f"    Registrar:  {r['registrar']}")
        if r['red_flags']:
            for flag in r['red_flags']:
                print(f"    [!] {flag}")
        elif r['creation_date']:
            print(f"    [OK] Domain age looks fine")
