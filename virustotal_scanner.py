import os
import requests
import base64
import time
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.environ.get('VT_API_KEY', '')
VT_BASE_URL = 'https://www.virustotal.com/api/v3'


def scan_url(url):
    """Submit a URL to VirusTotal and get the analysis report"""
    if not VT_API_KEY:
        return {'error': 'VT_API_KEY not set — export VT_API_KEY=your_key'}

    headers = {'x-apikey': VT_API_KEY}

    # Encode URL for VT API (base64url without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

    # Try to get existing report first
    resp = requests.get(f'{VT_BASE_URL}/urls/{url_id}', headers=headers, timeout=15)

    if resp.status_code == 404:
        # No existing report — submit for scanning
        submit_resp = requests.post(
            f'{VT_BASE_URL}/urls',
            headers=headers,
            data={'url': url},
            timeout=15
        )
        if submit_resp.status_code != 200:
            return {'error': f'Submit failed: {submit_resp.status_code}'}

        # Wait briefly and fetch result
        analysis_id = submit_resp.json()['data']['id']
        time.sleep(3)
        analysis_resp = requests.get(
            f'{VT_BASE_URL}/analyses/{analysis_id}',
            headers=headers,
            timeout=15
        )
        if analysis_resp.status_code != 200:
            return {'error': f'Analysis fetch failed: {analysis_resp.status_code}'}
        data = analysis_resp.json()['data']['attributes']
        stats = data.get('stats', {})
        return {
            'url': url,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'status': data.get('status', 'unknown')
        }

    elif resp.status_code == 200:
        data = resp.json()['data']['attributes']
        stats = data.get('last_analysis_stats', {})
        return {
            'url': url,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'reputation': data.get('reputation', 'N/A')
        }
    else:
        return {'error': f'VT API error: {resp.status_code}'}


def scan_ip(ip_address):
    """Check an IP address on VirusTotal"""
    if not VT_API_KEY:
        return {'error': 'VT_API_KEY not set — export VT_API_KEY=your_key'}

    headers = {'x-apikey': VT_API_KEY}
    resp = requests.get(f'{VT_BASE_URL}/ip_addresses/{ip_address}', headers=headers, timeout=15)

    if resp.status_code != 200:
        return {'error': f'VT API error: {resp.status_code}'}

    data = resp.json()['data']['attributes']
    stats = data.get('last_analysis_stats', {})
    return {
        'ip': ip_address,
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'harmless': stats.get('harmless', 0),
        'undetected': stats.get('undetected', 0),
        'owner': data.get('as_owner', 'N/A'),
        'country': data.get('country', 'N/A'),
        'reputation': data.get('reputation', 'N/A')
    }


def print_vt_report(vt_results):
    """Print VirusTotal scan results"""
    print(f"\n--- VirusTotal Scan ---")
    if not vt_results:
        print("  No results")
        return

    for result in vt_results:
        if 'error' in result:
            print(f"  Error: {result['error']}")
            continue

        label = result.get('url') or result.get('ip', '?')
        print(f"\n  Target: {label[:70]}")
        mal = result.get('malicious', 0)
        sus = result.get('suspicious', 0)
        total_bad = mal + sus
        print(f"    Malicious: {mal}  |  Suspicious: {sus}  |  Harmless: {result.get('harmless', 0)}  |  Undetected: {result.get('undetected', 0)}")
        if result.get('owner'):
            print(f"    Owner: {result['owner']}  |  Country: {result.get('country', 'N/A')}")
        if total_bad > 0:
            print(f"    [!] THREAT DETECTED — {total_bad} engine(s) flagged this")
        else:
            print(f"    [OK] Clean")
