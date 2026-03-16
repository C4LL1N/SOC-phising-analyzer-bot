import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSE_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
ABUSE_BASE_URL = 'https://api.abuseipdb.com/api/v2'


def check_ip(ip_address):
    """Check an IP address against AbuseIPDB"""
    if not ABUSE_API_KEY:
        return {'error': 'ABUSEIPDB_API_KEY not set — export ABUSEIPDB_API_KEY=your_key'}

    headers = {
        'Key': ABUSE_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90,
        'verbose': ''
    }

    resp = requests.get(f'{ABUSE_BASE_URL}/check', headers=headers, params=params, timeout=15)

    if resp.status_code != 200:
        return {'error': f'AbuseIPDB API error: {resp.status_code}'}

    data = resp.json().get('data', {})
    return {
        'ip': ip_address,
        'abuse_score': data.get('abuseConfidenceScore', 0),
        'country': data.get('countryCode', 'N/A'),
        'isp': data.get('isp', 'N/A'),
        'domain': data.get('domain', 'N/A'),
        'total_reports': data.get('totalReports', 0),
        'last_reported': data.get('lastReportedAt', 'Never'),
        'is_whitelisted': data.get('isWhitelisted', False),
        'usage_type': data.get('usageType', 'N/A')
    }


def print_abuse_report(result):
    """Print AbuseIPDB check result"""
    print(f"\n--- AbuseIPDB Check ---")
    if not result:
        print("  No IP to check")
        return

    if 'error' in result:
        print(f"  Error: {result['error']}")
        return

    print(f"  IP:             {result['ip']}")
    print(f"  Abuse Score:    {result['abuse_score']}%")
    print(f"  Country:        {result['country']}")
    print(f"  ISP:            {result['isp']}")
    print(f"  Domain:         {result['domain']}")
    print(f"  Usage Type:     {result['usage_type']}")
    print(f"  Total Reports:  {result['total_reports']}")
    print(f"  Last Reported:  {result['last_reported']}")

    score = result['abuse_score']
    if score >= 80:
        print(f"  [!!!] HIGH RISK — abuse score {score}%")
    elif score >= 25:
        print(f"  [!] SUSPICIOUS — abuse score {score}%")
    elif result['is_whitelisted']:
        print(f"  [OK] Whitelisted / trusted")
    else:
        print(f"  [OK] Low risk")
