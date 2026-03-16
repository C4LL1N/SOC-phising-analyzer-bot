import email
from email import policy
import hashlib
import os
from virustotal_scanner import VT_API_KEY, VT_BASE_URL

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.hta',
    '.cpl', '.inf', '.reg', '.lnk', '.docm', '.xlsm', '.pptm',
    '.dotm', '.xltm', '.potm', '.sldm', '.xlam', '.ppam',
    '.iso', '.img', '.cab', '.dll', '.sys'
}

MACRO_EXTENSIONS = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam', '.ppam'}

DOUBLE_EXTENSION_PATTERN = ['.pdf.exe', '.doc.exe', '.jpg.scr', '.txt.vbs', '.png.js']


def analyze_attachments(eml_path):
    """Extract and analyze all attachments from an .eml file"""
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    results = []

    for part in msg.walk():
        content_disposition = part.get_content_disposition()
        if content_disposition not in ('attachment', 'inline'):
            continue

        filename = part.get_filename()
        if not filename:
            continue

        payload = part.get_payload(decode=True)
        if not payload:
            continue

        entry = {
            'filename': filename,
            'size': len(payload),
            'content_type': part.get_content_type(),
            'sha256': hashlib.sha256(payload).hexdigest(),
            'md5': hashlib.md5(payload).hexdigest(),
            'red_flags': [],
            'vt_result': None
        }

        ext = os.path.splitext(filename)[1].lower()

        # Check suspicious extension
        if ext in SUSPICIOUS_EXTENSIONS:
            entry['red_flags'].append(f'Suspicious file type: {ext}')

        # Check for macros
        if ext in MACRO_EXTENSIONS:
            entry['red_flags'].append('File may contain macros (macro-enabled format)')

        # Check double extension trick
        fname_lower = filename.lower()
        for dbl in DOUBLE_EXTENSION_PATTERN:
            if fname_lower.endswith(dbl):
                entry['red_flags'].append(f'Double extension trick: {filename}')
                break

        # Check if extension doesn't match content type
        type_ext_map = {
            'application/pdf': '.pdf',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'text/plain': '.txt',
        }
        expected_ext = type_ext_map.get(entry['content_type'])
        if expected_ext and ext != expected_ext and ext not in ('.jpeg',):
            entry['red_flags'].append(
                f'Extension mismatch: {ext} but Content-Type is {entry["content_type"]}'
            )

        # Check for password-protected zip (common phishing tactic)
        if ext == '.zip' and payload[:2] == b'PK':
            # Check for encryption flag in local file header
            if len(payload) > 8 and (payload[6] & 0x01):
                entry['red_flags'].append('Password-protected ZIP — common phishing tactic')

        # VirusTotal hash lookup
        entry['vt_result'] = vt_hash_lookup(entry['sha256'])

        results.append(entry)

    return results


def vt_hash_lookup(file_hash):
    """Look up a file hash on VirusTotal"""
    if not VT_API_KEY:
        return {'error': 'VT_API_KEY not set'}

    import requests
    headers = {'x-apikey': VT_API_KEY}
    resp = requests.get(f'{VT_BASE_URL}/files/{file_hash}', headers=headers, timeout=15)

    if resp.status_code == 404:
        return {'status': 'not_found', 'message': 'Hash not in VT database'}
    elif resp.status_code == 200:
        data = resp.json()['data']['attributes']
        stats = data.get('last_analysis_stats', {})
        return {
            'status': 'found',
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'type_description': data.get('type_description', 'N/A'),
            'popular_threat_name': data.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
        }
    else:
        return {'error': f'VT API error: {resp.status_code}'}


def print_attachment_report(results):
    """Print attachment analysis report"""
    print(f"\n--- Attachment Analysis ({len(results)} attachments) ---")
    if not results:
        print("  No attachments found")
        return

    for i, entry in enumerate(results, 1):
        print(f"\n  [{i}] {entry['filename']}")
        print(f"      Size: {entry['size']} bytes  |  Type: {entry['content_type']}")
        print(f"      SHA256: {entry['sha256']}")
        print(f"      MD5:    {entry['md5']}")

        if entry['red_flags']:
            for flag in entry['red_flags']:
                print(f"      [!] {flag}")

        vt = entry.get('vt_result')
        if vt:
            if 'error' in vt:
                print(f"      VT: {vt['error']}")
            elif vt.get('status') == 'not_found':
                print(f"      VT: Hash not found in database")
            elif vt.get('status') == 'found':
                mal = vt.get('malicious', 0)
                sus = vt.get('suspicious', 0)
                print(f"      VT: Malicious={mal} Suspicious={sus} Harmless={vt.get('harmless',0)}")
                if vt.get('popular_threat_name', 'N/A') != 'N/A':
                    print(f"      VT Threat: {vt['popular_threat_name']}")
                if mal + sus > 0:
                    print(f"      [!!!] MALICIOUS ATTACHMENT DETECTED")
        else:
            print(f"      VT: Not checked")
