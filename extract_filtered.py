#!/usr/bin/env python3
# extract_filtered.py
import json
import sys
import re

def safe_get(obj, key, default=0):
    if obj and isinstance(obj, dict) and key in obj:
        return obj[key]
    return default

def main():
    if len(sys.argv) != 2:
        print("Usage: extract_filtered.py <report.json>", file=sys.stderr)
        sys.exit(1)

    json_file = sys.argv[1]

    # Baca file sebagai string mentah dulu untuk cari security_score secara manual
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            raw_content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    # Cari security_score secara manual dari string mentah
    # Pola: "security_score": <angka>
    match = re.search(r'"security_score"\s*:\s*([0-9]+(?:\.[0-9]+)?)', raw_content)
    if match:
        security_score_from_raw = float(match.group(1)) if '.' in match.group(1) else int(match.group(1))
        # print(f"DEBUG: Found security_score in raw content: {security_score_from_raw}", file=sys.stderr)
    else:
        security_score_from_raw = None
        # print("DEBUG: security_score not found in raw content", file=sys.stderr)

    # Parsing JSON seperti biasa
    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Ambil security_score dari hasil parsing JSON
    raw_security_score_from_json = data.get('security_score')

    # Gunakan nilai dari raw_content jika nilai dari json.load adalah null/None
    if raw_security_score_from_json is None and security_score_from_raw is not None:
        security_score = security_score_from_raw
        # print(f"DEBUG: Using security_score from raw content: {security_score}", file=sys.stderr)
    else:
        security_score = raw_security_score_from_json
        # print(f"DEBUG: Using security_score from json.load: {security_score}", file=sys.stderr)

    # --- Ambil Scoring ---
    scoring = {}

    # Prioritas 1: high_count, medium_count, low_count (Android lama)
    if 'high_count' in data:
        scoring = {
            'security_score': security_score, # Gunakan nilai yang sudah diambil
            'high_risk': data.get('high_count', 0),
            'medium_risk': data.get('medium_count', 0),
            'low_risk': data.get('low_count', 0),
            'total_issues': data.get('high_count', 0) + data.get('medium_count', 0) + data.get('low_count', 0)
        }
    # Prioritas 2: manifest_summary (Android baru)
    elif 'manifest_analysis' in data and 'manifest_summary' in data['manifest_analysis']:
        ms = data['manifest_analysis']['manifest_summary']
        scoring = {
            'security_score': security_score, # Gunakan nilai yang sudah diambil
            'high_risk': safe_get(ms, 'high'),
            'medium_risk': safe_get(ms, 'warning'),
            'low_risk': safe_get(ms, 'info'),
            'total_issues': safe_get(ms, 'high') + safe_get(ms, 'warning') + safe_get(ms, 'info')
        }
    # Prioritas 3: binary_analysis.summary (jika bukan array)
    elif 'binary_analysis' in data and isinstance(data['binary_analysis'], dict) and 'summary' in data['binary_analysis']:
        bs = data['binary_analysis']['summary']
        scoring = {
            'security_score': security_score, # Gunakan nilai yang sudah diambil
            'high_risk': safe_get(bs, 'high'),
            'medium_risk': safe_get(bs, 'warning'),
            'low_risk': safe_get(bs, 'info'),
            'total_issues': safe_get(bs, 'high') + safe_get(bs, 'warning') + safe_get(bs, 'info')
        }
    # Jika semua gagal
    else:
        scoring = {
            'security_score': security_score, # Gunakan nilai yang sudah diambil
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'total_issues': 0
        }

    # --- Ambil Malware Indicators ---
    apkid = data.get('apkid', {})
    malware_indicators = {
        'has_anti_debug': False,
        'has_anti_vm': False,
        'security_score_low': False
    }
    if apkid:
        for _, v in apkid.items():
            if isinstance(v, dict):
                if 'anti_debug' in v and len(v['anti_debug']) > 0:
                    malware_indicators['has_anti_debug'] = True
                if 'anti_vm' in v and len(v['anti_vm']) > 0:
                    malware_indicators['has_anti_vm'] = True

    if security_score is not None and security_score < 50:
        malware_indicators['security_score_low'] = True

    # --- Ambil Permissions ---
    permissions = []
    if 'permissions' in data and isinstance(data['permissions'], dict):
        permissions = list(data['permissions'].keys())

    # --- Buat Output ---
    output = {
        'file': data.get('file_name', 'N/A'),
        'package': data.get('package_name', data.get('bundle_id', 'N/A')),
        'permissions': permissions,
        'malware_indicators': malware_indicators,
        'scoring': scoring
    }

    print(json.dumps(output, indent=None))

if __name__ == '__main__':
    main()