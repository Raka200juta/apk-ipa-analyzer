#!/usr/bin/env python3
# extract_filtered.py
import json
import sys
import re
import os

def safe_get(obj, key, default=0):
    """Helper to safely retrieve a value from a dictionary."""
    if obj and isinstance(obj, dict) and key in obj:
        return obj[key]
    return default

def load_suspicious_indicators(script_dir):
    """Load list of suspicious permissions and indicators from JSON file."""
    indicators_file = os.path.join(script_dir, 'suspicious_indicators.json')
    try:
        with open(indicators_file, 'r') as f:
            raw_indicators = json.load(f)
        # Filter only Android permissions for now
        suspicious_perms = set(
            item['name'] for item in raw_indicators
            if item.get('platform') == 'android' and item.get('type') == 'permission'
        )
        return suspicious_perms
    except FileNotFoundError:
        print(f"Warning: File '{indicators_file}' not found. Classification will be skipped.", file=sys.stderr)
        return set()
    except json.JSONDecodeError as e:
        print(f"Warning: Error parsing '{indicators_file}': {e}. Classification will be skipped.", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"Warning: Error loading '{indicators_file}': {e}. Classification will be skipped.", file=sys.stderr)
        return set()

def classify_app(security_score, high_risk, medium_risk, low_risk, has_anti_debug, has_anti_vm, suspicious_perm_count, total_perms, suspicious_perms_found):
    """
    Classification logic based on various risk indicators.
    """
    # --- Define risk weights based on indicators ---
    score_weight = 0
    if security_score is not None:
        # Lower score means higher weight
        if security_score < 30:
            score_weight = 10
        elif security_score < 50:
            score_weight = 5
        elif security_score < 70:
            score_weight = 2
        else:
            score_weight = 0

    high_risk_weight = high_risk * 3
    medium_risk_weight = medium_risk * 2
    low_risk_weight = low_risk * 1

    anti_debug_weight = 5 if has_anti_debug else 0
    anti_vm_weight = 5 if has_anti_vm else 0

    # Weight for suspicious permissions
    perm_weight = suspicious_perm_count * 2

    # Calculate total risk weight
    total_risk_weight = score_weight + high_risk_weight + medium_risk_weight + low_risk_weight + anti_debug_weight + anti_vm_weight + perm_weight

    # --- Determine classification based on weights ---
    classification = "Unknown"
    reason_parts = []

    # Strong Malware Criteria
    if (has_anti_debug and has_anti_vm and security_score is not None and security_score < 40) or \
       (high_risk > 3) or \
       ("REQUEST_INSTALL_PACKAGES" in suspicious_perms_found):
        classification = "Malware"
        reason_parts.append("Strong malware indicators found (anti-debug, anti-vm, low score, or dangerous permissions).")
    # Strong Spyware Criteria
    elif (medium_risk > 10 and suspicious_perm_count > 5 and total_perms > 20):
        classification = "Spyware"
        reason_parts.append("Many suspicious permissions and medium risk.")
    # High-Risk App Criteria
    elif total_risk_weight > 20:
        classification = "Risk App"
        reason_parts.append(f"High risk weight ({total_risk_weight}).")
    # Safe Criteria
    elif security_score is not None and security_score > 70 and high_risk == 0 and not has_anti_debug:
        classification = "Safe"
        reason_parts.append("High security score and no suspicious indicators.")
    else:
        # Default if no specific criteria are met
        if total_risk_weight > 10:
            classification = "Risk App"
            reason_parts.append(f"Moderate risk weight ({total_risk_weight}).")
        else:
            classification = "Needs Manual Review"
            reason_parts.append("Low risk weight, but some indicators were found.")

    return classification, " ".join(reason_parts), total_risk_weight

def main():
    if len(sys.argv) != 2:
        print("Usage: extract_filtered.py <report.json>", file=sys.stderr)
        sys.exit(1)

    json_file = sys.argv[1]
    script_dir = os.path.dirname(os.path.realpath(__file__)) # Get directory where this script resides

    # --- 1. Load suspicious indicators ---
    suspicious_perms_db = load_suspicious_indicators(script_dir)
    # print(f"DEBUG: Loaded {len(suspicious_perms_db)} suspicious permissions.", file=sys.stderr) # For debugging

    # --- 2. Read and parse the JSON report file ---
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            raw_content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    # Manually search for security_score in raw string
    match = re.search(r'"security_score"\s*:\s*([0-9]+(?:\.[0-9]+)?)', raw_content)
    if match:
        security_score_from_raw = float(match.group(1)) if '.' in match.group(1) else int(match.group(1))
    else:
        security_score_from_raw = None

    # Parse JSON normally
    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Retrieve security_score
    raw_security_score_from_json = data.get('security_score')
    if raw_security_score_from_json is None and security_score_from_raw is not None:
        security_score = security_score_from_raw
    else:
        security_score = raw_security_score_from_json

    # --- 3. Extract Scoring ---
    scoring = {}
    if 'high_count' in data:
        scoring = {
            'security_score': security_score,
            'high_risk': data.get('high_count', 0),
            'medium_risk': data.get('medium_count', 0),
            'low_risk': data.get('low_count', 0),
            'total_issues': data.get('high_count', 0) + data.get('medium_count', 0) + data.get('low_count', 0)
        }
    elif 'manifest_analysis' in data and 'manifest_summary' in data['manifest_analysis']:
        ms = data['manifest_analysis']['manifest_summary']
        scoring = {
            'security_score': security_score,
            'high_risk': safe_get(ms, 'high'),
            'medium_risk': safe_get(ms, 'warning'),
            'low_risk': safe_get(ms, 'info'),
            'total_issues': safe_get(ms, 'high') + safe_get(ms, 'warning') + safe_get(ms, 'info')
        }
    elif 'binary_analysis' in data and isinstance(data['binary_analysis'], dict) and 'summary' in data['binary_analysis']:
        bs = data['binary_analysis']['summary']
        scoring = {
            'security_score': security_score,
            'high_risk': safe_get(bs, 'high'),
            'medium_risk': safe_get(bs, 'warning'),
            'low_risk': safe_get(bs, 'info'),
            'total_issues': safe_get(bs, 'high') + safe_get(bs, 'warning') + safe_get(bs, 'info')
        }
    else:
        scoring = {
            'security_score': security_score,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'total_issues': 0
        }

    # --- 4. Extract Malware Indicators ---
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

    # --- 5. Extract Permissions ---
    permissions = []
    if 'permissions' in data and isinstance(data['permissions'], dict):
        permissions = list(data['permissions'].keys())

    # --- 6. Match Against Suspicious Permissions ---
    matched_suspicious_perms = [
        perm for perm in permissions
        if any(susp_perm in perm for susp_perm in suspicious_perms_db)
    ]
    suspicious_perm_count = len(matched_suspicious_perms)
    total_perms = len(permissions)

    # --- 7. Automatic Classification ---
    classification, reason, risk_weight = classify_app(
        security_score=scoring.get('security_score'),
        high_risk=scoring.get('high_risk', 0),
        medium_risk=scoring.get('medium_risk', 0),
        low_risk=scoring.get('low_risk', 0),
        has_anti_debug=malware_indicators.get('has_anti_debug', False),
        has_anti_vm=malware_indicators.get('has_anti_vm', False),
        suspicious_perm_count=suspicious_perm_count,
        total_perms=total_perms,
        suspicious_perms_found=matched_suspicious_perms # For specific checks
    )

    # --- 8. Build Output ---
    output = {
        'file': data.get('file_name', 'N/A'),
        'package': data.get('package_name', data.get('bundle_id', 'N/A')),
        'permissions': permissions,
        'malware_indicators': malware_indicators,
        'scoring': scoring,
        'classification': classification,
        'risk_details': {
            'total_risk_weight': risk_weight,
            'suspicious_permission_count': suspicious_perm_count,
            'total_permissions': total_perms,
            'suspicious_permissions_matched': matched_suspicious_perms,
            'reason': reason
        }
    }

    print(json.dumps(output, indent=None))

if __name__ == '__main__':
    main()