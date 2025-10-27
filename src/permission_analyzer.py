"""Permission analyzer for MobSF reports.

This module processes MobSF JSON reports and generates permission-only reports
with custom scoring logic.
"""

import json
from typing import Dict, List, Tuple, Any
import os
from .permission_scoring import classify_permissions

def process_mobsf_json(json_path: str) -> Dict[str, Any]:
    """Process MobSF JSON report and extract permission-related information.
    
    Args:
        json_path: Path to MobSF JSON report file
    
    Returns:
        Dict containing processed permission data with scoring
    """
    with open(json_path) as f:
        mobsf_data = json.load(f)
    
    # Extract basic app info
    app_info = {
        'app_name': mobsf_data.get('app_name'),
        'package_name': mobsf_data.get('package_name'),
        'version_name': mobsf_data.get('version_name'),
        'version_code': mobsf_data.get('version_code'),
        'md5': mobsf_data.get('md5'),
        'sha1': mobsf_data.get('sha1'),
        'sha256': mobsf_data.get('sha256'),
    }

    # Extract and process permissions
    permissions = {}
    manifest_analysis = mobsf_data.get('manifest_analysis', [])
    for item in manifest_analysis:
        if item.get('title') == 'Permission Analysis':
            permissions = item.get('permissions', {})
            break
    
    # Apply our custom scoring
    safety_score, classification, reason, dangerous_list, risk_weight = classify_permissions(permissions)
    
    # Prepare the final report
    report = {
        'app_info': app_info,
        'permissions': permissions,
        'permission_analysis': {
            'safety_score': safety_score,
            'classification': classification,
            'reason': reason,
            'dangerous_permissions': dangerous_list,
            'risk_weight': risk_weight,
            'total_permissions': len(permissions),
            'dangerous_count': len(dangerous_list),
        }
    }
    
    return report

def generate_permission_report(json_path: str, output_path: str) -> None:
    """Generate a permission-only report from MobSF JSON report.
    
    Args:
        json_path: Path to MobSF JSON report file
        output_path: Path where to save the permission report
    """
    report = process_mobsf_json(json_path)
    
    # Save to file
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)