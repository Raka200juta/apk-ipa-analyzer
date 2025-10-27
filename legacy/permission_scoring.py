"""Permission scoring utilities.

This module provides a single implementation of the permission-based
classification so the logic isn't duplicated across the project.

Scoring approach (simple, explainable):
- Dangerous permissions have higher impact (weight=3)
- Normal permissions have medium impact (weight=1)
- Informational permissions have low impact (weight=0.5)
- The safety score is computed as an inverse of the weighted risk.

Returns: (safety_score:int, classification:str, reason:str, dangerous_list:list, risk_weight:float)
"""

def classify_permissions(permissions, suspicious_set=None):
    """Classify app based on permissions only.

    Arguments:
    - permissions: dict mapping permission->info where info may contain 'status'
    - suspicious_set: optional set of permission names treated as suspicious (kept for backward compatibility)

    The function returns a tuple used by the rest of the app:
    (safety_score, classification, reason, dangerous_found, risk_weight)
    """
    if not permissions:
        return 100, "Safe", "No permissions requested.", [], 0

    perm_list = list(permissions.keys()) if isinstance(permissions, dict) else []
    total_perms = len(perm_list)
    if total_perms == 0:
        return 100, "Safe", "No permissions requested.", [], 0

    # Count by status
    dangerous_count = 0
    normal_count = 0
    info_count = 0
    dangerous_found = []

    for perm_name, perm_info in permissions.items():
        status = None
        if isinstance(perm_info, dict):
            status = perm_info.get('status')
        # Fallback: use suspicious_set if provided
        if not status and suspicious_set and perm_name in suspicious_set:
            status = 'dangerous'

        if status:
            status = str(status).lower()
            if status == 'dangerous':
                dangerous_count += 1
                dangerous_found.append(perm_name)
            elif status == 'normal':
                normal_count += 1
            else:
                info_count += 1
        else:
            # Unknown -> treat as info
            info_count += 1

    # Weighted risk
    risk_weight = (dangerous_count * 3) + (normal_count * 1) + (info_count * 0.5)
    max_possible_risk = total_perms * 3
    safety_score = int((1 - (risk_weight / max_possible_risk)) * 100)
    safety_score = max(0, min(100, safety_score))

    # Critical permission handling
    if any(p in ("android.permission.REQUEST_INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES") for p in perm_list):
        return (
            min(40, safety_score),
            "Dangerous",
            "REQUEST_INSTALL_PACKAGES permission detected (critical risk indicator).",
            dangerous_found,
            risk_weight,
        )

    # Classification
    if safety_score > 70 and dangerous_count == 0:
        return (safety_score, "Safe", "Application has low risk permissions.", dangerous_found, risk_weight)
    if safety_score > 40 or (safety_score > 30 and dangerous_count <= 2):
        return (safety_score, "Malicious", f"High risk: {dangerous_count} dangerous permissions found.", dangerous_found, risk_weight)
    return (safety_score, "Dangerous", f"Critical risk: {dangerous_count} dangerous permissions detected.", dangerous_found, risk_weight)