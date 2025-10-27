"""Permission report endpoint handler for MobSF."""

from flask import Blueprint, render_template, send_file
import json
import os
import base64
import tempfile
import subprocess
from .permission_scoring import classify_permissions

permission_bp = Blueprint('permission_report', __name__)

def process_permissions(json_data):
    """Proses data permission dari MobSF report."""
    permissions = {}
    manifest_analysis = json_data.get('manifest_analysis', [])
    
    # Ekstrak permissions dari manifest analysis
    for item in manifest_analysis:
        if item.get('title') == 'Permission Analysis':
            permissions = item.get('permissions', {})
            break
    
    # Analisis dengan permission_scoring
    safety_score, classification, reason, dangerous_list, risk_weight = classify_permissions(permissions)
    
    # Format permissions untuk template
    formatted_perms = []
    dangerous_perms = []
    
    for perm_name, perm_info in permissions.items():
        formatted_perm = {
            'name': perm_name,
            'status': perm_info.get('status', 'unknown'),
            'description': perm_info.get('description', 'No description available')
        }
        formatted_perms.append(formatted_perm)
        
        if perm_info.get('status') == 'dangerous':
            dangerous_perms.append(formatted_perm)
    
    return {
        'permission_score': safety_score,
        'classification': classification,
        'permission_summary': reason,
        'dangerous_permissions': dangerous_perms,
        'permissions': formatted_perms,
        'total_permissions': len(permissions),
        'dangerous_permissions_count': len(dangerous_perms)
    }

@permission_bp.route('/permission_report/<hash>', methods=['GET'])
def permission_report(hash):
    """Generate permission-only report."""
    try:
        # Get MobSF report
        json_path = f"full_output/report_{hash}.json"
        if not os.path.exists(json_path):
            return {"error": "Report not found"}, 404
        
        with open(json_path) as f:
            mobsf_data = json.load(f)
        
        # Process permissions
        perm_data = process_permissions(mobsf_data)
        
        # Add basic app info
        template_data = {
            'file_name': mobsf_data.get('file_name'),
            'package_name': mobsf_data.get('package_name'),
            **perm_data
        }
        
        # Load fonts
        template_dir = os.path.join(os.path.dirname(__file__), '../templates')
        with open(os.path.join(template_dir, 'fonts/OpenSans-Regular.ttf'), 'rb') as f:
            template_data['open_sans_b64'] = base64.b64encode(f.read()).decode()
        with open(os.path.join(template_dir, 'fonts/Oswald-Regular.ttf'), 'rb') as f:
            template_data['oswald_b64'] = base64.b64encode(f.read()).decode()
        
        # Load CSS
        with open(os.path.join(template_dir, 'css/pdf_report.css')) as f:
            template_data['pdf_css'] = f.read()
        
        # Generate HTML
        html = render_template('permission_only.html', **template_data)
        
        # Convert to PDF
        pdf_path = f"pdf_output/permission_report_{hash}.pdf"
        
        # Use wkhtmltopdf for PDF generation
        with tempfile.NamedTemporaryFile(suffix='.html', mode='w', encoding='utf-8') as temp:
            temp.write(html)
            temp.flush()
            subprocess.run([
                'wkhtmltopdf',
                '--quiet',
                temp.name,
                pdf_path
            ], check=True)
        
        return send_file(pdf_path)
        
    except Exception as e:
        return {"error": str(e)}, 500