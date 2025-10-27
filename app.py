# app.py
import os
import json
import logging
import re
import yaml
import base64
import tempfile
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, Response, render_template
import requests
from functools import wraps
from src.mobsf import MobSFClient
from permission_scoring import classify_permissions

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Import and register blueprints
from src.permission_report import permission_bp
app.register_blueprint(permission_bp)

# Coba import WeasyPrint
try:
    from weasyprint import HTML
    HAVE_WEASY = True
except Exception as e:
    HAVE_WEASY = False
    logger.warning("WeasyPrint not available: %s", e)

# Configuration from environment
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY", "change-me-in-prod")

app = Flask(__name__, template_folder="templates")
SCRIPT_DIR = Path(__file__).parent

# Initialize MobSF client
mobsf = MobSFClient(
    base_url=os.getenv("MOBSF_URL", "http://mobsf:8001"),
    api_key=os.getenv("MOBSF_API_KEY"),
    timeout=int(os.getenv("MOBSF_TIMEOUT", "30"))
)

def read_font_b64(filename):
    with open(os.path.join(SCRIPT_DIR, "templates", "fonts", filename), "rb") as f:
        return base64.b64encode(f.read()).decode('utf-8')

OPEN_SANS_B64 = read_font_b64("OpenSans-Regular.ttf")
OSWALD_B64 = read_font_b64("Oswald-Regular.ttf")
# Read PDF CSS (MobSF style)
PDF_CSS = ""
try:
    with open(os.path.join(SCRIPT_DIR, "templates", "css", "pdf_report.css"), "r", encoding="utf-8") as f:
        PDF_CSS = f.read()
except Exception:
    logger.debug("Could not read templates/css/pdf_report.css")

# ========================
# Helper Functions
# ========================

def safe_get(obj, key, default=0):
    if obj and isinstance(obj, dict) and key in obj:
        return obj[key]
    return default

def load_suspicious_indicators(platform):
    """Load suspicious indicators based on platform."""
    results = set()
    if not platform:
        return results

    # Android: prefer Python lists in rules.android.malware_permissions, but
    # also try to load the YAML file as a fallback to cover more indicators.
    if platform == "android":
        try:
            from rules.android.malware_permissions import TOP_MALWARE_PERMISSIONS, OTHER_PERMISSIONS
            results.update(TOP_MALWARE_PERMISSIONS)
            results.update(OTHER_PERMISSIONS)
        except Exception:
            # Import may fail in some setups; continue to YAML fallback
            logger.debug("rules.android.malware_permissions not importable, falling back to YAML")

        # Try loading the large YAML list (if present)
        yaml_path = os.path.join(SCRIPT_DIR, "rules", "android", "suspicious_indicators_android.yaml")
        if os.path.exists(yaml_path):
            try:
                with open(yaml_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and 'id' in item:
                            results.add(item['id'])
                        elif isinstance(item, str):
                            results.add(item)
                else:
                    logger.debug("Unexpected format in %s, expecting list", yaml_path)
            except Exception as e:
                logger.warning("Failed to load %s: %s", yaml_path, e)

        return results

    # iOS and other platforms: currently no curated list, return empty set
    if platform == "ios":
        # Try to load ios api/permission indicators from rules (if provided)
        ios_yaml = os.path.join(SCRIPT_DIR, "rules", "android", "ios", "ios_apis.yaml")
        if os.path.exists(ios_yaml):
            try:
                data = yaml.safe_load(open(ios_yaml, 'r', encoding='utf-8'))
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and 'id' in item:
                            results.add(item['id'])
                        elif isinstance(item, str):
                            results.add(item)
                # if dict etc, ignore for now
            except Exception as e:
                logger.warning("Failed to load ios indicators %s: %s", ios_yaml, e)

        # If YAML absent or empty, provide a small default set of common iOS usage keys
        if not results:
            results = set([
                'NSCameraUsageDescription',
                'NSMicrophoneUsageDescription',
                'NSPhotoLibraryUsageDescription',
                'NSLocationWhenInUseUsageDescription',
                'NSLocationAlwaysAndWhenInUseUsageDescription',
                'NSContactsUsageDescription',
                'NSCalendarsUsageDescription',
                'NSRemindersUsageDescription',
                'NSHealthShareUsageDescription',
                'NSHealthUpdateUsageDescription',
                'NSSpeechRecognitionUsageDescription',
            ])

        return results

    return results

# classify_permissions is implemented centrally in permission_scoring.py

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-KEY") or request.args.get("api_key")
        if not key or key != SERVICE_API_KEY:
            logger.warning("Unauthorized access from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def fetch_mobsf_json(scan_hash):
    if not scan_hash or not isinstance(scan_hash, str) or len(scan_hash) < 10:
        raise ValueError("Invalid scan hash")
    logger.info("Fetching MobSF report for hash: %s", scan_hash)
    try:
        return mobsf.get_report_json(scan_hash)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            raise ValueError("Scan hash not found")
        raise

def detect_platform(report):
    if report.get("package_name"):
        return "android"
    elif report.get("bundle_id"):
        return "ios"
    else:
        return "unknown"

def extract_security_score(report):
    if "appsec" in report and "security_score" in report["appsec"]:
        return report["appsec"]["security_score"]
    content = json.dumps(report)
    match = re.search(r'"security_score"\s*:\s*([0-9]+)', content)
    if match:
        return int(match.group(1))
    return None

def extract_risk_counts(report):
    if "manifest_analysis" in report and "manifest_summary" in report["manifest_analysis"]:
        ms = report["manifest_analysis"]["manifest_summary"]
        return safe_get(ms, "high"), safe_get(ms, "warning"), safe_get(ms, "info")
    if "binary_analysis" in report and "summary" in report["binary_analysis"]:
        bs = report["binary_analysis"]["summary"]
        return safe_get(bs, "high"), safe_get(bs, "warning"), safe_get(bs, "info")
    if "appsec" in report:
        appsec = report["appsec"]
        return len(appsec.get("high", [])), len(appsec.get("warning", [])), len(appsec.get("info", []))
    return 0, 0, 0

def extract_malware_indicators(report):
    has_anti_debug = has_anti_vm = False
    apkid = report.get("apkid", {})
    if apkid:
        for v in apkid.values():
            if isinstance(v, dict):
                if v.get("anti_debug"):
                    has_anti_debug = True
                if v.get("anti_vm"):
                    has_anti_vm = True
    return has_anti_debug, has_anti_vm

def extract_ios_permissions(report):
    """Ekstrak permissions buatan untuk iOS berdasarkan Info.plist dan entitlements."""
    from rules.android.ios.permissions_analysis import check_permissions, COCOA_KEYS
    permissions = {}

    # Usage Descriptions: take anything present in info_plist
    info_plist = report.get("info_plist", {}) or {}
    
    # Use COCOA_KEYS mapping for known permissions
    perms = check_permissions(info_plist)
    permissions.update(perms)
    
    # Add any remaining Info.plist keys not in COCOA_KEYS
    for key, val in info_plist.items():
        if key not in COCOA_KEYS:
            permissions[key] = {
                "status": "info",
                "info": "Other Usage Description",
                "description": str(val)
            }

    # Entitlements (if MobSF provided them in binary_analysis)
    binary_analysis = report.get("binary_analysis", {}) or {}
    entitlements = binary_analysis.get("entitlements", {}) or {}
    for ent, val in entitlements.items():
        permissions[ent] = {
            "status": "dangerous" if ent == "get-task-allow" else "normal",
            "info": "Entitlement",
            "description": str(val)
        }

    return permissions

# ========================
# Endpoints
# ========================

@app.route("/health")
def health():
    """Health check endpoint."""
    try:
        # Check if MobSF is responding
        mobsf.wait_for_server(max_attempts=1)
        mobsf_status = "ok"
    except Exception as e:
        logger.error("MobSF health check failed: %s", e)
        mobsf_status = str(e)
    
    return jsonify({
        "status": "ok",
        "have_weasyprint": HAVE_WEASY,
        "mobsf_status": mobsf_status
    })

@app.route("/scan", methods=["POST"])
@require_api_key
def scan_file():
    """New endpoint to handle full scan workflow.
    
    Accepts:
        - File upload in request.files["file"]
        - Optional output_dir in request.form for PDF location
        
    Returns:
        {
            "hash": "<file_hash>",
            "report_url": "<mobsf_web_report_url>",
            "pdf_path": "<path_to_pdf>" (if PDF was requested)
            "report": { ... JSON report data ... }
        }
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400
    
    # Save uploaded file
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, file.filename)
    file.save(temp_path)
    
    try:
        # Upload to MobSF
        file_hash, upload_data = mobsf.upload_file(temp_path)
        
        # Start scan
        scan_data = mobsf.start_scan(file_hash)
        
        # Get JSON report
        report = mobsf.get_report_json(file_hash)
        
        result = {
            "hash": file_hash,
            "report_url": mobsf.get_report_url(file_hash),
            "report": report
        }
        
        # Generate PDF if requested
        output_dir = request.form.get("output_dir")
        if output_dir:
            pdf_path = os.path.join(
                output_dir,
                f"mobsf_report_{file_hash[:8]}.pdf"
            )
            mobsf.download_pdf(
                file_hash,
                pdf_path,
                scan_type="apk" if file.filename.endswith(".apk") else "ipa"
            )
            result["pdf_path"] = pdf_path
            
        return jsonify(result)
        
    except Exception as e:
        logger.error("Scan failed: %s", e)
        return jsonify({"error": str(e)}), 500
        
    finally:
        # Cleanup
        try:
            os.unlink(temp_path)
            os.rmdir(temp_dir)
        except Exception as e:
            logger.warning("Cleanup failed: %s", e)

@app.route("/permission_json")
@require_api_key
def permission_json():
    scan_hash = request.args.get("hash", "").strip()
    if not scan_hash:
        return jsonify({"error": "Missing 'hash' parameter"}), 400

    try:
        report = fetch_mobsf_json(scan_hash)
    except Exception as e:
        logger.error("MobSF fetch failed: %s", e)
        return jsonify({"error": "MobSF fetch failed", "detail": str(e)}), 502

    platform = detect_platform(report)

    if platform == "android":
        from rules.android.dvm_permissions import DVM_PERMISSIONS
        raw_permissions = report.get("permissions", {})
        permissions = {}
        for perm_name, perm_details in raw_permissions.items():
            # Get permission info from DVM_PERMISSIONS if available
            dvm_info = DVM_PERMISSIONS.get('MANIFEST_PERMISSION', {}).get(perm_name.split('.')[-1], None)
            if dvm_info:
                permissions[perm_name] = {
                    "status": dvm_info[0],  # dangerous/normal
                    "info": dvm_info[1],    # short description
                    "description": dvm_info[2]  # full description
                }
            else:
                # Fallback for unknown permissions
                permissions[perm_name] = {
                    "status": "info",
                    "info": "Custom Permission",
                    "description": str(perm_details) if perm_details else "No description available"
                }
        perm_list = list(permissions.keys())
    elif platform == "ios":
        permissions = extract_ios_permissions(report)
        perm_list = list(permissions.keys())
    else:
        permissions = {}
        perm_list = []

    # Scoring & Classification

    # --- Klasifikasi app berdasarkan permissions saja ---
    suspicious_set = load_suspicious_indicators(platform)
    safety_score, classification, reason, matched_suspicious, risk_weight = classify_permissions(permissions, suspicious_set)
    risk_points = risk_weight

    result = {
        "platform": platform,
        "file_name": report.get("file_name", "N/A"),
        "package_name": report.get("package_name") or report.get("bundle_id", "N/A"),
        "permissions": permissions,
        "safety_score": safety_score,
        "risk_score": risk_points,
        "classification": classification,
        "classification_reason": reason,
        "risk_weight": risk_weight,
        "suspicious_permissions": matched_suspicious
    }
    return jsonify(result)

@app.route("/permission_pdf")
@require_api_key
def permission_pdf():
    scan_hash = request.args.get("hash", "").strip()
    if not scan_hash:
        return jsonify({"error": "Missing 'hash' parameter"}), 400

    try:
        report = fetch_mobsf_json(scan_hash)
    except Exception as e:
        logger.error("MobSF fetch failed: %s", e)
        return jsonify({"error": "MobSF fetch failed", "detail": str(e)}), 502

    platform = detect_platform(report)

    # --- Build context (sama seperti permission_json) ---
    if platform == "android":
        permissions = report.get("permissions", {})
        perm_list = list(permissions.keys()) if isinstance(permissions, dict) else []
    elif platform == "ios":
        permissions = extract_ios_permissions(report)
        perm_list = list(permissions.keys())
    else:
        permissions = {}
        perm_list = []

    # --- Klasifikasi app berdasarkan permissions saja ---
    suspicious_set = load_suspicious_indicators(platform)
    safety_score, classification, reason, matched_suspicious, risk_weight = classify_permissions(permissions, suspicious_set)
    risk_points = risk_weight

    # Inject minimal appsec and other fallback fields so MobSF templates render
    if "appsec" not in report or not isinstance(report.get("appsec"), dict):
        report["appsec"] = {}
    report["appsec"]["security_score"] = safety_score
    report.setdefault("timestamp", "N/A")
    report.setdefault("trackers", {"detected_trackers": 0, "total_trackers": 0})
    report.setdefault("virus_total", None)
    report.setdefault("certificate_analysis", {"certificate_info": "Permission-only analysis"})

    context = {
        "platform": platform,
        "file_name": report.get("file_name", "N/A"),
        "package_name": report.get("package_name") or report.get("bundle_id", "N/A"),
        "permissions": permissions,
        "safety_score": safety_score,
        "classification": classification,
        "classification_reason": reason,
        "suspicious_permissions": matched_suspicious,
        "open_sans_b64": OPEN_SANS_B64,
        "oswald_b64": OSWALD_B64,
        "pdf_css": PDF_CSS,
        "base_url": request.host_url,
    }

    template_name = "android_permission_only.html" if platform == "android" else "ios_permission_only.html"
    html = render_template(template_name, **context)

    if request.args.get("debug") == "html":
        return Response(html, mimetype="text/html")

    try:
        if HAVE_WEASY:
            # ✅ WeasyPrint tersedia: base64 font langsung jalan
            pdf_data = HTML(string=html).write_pdf()
        else:
            # ✅ WeasyPrint tidak tersedia: pakai wkhtmltopdf + file:// font
            open_sans_path = os.path.abspath(os.path.join(SCRIPT_DIR, "templates", "fonts", "OpenSans-Regular.ttf"))
            oswald_path = os.path.abspath(os.path.join(SCRIPT_DIR, "templates", "fonts", "Oswald-Regular.ttf"))

            # Inject @font-face dengan file://
            font_style = f"""
            <style>
            @font-face {{
                font-family: 'Open Sans';
                src: url('file://{open_sans_path}') format('truetype');
            }}
            @font-face {{
                font-family: 'Oswald';
                src: url('file://{oswald_path}') format('truetype');
            }}
            </style>
            """
            html = html.replace("</head>", font_style + "</head>")

            # Simpan ke file sementara
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f_html:
                f_html.write(html)
                html_path = f_html.name

            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f_pdf:
                pdf_path = f_pdf.name

            try:
                cmd = [
                    'wkhtmltopdf',
                    '--print-media-type',
                    '--no-stop-slow-scripts',
                    '--quiet',
                    html_path,
                    pdf_path
                ]
                subprocess.run(cmd, check=True, timeout=60)
                with open(pdf_path, 'rb') as f:
                    pdf_data = f.read()
            finally:
                for path in [html_path, pdf_path]:
                    if os.path.exists(path):
                        os.remove(path)

        resp = Response(pdf_data, mimetype='application/pdf')
        resp.headers['Content-Disposition'] = f'inline; filename=permission_report_{scan_hash[:8]}.pdf'
        return resp

    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        return jsonify({"error": "PDF generation failed"}), 500
        
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5002))
    debug = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true")
    app.run(host="0.0.0.0", port=port, debug=debug)