#!/bin/bash
#
# APK/IPA Analyzer - Unified Script
# ================================
#
# USAGE:
#   ./scripts/start.sh                           # Start Flask web server only
#   ./scripts/start.sh <file.apk|ipa>            # Analyze APK/IPA (full workflow)
#   ./scripts/start.sh <file.apk|ipa> --server   # Analyze + then start server
#
# FEATURES:
#   - Setup: Creates venv, installs dependencies, creates .env
#   - Analysis: Uploads to MobSF, scans, generates reports
#   - Server: Runs Flask API for permission queries
#
# WORKFLOW:
#   1. Setup Phase (always runs first time)
#      - Create Python virtualenv
#      - Install requirements from pip
#      - Check for wkhtmltopdf system dependency
#      - Create default .env if missing
#
#   2. File Analysis Phase (optional, only if file provided)
#      - Wait for MobSF server to be ready
#      - Upload APK/IPA to MobSF
#      - Trigger security scan
#      - Download JSON report (full analysis)
#      - Download full PDF from MobSF
#      - Download permission-only PDF from MobSF
#      - Extract filtered JSON (if extract_filtered.py exists)
#
#   3. Server Phase (optional)
#      - Start Flask API on http://localhost:5002
#      - Ready to accept /permission_json and /permission_pdf queries
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"

# Virtualenv in project
VENV_DIR="$ROOT_DIR/venv"
if [[ ! -d "$VENV_DIR" ]]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

if [[ ! -f "$VENV_DIR/.requirements-installed" ]]; then
    echo "📥 Installing dependencies..."
    pip install -r "$ROOT_DIR/requirements.txt"
    touch "$VENV_DIR/.requirements-installed"
fi

if ! command -v wkhtmltopdf >/dev/null 2>&1; then
    echo "❌ wkhtmltopdf is not installed. Please install it first."
    exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "📝 Creating default .env file..."
    cat > "$ENV_FILE" << 'EOL'
MOBSF_URL="http://localhost:5001"
MOBSF_API_KEY=""
SERVICE_API_KEY="change-me-in-prod"
FLASK_ENV="development"
FLASK_APP="src.app"
PORT="5002"
EOL
fi

# Load env vars
if [[ -f "$ENV_FILE" ]]; then
    set -a
    source "$ENV_FILE"
    set +a
fi

mkdir -p "$ROOT_DIR/templates/fonts"
mkdir -p "$ROOT_DIR/templates/css"
mkdir -p "$ROOT_DIR/full_output"
mkdir -p "$ROOT_DIR/filtered_output"
mkdir -p "$ROOT_DIR/pdf_output"

# Parse arguments
INPUT_PATH="${1:-}"
START_SERVER="${2:-}"

if [[ -z "$INPUT_PATH" ]]; then
    # No file provided - start Flask server only
    echo ""
    echo "🚀 Starting Flask web server..."
    echo "📍 Server running at http://localhost:${PORT}"
    echo ""
    echo "USAGE:"
    echo "  $0 <path/to/file.apk|ipa>            # Analyze APK/IPA"
    echo "  $0 <path/to/file.apk|ipa> --server   # Analyze + start server"
    echo ""
    python3 -m flask run --port "${PORT}"
else
    # File provided - run analysis workflow
    FILE=$(realpath "$INPUT_PATH" 2>/dev/null || readlink -f "$INPUT_PATH" 2>/dev/null || echo "$INPUT_PATH")
    if [[ ! -f "$FILE" ]]; then
        echo "❌ File not found: $INPUT_PATH"
        exit 1
    fi

    BASENAME=$(basename "$FILE")
    REPORT_NAME="${BASENAME%.*}"

    if [[ "$BASENAME" == *.apk ]]; then
        SCAN_TYPE="apk"
    elif [[ "$BASENAME" == *.ipa ]]; then
        SCAN_TYPE="ipa"
    else
        SCAN_TYPE="app"
    fi

    # Initialize output variables (will be set during analysis)
    JSON_REPORT=""
    FULL_PDF=""
    PERMISSION_PDF=""
    FILTERED_JSON=""

    echo "[*] Waiting for MobSF to be ready..."
    for _ in {1..15}; do
        if curl -sf --max-time 2 "${MOBSF_URL}" >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done || { echo "❌ MobSF is not responding at ${MOBSF_URL}"; exit 1; }

    SECRET_FILE="$HOME/.MobSF/secret"
    if [[ ! -f "$SECRET_FILE" ]]; then
        echo "❌ File 'secret' not found. Please run MobSF at least once."
        exit 1
    fi

    SECRET_KEY=$(tr -d '\n\r' < "$SECRET_FILE")
    API_KEY=$(printf "%s" "$SECRET_KEY" | sha256sum | cut -d' ' -f1)

    echo "[*] Uploading: $BASENAME"
    UPLOAD_RESP=$(curl -s -F "file=@$FILE" -H "Authorization: $API_KEY" "${MOBSF_URL}/api/v1/upload")
    HASH=$(echo "$UPLOAD_RESP" | jq -r '.hash // empty')
    [[ -z "$HASH" ]] && { echo "❌ Upload failed"; echo "$UPLOAD_RESP" | jq .; exit 1; }

    echo "[*] Starting scan..."
    SCAN_RESP=$(curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "${MOBSF_URL}/api/v1/scan")
    if echo "$SCAN_RESP" | jq -e '.error // empty' >/dev/null; then
        echo "❌ Scan failed"; echo "$SCAN_RESP" | jq .; exit 1
    fi

    JSON_REPORT="$ROOT_DIR/full_output/report_${REPORT_NAME}.json"
    echo "[*] Saving full report to: $JSON_REPORT"
    curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "${MOBSF_URL}/api/v1/report_json" | jq '.' > "$JSON_REPORT"

    echo "[*] Downloading full PDF report from server..."
    FULL_PDF="$ROOT_DIR/pdf_output/report_${REPORT_NAME}_server.pdf"
    curl -X POST \
         -H "Authorization: $API_KEY" \
         -F "hash=$HASH" \
         -F "scan_type=$SCAN_TYPE" \
         "${MOBSF_URL}/api/v1/download_pdf" \
         -o "$FULL_PDF"
    echo "    ✅ Full PDF: $FULL_PDF"

    echo "[*] Downloading permission-only PDF from server..."
    PERMISSION_PDF="$ROOT_DIR/pdf_output/permission_report_${REPORT_NAME}.pdf"
    PERM_RESP=$(curl -s -w "%{http_code}" -o "$PERMISSION_PDF" -X POST \
        -H "Authorization: $API_KEY" \
        -F "hash=$HASH" \
        -F "scan_type=$SCAN_TYPE" \
        "${MOBSF_URL}/api/v1/permissions_pdf")

    HTTP_CODE="$PERM_RESP"
    if [[ "$HTTP_CODE" != "200" ]]; then
        echo "    ⚠️  Permission PDF failed (HTTP $HTTP_CODE), trying fallback..."
        curl -s -w "%{http_code}" -o "$PERMISSION_PDF" -G \
            -H "Authorization: $API_KEY" \
            --data-urlencode "hash=$HASH" \
            --data-urlencode "scan_type=$SCAN_TYPE" \
            "${MOBSF_URL}/api/v1/permissions_pdf" > /tmp/perm_http_code 2>&1 || true
        FALLBACK_HTTP=$(cat /tmp/perm_http_code 2>/dev/null || echo "")
        rm -f /tmp/perm_http_code
        if [[ "$FALLBACK_HTTP" != "200" ]]; then
            echo "    ⚠️  Fallback also failed, skipping permission PDF"
            rm -f "$PERMISSION_PDF"
        else
            echo "    ✅ Permission PDF: $PERMISSION_PDF"
        fi
    else
        echo "    ✅ Permission PDF: $PERMISSION_PDF"
    fi

    EXTRACT_SCRIPT="$ROOT_DIR/extract_filtered.py"
    if [[ -f "$EXTRACT_SCRIPT" ]]; then
        echo "[*] Extracting filtered JSON..."
        FILTERED_JSON="$ROOT_DIR/filtered_output/filtered_${REPORT_NAME}.json"
        python3 "$EXTRACT_SCRIPT" "$JSON_REPORT" | jq '.' > "$FILTERED_JSON"
        echo "    ✅ Filtered JSON: $FILTERED_JSON"
    fi

    echo ""
    echo "📊 ✅ ANALYSIS COMPLETE!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Reports generated:"
    echo "  📄 Full Report:      $JSON_REPORT"
    echo "  📑 Full PDF:         $FULL_PDF"
    [[ -f "$PERMISSION_PDF" ]] && echo "  🔐 Permission PDF:   $PERMISSION_PDF"
    [[ -f "$FILTERED_JSON" ]] && echo "  🔍 Filtered JSON:    $FILTERED_JSON"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
fi

# Check if user wants to start server after analysis
if [[ "${START_SERVER}" == "--server" ]]; then
    echo "🚀 Starting Flask web server on port ${PORT:-5002}..."
    echo "📍 http://localhost:${PORT:-5002}"
    echo ""
    python3 -m flask run --port "${PORT:-5002}"
elif [[ -n "$INPUT_PATH" ]]; then
    echo "💡 To start the web server, run: $0 <file> --server"
    echo "   Or run Flask manually: source venv/bin/activate && python3 -m flask run"
fi
