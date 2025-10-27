#!/bin/bash
# run.sh - MobSF CLI
# Output: filtered JSON (permissions, malware indicators, scoring), PDF report from server
# Compatible with jq 1.5+ (but does not use jq for main filtering)
# Output saved to fixed subfolders: full_output/, filtered_output/, pdf_output/ inside ~/apk-ipa-analyzer
# Usage: ./run.sh /path/to/app.apk

set -euo pipefail

# === Determine working directory and output paths ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FULL_OUTPUT_DIR="$SCRIPT_DIR/full_output"
FILTERED_OUTPUT_DIR="$SCRIPT_DIR/filtered_output"
# Tambahkan folder output untuk PDF
PDF_OUTPUT_DIR="$SCRIPT_DIR/pdf_output"

# Create output directories if they don't exist
mkdir -p "$FULL_OUTPUT_DIR" "$FILTERED_OUTPUT_DIR" "$PDF_OUTPUT_DIR"

MOBSF_URL="http://localhost:8001"
INPUT_PATH="${1:-}"

# === Validate Input ===
if [[ -z "$INPUT_PATH" ]]; then
    echo "❌ Usage: $0 <path/to/file.apk|ipa>"
    exit 1
fi

FILE=$(realpath "$INPUT_PATH" 2>/dev/null || readlink -f "$INPUT_PATH" 2>/dev/null || echo "$INPUT_PATH")
if [[ ! -f "$FILE" ]]; then
    echo "❌ File not found: $INPUT_PATH"
    exit 1
fi

BASENAME=$(basename "$FILE")
REPORT_NAME="${BASENAME%.*}"

# === Determine scan_type from file extension ===
if [[ "$BASENAME" == *.apk ]]; then
    SCAN_TYPE="apk"
elif [[ "$BASENAME" == *.ipa ]]; then
    SCAN_TYPE="ipa"
else
    # Default or error handling if needed
    SCAN_TYPE="app"
fi

# === Wait for Server to be Ready ===
echo "[*] Waiting for MobSF to be ready..."
for _ in {1..15}; do
    if curl -sf --max-time 2 "$MOBSF_URL" >/dev/null; then
        break
    fi
    sleep 2
done || { echo "❌ MobSF is not responding"; exit 1; }

# === Generate API Key from ~/.MobSF/secret ===
SECRET_FILE="$HOME/.MobSF/secret"
if [[ ! -f "$SECRET_FILE" ]]; then
    echo "❌ File 'secret' not found. Please run MobSF at least once."
    exit 1
fi

SECRET_KEY=$(tr -d '\n\r' < "$SECRET_FILE")
API_KEY=$(printf "%s" "$SECRET_KEY" | sha256sum | cut -d' ' -f1)

if [[ ! "$API_KEY" =~ ^[a-f0-9]{64}$ ]]; then
    echo "❌ Failed to generate API key."
    exit 1
fi

# === Upload & Scan ===
echo "[*] Uploading: $BASENAME"
UPLOAD_RESP=$(curl -s -F "file=@$FILE" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/upload")
HASH=$(echo "$UPLOAD_RESP" | jq -r '.hash // empty')
[[ -z "$HASH" ]] && { echo "❌ Upload failed"; echo "$UPLOAD_RESP" | jq .; exit 1; }

echo "[*] Starting scan..."
SCAN_RESP=$(curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/scan")
if echo "$SCAN_RESP" | jq -e '.error // empty' >/dev/null; then
    echo "❌ Scan failed"; echo "$SCAN_RESP" | jq .; exit 1
fi

# === Save Full Report (in full_output/) ===
JSON_REPORT="$FULL_OUTPUT_DIR/report_${REPORT_NAME}.json"
echo "[*] Saving full report to: $JSON_REPORT"
curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/report_json" | jq '.' > "$JSON_REPORT"

# === Download PDF Report from Server (in pdf_output/) ===
SERVER_PDF="$PDF_OUTPUT_DIR/report_${REPORT_NAME}_server.pdf"
echo "[*] Downloading PDF report from server to: $SERVER_PDF"
curl -X POST \
     -H "Authorization: $API_KEY" \
     -F "hash=$HASH" \
     -F "scan_type=$SCAN_TYPE" \
     "$MOBSF_URL/api/v1/download_pdf" \
     -o "$SERVER_PDF"

if [[ $? -eq 0 ]]; then
    echo "[✓] Server PDF downloaded: $SERVER_PDF"
else
    echo "[❌] Failed to download PDF report from server for hash $HASH"
    # Opsional: exit 1 jika PDF wajib
    # exit 1
fi

# === FILTER: permissions, malware, scoring (via Python) (in filtered_output/) ===
FILTERED_JSON="$FILTERED_OUTPUT_DIR/filtered_${REPORT_NAME}.json"
EXTRACT_SCRIPT="$SCRIPT_DIR/extract_filtered.py"
echo "[*] Filtering results to: $FILTERED_JSON"
python3 "$EXTRACT_SCRIPT" "$JSON_REPORT" | jq '.' > "$FILTERED_JSON"

# === Display Summary of Filtered Results ===
echo
echo "✅ ANALYSIS COMPLETE!"
echo "──────────────────────────────"
echo "📁 Input File   : $BASENAME"
echo "📂 Full Output  : $JSON_REPORT"
echo "📂 Filtered Output: $FILTERED_JSON"
echo "📄 Server PDF Output: $SERVER_PDF" # Tambahkan baris ini
echo "📱 App Name     : $(jq -r 'if .app_name != null then .app_name else "N/A" end' "$JSON_REPORT")"
echo "📦 Package      : $(jq -r 'if .package_name != null then .package_name else (if .bundle_id != null then .bundle_id else "N/A" end) end' "$JSON_REPORT")"
HIGH_RISK=$(python3 "$EXTRACT_SCRIPT" "$JSON_REPORT" | jq -r '.scoring.high_risk')
echo "🔴 High Risk    : $HIGH_RISK"
echo "📄 Report URL   : $MOBSF_URL/report/$HASH"
echo

# === Display Content of Filtered JSON ===
echo "🔍 FILTERED RESULT CONTENT:"
cat "$FILTERED_JSON" | jq .
echo

# === Auto-login & Open in Browser (optional) ===
COOKIES_FILE="/tmp/mobsf_session.txt"
LOGIN_URL="$MOBSF_URL/login"
REPORT_URL="$MOBSF_URL/report/$HASH"

CSRF_TOKEN=$(curl -s -c "$COOKIES_FILE" "$LOGIN_URL" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')
curl -s -b "$COOKIES_FILE" -c "$COOKIES_FILE" \
  -d "username=mobsf" \
  -d "password=mobsf" \
  -d "csrfmiddlewaretoken=$CSRF_TOKEN" \
  -H "Referer: $LOGIN_URL" \
  "$LOGIN_URL" >/dev/null

echo "[*] Report available at: $REPORT_URL"
# Uncomment the line below if you want to automatically open the browser
# xdg-open "$REPORT_URL" >/dev/null 2>&1 # For Linux
# cmd.exe /c start "$REPORT_URL" >/dev/null 2>&1 # For WSL

echo "[+] Done!"