#!/bin/bash
set -euo pipefail

# Thin wrapper of the original top-level run.sh, moved to scripts/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export MOBSF_URL="http://localhost:8001"
FULL_OUTPUT_DIR="$ROOT_DIR/full_output"
FILTERED_OUTPUT_DIR="$ROOT_DIR/filtered_output"
PDF_OUTPUT_DIR="$ROOT_DIR/pdf_output"

mkdir -p "$FULL_OUTPUT_DIR" "$FILTERED_OUTPUT_DIR" "$PDF_OUTPUT_DIR"

INPUT_PATH="${1:-}"
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

if [[ "$BASENAME" == *.apk ]]; then
    SCAN_TYPE="apk"
elif [[ "$BASENAME" == *.ipa ]]; then
    SCAN_TYPE="ipa"
else
    SCAN_TYPE="app"
fi

echo "[*] Waiting for MobSF to be ready..."
for _ in {1..15}; do
    if curl -sf --max-time 2 "$MOBSF_URL" >/dev/null; then
        break
    fi
    sleep 2
done || { echo "❌ MobSF is not responding"; exit 1; }

SECRET_FILE="$HOME/.MobSF/secret"
if [[ ! -f "$SECRET_FILE" ]]; then
    echo "❌ File 'secret' not found. Please run MobSF at least once."
    exit 1
fi

SECRET_KEY=$(tr -d '\n\r' < "$SECRET_FILE")
API_KEY=$(printf "%s" "$SECRET_KEY" | sha256sum | cut -d' ' -f1)

echo "[*] Uploading: $BASENAME"
UPLOAD_RESP=$(curl -s -F "file=@$FILE" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/upload")
HASH=$(echo "$UPLOAD_RESP" | jq -r '.hash // empty')
[[ -z "$HASH" ]] && { echo "❌ Upload failed"; echo "$UPLOAD_RESP" | jq .; exit 1; }

echo "[*] Starting scan..."
SCAN_RESP=$(curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/scan")
if echo "$SCAN_RESP" | jq -e '.error // empty' >/dev/null; then
    echo "❌ Scan failed"; echo "$SCAN_RESP" | jq .; exit 1
fi

JSON_REPORT="$FULL_OUTPUT_DIR/report_${REPORT_NAME}.json"
echo "[*] Saving full report to: $JSON_REPORT"
curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/report_json" | jq '.' > "$JSON_REPORT"

SERVER_PDF="$PDF_OUTPUT_DIR/report_${REPORT_NAME}_server.pdf"
echo "[*] Downloading PDF report from server to: $SERVER_PDF"
curl -X POST \
     -H "Authorization: $API_KEY" \
     -F "hash=$HASH" \
     -F "scan_type=$SCAN_TYPE" \
     "$MOBSF_URL/api/v1/download_pdf" \
     -o "$SERVER_PDF"

EXTRACT_SCRIPT="$ROOT_DIR/extract_filtered.py"
FILTERED_JSON="$FILTERED_OUTPUT_DIR/filtered_${REPORT_NAME}.json"
python3 "$EXTRACT_SCRIPT" "$JSON_REPORT" | jq '.' > "$FILTERED_JSON"

echo
echo "✅ ANALYSIS COMPLETE!"
echo "Report: $JSON_REPORT"
echo "Filtered: $FILTERED_JSON"
echo "Server PDF: $SERVER_PDF"
echo
