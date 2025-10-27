#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export MOBSF_URL="http://localhost:5001"
FULL_OUTPUT_DIR="$ROOT_DIR/full_output"
PDF_OUTPUT_DIR="$ROOT_DIR/pdf_output"

mkdir -p "$FULL_OUTPUT_DIR" "$PDF_OUTPUT_DIR"

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

echo "[*] Waiting for MobSF to be ready..."
for _ in {1..15}; do
    if curl -sf --max-time 2 "$MOBSF_URL" >/dev/null; then
        break
    fi
    sleep 2
done || { echo "❌ MobSF is not responding"; exit 1; }

# Get API key from secret
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

echo "[*] Generating permission-only PDF from MobSF..."
PERMISSION_PDF="$PDF_OUTPUT_DIR/permission_report_${REPORT_NAME}.pdf"

# Use the new MobSF API endpoint /api/v1/permissions_pdf (POST with hash + scan_type)
PERM_RESP=$(curl -s -w "%{http_code}" -o "$PERMISSION_PDF" -X POST \
    -H "Authorization: $API_KEY" \
    -F "hash=$HASH" \
    -F "scan_type=apk" \
    "$MOBSF_URL/api/v1/permissions_pdf")

# curl -w printed HTTP status after saving response body to file, capture and check it
HTTP_CODE="$PERM_RESP"
if [[ "$HTTP_CODE" != "200" ]]; then
    echo "❌ Failed to generate permission PDF from MobSF (HTTP $HTTP_CODE)."
    # Print any JSON error returned (try to cat the file)
    if [[ -s "$PERMISSION_PDF" ]]; then
        echo "Server response:" 
        cat "$PERMISSION_PDF" || true
        rm -f "$PERMISSION_PDF"
    fi
    echo "[*] Trying fallback: GET with query parameters..."
    # Try GET fallback in case server expects GET
    curl -s -w "%{http_code}" -o "$PERMISSION_PDF" -G \
        -H "Authorization: $API_KEY" \
        --data-urlencode "hash=$HASH" \
        --data-urlencode "scan_type=apk" \
        "$MOBSF_URL/api/v1/permissions_pdf" > /tmp/perm_http_code || true
    FALLBACK_HTTP=$(cat /tmp/perm_http_code || echo "")
    rm -f /tmp/perm_http_code
    if [[ "$FALLBACK_HTTP" != "200" ]]; then
        echo "❌ Fallback GET also failed (HTTP ${FALLBACK_HTTP:-unknown})."
        if [[ -s "$PERMISSION_PDF" ]]; then
            echo "Server response:" 
            cat "$PERMISSION_PDF" || true
            rm -f "$PERMISSION_PDF"
        fi
        exit 1
    fi
fi

echo "[*] Permission-only PDF saved as: $PERMISSION_PDF"