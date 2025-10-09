#!/bin/bash
# run.sh - MobSF CLI untuk WSL
# Output: filtered JSON (permissions, malware indicators, scoring)
# Kompatibel jq 1.5+ (tapi tidak menggunakan jq untuk filter utama)
# Penggunaan: ./run.sh /path/to/app.apk

set -euo pipefail

MOBSF_URL="http://localhost:8000"
INPUT_PATH="${1:-}"

# === Validasi Input ===
if [[ -z "$INPUT_PATH" ]]; then
    echo "❌ Penggunaan: $0 <path/ke/file.apk|ipa>"
    exit 1
fi

FILE=$(realpath "$INPUT_PATH" 2>/dev/null || readlink -f "$INPUT_PATH" 2>/dev/null || echo "$INPUT_PATH")
if [[ ! -f "$FILE" ]]; then
    echo "❌ File tidak ditemukan: $INPUT_PATH"
    exit 1
fi

BASENAME=$(basename "$FILE")
REPORT_NAME="${BASENAME%.*}"

# === Tunggu Server Siap ===
echo "[*] Menunggu MobSF siap..."
for _ in {1..15}; do
    if curl -sf --max-time 2 "$MOBSF_URL" >/dev/null; then
        break
    fi
    sleep 2
done || { echo "❌ MobSF tidak merespons"; exit 1; }

# === Generate API Key dari ~/.MobSF/secret ===
SECRET_FILE="$HOME/.MobSF/secret"
if [[ ! -f "$SECRET_FILE" ]]; then
    echo "❌ File 'secret' tidak ditemukan. Jalankan MobSF sekali dulu."
    exit 1
fi

SECRET_KEY=$(tr -d '\n\r' < "$SECRET_FILE")
API_KEY=$(printf "%s" "$SECRET_KEY" | sha256sum | cut -d' ' -f1)

if [[ ! "$API_KEY" =~ ^[a-f0-9]{64}$ ]]; then
    echo "❌ Gagal generate API key."
    exit 1
fi

# === Upload & Scan ===
echo "[*] Upload: $BASENAME"
UPLOAD_RESP=$(curl -s -F "file=@$FILE" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/upload")
HASH=$(echo "$UPLOAD_RESP" | jq -r '.hash // empty')
[[ -z "$HASH" ]] && { echo "❌ Upload gagal"; echo "$UPLOAD_RESP" | jq .; exit 1; }

echo "[*] Memulai scan..."
SCAN_RESP=$(curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/scan")
if echo "$SCAN_RESP" | jq -e '.error // empty' >/dev/null; then
    echo "❌ Scan gagal"; echo "$SCAN_RESP" | jq .; exit 1
fi

# === Simpan Laporan Lengkap ===
JSON_REPORT="report_${REPORT_NAME}.json"
curl -s -d "hash=$HASH" -H "Authorization: $API_KEY" "$MOBSF_URL/api/v1/report_json" > "$JSON_REPORT"

# === FILTER: permissions, malware, scoring (via Python) ===
FILTERED_JSON="filtered_${REPORT_NAME}.json"
python3 ~/mobsf-cli/extract_filtered.py "$JSON_REPORT" > "$FILTERED_JSON"

# === Tampilkan Hasil Filter ===
echo
echo "✅ ANALISIS SELESAI!"
echo "──────────────────────────────"
echo "📁 File        : $BASENAME"
echo "📱 App         : $(jq -r 'if .app_name != null then .app_name else "N/A" end' "$JSON_REPORT")"
echo "📦 Package     : $(jq -r 'if .package_name != null then .package_name else (if .bundle_id != null then .bundle_id else "N/A" end) end' "$JSON_REPORT")"
# Gunakan Python untuk mendapatkan high_risk juga
HIGH_RISK=$(python3 ~/mobsf-cli/extract_filtered.py "$JSON_REPORT" | jq -r '.scoring.high_risk')
echo "🔴 High Risk   : $HIGH_RISK"
echo "📄 Laporan     : $MOBSF_URL/report/$HASH"
echo "🎯 Filter JSON : $FILTERED_JSON"
echo
echo "🔍 HASIL FILTER:"
cat "$FILTERED_JSON" | jq .
echo

# === Auto-login & Buka di Browser Windows ===
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

echo "[*] Membuka laporan di browser Windows..."
cmd.exe /c start "$REPORT_URL" >/dev/null 2>&1

echo "[+] Selesai!"