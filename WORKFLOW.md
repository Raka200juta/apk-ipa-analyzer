# Unified Workflow Documentation

## 🎯 Single Entry Point: `./scripts/start.sh`

Semua fitur sekarang bisa diakses dari satu script dengan 3 mode berbeda.

---

## 📌 Mode 1: Web Server Only

**Command:**
```bash
./scripts/start.sh
```

**Flow:**
```
┌─ Setup Phase ──────────────────┐
│ ├─ Create venv (if not exist)  │
│ ├─ Install dependencies        │
│ ├─ Check wkhtmltopdf           │
│ └─ Create .env config          │
└────────────────────────────────┘
              ↓
┌─ Server Phase ─────────────────┐
│ ├─ Load .env                   │
│ ├─ Start Flask on port 5002    │
│ ├─ Listen for requests:        │
│ │  • /health                   │
│ │  • /permission_json          │
│ │  • /permission_pdf           │
│ └─ Ready for queries!          │
└────────────────────────────────┘
```

**Use Case:** 
- MobSF sudah generate hash & JSON
- Tinggal query permission via REST API

**Example:**
```bash
# Terminal 1
./scripts/start.sh

# Terminal 2 (query with hash from MobSF)
curl "http://localhost:5002/permission_json?hash=abc123&api_key=change-me-in-prod" | jq .
```

---

## 📌 Mode 2: Analyze APK/IPA Only

**Command:**
```bash
./scripts/start.sh /path/to/app.apk
```

**Flow:**
```
┌─ Setup Phase ──────────────────┐
│ ├─ Create venv                 │
│ ├─ Install dependencies        │
│ └─ Create .env config          │
└────────────────────────────────┘
              ↓
┌─ File Analysis Phase ──────────┐
│ ├─ Wait MobSF ready            │
│ ├─ Upload APK to MobSF         │
│ ├─ Trigger scan                │
│ ├─ Download JSON report        │
│ ├─ Download full PDF           │
│ ├─ Download permission PDF     │
│ ├─ Extract filtered JSON       │
│ └─ Save all outputs            │
└────────────────────────────────┘
              ↓
  [Analysis Complete - Script Ends]
  (No server started)
```

**Output:**
- `full_output/report_*.json`
- `pdf_output/report_*_server.pdf`
- `pdf_output/permission_report_*.pdf`
- `filtered_output/filtered_*.json`

**Use Case:**
- Batch analysis of APK/IPA files
- Generate reports locally
- No need for server

**Example:**
```bash
./scripts/start.sh ~/apps/instagram.apk
./scripts/start.sh ~/apps/tiktok.ipa
# Reports saved to output folders
```

---

## 📌 Mode 3: Analyze + Start Server

**Command:**
```bash
./scripts/start.sh /path/to/app.apk --server
```

**Flow:**
```
┌─ Setup Phase ──────────────────┐
│ └─ Create venv & install       │
└────────────────────────────────┘
              ↓
┌─ File Analysis Phase ──────────┐
│ ├─ Upload & scan on MobSF      │
│ ├─ Generate all reports        │
│ ├─ Save outputs                │
│ └─ Analysis complete           │
└────────────────────────────────┘
              ↓
┌─ Server Phase ─────────────────┐
│ ├─ Start Flask server          │
│ ├─ Ready for queries           │
│ └─ Keep running...             │
└────────────────────────────────┘
```

**Use Case:**
- Analyze + immediately query results
- Single terminal session
- Continuous server for other queries

**Example:**
```bash
./scripts/start.sh ~/apps/app.apk --server
# After analysis, server keeps running
# Can then query: curl "http://localhost:5002/permission_json?hash=abc123..."
```

---

## 🔄 Internal Flow Detail

### Setup Phase (Runs First Time Always)

```
1. Create virtualenv → /home/user/apk-ipa-analyzer/venv
2. Install pip packages:
   ✓ Flask 3.0.3
   ✓ requests (HTTP calls)
   ✓ PyYAML (config loading)
   ✓ pdfkit (PDF generation)
   ✓ python-dotenv (.env parsing)
3. Check system binary: wkhtmltopdf
4. Create .env with defaults:
   MOBSF_URL=http://localhost:5001
   MOBSF_API_KEY=
   SERVICE_API_KEY=change-me-in-prod
   FLASK_ENV=development
   PORT=5002
5. Create output directories:
   - /full_output
   - /filtered_output
   - /pdf_output
```

### File Analysis Phase (If File Provided)

```
1. Validate file exists & readable
2. Determine file type (APK/IPA)
3. Wait for MobSF @ http://localhost:5001 (up to 30 sec)
4. Read MobSF secret from $HOME/.MobSF/secret
5. Generate API key via SHA256(secret)
6. Upload file:
   POST /api/v1/upload
   Response: { hash: "abc123..." }
7. Start scan:
   POST /api/v1/scan { hash: "abc123" }
8. Download reports:
   a) GET /api/v1/report_json → full_output/report_*.json
   b) POST /api/v1/download_pdf → pdf_output/report_*_server.pdf
   c) POST /api/v1/permissions_pdf → pdf_output/permission_report_*.pdf
9. Optional: Extract filtered JSON (if extract_filtered.py exists)
```

### Server Phase (If No File Or --server Flag)

```
1. Load environment from .env
2. Initialize Flask app from src/app.py
3. Start WSGI server on 0.0.0.0:5002
4. Endpoints available:
   
   GET /health
   └─ Returns: { status: "ok" }
   
   GET /permission_json?hash=<hash>&api_key=<key>
   ├─ Fetch report from MobSF
   ├─ Parse permissions
   ├─ Classify risk level
   └─ Returns: { safety_score, classification, ... }
   
   GET /permission_pdf?hash=<hash>&api_key=<key>
   ├─ Fetch report from MobSF
   ├─ Parse permissions
   ├─ Render HTML template
   ├─ Convert to PDF (wkhtmltopdf)
   └─ Returns: PDF binary

5. Server runs indefinitely (Ctrl+C to stop)
```

---

## 📊 Data Flow Diagram

```
┌──────────────────────────────────────────────────────────┐
│                   start.sh Entry Point                   │
└────────────────────┬─────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
   FILE PROVIDED?            NO FILE?
        │                         │
        ▼                         ▼
   ┌─ANALYZE─┐             ┌─SERVER─┐
   │ MODE 2/3│             │ MODE 1 │
   └────┬────┘             └────┬───┘
        │                       │
        ├─────────┬─────────┬───┤
        │         │         │   │
        ▼         ▼         ▼   ▼
      MobSF    JSON PDF   Filter Flask
      Upload   Report PDF  JSON  API
      Scan
        │
        └─────────┬──────────────┘
                  │
           ┌──────┴──────┐
           │             │
       --server?      NO
       (flag)         └─ Exit
           │
          YES
           │
           ▼
        Flask Server
        (continuous)
```

---

## 🔑 Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `MOBSF_URL` | `http://localhost:5001` | MobSF API server URL |
| `MOBSF_API_KEY` | *(empty)* | MobSF API key (auto from secret) |
| `SERVICE_API_KEY` | `change-me-in-prod` | Flask API authentication |
| `FLASK_ENV` | `development` | Flask environment mode |
| `FLASK_APP` | `src.app` | Flask application entry point |
| `PORT` | `5002` | Flask server port |

---

## ✅ Checklist Before Running

- [ ] MobSF running at `http://localhost:5001`
- [ ] `wkhtmltopdf` installed: `which wkhtmltopdf`
- [ ] Python 3.10+: `python3 --version`
- [ ] Bash available: `bash --version`
- [ ] For analysis: APK/IPA file ready
- [ ] `.env` file created (auto if not exist)

---

## 🐛 Troubleshooting

**Problem:** "MobSF is not responding"
- Check: `curl http://localhost:5001`
- Fix: Start MobSF first

**Problem:** "wkhtmltopdf is not installed"
- Ubuntu/Debian: `sudo apt-get install wkhtmltopdf`
- macOS: `brew install wkhtmltopdf`

**Problem:** "File 'secret' not found"
- Fix: Run MobSF at least once to generate secret
- Location: `$HOME/.MobSF/secret`

**Problem:** Permission denied on script
- Fix: `chmod +x scripts/start.sh`

---

## 📞 API Response Examples

### /permission_json
```json
{
  "platform": "android",
  "file_name": "app.apk",
  "package_name": "com.example.app",
  "safety_score": 83,
  "classification": "Safe",
  "classification_reason": "Low-risk permissions detected",
  "permissions": {
    "android.permission.INTERNET": {...},
    "android.permission.CAMERA": {...}
  },
  "suspicious_permissions": ["android.permission.CAMERA"]
}
```

### /permission_pdf
- Content-Type: `application/pdf`
- Binary PDF file with formatted permission report

