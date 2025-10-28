# APK/IPA Permission Analyzer

**Comprehensive mobile app security analyzer** with MobSF integration for automated permission extraction, risk scoring, and multi-format reporting.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 Overview

Analyze Android APK and iOS IPA files for security permissions and generate detailed reports with:
- **Risk Classification** (Safe/Dangerous/Malicious)
- **Permission-only Analysis** (focus on what app can do)
- **Multi-format Reports** (JSON, PDF, filtered extracts)
- **REST API** (query analysis results programmatically)
- **Auto-Setup** (virtualenv + dependencies on first run)

---

## ⚡ Quick Start

### Prerequisites
- **MobSF** running at `http://localhost:5001`
- **Python 3.10+** installed
- **wkhtmltopdf** system package installed
- **bash** shell

### Installation & First Run
```bash
# Clone repository
git clone <repo-url>
cd apk-ipa-analyzer

# Run script - auto-setup happens on first run!
./scripts/start.sh
```

### Usage Examples

**Mode 1: Start web server (query via API)**
```bash
./scripts/start.sh
# Server runs at http://localhost:5002
# Query: curl "http://localhost:5002/permission_json?hash=<hash>&api_key=change-me-in-prod"
```

**Mode 2: Analyze APK/IPA (generate reports)**
```bash
./scripts/start.sh /path/to/app.apk
# Outputs: JSON + PDFs in output/ folders
```

**Mode 3: Analyze + start server (for immediate queries)**
```bash
./scripts/start.sh /path/to/app.apk --server
# Generates reports, then starts server
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| **[README.md](README.md)** | This file - overview & quick start |
| **[WORKFLOW.md](WORKFLOW.md)** | Detailed flow diagrams & internal architecture |
| **[requirements.txt](requirements.txt)** | Python dependencies |

---

## 🔄 Workflow Overview

```
┌─ SETUP (first run) ────────────────────┐
│ • Create Python virtualenv             │
│ • Install pip dependencies             │
│ • Verify system requirements           │
│ • Generate .env config                 │
└────────────────────────────────────────┘
              ↓
┌─ ANALYSIS (if file provided) ──────────┐
│ • Wait for MobSF to be ready           │
│ • Upload APK/IPA                       │
│ • Execute security scan                │
│ • Download full analysis JSON          │
│ • Extract permission reports           │
│ • Generate permission-only PDFs        │
│ • Extract filtered JSON (optional)     │
└────────────────────────────────────────┘
              ↓
┌─ SERVER (if --server or no file) ──────┐
│ • Initialize Flask application         │
│ • Start REST API server @ port 5002    │
│ • Listen for permission queries        │
│ • Keep running indefinitely            │
└────────────────────────────────────────┘
```

See **[WORKFLOW.md](WORKFLOW.md)** for detailed diagrams and internal flow.

---

## 🔌 REST API Endpoints

### Health Check
```bash
GET /health
```
**Response:**
```json
{ "status": "ok" }
```

### Permission Analysis (JSON)
```bash
GET /permission_json?hash=<HASH>&api_key=<KEY>
```
**Response:**
```json
{
  "platform": "android",
  "file_name": "app.apk",
  "package_name": "com.example.app",
  "safety_score": 83,
  "classification": "Safe",
  "classification_reason": "Low-risk permissions detected",
  "permissions": {...},
  "suspicious_permissions": [...],
  "risk_weight": 1.5
}
```

### Permission Analysis (PDF)
```bash
GET /permission_pdf?hash=<HASH>&api_key=<KEY>
```
**Response:** Binary PDF file with formatted permission report

---

## 📊 Permission Classification

| Classification | Score | Meaning |
|---|---|---|
| **Safe** | > 60 | Low-risk permissions only |
| **Dangerous** | 21-60 | Multiple dangerous permissions detected |
| **Malicious** | ≤ 20 | Critical permissions for tracking/stealing |

---

## 📁 Project Structure

```
apk-ipa-analyzer/
├── scripts/
│   └── start.sh              ← MAIN ENTRY POINT (3 modes)
├── src/
│   ├── app.py               ← Flask API server
│   └── permission_scoring.py ← Risk classification logic
├── rules/
│   ├── android/
│   │   ├── dvm_permissions.py
│   │   ├── malware_permissions.py
│   │   └── suspicious_indicators_android.yaml
│   └── ios/
│       ├── ios_apis.yaml
│       └── permissions_analysis.py
├── templates/               ← HTML/CSS for PDF reports
├── output/
│   ├── full_output/        ← Complete analysis JSON
│   ├── filtered_output/    ← Extracted permissions JSON
│   └── pdf_output/         ← Generated PDF reports
├── README.md               ← This file
├── WORKFLOW.md             ← Detailed flow documentation
├── requirements.txt        ← Python dependencies
└── .env                    ← Configuration (auto-generated)
```

---

## ⚙️ Configuration

### .env File (Auto-generated)

```properties
# MobSF API Server
MOBSF_URL=http://localhost:5001
MOBSF_API_KEY=                    # Leave empty (auto from MobSF)

# Flask API Server
SERVICE_API_KEY=change-me-in-prod  # Change in production!
FLASK_ENV=development
FLASK_APP=src.app
PORT=5002
```

### Customization

Edit `.env` after first run to customize:
```bash
# Change Flask port
PORT=8080

# Change MobSF location (if not localhost:5001)
MOBSF_URL=http://192.168.1.100:5001

# Change API key for production
SERVICE_API_KEY=your-secure-key-here
```

---

## 🚀 Installation

### System Requirements

**Ubuntu/Debian:**
```bash
# Install Python & dependencies
sudo apt-get update
sudo apt-get install python3 python3-venv wkhtmltopdf jq curl

# Verify installations
python3 --version
which wkhtmltopdf
```

**macOS:**
```bash
# Install via Homebrew
brew install python wkhtmltopdf

# Verify
python3 --version
which wkhtmltopdf
```

**Windows:** (Git Bash recommended)
```bash
# Install Python from python.org
# Install wkhtmltopdf: https://wkhtmltopdf.org/downloads.html
```

### Python Dependencies

Auto-installed on first run via `requirements.txt`:
- **Flask 3.0.3** - Web framework
- **requests 2.32.3** - HTTP client
- **Jinja2 3.1.4** - Template engine
- **pdfkit 1.0.0** - PDF generation
- **python-dotenv 1.0.0** - .env parser
- **PyYAML 6.0+** - YAML config parser

---

## 🔍 Example Workflows

### Workflow 1: Batch Analysis (No Server)
```bash
# Analyze multiple apps
./scripts/start.sh ~/Downloads/instagram.apk
./scripts/start.sh ~/Downloads/tiktok.ipa
./scripts/start.sh ~/Downloads/facebook.apk

# Reports automatically saved to output/ folders
```

### Workflow 2: API Server (Persistent)
```bash
# Terminal 1: Start server
./scripts/start.sh

# Terminal 2: Query with hashes from MobSF
curl "http://localhost:5002/permission_json?hash=hash1&api_key=change-me-in-prod"
curl "http://localhost:5002/permission_json?hash=hash2&api_key=change-me-in-prod"
```

### Workflow 3: Analyze + Query (Single Session)
```bash
./scripts/start.sh ~/Downloads/app.apk --server

# After analysis completes:
# - Get hash from the JSON report
# - Query via API while server is running
curl "http://localhost:5002/permission_json?hash=<hash>&api_key=change-me-in-prod" | jq .
```

---

## 🐛 Troubleshooting

### "MobSF is not responding"
```bash
# Check if MobSF is running
curl http://localhost:5001

# If not, start MobSF:
# (Follow MobSF documentation)
```

### "wkhtmltopdf is not installed"
```bash
# Ubuntu/Debian
sudo apt-get install wkhtmltopdf

# macOS
brew install wkhtmltopdf

# Then re-run: ./scripts/start.sh
```

### "File 'secret' not found"
```bash
# Run MobSF at least once to generate secret
# Location: $HOME/.MobSF/secret
```

### "Permission denied"
```bash
# Make script executable
chmod +x scripts/start.sh
```

### "Port 5002 already in use"
```bash
# Kill existing process
lsof -ti:5002 | xargs kill -9

# Or use different port
PORT=8080 ./scripts/start.sh
```

---

## 🔑 Security Notes

⚠️ **Production Deployment:**
- Change `SERVICE_API_KEY` in `.env`
- Use HTTPS for API calls
- Implement proper authentication
- Run MobSF in secure environment
- Review `FLASK_ENV=production`

---

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Submit Pull Request

---

## 📞 Support

For issues or questions:
- Check [WORKFLOW.md](WORKFLOW.md) for detailed documentation
- Review troubleshooting section above
- Check MobSF logs for API issues

---

## 🙏 Acknowledgments

- **MobSF** - Mobile Security Framework
- **Flask** - Python web framework
- **pdfkit/wkhtmltopdf** - PDF generation


