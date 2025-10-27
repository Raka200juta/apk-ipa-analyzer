#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

# Check for Python virtual environment
VENV_DIR="$SCRIPT_DIR/venv"
if [[ ! -d "$VENV_DIR" ]]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Install requirements if needed
if [[ ! -f "$VENV_DIR/.requirements-installed" ]]; then
    echo "📥 Installing dependencies..."
    pip install -r "$SCRIPT_DIR/requirements.txt"
    touch "$VENV_DIR/.requirements-installed"
fi

# Check for wkhtmltopdf
if ! command -v wkhtmltopdf >/dev/null 2>&1; then
    echo "❌ wkhtmltopdf is not installed. Please install it first:"
    echo "Ubuntu/Debian: sudo apt-get install wkhtmltopdf"
    echo "CentOS/RHEL: sudo yum install wkhtmltopdf"
    echo "macOS: brew install wkhtmltopdf"
    exit 1
fi

# Create .env file if it doesn't exist
if [[ ! -f "$ENV_FILE" ]]; then
    echo "📝 Creating default .env file..."
    cat > "$ENV_FILE" << EOL
MOBSF_URL=http://mobsf:8001
MOBSF_API_KEY=
SERVICE_API_KEY=change-me-in-prod
FLASK_ENV=development
FLASK_APP=app.py
PORT=5002
EOL
fi

# Source .env file if it exists
if [[ -f "$ENV_FILE" ]]; then
    export $(cat "$ENV_FILE" | grep -v '^#' | xargs)
fi

# Create necessary directories
mkdir -p "$SCRIPT_DIR/templates/fonts"
mkdir -p "$SCRIPT_DIR/templates/css"

# Start Flask server
echo "🚀 Starting Flask server on port ${PORT:-5002}..."
python3 -m flask run --host=0.0.0.0 --port="${PORT:-5002}"