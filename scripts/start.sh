#!/bin/bash

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
MOBSF_URL="http://mobsf:8001"
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

echo "🚀 Starting Flask server on port ${PORT:-5002}..."
python3 -m flask run --host=0.0.0.0 --port="${PORT:-5002}"
