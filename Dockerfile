FROM python:3.12-slim-bullseye

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

# System deps + wkhtmltopdf (bullseye .deb)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl jq ca-certificates xfonts-75dpi xfonts-base \
      libxrender1 libxext6 libfontconfig1 libfreetype6 && \
    curl -L -o /tmp/wkhtml.deb \
      "https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb" && \
    dpkg -I /tmp/wkhtml.deb || (echo "Invalid wkhtmltopdf .deb, aborting build" && exit 1) && \
    apt-get install -y /tmp/wkhtml.deb || apt-get -f install -y && \
    rm -f /tmp/wkhtml.deb && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY . /app

# Install python deps globally (no venv in docker)
RUN python -m pip install --upgrade pip setuptools wheel && \
    python -m pip install -r requirements.txt

# create non-root user
RUN groupadd -g 1000 appuser && useradd -u 1000 -g appuser -m appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 5002
ENTRYPOINT ["/bin/bash", "scripts/start.sh"]