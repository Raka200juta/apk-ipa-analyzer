FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y wkhtmltopdf curl jq && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install -r requirements.txt

EXPOSE 5002

ENTRYPOINT ["/bin/bash", "scripts/start.sh"]