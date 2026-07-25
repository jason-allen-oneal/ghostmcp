FROM python:3.12-slim@sha256:f3fa41d74a768c2fce8016b98c191ae8c1bacd8f1152870a3f9f87d350920b7c

# Keep OS packages patched so Trivy does not fail on fixed CVEs baked into the base image.
RUN apt-get update \
  && apt-get upgrade -y \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=/app

# Install locked dependencies with hashes.
COPY requirements.lock.txt /app/requirements.lock.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.lock.txt

# Copy app source (run from source, do not pip-install the project).
COPY ghostmcp /app/ghostmcp

RUN groupadd --system --gid 10001 ghostmcp \
  && useradd --system --uid 10001 --gid ghostmcp --home-dir /nonexistent \
       --shell /usr/sbin/nologin ghostmcp \
  && install -d -o ghostmcp -g ghostmcp -m 0700 /data /audit

ENV GHOSTMCP_CREDENTIAL_STORE=/data/credentials.bin \
  GHOSTMCP_DB_PATH=/data/ghostmcp.db \
  GHOSTMCP_AUDIT_SINK_PATH=/audit/audit.jsonl \
  GHOSTMCP_ALLOW_RAW_TOOLS=false \
  GHOSTMCP_ALLOW_UNSCOPED_INTRUSIVE=false

VOLUME ["/data", "/audit"]
EXPOSE 8000

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-m", "ghostmcp", "--healthcheck"]

ENTRYPOINT ["python", "-m", "ghostmcp"]
