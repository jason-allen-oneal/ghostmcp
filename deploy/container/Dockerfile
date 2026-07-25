FROM python:3.12-slim@sha256:f3fa41d74a768c2fce8016b98c191ae8c1bacd8f1152870a3f9f87d350920b7c

# Keep OS packages patched so Trivy does not fail on fixed CVEs baked into the base image.
RUN apt-get update \
  && apt-get upgrade -y \
  && groupadd --system --gid 10001 ghostmcp \
  && useradd --system --uid 10001 --gid ghostmcp --home-dir /app --shell /usr/sbin/nologin ghostmcp \
  && install -d -o ghostmcp -g ghostmcp -m 0750 /var/lib/ghostmcp /var/log/ghostmcp \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=/app \
  GHOSTMCP_DB_PATH=/var/lib/ghostmcp/ghostmcp.db

# Install locked dependencies with hashes.
COPY requirements.lock.txt /app/requirements.lock.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.lock.txt

# Copy app source (run from source, do not pip-install the project).
COPY --chown=ghostmcp:ghostmcp ghostmcp /app/ghostmcp

USER ghostmcp:ghostmcp

# The remote gateway defaults to GHOSTMCP_HTTP_PORT=8000.
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD ["python", "-m", "ghostmcp", "--healthcheck"]

ENTRYPOINT ["python", "-m", "ghostmcp"]
