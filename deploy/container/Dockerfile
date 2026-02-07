FROM python:3.12-slim

RUN useradd -m -u 10001 ghostmcp
WORKDIR /app

COPY pyproject.toml README.md /app/
COPY ghostmcp /app/ghostmcp

RUN pip install --no-cache-dir .

USER 10001
ENV GHOSTMCP_ALLOW_RUN_AS_ROOT=false
ENTRYPOINT ["ghostmcp"]
