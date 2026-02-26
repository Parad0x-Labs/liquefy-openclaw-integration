FROM python:3.12-slim AS base

LABEL maintainer="Parad0x Labs"
LABEL description="Liquefy OpenClaw — compression, auditing, and observability for AI agent runs"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    make \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt api/requirements.txt api/
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x tools/*.py 2>/dev/null || true

ENV PYTHONPATH=/app/api:/app/tools
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import liquefy_audit_chain; print('ok')" || exit 1

ENTRYPOINT ["python"]
CMD ["--help"]
