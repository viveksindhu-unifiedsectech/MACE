FROM python:3.11-slim

# Build args for multi-region (set at build time)
ARG DEPLOYMENT_REGION=us-east-1
ARG DATA_RESIDENCY_JURISDICTION=US

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY mace_platform/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MACE v2 algorithm (patent-protected core)
# Build context is the repo root (UnifiedSec_MACE_Complete) so the relative
# path picks up the algorithm package alongside the backend tree.
COPY UnifiedSec_MACE_v2/core /app/core

# Copy application
COPY mace_platform/backend/app/ ./app/
COPY mace_platform/backend/alembic/ ./alembic/
COPY mace_platform/backend/alembic.ini .
COPY mace_platform/backend/scripts/ ./scripts/
RUN touch ./scripts/__init__.py

# Non-root user
RUN adduser --disabled-password --gecos "" maceuser
RUN chown -R maceuser:maceuser /app
USER maceuser

ENV PYTHONPATH=/app
ENV MACE_CORE_PATH=/app
ENV DEPLOYMENT_REGION=${DEPLOYMENT_REGION}
ENV DATA_RESIDENCY_JURISDICTION=${DATA_RESIDENCY_JURISDICTION}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "4", "--loop", "uvloop", "--log-level", "info"]
