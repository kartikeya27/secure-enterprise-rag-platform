# Minimal runtime target: no test frameworks or build toolchain in deployable image.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -m -u 10001 appuser
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser scripts ./scripts
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]

FROM base AS runtime

# Compose uses test stage locally; production images should target 'runtime'.
FROM base AS test
USER root
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY --chown=appuser:appuser tests ./tests
COPY --chown=appuser:appuser pyproject.toml ./pyproject.toml
USER appuser
