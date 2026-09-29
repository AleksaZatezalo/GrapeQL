# syntax=docker/dockerfile:1

# --------------------------------------------------------------------------- #
#  Stage 1: build the React frontend
# --------------------------------------------------------------------------- #
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build
# -> /build/dist

# --------------------------------------------------------------------------- #
#  Stage 2: python runtime serving the API + built frontend
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PYTHONIOENCODING=UTF-8 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    GRAPEQL_TESTCASES_DIR=/data/test_cases \
    GRAPEQL_STATIC_DIR=/app/frontend/dist \
    QWEN_BASE_URL=http://localhost:11434/v1 \
    QWEN_MODEL=qwen2.5-coder:7b

# Install the grapeql package and web API dependencies
COPY pyproject.toml setup.py README.md MANIFEST.in ./
COPY grapeql/ ./grapeql/
COPY webapi/ ./webapi/
RUN pip install --no-cache-dir . \
    && pip install --no-cache-dir -r webapi/requirements.txt

# Bring in the built frontend
COPY --from=frontend /build/dist ./frontend/dist

# Writable directory for editable/uploaded test cases (seeded on first run)
RUN mkdir -p /data/test_cases

EXPOSE 8000
CMD ["uvicorn", "webapi.server:app", "--host", "0.0.0.0", "--port", "8000"]
