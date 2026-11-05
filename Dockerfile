FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NV_HOST=0.0.0.0 \
    NV_SECURE_COOKIES=1 \
    NV_TRUST_PROXY=1 \
    NV_DB=/data/nordvale.sqlite3

# Copy the whole context; .dockerignore keeps the db and caches out.
COPY . .

# Fail the build early and loudly if the app files are not where the CMD expects them.
RUN test -f server.py \
 && test -f db.py \
 && test -f security.py \
 && test -f static/index.html \
 && mkdir -p /data \
 && python -c "import ast, pathlib; [ast.parse(p.read_text(encoding='utf-8')) for p in pathlib.Path('.').glob('*.py')]"

EXPOSE 8081

# server.py reads PORT (provided by the host) and falls back to 8081.
CMD ["python", "server.py"]
