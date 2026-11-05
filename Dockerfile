FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NV_HOST=0.0.0.0 \
    NV_SECURE_COOKIES=1 \
    NV_TRUST_PROXY=1 \
    NV_DB=/data/nordvale.sqlite3

COPY . .

# Print what actually landed in the image, flatten common layouts, then assert.
RUN set -eux; \
    echo "--- repo contents ---"; \
    ls -la; \
    if [ ! -f server.py ]; then \
      for d in */; do \
        if [ -f "${d}server.py" ]; then echo "flattening ${d}"; cp -a "${d}." .; break; fi; \
      done; \
    fi; \
    mkdir -p static; \
    for f in index.html style.css app.js; do \
      if [ ! -f "static/$f" ] && [ -f "$f" ]; then mv "$f" "static/$f"; fi; \
    done; \
    echo "--- normalized ---"; \
    ls -la; ls -la static; \
    test -f server.py; \
    test -f db.py; \
    test -f security.py; \
    test -f static/index.html; \
    test -f static/style.css; \
    test -f static/app.js; \
    mkdir -p /data; \
    python -c "import ast,pathlib; [ast.parse(p.read_text(encoding='utf-8')) for p in pathlib.Path('.').glob('*.py')]"

EXPOSE 8081

CMD ["python", "server.py"]
