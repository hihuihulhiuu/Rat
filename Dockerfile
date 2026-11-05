FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NV_HOST=0.0.0.0 \
    NV_SECURE_COOKIES=1 \
    NV_TRUST_PROXY=1 \
    NV_DB=/data/nordvale.sqlite3

COPY db.py security.py server.py ./
COPY static ./static

RUN mkdir -p /data

EXPOSE 8081

CMD ["python", "server.py"]
