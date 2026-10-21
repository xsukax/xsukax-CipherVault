FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 VAULT_DATA_DIR=/data
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && groupadd -g 10001 vault && useradd --no-log-init -u 10001 -g 10001 -M -s /usr/sbin/nologin vault
COPY --chown=10001:10001 app ./app
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
