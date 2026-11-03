# CyberSwarm Control — processo único (HTTP + workers em threads).
# Adequado a Render free / contentores sem segundo processo.
# [Docker não executado neste box]
FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e . \
 && useradd -r -u 10001 -d /data cs \
 && mkdir -p /data && chown -R cs:cs /data /app \
 && chmod +x /app/deploy/render/entrypoint.sh
ENV CONTROL_DATA=/data \
    CONTROL_HOST=0.0.0.0 \
    CONTROL_ALLOW_LAN=1 \
    CONTROL_SECURE_COOKIE=1 \
    PORT=8770 \
    PYTHONUNBUFFERED=1
EXPOSE 8770
USER cs
CMD ["/app/deploy/render/entrypoint.sh"]
