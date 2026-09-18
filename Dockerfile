# syntax=docker/dockerfile:1

FROM python:3.12-slim

# mariadb-client serve all'avvio per applicare lo schema; curl per il
# controllo di salute del contenitore.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        mariadb-client \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ILO_MONITOR_BASE=/opt/ilo-monitor

WORKDIR /opt/ilo-monitor

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY web/ ./web/
COPY sql/ ./sql/
COPY bin/ ./bin/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh ./bin/* \
    && ln -sf /opt/ilo-monitor/bin/ilo-monitor-user /usr/local/bin/ilo-monitor-user \
    && sed -i '1s|.*|#!/usr/local/bin/python3|' /opt/ilo-monitor/bin/ilo-monitor-user \
    && mkdir -p /opt/ilo-monitor/config /opt/ilo-monitor/logs

# config/ contiene secret.key, la chiave che cifra le password iLO:
# va su un volume, altrimenti a ogni ricreazione del contenitore le
# password salvate diventano illeggibili.
VOLUME ["/opt/ilo-monitor/config"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["api"]
