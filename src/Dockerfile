FROM python:3.11-slim

WORKDIR /app

RUN useradd -u 10001 -m -s /usr/sbin/nologin appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/cleanup_rancher_nodenotfound.py /app/cleanup_rancher_nodenotfound.py
RUN chmod 0555 /app/cleanup_rancher_nodenotfound.py \
 && chown -R 10001:10001 /app

USER 10001:10001

ENTRYPOINT ["/app/cleanup_rancher_nodenotfound.py"]