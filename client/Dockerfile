FROM python:3.11-slim
WORKDIR /client
COPY requirements.txt ./
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir -r requirements.txt
COPY update_dns.py ./
ENTRYPOINT ["python", "update_dns.py"]
