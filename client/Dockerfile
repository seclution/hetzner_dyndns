FROM python:3.11.7-alpine
WORKDIR /client
COPY requirements.txt ./
RUN apk add --no-cache ca-certificates \
 && pip install --no-cache-dir -r requirements.txt
COPY update_dns.py ./
ENTRYPOINT ["python", "update_dns.py"]
