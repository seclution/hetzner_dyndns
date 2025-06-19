FROM python:3.11-slim
WORKDIR /client
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY update_dns.py ./
ENTRYPOINT ["python", "update_dns.py"]
