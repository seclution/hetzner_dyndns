FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
EXPOSE 80
ENV LISTEN_PORT=80
CMD ["python", "app.py"]
