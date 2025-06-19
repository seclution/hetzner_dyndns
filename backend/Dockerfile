FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn
COPY . ./
EXPOSE 80
ENV LISTEN_PORT=80
CMD ["gunicorn", "-b", "0.0.0.0:80", "app:app"]
