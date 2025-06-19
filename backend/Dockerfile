FROM python:3.11-slim

# create non-root user
RUN adduser --disabled-password --gecos '' appuser

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn
COPY . ./

# ensure pre-shared-key exists with restricted permissions
RUN touch /pre-shared-key \
    && chown appuser:appuser /pre-shared-key \
    && chmod 600 /pre-shared-key

EXPOSE 80
ENV LISTEN_PORT=80

# drop privileges
USER appuser

CMD ["gunicorn", "-b", "0.0.0.0:80", "app:app"]
