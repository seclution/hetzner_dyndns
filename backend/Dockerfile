FROM python:3.11.7-alpine

# create non-root user
RUN adduser -D -g '' appuser

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn
COPY app.py ./

# ensure pre-shared-key exists with restricted permissions
RUN touch /pre-shared-key \
    && chown appuser:appuser /pre-shared-key \
    && chmod 600 /pre-shared-key

EXPOSE 80
ENV LISTEN_PORT=80

# drop privileges
USER appuser

CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${LISTEN_PORT:-80} app:app"]
