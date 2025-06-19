# Hetzner DynDNS

This project provides a lightweight REST API for updating Hetzner DNS A records.
It consists of a backend service that communicates with the Hetzner DNS API and
an optional client that can be run on remote systems to trigger updates.

## Backend

The backend is a small Flask application with a single `/update` endpoint.  The
endpoint accepts JSON payloads of the form:

```json
{ "fqdn": "host.example.com", "ip": "1.2.3.4" }
```

`ip` is optional. If omitted, the source IP of the HTTP request is used. The
service notifies a configured NTFY topic about success or failure.

### Environment variables

The container reads the following variables which should be provided via a
`.secrets` file or other means:

- `HETZNER_TOKEN` – API token for the Hetzner DNS API
- `NTFY_URL` – Base URL of your NTFY instance
- `NTFY_TOPIC` – Topic name used for notifications

## Client

A small Python script is provided in `client/update_dns.py`.  It sends a request
to the backend REST API and can be used directly or inside the included client
container.  Usage:

```bash
python update_dns.py <backend_url> <fqdn> [ip]
```

Environment variables `BACKEND_URL`, `FQDN` and `IP` can also be used instead of
command‑line arguments.

## Docker Compose

An example `docker-compose.yml` is included.  It starts the backend and a sample
client container:

```bash
docker compose --env-file .secrets up
```

Edit `.secrets.example` and save it as `.secrets` with your credentials before
starting the stack.

## GitHub Actions

The repository contains a workflow that builds the backend Docker image and
pushes it to Docker Hub.  Provide `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` as
repository secrets for automated builds.

