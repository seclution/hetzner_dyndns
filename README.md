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

Separate compose files are provided for the backend and the client. Each
component comes with its own `Dockerfile` inside the respective
`backend` and `client` directories. By default the compose files pull the
public images `nmbit/hetzner-dyndns-backend` and `nmbit/hetzner-dyndns-client`.
Uncomment the `build` sections if you want to build the images locally.

Start the backend service:

```bash
docker compose -f backend/docker-compose.yml up
```
The compose file already includes an `env_file` entry pointing to `.secrets`, so
there is no need to pass it explicitly on the command line.

Run the client (typically on another host) and point it to your backend:

```bash
docker compose -f client/docker-compose.yml up
```

Edit `.secrets.example` and save it as `.secrets` with your credentials before
starting the backend.

## GitHub Actions

A workflow builds the Docker images from the local Dockerfiles and
pushes them to Docker Hub. Provide these repository secrets so the
workflow can publish your images:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
- `IMAGE_NAME_BACKEND`
- `IMAGE_NAME_CLIENT`

The backend image is pushed to `IMAGE_NAME_BACKEND` and the client
image to `IMAGE_NAME_CLIENT`.

