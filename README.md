# Hetzner DynDNS

## TL;DR Quickstart

The repository contains two parts:

- **backend** – small Flask service that updates Hetzner DNS records.
- **client** – optional container/script calling the backend from the host whose
  IP should be used.

1. Copy [`backend/.secrets.example`](backend/.secrets.example) to
   `backend/.secrets` and fill in at
   least these variables:
   - `HETZNER_TOKEN` – your Hetzner DNS API token
   - `NTFY_URL` – base URL of your NTFY instance
   - `NTFY_TOPIC` – topic name for notifications
2. Create a writable `backend/pre-shared-key` file for the container:

   ```bash
   touch backend/pre-shared-key
   sudo chown 1000:1000 backend/pre-shared-key
   chmod 600 backend/pre-shared-key
   ```
3. In `client/docker-compose.yml` adjust the environment variables:
   - `BACKEND_URL` – URL of the running backend
   - `FQDN` – fully qualified domain name to update
   - `API_KEY` – value from `backend/pre-shared-key` (created on first backend start)
4. Start the containers:

```bash
docker compose -f backend/docker-compose.yml up  # on server side
docker compose -f client/docker-compose.yml up  # on client side
```

Compose files live in [`backend/docker-compose.yml`](backend/docker-compose.yml)
and [`client/docker-compose.yml`](client/docker-compose.yml).

---

# Readme

This project provides a lightweight REST API for updating Hetzner DNS A/AAAA records.
It consists of a backend service that communicates with the Hetzner DNS API and
an optional client that can be run on remote systems to trigger updates.

## Backend

The backend is a small Flask application with a single `/update` endpoint.  The
endpoint accepts JSON payloads of the form:

```json
{ "fqdn": "host.example.com", "ip": "1.2.3.4" }
```

`ip` is optional. If omitted, the backend uses the `X-Real-Ip` header if
present, then `X-Forwarded-For`, and finally the source IP of the HTTP request.
An optional `type` field may be provided with `A` or `AAAA` to explicitly select
the record type. Without it the backend defaults to an IPv4 `A` record.
Both IPv4 and IPv6 addresses are validated using Python's `ipaddress`
module before being accepted. The service notifies a configured NTFY topic
about success or failure.
Install the requirements with `pip install -r backend/requirements.txt` before running the service directly.

The backend authenticates requests using a pre-shared key stored in
`./pre-shared-key` on the host and mounted into the container at
`/pre-shared-key` (see `backend/docker-compose.yml`). If the file does
not exist on the first start, the service creates it and writes a random
token. Use this value for the client's `API_KEY` setting.

When using Docker Compose, make sure the file exists and is writable by the
container user. Otherwise Docker may create a directory instead of a file and
the service fails with a permission error. Create the file and set the
permissions like so:

```bash
touch backend/pre-shared-key
sudo chown 1000:1000 backend/pre-shared-key
chmod 600 backend/pre-shared-key
```

### Environment variables

The container reads the following variables which should be provided via a
`backend/.secrets` file or other means:

- `HETZNER_TOKEN` – API token for the Hetzner DNS API
- `NTFY_URL` – Base URL of your NTFY instance
- `NTFY_TOPIC` – Topic name used for notifications
- `NTFY_USERNAME` / `NTFY_PASSWORD` – credentials for basic auth with NTFY (optional)
- `DEBUG_LOGGING` – set to `1` to enable verbose debug logs and Flask debug mode (default `0`)
- `LOG_FILE` – path to the rotating log file. Leave empty to disable file
  logging and use stdout only
- `LOG_MAX_BYTES` – maximum size of the log file before rotation (default 1048576)
- `LOG_BACKUP_COUNT` – number of rotated log files to keep (default 3)
- `LISTEN_PORT` – port the application listens on (default `80`)
- `ALLOWED_ZONES` – comma-separated list of domain zones allowed for updates
  (empty means all zones are allowed)
- `RECORD_TTL` – TTL for DNS records in seconds (default `86400`)
- `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD` – enable HTTP basic auth for the update endpoints

## Client

A small Python script is provided in `client/update_dns.py`.  It sends a request
to the backend REST API and can be used directly or inside the included client
container.  Usage:
Install the requirements with `pip install -r client/requirements.txt` before running the script directly.

```bash
python update_dns.py <backend_url> <fqdn> [ip]
```

### Environment variables

The client can be configured via environment variables instead of command-line
arguments:

- `BACKEND_URL` – URL of the backend service
- `FQDN` – fully qualified domain name to update
- `API_KEY` – token from `backend/pre-shared-key`
- `IP` – explicit IP address to set (optional)
- `INTERVAL` – run repeatedly every given seconds (e.g. `3600` for hourly)
- `CA_BUNDLE` – override certificate bundle path (optional)
- `VERIFY_SSL` – set to `0` to disable certificate verification

Use the same variables in `client/docker-compose.yml` when running the container.

The client uses the [`certifi`](https://pypi.org/project/certifi/) package for
certificate verification.  Set `CA_BUNDLE` to override the bundle path or set
`VERIFY_SSL=0` to disable verification entirely.

### Cron-based setup

If you don't want to run the Docker client or the Python script continuously,
you can trigger DNS updates from a cron job. The idea is to periodically call
the backend's `/update` endpoint from your host.

Example cron entry using `curl`:

```cron
*/5 * * * * curl -sf -X POST -H 'Content-Type: application/json' \
  -H 'X-API-Key: <token>' \
  -d '{"fqdn":"host.example.com"}' https://backend.example.com/update
```

Replace the URL and `fqdn` with your values. The backend will use the IP address
of the HTTP request if no `ip` field is supplied. This method is lightweight but
lacks the built-in logging and isolated environment that the Docker client
provides.

### Router setup

Many consumer routers support custom DynDNS services using the dyndns2 protocol.
Point them to your backend's `/nic/update` endpoint. Example URLs:

- **Fritz!Box** – `https://user:pass@your-backend.example.com/nic/update?hostname=host.example.com`
- **Speedport** – `https://your-backend.example.com/nic/update?hostname=host.example.com&user=user&pass=pass`
- **Vodafone Station** – `https://user:pass@your-backend.example.com/nic/update?hostname=host.example.com&myip=%IP%`

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
The compose file already includes an `env_file` entry pointing to
`backend/.secrets`, so there is no need to pass it explicitly on the
command line.

Run the client (typically on another host) and point it to your backend:

```bash
docker compose -f client/docker-compose.yml up
```

Edit `backend/.secrets.example` and save it as `backend/.secrets` with your credentials before
starting the backend.

## GitHub Actions

A workflow builds the Docker images from the local Dockerfiles when a
GitHub release is published. The images are tagged with the release
version as well as `latest` and then pushed to Docker Hub. Provide these
repository secrets so the workflow can publish your images:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
- `IMAGE_NAME_BACKEND`
- `IMAGE_NAME_CLIENT`

The backend image is pushed to `IMAGE_NAME_BACKEND` and the client
image to `IMAGE_NAME_CLIENT`.

## Development

Install the development requirements and set up the pre-commit hook:

```bash
pip install -r requirements-dev.txt
pre-commit install
```

Run the test suite with `pytest` or invoke all hooks using:

```bash
pre-commit run --all-files
```

