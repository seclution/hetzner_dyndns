import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, abort
import requests
import secrets
import ipaddress
import time
import threading

app = Flask(__name__)


def _get_int_env(name: str, default: int) -> int:
    value = os.environ.get(name, str(default))
    try:
        return int(value)
    except ValueError:
        logging.getLogger(__name__).warning(
            "Invalid %s=%r, using default %s", name, value, default
        )
        return default

HETZNER_TOKEN = os.environ.get("HETZNER_TOKEN")
NTFY_URL = os.environ.get("NTFY_URL")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
NTFY_USERNAME = os.environ.get("NTFY_USERNAME")
NTFY_PASSWORD = os.environ.get("NTFY_PASSWORD")
BASIC_AUTH_USERNAME = os.environ.get("BASIC_AUTH_USERNAME")
BASIC_AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD")

# Cache for zone information to reduce API calls
ZONE_CACHE = {"zones": None, "expires": 0}
# Default TTL for the zone list; zone IDs rarely change so cache for a day
ZONE_CACHE_TTL = _get_int_env("ZONE_CACHE_TTL", 86400)  # seconds

# Cache last seen IP for FQDN/type combinations to avoid redundant updates
# Mapping of (fqdn.lower(), record_type) -> {"ip": str, "expires": timestamp}
REQUEST_CACHE = {}
REQUEST_CACHE_TTL = _get_int_env("REQUEST_CACHE_TTL", 300)  # seconds

# Default TTL for created or updated DNS records
RECORD_TTL = _get_int_env("RECORD_TTL", 21600)

# Pre-shared key configuration
PRE_SHARED_KEY_FILE = "/pre-shared-key"
REGISTERED_FQDNS = [
    h.strip().lower()
    for h in os.environ.get("REGISTERED_FQDNS", "").split(",")
    if h.strip()
]

# Connection monitoring configuration
LOST_CONNECTION_TIMEOUT = _get_int_env("LOST_CONNECTION_TIMEOUT", 3 * 3600)
CONNECTION_CHECK_INTERVAL = _get_int_env("CONNECTION_CHECK_INTERVAL", 60)

# Mapping of url -> last update timestamp
ESTABLISHED_CONNECTIONS = {}
_CONNECTION_LOCK = threading.Lock()
_MONITOR_THREAD = None


def _load_pre_shared_keys(urls: list[str]) -> dict[str, str]:
    keys: dict[str, str] = {}
    try:
        if os.path.exists(PRE_SHARED_KEY_FILE):
            with open(PRE_SHARED_KEY_FILE, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) == 2:
                        keys[parts[0].lower()] = parts[1]
    except Exception:  # pragma: no cover - shouldn't happen
        app.logger.exception("Failed to read API key file")
    changed = False
    for url in urls:
        url = url.lower()
        if url not in keys:
            keys[url] = secrets.token_urlsafe(32)
            changed = True
    if changed:
        try:
            with open(PRE_SHARED_KEY_FILE, "w") as f:
                for host, key in keys.items():
                    f.write(f"{host} {key}\n")
            os.chmod(PRE_SHARED_KEY_FILE, 0o600)
        except Exception:  # pragma: no cover - shouldn't happen
            app.logger.exception("Failed to write API key file")
    return keys


# Logging configuration
DEBUG_LOGGING = os.environ.get("DEBUG_LOGGING", "0").lower() in (
    "1",
    "true",
    "yes",
)
LOG_FILE = os.environ.get("LOG_FILE")
LOG_MAX_BYTES = _get_int_env("LOG_MAX_BYTES", 1 * 1024 * 1024)
LOG_BACKUP_COUNT = _get_int_env("LOG_BACKUP_COUNT", 3)

log_level = logging.DEBUG if DEBUG_LOGGING else logging.INFO
_log_handlers = [logging.StreamHandler()]
_file_handler_error = None
if LOG_FILE:
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        _log_handlers.append(
            RotatingFileHandler(
                LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
            )
        )
    except Exception as exc:  # pragma: no cover - shouldn't happen
        _file_handler_error = exc

logging.basicConfig(
    level=log_level,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=_log_handlers,
    force=True,
)
if _file_handler_error:
    logging.getLogger(__name__).error(
        "Failed to set up file logging: %s", _file_handler_error
    )

app.logger.setLevel(log_level)

if DEBUG_LOGGING:
    app.logger.debug("REGISTERED_FQDNS: %s", REGISTERED_FQDNS)

PRE_SHARED_KEYS = _load_pre_shared_keys(REGISTERED_FQDNS)


def get_zones(force_refresh: bool = False):
    """Return list of zones using a simple in-memory cache."""
    now = time.time()
    if (
        not force_refresh
        and ZONE_CACHE["zones"] is not None
        and now < ZONE_CACHE["expires"]
    ):
        return ZONE_CACHE["zones"]

    try:
        resp = requests.get(
            "https://dns.hetzner.com/api/v1/zones",
            headers={"Auth-API-Token": HETZNER_TOKEN},
            timeout=10,
        )
    except requests.RequestException as exc:
        app.logger.exception("Zone fetch exception")
        send_ntfy("Zone Fetch Error", str(exc), is_error=True)
        # If we have cached zones, return them even on failure
        if ZONE_CACHE["zones"] is not None:
            return ZONE_CACHE["zones"]
        return None

    if resp.status_code != 200:
        app.logger.error("Zone fetch failed: %s", resp.text)
        send_ntfy("Zone Fetch Failed", resp.text, is_error=True)
        if ZONE_CACHE["zones"] is not None:
            return ZONE_CACHE["zones"]
        return None

    zones = resp.json().get("zones", [])
    ZONE_CACHE.update({"zones": zones, "expires": now + ZONE_CACHE_TTL})
    return zones


def find_zone(fqdn: str, zones):
    """Return zone id, zone name and subdomain for *fqdn*.

    Instead of iterating linearly over ``zones`` for every lookup, build a
    mapping of zone names to their objects and check suffixes of ``fqdn`` from
    longest to shortest.  This reduces the amount of work when the list of
    zones becomes large.
    """

    zone_map = {z.get("name", "").lower(): z for z in zones}
    parts = fqdn.split(".")
    for i in range(len(parts)):
        suffix = ".".join(parts[i:]).lower()
        if suffix in zone_map:
            zone = zone_map[suffix]
            zone_id = zone.get("id")
            zone_name = zone.get("name")
            subdomain = ".".join(parts[:i]) if i > 0 else ""
            return zone_id, zone_name, subdomain

    return None, None, None


def send_ntfy(
    title: str,
    message: str,
    *,
    is_error: bool = False,
    priority: int | None = None,
) -> None:
    """Send a notification via ntfy.

    Success messages are only emitted when ``DEBUG_LOGGING`` is enabled. Error
    notifications are always sent.
    """

    if not DEBUG_LOGGING and not is_error:
        return
    if not NTFY_URL:
        return
    headers = {"Title": title} if title else {}
    if priority is not None:
        headers["Priority"] = str(priority)
    auth = None
    if NTFY_USERNAME and NTFY_PASSWORD:
        auth = (NTFY_USERNAME, NTFY_PASSWORD)
    try:
        resp = requests.post(
            f"{NTFY_URL}/{NTFY_TOPIC}" if NTFY_TOPIC else NTFY_URL,
            headers=headers,
            data=message,
            auth=auth,
            timeout=10,
        )
        if not resp.ok:
            log = app.logger.error if is_error else app.logger.warning
            log("ntfy returned %s: %s", resp.status_code, resp.text)
    except requests.RequestException:
        app.logger.exception("Failed to send ntfy message")


def update_connection(url: str, *, now: float | None = None) -> None:
    """Update or create the timestamp entry for *url*."""
    if now is None:
        now = time.time()
    url = url.lower()
    start_thread = False
    with _CONNECTION_LOCK:
        if url not in ESTABLISHED_CONNECTIONS:
            app.logger.info("dyndns connection established with %s", url)
            start_thread = True
        ESTABLISHED_CONNECTIONS[url] = now
    if start_thread:
        _ensure_monitor_thread()


def check_connections(*, now: float | None = None) -> None:
    """Check for lost connections and emit notifications."""
    if now is None:
        now = time.time()
    expired = []
    with _CONNECTION_LOCK:
        for url, ts in list(ESTABLISHED_CONNECTIONS.items()):
            if now - ts > LOST_CONNECTION_TIMEOUT:
                expired.append(url)
    for url in expired:
        app.logger.error("lost dyndns connection to %s", url)
        send_ntfy(
            "DynDNS Lost Connection",
            f"Lost dyndns connection to {url}",
            is_error=True,
            priority=4,
        )
        with _CONNECTION_LOCK:
            ESTABLISHED_CONNECTIONS.pop(url, None)


def _monitor_loop() -> None:
    while True:
        time.sleep(CONNECTION_CHECK_INTERVAL)
        check_connections()


def _ensure_monitor_thread() -> None:
    global _MONITOR_THREAD
    if _MONITOR_THREAD is None and CONNECTION_CHECK_INTERVAL > 0:
        _MONITOR_THREAD = threading.Thread(target=_monitor_loop, daemon=True)
        _MONITOR_THREAD.start()


def purge_request_cache(*, now: float | None = None) -> None:
    """Remove expired entries from :data:`REQUEST_CACHE`."""
    if now is None:
        now = time.time()
    for key, value in list(REQUEST_CACHE.items()):
        if value.get("expires", 0) < now:
            REQUEST_CACHE.pop(key, None)


def perform_update(
    fqdn: str, ip: str, record_type: str = "A", *, skip_no_change: bool = False
):
    """Create or update a DNS record and return the action performed."""

    purge_request_cache()

    domain_parts = fqdn.split(".")
    if len(domain_parts) < 2:
        app.logger.error(
            "Request from %s invalid fqdn: %s", request.remote_addr, fqdn
        )
        send_ntfy("Param Error", "Invalid FQDN", is_error=True)
        return {"error": "Invalid FQDN"}, 400

    if not REGISTERED_FQDNS:
        app.logger.error(
            "Request from %s attempted update but backend not configured for updates",
            request.remote_addr,
        )
        send_ntfy("Backend Not Configured", fqdn, is_error=True)
        return {"error": "backend not configured for updates"}, 500
    if fqdn.lower() not in REGISTERED_FQDNS:
        app.logger.error(
            "Request from %s disallowed fqdn: %s",
            request.remote_addr,
            fqdn,
        )
        send_ntfy("FQDN Not Allowed", fqdn, is_error=True)
        return {"error": "FQDN not allowed"}, 403

    zones = get_zones()
    if zones is None:
        return {"error": "Failed to fetch zones"}, 500

    zone_id, zone_name, subdomain = find_zone(fqdn, zones)

    if not zone_id:
        zones = get_zones(force_refresh=True)
        if zones is None:
            return {"error": "Failed to fetch zones"}, 500
        zone_id, zone_name, subdomain = find_zone(fqdn, zones)

    if not zone_id:
        app.logger.error(
            "Zone not found for %s from %s", fqdn, request.remote_addr
        )
        send_ntfy("Zone Not Found", f"No matching zone for {fqdn}", is_error=True)
        return {"error": "Zone not found"}, 404



    if subdomain == "":
        app.logger.error(
            "Request from %s missing subdomain for %s",
            request.remote_addr,
            fqdn,
        )
        send_ntfy("Param Error", "Missing subdomain", is_error=True)
        return {"error": "Missing subdomain"}, 400

    # Check request cache before hitting the Hetzner API
    cache_key = (fqdn.lower(), record_type)
    now = time.time()
    cached = REQUEST_CACHE.get(cache_key)
    if cached and now < cached.get("expires", 0) and cached.get("ip") == ip:
        if DEBUG_LOGGING:
            app.logger.info(
                "No change for %s from %s (cache)", fqdn, request.remote_addr
            )
        send_ntfy("DynDNS Success", f"No change for {fqdn} -> {ip}")
        return {"status": "unchanged", "ip": ip}, 200

    try:
        records_resp = requests.get(
            f"https://dns.hetzner.com/api/v1/records?zone_id={zone_id}",
            headers={"Auth-API-Token": HETZNER_TOKEN},
            timeout=10,
        )
    except requests.RequestException as exc:
        app.logger.exception(
            "Records fetch exception for %s from %s", fqdn, request.remote_addr
        )
        send_ntfy("Records Fetch Error", str(exc), is_error=True)
        return {"error": "Failed to fetch records", "detail": str(exc)}, 500
    if records_resp.status_code != 200:
        app.logger.error(
            "Records fetch failed for %s from %s: %s",
            fqdn,
            request.remote_addr,
            records_resp.text,
        )
        send_ntfy("Records Fetch Failed", records_resp.text, is_error=True)
        return {"error": "Failed to fetch records"}, 500

    record_id = None
    current_value = None
    for record in records_resp.json().get("records", []):
        if (
            record.get("name") == subdomain
            and record.get("type") == record_type
        ):
            record_id = record.get("id")
            current_value = record.get("value")
            break

    if record_id and skip_no_change and current_value == ip:
        app.logger.info("No change for %s from %s", fqdn, request.remote_addr)
        send_ntfy("DynDNS Success", f"No change for {fqdn} -> {ip}")
        REQUEST_CACHE[cache_key] = {"ip": ip, "expires": now + REQUEST_CACHE_TTL}
        return {"status": "unchanged", "ip": ip}, 200

    payload = {
        "value": ip,
        "ttl": RECORD_TTL,
        "type": record_type,
        "name": subdomain,
        "zone_id": zone_id,
    }

    if record_id:
        try:
            resp = requests.put(
                f"https://dns.hetzner.com/api/v1/records/{record_id}",
                headers={
                    "Auth-API-Token": HETZNER_TOKEN,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=10,
            )
        except requests.RequestException as exc:
            app.logger.exception(
                "Update record exception for %s from %s",
                fqdn,
                request.remote_addr,
            )
            send_ntfy("Update Record Error", str(exc), is_error=True)
            return {
                "error": "Failed to update record",
                "detail": str(exc),
            }, 500
        action = "Updated"
    else:
        try:
            resp = requests.post(
                "https://dns.hetzner.com/api/v1/records",
                headers={
                    "Auth-API-Token": HETZNER_TOKEN,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=10,
            )
        except requests.RequestException as exc:
            app.logger.exception(
                "Create record exception for %s from %s",
                fqdn,
                request.remote_addr,
            )
            send_ntfy("Create Record Error", str(exc), is_error=True)
            return {
                "error": "Failed to create record",
                "detail": str(exc),
            }, 500
        action = "Created"

    if resp.ok:
        app.logger.info(
            "%s request from %s for %s -> %s",
            action.lower(),
            request.remote_addr,
            fqdn,
            ip,
        )
        send_ntfy(
            "DynDNS Success",
            f"{action} {record_type} record for {fqdn} -> {ip}",
        )
        REQUEST_CACHE[cache_key] = {"ip": ip, "expires": now + REQUEST_CACHE_TTL}
        return {"status": action.lower(), "ip": ip}, 200
    else:
        app.logger.error(
            "Failed to %s record for %s from %s: %s",
            action.lower(),
            fqdn,
            request.remote_addr,
            resp.text,
        )
        send_ntfy(f"{action} Failed", resp.text, is_error=True)
        return {"error": "API failure", "detail": resp.text}, 500


@app.route("/update", methods=["POST"])
def update():
    if not HETZNER_TOKEN:
        abort(500, "Backend not configured")

    data = request.get_json(silent=True) or {}
    if DEBUG_LOGGING:
        app.logger.debug("Request JSON: %s", data)
        headers = dict(request.headers)
        if "X-Pre-Shared-Key" in headers:
            headers["X-Pre-Shared-Key"] = "[REDACTED]"
        app.logger.debug("Request headers: %s", headers)
        app.logger.debug("Remote address: %s", request.remote_addr)
        if "X-Real-Ip" in request.headers:
            app.logger.debug("X-Real-Ip: %s", request.headers.get("X-Real-Ip"))
        if "X-Forwarded-For" in request.headers:
            app.logger.debug(
                "X-Forwarded-For: %s", request.headers.get("X-Forwarded-For")
            )
    url = data.get("fqdn") or data.get("url")
    if not url:
        app.logger.error("Request from %s missing fqdn", request.remote_addr)
        send_ntfy("Param Error", "Missing FQDN", is_error=True)
        return {"error": "Missing FQDN"}, 400

    auth_ok = False
    expected_key = PRE_SHARED_KEYS.get(url.lower())
    if expected_key and request.headers.get("X-Pre-Shared-Key") == expected_key:
        auth_ok = True
    if not auth_ok and BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD:
        auth = request.authorization
        if (
            auth
            and auth.username == BASIC_AUTH_USERNAME
            and auth.password == BASIC_AUTH_PASSWORD
        ):
            auth_ok = True
    if not auth_ok:
        return {"error": "Unauthorized"}, 401

    record_type = data.get("type", "A").upper()
    if record_type not in ("A", "AAAA"):
        app.logger.error(
            "Request from %s invalid type: %s",
            request.remote_addr,
            record_type,
        )
        send_ntfy("Param Error", "Invalid type", is_error=True)
        return {"error": "Invalid type"}, 400

    ip = data.get("ip")
    if not ip:
        ip = request.headers.get("X-Real-Ip")
    if not ip and "X-Forwarded-For" in request.headers:
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    if not ip:
        ip = request.remote_addr

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        app.logger.error(
            "Request from %s invalid ip: %s", request.remote_addr, ip
        )
        send_ntfy("Param Error", "Invalid IP", is_error=True)
        return {"error": "Invalid IP"}, 400

    if record_type == "A" and ip_obj.version != 4:
        app.logger.error(
            "Request from %s ip version mismatch: %s", request.remote_addr, ip
        )
        send_ntfy("Param Error", "IP version mismatch", is_error=True)
        return {"error": "IP version mismatch"}, 400
    if record_type == "AAAA" and ip_obj.version != 6:
        app.logger.error(
            "Request from %s ip version mismatch: %s", request.remote_addr, ip
        )
        send_ntfy("Param Error", "IP version mismatch", is_error=True)
        return {"error": "IP version mismatch"}, 400

    result, status = perform_update(url, ip, record_type)
    if status == 200:
        update_connection(url)
    return jsonify(result), status


@app.route("/nic/update", methods=["GET", "POST"])
def nic_update():
    if not HETZNER_TOKEN:
        abort(500, "Backend not configured")

    user = None
    pw = None
    if request.authorization:
        user = request.authorization.username
        pw = request.authorization.password
    if not user:
        user = request.args.get("user")
        pw = request.args.get("pass")

    hostname = request.args.get("hostname") or request.form.get("hostname")
    if not hostname:
        return "nohost", 400

    expected_user = hostname.split(".")[0]
    expected_pw = PRE_SHARED_KEYS.get(hostname.lower())
    auth_ok = False
    if user == expected_user and pw == expected_pw:
        auth_ok = True
    elif BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD:
        if user == BASIC_AUTH_USERNAME and pw == BASIC_AUTH_PASSWORD:
            auth_ok = True
    if not auth_ok:
        return "badauth", 401

    ip = request.args.get("myip") or request.form.get("myip")
    if not ip:
        ip = request.remote_addr

    record_type = "AAAA" if ":" in ip else "A"

    result, status = perform_update(
        hostname, ip, record_type, skip_no_change=True
    )
    if status == 200:
        update_connection(hostname)
        if result["status"] == "unchanged":
            return f"nochg {result['ip']}", 200
        return f"good {result['ip']}", 200
    return jsonify(result), status


if __name__ == "__main__":
    port = _get_int_env("LISTEN_PORT", 80)
    app.run(host="0.0.0.0", port=port, debug=DEBUG_LOGGING)
