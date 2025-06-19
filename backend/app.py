import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, abort
import requests
import secrets
import ipaddress
import time

app = Flask(__name__)

HETZNER_TOKEN = os.environ.get("HETZNER_TOKEN")
NTFY_URL = os.environ.get("NTFY_URL")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
NTFY_USERNAME = os.environ.get("NTFY_USERNAME")
NTFY_PASSWORD = os.environ.get("NTFY_PASSWORD")
ALLOWED_ZONES = [z.strip().lower() for z in os.environ.get("ALLOWED_ZONES", "").split(',') if z.strip()]
BASIC_AUTH_USERNAME = os.environ.get("BASIC_AUTH_USERNAME")
BASIC_AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD")

# Cache for zone information to reduce API calls
ZONE_CACHE = {"zones": None, "expires": 0}
ZONE_CACHE_TTL = int(os.environ.get("ZONE_CACHE_TTL", "300"))  # seconds
# TTL for created/updated DNS records
RECORD_TTL = int(os.environ.get("RECORD_TTL", "86400"))  # seconds

# Pre-shared API key configuration
API_KEY_FILE = "/pre-shared-key"


def _load_api_key() -> str:
    key = ""
    try:
        if os.path.exists(API_KEY_FILE):
            with open(API_KEY_FILE, "r") as f:
                key = f.read().strip()
    except Exception:  # pragma: no cover - shouldn't happen
        app.logger.exception("Failed to read API key")
    if not key:
        key = secrets.token_urlsafe(32)
        try:
            with open(API_KEY_FILE, "w") as f:
                f.write(key)
            os.chmod(API_KEY_FILE, 0o600)
        except Exception:  # pragma: no cover - shouldn't happen
            app.logger.exception("Failed to write API key")
    return key


# Logging configuration
DEBUG_LOGGING = os.environ.get("DEBUG_LOGGING", "0").lower() in ("1", "true", "yes")
LOG_FILE = os.environ.get("LOG_FILE", "app.log")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(1 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "3"))

log_level = logging.DEBUG if DEBUG_LOGGING else logging.INFO
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES,
                              backupCount=LOG_BACKUP_COUNT)
logging.basicConfig(level=log_level,
                    format="%(asctime)s %(levelname)s %(message)s",
                    handlers=[handler, logging.StreamHandler()],
                    force=True)

app.logger.setLevel(log_level)

API_KEY = _load_api_key()


def get_zones(force_refresh: bool = False):
    """Return list of zones using a simple in-memory cache."""
    now = time.time()
    if not force_refresh and ZONE_CACHE["zones"] is not None and now < ZONE_CACHE["expires"]:
        return ZONE_CACHE["zones"]

    try:
        resp = requests.get(
            'https://dns.hetzner.com/api/v1/zones',
            headers={'Auth-API-Token': HETZNER_TOKEN},
            timeout=10,
        )
    except requests.RequestException as exc:
        app.logger.exception("Zone fetch exception")
        send_ntfy('Zone Fetch Error', str(exc))
        # If we have cached zones, return them even on failure
        if ZONE_CACHE["zones"] is not None:
            return ZONE_CACHE["zones"]
        return None

    if resp.status_code != 200:
        app.logger.error("Zone fetch failed: %s", resp.text)
        send_ntfy('Zone Fetch Failed', resp.text)
        if ZONE_CACHE["zones"] is not None:
            return ZONE_CACHE["zones"]
        return None

    zones = resp.json().get('zones', [])
    ZONE_CACHE.update({'zones': zones, 'expires': now + ZONE_CACHE_TTL})
    return zones


def find_zone(fqdn: str, zones):
    zone_id = None
    zone_name = None
    subdomain = None
    longest = 0
    fqdn_lower = fqdn.lower()
    for zone in zones:
        name = zone.get('name', '')
        lower_name = name.lower()
        if fqdn_lower == lower_name:
            if len(name) > longest:
                zone_id = zone.get('id')
                zone_name = name
                subdomain = ''
                longest = len(name)
        elif fqdn_lower.endswith('.' + lower_name):
            if len(name) > longest:
                zone_id = zone.get('id')
                zone_name = name
                subdomain = fqdn[:-len(name) - 1]
                longest = len(name)
    return zone_id, zone_name, subdomain


def send_ntfy(title: str, message: str) -> None:
    if not NTFY_URL:
        return
    headers = {"Title": title} if title else {}
    auth = None
    if NTFY_USERNAME and NTFY_PASSWORD:
        auth = (NTFY_USERNAME, NTFY_PASSWORD)
    try:
        requests.post(
            f"{NTFY_URL}/{NTFY_TOPIC}" if NTFY_TOPIC else NTFY_URL,
            headers=headers,
            data=message,
            auth=auth,
            timeout=10,
        )
    except requests.RequestException:
        app.logger.exception("Failed to send ntfy message")


def perform_update(fqdn: str, ip: str, record_type: str = 'A', *, skip_no_change: bool = False):
    """Create or update a DNS record and return the action performed."""

    domain_parts = fqdn.split('.')
    if len(domain_parts) < 2:
        app.logger.error("Request from %s invalid fqdn: %s", request.remote_addr, fqdn)
        send_ntfy('Param Error', 'Invalid FQDN')
        return {'error': 'Invalid FQDN'}, 400

    if ALLOWED_ZONES:
        allowed = False
        fqdn_lower = fqdn.lower()
        for zone in ALLOWED_ZONES:
            zone_lower = zone.lower()
            if fqdn_lower == zone_lower or fqdn_lower.endswith('.' + zone_lower):
                allowed = True
                break
        if not allowed:
            app.logger.error("Request from %s disallowed domain: %s", request.remote_addr, fqdn)
            send_ntfy('Domain Not Allowed', fqdn)
            return {'error': 'Domain not allowed'}, 403

    zones = get_zones()
    if zones is None:
        return {'error': 'Failed to fetch zones'}, 500

    zone_id, zone_name, subdomain = find_zone(fqdn, zones)

    if not zone_id:
        zones = get_zones(force_refresh=True)
        if zones is None:
            return {'error': 'Failed to fetch zones'}, 500
        zone_id, zone_name, subdomain = find_zone(fqdn, zones)

    if not zone_id:
        app.logger.error("Zone not found for %s from %s", fqdn, request.remote_addr)
        send_ntfy('Zone Not Found', f'No matching zone for {fqdn}')
        return {'error': 'Zone not found'}, 404

    if ALLOWED_ZONES and zone_name.lower() not in ALLOWED_ZONES:
        app.logger.error("Request from %s disallowed domain: %s", request.remote_addr, zone_name)
        send_ntfy('Domain Not Allowed', zone_name)
        return {'error': 'Domain not allowed'}, 403

    if subdomain == '':
        app.logger.error("Request from %s missing subdomain for %s", request.remote_addr, fqdn)
        send_ntfy('Param Error', 'Missing subdomain')
        return {'error': 'Missing subdomain'}, 400

    try:
        records_resp = requests.get(
            f'https://dns.hetzner.com/api/v1/records?zone_id={zone_id}',
            headers={'Auth-API-Token': HETZNER_TOKEN},
            timeout=10,
        )
    except requests.RequestException as exc:
        app.logger.exception("Records fetch exception for %s from %s", fqdn, request.remote_addr)
        send_ntfy('Records Fetch Error', str(exc))
        return {'error': 'Failed to fetch records', 'detail': str(exc)}, 500
    if records_resp.status_code != 200:
        app.logger.error("Records fetch failed for %s from %s: %s", fqdn, request.remote_addr, records_resp.text)
        send_ntfy('Records Fetch Failed', records_resp.text)
        return {'error': 'Failed to fetch records'}, 500

    record_id = None
    current_value = None
    for record in records_resp.json().get('records', []):
        if record.get('name') == subdomain and record.get('type') == record_type:
            record_id = record.get('id')
            current_value = record.get('value')
            break

    if record_id and skip_no_change and current_value == ip:
        app.logger.info("No change for %s from %s", fqdn, request.remote_addr)
        send_ntfy('DynDNS Success', f'No change for {fqdn} -> {ip}')
        return {'status': 'unchanged', 'ip': ip}, 200

    payload = {
        'value': ip,
        'ttl': RECORD_TTL,
        'type': record_type,
        'name': subdomain,
        'zone_id': zone_id
    }

    if record_id:
        try:
            resp = requests.put(
                f'https://dns.hetzner.com/api/v1/records/{record_id}',
                headers={
                    'Auth-API-Token': HETZNER_TOKEN,
                    'Content-Type': 'application/json',
                },
                json=payload,
                timeout=10,
            )
        except requests.RequestException as exc:
            app.logger.exception("Update record exception for %s from %s", fqdn, request.remote_addr)
            send_ntfy('Update Record Error', str(exc))
            return {'error': 'Failed to update record', 'detail': str(exc)}, 500
        action = 'Updated'
    else:
        try:
            resp = requests.post(
                'https://dns.hetzner.com/api/v1/records',
                headers={
                    'Auth-API-Token': HETZNER_TOKEN,
                    'Content-Type': 'application/json',
                },
                json=payload,
                timeout=10,
            )
        except requests.RequestException as exc:
            app.logger.exception("Create record exception for %s from %s", fqdn, request.remote_addr)
            send_ntfy('Create Record Error', str(exc))
            return {'error': 'Failed to create record', 'detail': str(exc)}, 500
        action = 'Created'

    if resp.ok:
        app.logger.info("%s request from %s for %s -> %s", action.lower(), request.remote_addr, fqdn, ip)
        send_ntfy('DynDNS Success', f'{action} {record_type} record for {fqdn} -> {ip}')
        return {'status': action.lower(), 'ip': ip}, 200
    else:
        app.logger.error("Failed to %s record for %s from %s: %s", action.lower(), fqdn, request.remote_addr, resp.text)
        send_ntfy(f'{action} Failed', resp.text)
        return {'error': 'API failure', 'detail': resp.text}, 500


@app.route('/update', methods=['POST'])
def update():
    if not HETZNER_TOKEN:
        abort(500, 'Backend not configured')

    auth_ok = False
    if API_KEY and request.headers.get('X-API-Key') == API_KEY:
        auth_ok = True
    if not auth_ok and BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD:
        auth = request.authorization
        if auth and auth.username == BASIC_AUTH_USERNAME and auth.password == BASIC_AUTH_PASSWORD:
            auth_ok = True
    if not auth_ok:
        return {'error': 'Unauthorized'}, 401

    data = request.get_json(silent=True) or {}
    if DEBUG_LOGGING:
        app.logger.debug("Request JSON: %s", data)
        headers = dict(request.headers)
        if 'X-API-Key' in headers:
            headers['X-API-Key'] = '[REDACTED]'
        app.logger.debug("Request headers: %s", headers)
        app.logger.debug("Remote address: %s", request.remote_addr)
        if 'X-Real-Ip' in request.headers:
            app.logger.debug("X-Real-Ip: %s", request.headers.get('X-Real-Ip'))
        if 'X-Forwarded-For' in request.headers:
            app.logger.debug("X-Forwarded-For: %s", request.headers.get('X-Forwarded-For'))
    url = data.get('fqdn') or data.get('url')
    if not url:
        app.logger.error("Request from %s missing fqdn", request.remote_addr)
        send_ntfy('Param Error', 'Missing FQDN')
        return {'error': 'Missing FQDN'}, 400

    record_type = data.get('type', 'A').upper()
    if record_type not in ('A', 'AAAA'):
        app.logger.error("Request from %s invalid type: %s", request.remote_addr,
                         record_type)
        send_ntfy('Param Error', 'Invalid type')
        return {'error': 'Invalid type'}, 400

    ip = data.get('ip')
    if not ip:
        ip = request.headers.get('X-Real-Ip')
    if not ip and 'X-Forwarded-For' in request.headers:
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if not ip:
        ip = request.remote_addr

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        app.logger.error("Request from %s invalid ip: %s", request.remote_addr, ip)
        send_ntfy('Param Error', 'Invalid IP')
        return {'error': 'Invalid IP'}, 400

    if record_type == 'A' and ip_obj.version != 4:
        app.logger.error("Request from %s ip version mismatch: %s", request.remote_addr, ip)
        send_ntfy('Param Error', 'IP version mismatch')
        return {'error': 'IP version mismatch'}, 400
    if record_type == 'AAAA' and ip_obj.version != 6:
        app.logger.error("Request from %s ip version mismatch: %s", request.remote_addr, ip)
        send_ntfy('Param Error', 'IP version mismatch')
        return {'error': 'IP version mismatch'}, 400

    result, status = perform_update(url, ip, record_type)
    return jsonify(result), status


@app.route('/nic/update', methods=['GET', 'POST'])
def nic_update():
    if not HETZNER_TOKEN:
        abort(500, 'Backend not configured')

    user = None
    pw = None
    if request.authorization:
        user = request.authorization.username
        pw = request.authorization.password
    if not user:
        user = request.args.get('user')
        pw = request.args.get('pass')

    if not (user == BASIC_AUTH_USERNAME and pw == BASIC_AUTH_PASSWORD):
        return "badauth", 401

    hostname = request.args.get('hostname') or request.form.get('hostname')
    ip = request.args.get('myip') or request.form.get('myip')
    if not ip:
        ip = request.remote_addr

    record_type = 'AAAA' if ':' in ip else 'A'

    result, status = perform_update(hostname, ip, record_type, skip_no_change=True)
    if status != 200:
        return jsonify(result), status
    if result['status'] == 'unchanged':
        return f"nochg {result['ip']}", 200
    return f"good {result['ip']}", 200


if __name__ == '__main__':
    port = int(os.environ.get('LISTEN_PORT', '80'))
    app.run(host='0.0.0.0', port=port, debug=DEBUG_LOGGING)
