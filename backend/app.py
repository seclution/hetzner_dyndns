import os
from flask import Flask, request, jsonify, abort
import requests

app = Flask(__name__)

HETZNER_TOKEN = os.environ.get("HETZNER_TOKEN")
NTFY_URL = os.environ.get("NTFY_URL")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")


def send_ntfy(title: str, message: str) -> None:
    if not NTFY_URL:
        return
    headers = {"Title": title} if title else {}
    try:
        requests.post(f"{NTFY_URL}/{NTFY_TOPIC}" if NTFY_TOPIC else NTFY_URL,
                      headers=headers, data=message)
    except Exception:
        app.logger.exception("Failed to send ntfy message")


@app.route('/update', methods=['POST'])
def update():
    if not HETZNER_TOKEN:
        abort(500, 'Backend not configured')

    data = request.get_json(silent=True) or {}
    url = data.get('fqdn') or data.get('url')
    if not url:
        send_ntfy('Param Error', 'Missing FQDN')
        return jsonify({'error': 'Missing FQDN'}), 400

    ip = data.get('ip')
    if not ip:
        ip = request.remote_addr

    domain_parts = url.split('.')
    if len(domain_parts) < 2:
        send_ntfy('Param Error', 'Invalid FQDN')
        return jsonify({'error': 'Invalid FQDN'}), 400

    domain = '.'.join(domain_parts[-2:])
    subdomain = url[:-len(domain) - 1]

    zones_resp = requests.get('https://dns.hetzner.com/api/v1/zones',
                              headers={'Auth-API-Token': HETZNER_TOKEN})
    if zones_resp.status_code != 200:
        send_ntfy('Zone Fetch Failed', zones_resp.text)
        return jsonify({'error': 'Failed to fetch zones'}), 500

    zone_id = None
    for zone in zones_resp.json().get('zones', []):
        if zone.get('name') == domain:
            zone_id = zone.get('id')
            break

    if not zone_id:
        send_ntfy('Zone Not Found', f'No matching zone for {domain}')
        return jsonify({'error': 'Zone not found'}), 404

    records_resp = requests.get(
        f'https://dns.hetzner.com/api/v1/records?zone_id={zone_id}',
        headers={'Auth-API-Token': HETZNER_TOKEN})
    if records_resp.status_code != 200:
        send_ntfy('Records Fetch Failed', records_resp.text)
        return jsonify({'error': 'Failed to fetch records'}), 500

    record_id = None
    for record in records_resp.json().get('records', []):
        if record.get('name') == subdomain and record.get('type') == 'A':
            record_id = record.get('id')
            break

    payload = {
        'value': ip,
        'ttl': 86400,
        'type': 'A',
        'name': subdomain,
        'zone_id': zone_id
    }

    if record_id:
        resp = requests.put(
            f'https://dns.hetzner.com/api/v1/records/{record_id}',
            headers={'Auth-API-Token': HETZNER_TOKEN,
                     'Content-Type': 'application/json'},
            json=payload)
        action = 'Updated'
    else:
        resp = requests.post(
            'https://dns.hetzner.com/api/v1/records',
            headers={'Auth-API-Token': HETZNER_TOKEN,
                     'Content-Type': 'application/json'},
            json=payload)
        action = 'Created'

    if resp.ok:
        send_ntfy('DynDNS Success', f'{action} A record for {url} -> {ip}')
        return jsonify({'status': action.lower(), 'ip': ip}), 200
    else:
        send_ntfy(f'{action} Failed', resp.text)
        return jsonify({'error': 'API failure', 'detail': resp.text}), 500


if __name__ == '__main__':
    port = int(os.environ.get('LISTEN_PORT', '80'))
    app.run(host='0.0.0.0', port=port)
