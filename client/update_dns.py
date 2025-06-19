import os
import sys
import time
import requests

def main():
    backend = os.environ.get('BACKEND_URL')
    fqdn = os.environ.get('FQDN')
    ip = os.environ.get('IP')
    interval = int(os.environ.get('INTERVAL', '0'))

    if len(sys.argv) > 1:
        backend = sys.argv[1]
    if len(sys.argv) > 2:
        fqdn = sys.argv[2]
    if len(sys.argv) > 3:
        ip = sys.argv[3]

    if not backend or not fqdn:
        print('Usage: update_dns.py <backend_url> <fqdn> [ip]')
        sys.exit(1)

    payload = {'fqdn': fqdn}
    if ip:
        payload['ip'] = ip

    while True:
        resp = requests.post(f"{backend.rstrip('/')}/update", json=payload)
        print(resp.status_code, resp.text)
        if interval <= 0:
            break
        time.sleep(interval)

if __name__ == '__main__':
    main()
