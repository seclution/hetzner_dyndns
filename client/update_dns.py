import os
import sys
import requests
try:
    import certifi
except ImportError:  # certifi might not be installed in some environments
    certifi = None

def get_verify_option():
    """Return the verify parameter for requests based on environment vars."""
    ca_bundle = os.environ.get("CA_BUNDLE")
    if ca_bundle:
        return ca_bundle
    verify_env = os.environ.get("VERIFY_SSL")
    if verify_env is not None and verify_env.lower() in ("0", "false", "no"):
        return False
    if certifi is not None:
        return certifi.where()
    return True

def main():
    backend = os.environ.get('BACKEND_URL')
    fqdn = os.environ.get('FQDN')
    ip = os.environ.get('IP')

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

    verify = get_verify_option()
    resp = requests.post(f"{backend.rstrip('/')}/update", json=payload, verify=verify)
    print(resp.status_code, resp.text)

if __name__ == '__main__':
    main()
