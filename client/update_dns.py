import os
import sys
import time
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
    backend = os.environ.get("BACKEND_URL")
    pre_shared_key = os.environ.get("PRE_SHARED_KEY")
    fqdn = os.environ.get("FQDN")
    ip = os.environ.get("IP")
    try:
        interval = int(os.environ.get("INTERVAL", "60"))
    except (TypeError, ValueError):
        print("Invalid INTERVAL, defaulting to 60")
        interval = 60
    interval = max(0, interval)

    if len(sys.argv) > 1:
        backend = sys.argv[1]
    if len(sys.argv) > 2:
        fqdn = sys.argv[2]
    if len(sys.argv) > 3:
        ip = sys.argv[3]

    if not pre_shared_key:
        print("PRE_SHARED_KEY not set")
        sys.exit(1)

    if not backend or not fqdn:
        print("Usage: update_dns.py <backend_url> <fqdn> [ip]")
        sys.exit(1)

    payload = {"fqdn": fqdn}
    if ip:
        payload["ip"] = ip

    while True:
        verify = get_verify_option()
        # Log the request that is about to be sent so it appears in docker logs
        msg = f"Sending update to {backend} for {fqdn}"
        if ip:
            msg += f" ip={ip}"
        print(msg, flush=True)
        try:
            resp = requests.post(
                f"{backend.rstrip('/')}/update",
                json=payload,
                headers={"X-Pre-Shared-Key": pre_shared_key} if pre_shared_key else None,
                verify=verify,
                timeout=10,
            )
            print(f"{resp.status_code} {resp.text}", flush=True)
            success = 200 <= resp.status_code < 300
        except requests.exceptions.RequestException as exc:
            print(exc, flush=True)
            success = False

        if not success and interval <= 0:
            sys.exit(1)

        if interval <= 0:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
