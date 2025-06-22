# Backend Automation API (Backend-AP)

This document outlines the planned API extension to automate the Hetzner DynDNS
backend. The goal is to allow external systems (e.g. a webshop) to create new
DynDNS entries and retrieve their tokens automatically.

## Overview

The backend will expose a small administrative API which is protected by a
single API token. Through this API a new fully qualified domain name (FQDN) can
be registered and the associated pre‑shared token can be queried. The token will
then be sent to the end user by the webshop.

All calls must include the header `X-Api-Token` with the value configured in the
backend. Without this token the request is rejected.

## Planned Endpoints

### `POST /register`
Registers a new FQDN and returns the generated token.

Request body:
```json
{ "fqdn": "host.example.com" }
```

Response body:
```json
{ "fqdn": "host.example.com", "token": "..." }
```

If the FQDN already exists, the existing token is returned. The FQDN is stored in
the `pre-shared-key` file so that it persists across restarts.

### `GET /token/<fqdn>`
Returns the token for an already registered FQDN.

Example:
```bash
curl -H "X-Api-Token: <admin-token>" \
     https://backend.example.com/token/host.example.com
```

Response body:
```json
{ "fqdn": "host.example.com", "token": "..." }
```

## Configuration

A new environment variable `API_TOKEN` will hold the administrative token. The
backend must be restarted after changing this value. When no token is set, the
administrative API is disabled.

Tokens for registered FQDNs are stored in `backend/pre-shared-key`. This file is
updated whenever a new FQDN is registered through the API. On startup the file
is read and all entries are loaded into memory.

## Implementation Tasks

1. Extend `backend/app.py`
   - Load `API_TOKEN` from the environment.
   - Add helper functions to read and write the `pre-shared-key` file.
   - Implement the `/register` and `/token/<fqdn>` routes with token
     authentication.
2. Write unit tests covering the new functionality.
3. Document the new API in the main `README.md`.

After these steps the webshop can call the administrative API to register new
FQDNs and distribute the generated tokens to customers.
