# DIDS Minimal Implementation Guide (v1)

This guide describes the smallest practical way to run a DIDS
(Decentralized Identity Domain Service) using NGINX and static files.
It also explains how to do the same on pure static hosting.

The result:
- DID name (handle) → DID via HTTPS
- DID → did.json via HTTPS (static, did:web)

---

## 0. Requirements

- A domain name (example: greything.com)
- HTTPS enabled (Let’s Encrypt is sufficient)
- Optional but recommended: a separate subdomain for DID hosting
  (example: did.greything.com)

Recommended split:
- greything.com — website + DID name resolver
- did.greything.com — static DID documents

---

## 1. Naming scheme (v1)

DID name (human-readable):
alice@greything.com

Canonical user DID (opaque):
did:web:did.greything.com:u:<id>

Example:
did:web:did.greything.com:u:3x9f2k7m

DID Document URL (did:web rule):
https://did.greything.com/u/3x9f2k7m/did.json

---

## 2. VPS + NGINX implementation (static)

### 2.1 Directory structure

Create the following directories:

/var/www/did/
  .well-known/
  u/
    3x9f2k7m/

/var/www/greything/
  .well-known/
    greything/
      names/

---

## 2.2 User DID Document

Create the file:

/var/www/did/u/3x9f2k7m/did.json

Example content:

{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:did.greything.com:u:3x9f2k7m",
  "verificationMethod": [
    {
      "id": "#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.greything.com:u:3x9f2k7m",
      "publicKeyMultibase": "z6Mk..."
    }
  ],
  "assertionMethod": ["#key-1"]
}

---

## 2.3 DID name mapping (one file per name)

Create:

/var/www/greything/.well-known/greything/names/alice.json

Content:

{
  "name": "alice@greything.com",
  "did": "did:web:did.greything.com:u:3x9f2k7m"
}

This “one JSON file per name” pattern enables fully static DIDS.

---

## 3. NGINX configuration

### 3.1 did.greything.com — DID hosting

server {
  server_name did.greything.com;

  location = /.well-known/did.json {
    root /var/www/did;
    default_type application/json;
    add_header Cache-Control "public, max-age=300";
    try_files $uri =404;
  }

  location /u/ {
    root /var/www/did;
    default_type application/json;
    add_header Cache-Control "public, max-age=3600";
    try_files $uri =404;
  }

  location / { return 200 'ok'; add_header Content-Type text/plain; }

  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/did.greything.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/did.greything.com/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

---

### 3.2 greything.com — DID name resolver

This maps:
/.well-known/greything/resolve?name=alice
to:
/.well-known/greything/names/alice.json

server {
  server_name greything.com;

  location = /.well-known/greything/resolve {
    root /var/www/greything;
    default_type application/json;
    add_header Cache-Control "public, max-age=60";

    if ($arg_name = "") { return 400; }

    try_files /.well-known/greything/names/$arg_name.json =404;
  }

  location /.well-known/greything/names/ {
    root /var/www/greything;
    default_type application/json;
    add_header Cache-Control "public, max-age=60";
    try_files $uri =404;
  }

  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/greything.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/greything.com/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

Reload NGINX after changes.

---

## 4. Verification with curl

Resolve DID name to DID:

curl https://greything.com/.well-known/greything/resolve?name=alice

Resolve DID to DID Document:

curl https://did.greything.com/u/3x9f2k7m/did.json

---

## 5. Pure static hosting (no server logic)

For hosts that cannot route query parameters, use path-based resolution.

Instead of:
/.well-known/greything/resolve?name=alice

Use:
/.well-known/greything/resolve/alice.json

File:
/.well-known/greything/resolve/alice.json

Content:
{
  "name": "alice@greything.com",
  "did": "did:web:did.greything.com:u:3x9f2k7m"
}

This works on S3, R2, GitHub Pages, Netlify, etc.

---

## 6. Operational notes

- DID name resolution is convenience-only.
- DID resolution via did:web is authoritative.
- DID documents should be static and cacheable.
- Name mappings should use short cache TTLs.
- Never store private keys on the server.
- Reserve critical names such as admin, support, and brand terms.

---

## 7. Minimal checklist

You are running a DIDS if:

- /.well-known/greything/resolve returns a DID for a name
- did.json files are reachable over HTTPS
- no central registry or signing service is required

---

## 8. Next steps

- Add an HTML resolver page (/@alice)
- Add a small admin UI or script to generate JSON files
- Add signed migration claims for domain changes
- Package this as a WordPress plugin
