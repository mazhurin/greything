# GreyThing Deployment Guide

## Server Requirements

- Debian 12 (or similar)
- User `gt` with sudo access
- Domains pointing to server IP: `did.greything.com`, `storage.greything.com`, `greything.com`
- Nginx, certbot installed

## Architecture

```
                    ┌──────────────┐
                    │    nginx     │
                    │  :443/:80   │
                    └──┬───┬───┬──┘
                       │   │   │
          ┌────────────┘   │   └────────────┐
          ▼                ▼                 ▼
   did.greything.com  storage.greything.com  greything.com
          │                │                 │
          ▼                ▼                 ▼
      gt-dids:8080    gt-core:8090      static files
      (DID registry)  (Storage API)
```

**gt-core** — Storage API (blobs, heads, inbox, grants). Port 8090.
**gt-dids** — DID registry, user registration, claims search. Port 8080.

Data lives in `/var/lib/greything/core` (blobs, heads, inbox, grants).
DID documents live in `/var/www/did/u/{userId}/did.json`.
HTML frontend lives in `/var/www/did/*.html`.

## Fresh Deploy (from scratch)

### 1. Server Setup

```bash
ssh gt@gt

# Install dependencies
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx

# Create user if needed
sudo useradd -m -s /bin/bash gt

# Create directories
sudo mkdir -p /home/gt/bin
sudo mkdir -p /var/lib/greything/core
sudo mkdir -p /var/www/did
sudo mkdir -p /var/www/greything
sudo chown -R gt:gt /home/gt/bin /var/lib/greything
sudo chown -R gt:gt /var/www/did /var/www/greything
```

### 2. Build Binaries (on local machine)

```bash
GOOS=linux GOARCH=amd64 go build -o /tmp/gt-core-linux ./cmd/gt-core
GOOS=linux GOARCH=amd64 go build -o /tmp/gt-dids-linux ./cmd/gt-dids
```

### 3. Upload Binaries

```bash
scp /tmp/gt-core-linux gt@gt:/home/gt/bin/gt-core
scp /tmp/gt-dids-linux gt@gt:/home/gt/bin/gt-dids
ssh gt@gt "chmod +x /home/gt/bin/gt-core /home/gt/bin/gt-dids"
```

### 4. Upload HTML

```bash
scp www/did/index.html www/did/register.html www/did/profile.html \
    www/did/resolve.html www/did/submit.html \
    gt@gt:/tmp/
ssh gt@gt "sudo cp /tmp/index.html /tmp/register.html /tmp/profile.html /tmp/resolve.html /tmp/submit.html /var/www/did/"
```

### 5. Upload Nginx Configs

```bash
scp nginx/did.greything.com nginx/storage.greything.com nginx/greything.com \
    gt@gt:/tmp/
ssh gt@gt "sudo cp /tmp/did.greything.com /tmp/storage.greything.com /tmp/greything.com /etc/nginx/sites-available/"
ssh gt@gt "sudo ln -sf /etc/nginx/sites-available/did.greything.com /etc/nginx/sites-enabled/"
ssh gt@gt "sudo ln -sf /etc/nginx/sites-available/storage.greything.com /etc/nginx/sites-enabled/"
ssh gt@gt "sudo ln -sf /etc/nginx/sites-available/greything.com /etc/nginx/sites-enabled/"
```

### 6. SSL Certificates

```bash
ssh gt@gt

# First time — get certificates (nginx configs reference them, so get certs before enabling)
# Temporarily comment out ssl lines in nginx configs, or:
sudo certbot --nginx -d did.greything.com
sudo certbot --nginx -d storage.greything.com
sudo certbot --nginx -d greything.com
```

### 7. Upload and Enable Systemd Services

```bash
scp systemd/gt-core.service systemd/gt-dids.service gt@gt:/tmp/
ssh gt@gt "sudo cp /tmp/gt-core.service /tmp/gt-dids.service /etc/systemd/system/"
ssh gt@gt "sudo systemctl daemon-reload"
ssh gt@gt "sudo systemctl enable --now gt-core gt-dids"
```

### 8. Verify

```bash
# Test nginx
ssh gt@gt "sudo nginx -t && sudo systemctl reload nginx"

# Check services are running
ssh gt@gt "sudo systemctl status gt-core gt-dids"

# Test endpoints
curl https://storage.greything.com/gt/v1/health
curl https://did.greything.com/.well-known/did.json
```

## Routine Update (code changes only)

### Update gt-core binary

```bash
GOOS=linux GOARCH=amd64 go build -o /tmp/gt-core-linux ./cmd/gt-core
scp /tmp/gt-core-linux gt@gt:/home/gt/bin/gt-core.new
ssh gt@gt "sudo systemctl stop gt-core && cp /home/gt/bin/gt-core /home/gt/bin/gt-core.bak && mv /home/gt/bin/gt-core.new /home/gt/bin/gt-core && sudo systemctl start gt-core"
```

### Update gt-dids binary

```bash
GOOS=linux GOARCH=amd64 go build -o /tmp/gt-dids-linux ./cmd/gt-dids
scp /tmp/gt-dids-linux gt@gt:/home/gt/bin/gt-dids.new
ssh gt@gt "sudo systemctl stop gt-dids && cp /home/gt/bin/gt-dids /home/gt/bin/gt-dids.bak && mv /home/gt/bin/gt-dids.new /home/gt/bin/gt-dids && sudo systemctl start gt-dids"
```

### Update HTML

```bash
scp www/did/index.html gt@gt:/tmp/index.html
ssh gt@gt "sudo cp /tmp/index.html /var/www/did/"
```

### Update Nginx Config

```bash
scp nginx/storage.greything.com gt@gt:/tmp/storage.greything.com
ssh gt@gt "sudo cp /tmp/storage.greything.com /etc/nginx/sites-available/ && sudo nginx -t && sudo systemctl reload nginx"
```

## Rollback

```bash
# Rollback binary
ssh gt@gt "sudo systemctl stop gt-core && mv /home/gt/bin/gt-core.bak /home/gt/bin/gt-core && sudo systemctl start gt-core"
```

## Logs

```bash
ssh gt@gt "sudo journalctl -u gt-core -f"         # gt-core logs
ssh gt@gt "sudo journalctl -u gt-dids -f"         # gt-dids logs
ssh gt@gt "sudo tail -f /var/log/nginx/error.log"  # nginx errors
```

## Ports

| Service | Port | Exposed via |
|---------|------|-------------|
| gt-core | 8090 | storage.greything.com (nginx proxy) |
| gt-dids | 8080 | did.greything.com/api/v1/ (nginx proxy) |

## File Locations (on server)

| What | Path |
|------|------|
| Binaries | `/home/gt/bin/gt-core`, `/home/gt/bin/gt-dids` |
| Storage data | `/var/lib/greything/core/` |
| DID documents | `/var/www/did/u/{userId}/did.json` |
| Frontend HTML | `/var/www/did/*.html` |
| Nginx configs | `/etc/nginx/sites-available/{did,storage,greything}.greything.com` |
| Systemd units | `/etc/systemd/system/gt-core.service`, `gt-dids.service` |
| SSL certs | `/etc/letsencrypt/live/{did,storage,greything}.greything.com/` |

## Source File Locations (in repo)

| What | Path |
|------|------|
| gt-core entry point | `cmd/gt-core/main.go` |
| gt-dids entry point | `cmd/gt-dids/main.go` |
| Systemd units | `systemd/*.service` |
| Nginx configs | `nginx/*` |
| Frontend HTML | `www/did/*.html` |
