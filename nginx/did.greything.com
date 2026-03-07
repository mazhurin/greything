server {
  server_name did.greything.com;

  location = /.well-known/did.json {
    root /var/www/did;
    default_type application/json;
    add_header Cache-Control "public, max-age=300";
    add_header Access-Control-Allow-Origin "*" always;
    try_files $uri =404;
  }

  location /u/ {
    root /var/www/did;
    default_type application/json;
    add_header Cache-Control "public, max-age=3600";
    add_header Access-Control-Allow-Origin "*" always;
    try_files $uri =404;
  }

  # Name resolver page
  location = /resolve.html {
    root /var/www/did;
    try_files $uri =404;
  }

  # Registration page
  location = /register.html {
    root /var/www/did;
    try_files $uri =404;
  }

  # Profile editor
  location = /profile.html {
    root /var/www/did;
    try_files $uri =404;
  }

  # Name mappings API
  location /.well-known/greything/names/ {
    root /var/www/did;
    default_type application/json;
    add_header Cache-Control "public, max-age=60";
    try_files $uri =404;
  }

  # DIDS API — proxy to gt-dids
  location /api/v1/ {
    # CORS for cross-origin requests (e.g. WordPress plugin submitting DIDs)
    add_header Access-Control-Allow-Origin $http_origin always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, X-GT-DID, X-GT-Timestamp, X-GT-Signature" always;
    add_header Access-Control-Max-Age 86400 always;

    if ($request_method = OPTIONS) {
      return 204;
    }

    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 1M;
  }

  location / {
    root /var/www/did;
    index index.html;
    try_files $uri $uri/ =404;
  }

  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/did.greything.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/did.greything.com/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
  listen 80;
  server_name did.greything.com;
  return 301 https://$host$request_uri;
}
