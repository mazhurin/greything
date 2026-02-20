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

  # Name resolver page
  location = /resolve.html {
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
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 1M;
  }

  location / {
    return 200 'ok';
    add_header Content-Type text/plain;
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
