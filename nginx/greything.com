server {
  server_name greything.com;

  # DID name resolver API
  location = /.well-known/greything/resolve {
    root /var/www/greything;
    default_type application/json;
    add_header Cache-Control "public, max-age=60";

    if ($arg_name = "") { return 400 '{"error":"name parameter required"}'; }

    try_files /.well-known/greything/names/$arg_name.json =404;
  }

  # Direct access to name mappings
  location /.well-known/greything/names/ {
    root /var/www/greything;
    default_type application/json;
    add_header Cache-Control "public, max-age=60";
    try_files $uri =404;
  }

  # Human-readable profile redirect: /@alice -> resolve
  location ~ ^/@([a-zA-Z0-9_-]+)$ {
    return 302 /.well-known/greything/resolve?name=$1;
  }

  # Google verification
  location ~ ^/google.*\.html$ {
    root /var/www/greything;
    try_files $uri =404;
  }

  # DID resolver page
  location = /resolve.html {
    root /var/www/greything;
    try_files $uri =404;
  }


  location / {
    return 200 'greything.com';
    add_header Content-Type text/plain;
  }

  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/greything.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/greything.com/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
  listen 80;
  server_name greything.com;
  return 301 https://$host$request_uri;
}
