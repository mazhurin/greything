limit_req_zone $http_x_gt_did zone=core_write:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=core_read:10m rate=100r/s;
limit_conn_zone $binary_remote_addr zone=core_conn:10m;

server {
    server_name storage.greything.com;

    client_max_body_size 50M;
    client_body_timeout 60s;
    client_body_buffer_size 1M;

    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
    proxy_buffering off;

    # Health check (no rate limit)
    location = /gt/v1/health {
        proxy_pass http://127.0.0.1:8090;
    }

    # GT Core API
    location /gt/v1/ {
        add_header Access-Control-Allow-Origin $http_origin always;
        add_header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, X-GT-DID, X-GT-Timestamp, X-GT-Signature, X-GT-Grant" always;

        if ($request_method = OPTIONS) {
            return 204;
        }

        limit_req zone=core_write burst=20 nodelay;
        limit_conn core_conn 20;

        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        return 404 '{"error":"not_found","message":"use /gt/v1/"}';
        default_type application/json;
    }

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/storage.greything.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/storage.greything.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    listen 80;
    server_name storage.greything.com;
    return 301 https://$host$request_uri;
}
