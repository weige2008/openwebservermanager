#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-23876}"
PUBLIC_HOST="${2:-}"

if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "invalid backend port: $PORT" >&2
  exit 1
fi
if [[ -z "$PUBLIC_HOST" ]]; then
  echo "public host is required" >&2
  exit 1
fi
if [[ ! "$PUBLIC_HOST" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "invalid public host: $PUBLIC_HOST" >&2
  exit 1
fi

if [[ -x /www/server/nginx/sbin/nginx && -d /www/server/panel/vhost/nginx ]]; then
  NGINX_BIN=/www/server/nginx/sbin/nginx
  VHOST_DIR=/www/server/panel/vhost/nginx
else
  NGINX_BIN="$(command -v nginx || true)"
  VHOST_DIR=/etc/nginx/conf.d
fi
if [[ -z "$NGINX_BIN" || ! -x "$NGINX_BIN" ]]; then
  echo "nginx is required for HTTPS termination" >&2
  exit 1
fi

WEBROOT=/var/www/letsencrypt
VHOST_PATH="$VHOST_DIR/openwebservermanager.conf"
VHOST_BACKUP=""
CERT_PATH="/etc/letsencrypt/live/$PUBLIC_HOST/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$PUBLIC_HOST/privkey.pem"
mkdir -p "$WEBROOT/.well-known/acme-challenge" "$VHOST_DIR"

if [[ -e "$VHOST_PATH" ]]; then
  VHOST_BACKUP="$(mktemp)"
  cp -a "$VHOST_PATH" "$VHOST_BACKUP"
fi

restore_vhost() {
  if [[ -n "$VHOST_BACKUP" && -e "$VHOST_BACKUP" ]]; then
    cp -a "$VHOST_BACKUP" "$VHOST_PATH"
  else
    rm -f "$VHOST_PATH"
  fi
  "$NGINX_BIN" -t >/dev/null 2>&1 && "$NGINX_BIN" -s reload >/dev/null 2>&1 || true
}

cleanup() {
  rm -f "$VHOST_BACKUP"
}

trap 'restore_vhost; cleanup' ERR
trap cleanup EXIT

write_proxy_locations() {
  cat <<EOF
    client_max_body_size 1g;

    location /.well-known/acme-challenge/ {
        root $WEBROOT;
        default_type text/plain;
    }

    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
        proxy_request_buffering off;
    }
EOF
}

write_http_bootstrap() {
  {
    echo "server {"
    echo "    listen 80;"
    echo "    server_name $PUBLIC_HOST;"
    write_proxy_locations
    echo "}"
  } >"$VHOST_PATH"
}

write_https_vhost() {
  cat >"$VHOST_PATH" <<EOF
server {
    listen 80;
    server_name $PUBLIC_HOST;

    location /.well-known/acme-challenge/ {
        root $WEBROOT;
        default_type text/plain;
    }

    location / {
        return 308 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $PUBLIC_HOST;

    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:OWMSsl:10m;
    ssl_session_timeout 1d;
    add_header Strict-Transport-Security "max-age=31536000" always;

EOF
  write_proxy_locations >>"$VHOST_PATH"
  echo "}" >>"$VHOST_PATH"
}

reload_nginx() {
  "$NGINX_BIN" -t
  "$NGINX_BIN" -s reload
}

if [[ ! -s "$CERT_PATH" || ! -s "$KEY_PATH" ]]; then
  write_http_bootstrap
  reload_nginx
  if ! command -v certbot >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y certbot
  fi
  certbot certonly --webroot --webroot-path "$WEBROOT" --domain "$PUBLIC_HOST" --non-interactive --agree-tos --register-unsafely-without-email
fi

write_https_vhost
reload_nginx
trap - ERR

HOOK=/etc/letsencrypt/renewal-hooks/deploy/openwebservermanager-nginx-reload.sh
mkdir -p "$(dirname "$HOOK")"
cat >"$HOOK" <<EOF
#!/usr/bin/env bash
set -e
$NGINX_BIN -t
$NGINX_BIN -s reload
EOF
chmod 0755 "$HOOK"

echo "HTTPS ready at https://$PUBLIC_HOST/"
