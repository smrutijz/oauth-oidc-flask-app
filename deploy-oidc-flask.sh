#!/usr/bin/env bash
set -euo pipefail

# Usage check
DOMAIN=${1:? "Usage: $0 <domain> <email>"}
EMAIL=${2:? "Usage: $0 <domain> <email>"}

echo "🏷️ Setting up for domain: $DOMAIN with email: $EMAIL"

# ------------------------
# 🐳 Install Docker if not already installed
# ------------------------
if ! command -v docker &> /dev/null; then
  echo "🛠 Installing Docker..."
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
else
  echo "✅ Docker already installed"
fi

# Start Docker if not running
sudo systemctl start docker

# ------------------------
# 🌐 Install Nginx and Certbot
# ------------------------
echo "🌐 Installing Nginx and Certbot..."
sudo apt-get install -y nginx certbot python3-certbot-nginx

# ------------------------
# 🔒 Temporary Nginx config for Certbot challenge
# ------------------------
echo "⚙️ Configuring Nginx for Let's Encrypt challenge..."
sudo tee /etc/nginx/sites-available/$DOMAIN-temp >/dev/null <<EOF
server {
  listen 80;
  server_name $DOMAIN;

  location /.well-known/acme-challenge/ {
    root /var/www/html;
  }

  location / {
    return 200 'OK';
    add_header Content-Type text/plain;
  }
}
EOF

sudo ln -sf /etc/nginx/sites-available/$DOMAIN-temp /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# ------------------------
# 🔐 Obtain SSL Certificate
# ------------------------
echo "🔐 Requesting SSL certificate from Let's Encrypt..."
sudo certbot --non-interactive --agree-tos --email "$EMAIL" --nginx -d "$DOMAIN"

# ------------------------
# 🔁 Final Nginx Reverse Proxy Configuration
# ------------------------
echo "🔁 Setting up final Nginx reverse proxy config..."

sudo tee /etc/nginx/sites-available/$DOMAIN >/dev/null <<EOF
server {
  listen 80;
  server_name $DOMAIN;
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl;
  listen [::]:443 ssl;

  server_name $DOMAIN;

  ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
  include             /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

  location / {
    proxy_pass http://localhost:8080;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
EOF

sudo ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# ------------------------
# 🚀 Launch Docker App
# ------------------------
echo "🚀 Launching app with Docker Compose..."
sudo docker compose pull
sudo docker compose up -d

echo ""
echo "✅ Deployment complete!"
echo "🌍 Visit: https://$DOMAIN"
