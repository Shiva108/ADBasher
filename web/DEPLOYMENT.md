# ADBasher Web Dashboard - Secure Deployment Guide

## Environment Variables

Create a `.env` file in the `/home/e/ADBasher/web` directory with the following:

```bash
# Flask Configuration
FLASK_ENV=production
SECRET_KEY=<generate-strong-random-key>

# Encryption Key (generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
ADBASHER_ENCRYPTION_KEY=<your-encryption-key-here>

# Security Settings
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
```

## HTTPS Configuration

### Using Nginx as Reverse Proxy (Recommended)

1. Install nginx and certbot:

```bash
sudo apt-get install nginx certbot python3-certbot-nginx
```

2. Create nginx configuration (`/etc/nginx/sites-available/adbasher`):

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration (managed by certbot)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Frontend
    location / {
        root /home/e/ADBasher/web/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # API Backend
    location /api {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket Support
    location /socket.io {
        proxy_pass http://127.0.0.1:5000/socket.io;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. Enable configuration and get SSL certificate:

```bash
sudo ln -s /etc/nginx/sites-available/adbasher /etc/nginx/sites-enabled/
sudo certbot --nginx -d your-domain.com
sudo systemctl restart nginx
```

## Production Deployment

### 1. Build Frontend

```bash
cd /home/e/ADBasher/web/frontend
npm run build
```

### 2. Run Backend with Gunicorn

Install gunicorn:

```bash
cd /home/e/ADBasher/web
pip3 install gunicorn eventlet
```

Create systemd service (`/etc/systemd/system/adbasher-web.service`):

```ini
[Unit]
Description=ADBasher Web Dashboard
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/home/e/ADBasher/web
Environment="PATH=/usr/bin:/usr/local/bin"
ExecStart=/usr/bin/gunicorn --worker-class eventlet -w 1 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable adbasher-web
sudo systemctl start adbasher-web
```

## Security Checklist

- [ ] Change all default credentials
- [ ] Set strong SECRET_KEY and ADBASHER_ENCRYPTION_KEY
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Configure firewall to only allow ports 80 and 443
- [ ] Set SESSION_COOKIE_SECURE=True in production
- [ ] Enable rate limiting (already configured)
- [ ] Review and configure CORS origins (currently set to \*)
- [ ] Setup log rotation for /home/e/ADBasher/web/logs
- [ ] Backup encryption keys securely
- [ ] Implement authentication/authorization (future)
- [ ] Regularly update dependencies

## Monitoring

Monitor logs:

```bash
# Application logs
tail -f /home/e/ADBasher/web/logs/app.log

# Error logs
tail -f /home/e/ADBasher/web/logs/errors.log

# Audit logs
tail -f /home/e/ADBasher/web/logs/audit.log
```

## Firewall Configuration

```bash
# Allow SSH (change port if needed)
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```
