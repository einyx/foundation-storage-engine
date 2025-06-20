#!/bin/bash
# Post-installation script for s3proxy

# Create s3proxy user if it doesn't exist
if ! id -u s3proxy >/dev/null 2>&1; then
    useradd --system --shell /bin/false --home-dir /var/lib/s3proxy --create-home s3proxy
fi

# Create necessary directories
mkdir -p /var/lib/s3proxy
mkdir -p /var/log/s3proxy
mkdir -p /etc/s3proxy

# Set permissions
chown -R s3proxy:s3proxy /var/lib/s3proxy
chown -R s3proxy:s3proxy /var/log/s3proxy
chown root:s3proxy /etc/s3proxy
chmod 750 /etc/s3proxy

# Make binary executable
chmod +x /usr/bin/s3proxy

# Copy example config if no config exists
if [ ! -f /etc/s3proxy/config.yaml ]; then
    if [ -f /etc/s3proxy/config.yaml.example ]; then
        cp /etc/s3proxy/config.yaml.example /etc/s3proxy/config.yaml
        chown root:s3proxy /etc/s3proxy/config.yaml
        chmod 640 /etc/s3proxy/config.yaml
        echo "Example configuration copied to /etc/s3proxy/config.yaml"
        echo "Please edit the configuration file before starting the service."
    fi
fi

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable s3proxy.service

echo "S3Proxy installed successfully!"
echo "Edit /etc/s3proxy/config.yaml and then start with: systemctl start s3proxy"
