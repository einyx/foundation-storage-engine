#!/bin/bash
# Post-installation script for foundation-storage-engine

# Create foundation-storage-engine user if it doesn't exist
if ! id -u foundation-storage-engine >/dev/null 2>&1; then
    useradd --system --shell /bin/false --home-dir /var/lib/foundation-storage-engine --create-home foundation-storage-engine
fi

# Create necessary directories
mkdir -p /var/lib/foundation-storage-engine
mkdir -p /var/log/foundation-storage-engine
mkdir -p /etc/foundation-storage-engine

# Set permissions
chown -R foundation-storage-engine:foundation-storage-engine /var/lib/foundation-storage-engine
chown -R foundation-storage-engine:foundation-storage-engine /var/log/foundation-storage-engine
chown root:foundation-storage-engine /etc/foundation-storage-engine
chmod 750 /etc/foundation-storage-engine

# Make binary executable
chmod +x /usr/bin/foundation-storage-engine

# Copy example config if no config exists
if [ ! -f /etc/foundation-storage-engine/config.yaml ]; then
    if [ -f /etc/foundation-storage-engine/config.yaml.example ]; then
        cp /etc/foundation-storage-engine/config.yaml.example /etc/foundation-storage-engine/config.yaml
        chown root:foundation-storage-engine /etc/foundation-storage-engine/config.yaml
        chmod 640 /etc/foundation-storage-engine/config.yaml
        echo "Example configuration copied to /etc/foundation-storage-engine/config.yaml"
        echo "Please edit the configuration file before starting the service."
    fi
fi

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable foundation-storage-engine.service

echo "Foundation Storage Engine installed successfully!"
echo "Edit /etc/foundation-storage-engine/config.yaml and then start with: systemctl start foundation-storage-engine"
