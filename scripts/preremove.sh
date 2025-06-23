#!/bin/bash
# Pre-removal script for foundation-storage-engine

# Stop and disable service
systemctl stop foundation-storage-engine.service 2>/dev/null || true
systemctl disable foundation-storage-engine.service 2>/dev/null || true

echo "Foundation Storage Engine service stopped and disabled"
