#!/bin/bash
# Pre-removal script for s3proxy

# Stop and disable service
systemctl stop s3proxy.service 2>/dev/null || true
systemctl disable s3proxy.service 2>/dev/null || true

echo "S3Proxy service stopped and disabled"
