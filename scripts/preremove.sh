#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="foundation-storage-engine"

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active "${SERVICE_NAME}" >/dev/null 2>&1; then
    systemctl stop "${SERVICE_NAME}"
  fi
fi
