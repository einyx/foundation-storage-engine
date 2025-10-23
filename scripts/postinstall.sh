#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="foundation-storage-engine"
SYSTEMD_SERVICE_PATH="/lib/systemd/system/${SERVICE_NAME}.service"

if command -v systemctl >/dev/null 2>&1 && [[ -f "${SYSTEMD_SERVICE_PATH}" ]]; then
  systemctl daemon-reload
  if systemctl is-enabled "${SERVICE_NAME}" >/dev/null 2>&1; then
    systemctl restart "${SERVICE_NAME}"
  fi
fi
