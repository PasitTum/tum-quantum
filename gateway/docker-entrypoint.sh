#!/bin/sh
# ==============================================================================
# TUM-Quantum Reverse Proxy Gateway - Container Entrypoint
# Copyright (c) 2026 TUMQuantum Co., Ltd. All rights reserved.
# ==============================================================================

set -e

echo "======================================================================"
echo "  🚀 Starting TUM-Quantum Reverse Proxy Gateway (v1.0.0-FIPS203-204)  "
echo "  Standard: NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA) TLS 1.3        "
echo "  Copyright (c) 2026 TUMQuantum Co., Ltd.                             "
echo "======================================================================"

# Step 1: Ensure SSL certificates exist
if [ ! -f /etc/ssl/tum-quantum/server.crt ] || [ ! -f /etc/ssl/tum-quantum/server.key ]; then
    echo "[TUM-Quantum] Certificates missing. Running automatic generator..."
    /usr/local/bin/generate-pqc-certs.sh
fi

# Step 2: Validate Nginx configuration syntax
echo "[TUM-Quantum] Validating Nginx configuration syntax..."
nginx -t

echo "[TUM-Quantum] Gateway initialization complete. Listening on:"
echo "  - Port 80  (HTTP  -> Automatic 301 Redirect to HTTPS)"
echo "  - Port 443 (HTTPS -> PQC TLS 1.3 Termination & Header Injection)"
echo "======================================================================"

# Step 3: Launch Nginx as foreground process
exec nginx -g "daemon off;"
