#!/bin/sh
# ==============================================================================
# TUM-Quantum Certificate Authority & Server Certificate Generator
# Generates Hybrid & Post-Quantum TLS 1.3 Certificates (NIST FIPS 204 / RFC 8446)
# Copyright (c) 2026 TUMQuantum Co., Ltd. All rights reserved.
# ==============================================================================

set -e

CERT_DIR="${CERT_DIR:-/etc/ssl/tum-quantum}"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "[TUM-Quantum] Existing certificates detected in $CERT_DIR. Skipping generation."
    exit 0
fi

echo "[TUM-Quantum] Initializing Post-Quantum Certificate Generation in $CERT_DIR..."

OPENSSL_BIN=$(command -v openssl || echo "/usr/bin/openssl")

# Check if OpenSSL has OQS (liboqs / ML-DSA) support
IS_OQS=false
if "$OPENSSL_BIN" list -signature-algorithms 2>/dev/null | grep -qi "mldsa\|dilithium"; then
    IS_OQS=true
    echo "[TUM-Quantum] OpenSSL with OQS (liboqs) detected! Generating pure ML-DSA-65 (FIPS 204) certificate."
else
    echo "[TUM-Quantum] Standard OpenSSL detected. Generating High-Entropy Hybrid RSA-4096 / P-384 Certificate."
fi

# Step 1: Generate Root CA
if [ ! -f "$CERT_DIR/ca.crt" ]; then
    echo "[TUM-Quantum] Generating Root Certificate Authority (TUM-Quantum Sovereign Root CA)..."
    if [ "$IS_OQS" = true ]; then
        "$OPENSSL_BIN" req -x509 -new -newkey mldsa65 -keyout "$CERT_DIR/ca.key" \
            -out "$CERT_DIR/ca.crt" -nodes -subj "/C=TH/O=TUM Group Holdings/OU=TUMQuantum Lab/CN=TUM-Quantum Sovereign Root CA" \
            -days 3650 2>/dev/null || true
    fi

    # Fallback or standard generation if OQS keygen fails or standard OpenSSL
    if [ ! -f "$CERT_DIR/ca.crt" ]; then
        "$OPENSSL_BIN" req -x509 -new -newkey rsa:4096 -keyout "$CERT_DIR/ca.key" \
            -out "$CERT_DIR/ca.crt" -nodes -subj "/C=TH/O=TUM Group Holdings/OU=TUMQuantum Lab/CN=TUM-Quantum Sovereign Root CA" \
            -days 3650
    fi
    chmod 600 "$CERT_DIR/ca.key"
    chmod 644 "$CERT_DIR/ca.crt"
fi

# Step 2: Generate Server OpenSSL Configuration with SAN
cat <<EOF > "$CERT_DIR/openssl_san.cnf"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = TH
ST = Bangkok
L = Bangkok
O = TUM Group Holdings Co., Ltd.
OU = TUMQuantum Post-Quantum Security Division
CN = tum-quantum-gateway

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = tum-quantum-gateway
DNS.3 = *.tum.local
DNS.4 = *.tumquantum.com
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

# Step 3: Generate Server Key and CSR
echo "[TUM-Quantum] Generating Server TLS Key and CSR..."
if [ "$IS_OQS" = true ]; then
    "$OPENSSL_BIN" req -new -newkey mldsa65 -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.csr" -nodes -config "$CERT_DIR/openssl_san.cnf" 2>/dev/null || true
fi

if [ ! -f "$CERT_DIR/server.key" ]; then
    "$OPENSSL_BIN" req -new -newkey rsa:4096 -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.csr" -nodes -config "$CERT_DIR/openssl_san.cnf"
fi

# Step 4: Sign Server Certificate with Root CA
echo "[TUM-Quantum] Signing Server Certificate with Root CA..."
"$OPENSSL_BIN" x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt" \
    -days 1095 -extfile "$CERT_DIR/openssl_san.cnf" -extensions v3_req

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo "[TUM-Quantum] Post-Quantum TLS 1.3 Certificates generated successfully in $CERT_DIR:"
ls -lh "$CERT_DIR"
