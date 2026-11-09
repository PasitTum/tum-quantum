# ==============================================================================
# TUM-Quantum Reverse Proxy Gateway Dockerfile
# Native Post-Quantum Cryptography (NIST FIPS 203 ML-KEM & FIPS 204 ML-DSA)
# Terminates PQC TLS 1.3 and protects legacy Web Servers (Nginx / IIS / Apache)
# Copyright (c) 2026 TUMQuantum Co., Ltd. All rights reserved.
# ==============================================================================

# Production Stage: Open-Quantum-Safe Nginx runtime with liboqs and oqs-provider
FROM openquantumsafe/nginx:latest

LABEL maintainer="TUMQuantum Architecture Team <quantum@tum.co.th>"
LABEL description="TUM-Quantum Reverse Proxy Gateway with NIST FIPS 203 & 204 TLS 1.3 Termination"
LABEL version="1.0.0-FIPS203-204"

USER root

# Install essential operational tools
RUN if command -v apt-get >/dev/null 2>&1; then \
        apt-get update && apt-get install -y --no-install-recommends curl openssl ca-certificates && rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache curl openssl ca-certificates; \
    fi

# Setup directory structure for SSL certificates and proxy logs
RUN mkdir -p /etc/ssl/tum-quantum /var/log/nginx /var/cache/nginx

# Copy custom Nginx configuration and entrypoint scripts
COPY nginx.conf /etc/nginx/nginx.conf
COPY generate-pqc-certs.sh /usr/local/bin/generate-pqc-certs.sh
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/generate-pqc-certs.sh /usr/local/bin/docker-entrypoint.sh

# Pre-generate self-signed sovereign PQC certificates during build
RUN /usr/local/bin/generate-pqc-certs.sh

# Expose HTTP (80) and Quantum-Safe HTTPS (443)
EXPOSE 80 443

# Healthcheck testing the local Quantum Status endpoint over HTTPS
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -k -f https://localhost/gateway/status || curl -f http://localhost/gateway/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
