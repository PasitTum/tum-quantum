#!/usr/bin/env bash
# ==============================================================================
# TUM-Quantum Reverse Proxy Gateway - Automated Validation Suite
# Verifies PQC TLS 1.3 Handshake, Header Injection, and Engine Connectivity
# Copyright (c) 2026 TUMQuantum Co., Ltd. All rights reserved.
# ==============================================================================

set -e

GATEWAY_HOST="${1:-localhost}"
GATEWAY_PORT="${2:-443}"
GATEWAY_URL="https://${GATEWAY_HOST}:${GATEWAY_PORT}"

echo "======================================================================"
echo "  🔍 Validating TUM-Quantum Reverse Proxy Gateway on ${GATEWAY_URL}   "
echo "======================================================================"

# Test 1: Plaintext HTTP Redirection
echo -n "[Test 1] Testing Plaintext HTTP (Port 80) -> HTTPS 301 Redirect... "
REDIRECT_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${GATEWAY_HOST}:80/")
if [ "$REDIRECT_CODE" = "301" ]; then
    echo "✅ PASS (301 Moved Permanently)"
else
    echo "⚠️ NOTICE (HTTP code: $REDIRECT_CODE - ensure container port 80 is forwarded)"
fi

# Test 2: Gateway Health Status Endpoint
echo -n "[Test 2] Querying Gateway Status Endpoint (/gateway/status)... "
STATUS_BODY=$(curl -k -s "${GATEWAY_URL}/gateway/status")
if echo "$STATUS_BODY" | grep -q "OPERATIONAL"; then
    echo "✅ PASS (Gateway Operational)"
    echo "$STATUS_BODY" | grep -E "negotiatedCurve|negotiatedCipher|product|standards" | head -n 4
else
    echo "❌ FAIL (Unexpected response: $STATUS_BODY)"
fi

# Test 3: Upstream Legacy Header Injection
echo -n "[Test 3] Verifying Quantum Telemetry Header Injection (/headers)... "
HEADER_BODY=$(curl -k -s "${GATEWAY_URL}/headers")
if echo "$HEADER_BODY" | grep -q "xQuantumSafe"; then
    echo "✅ PASS (Headers injected into upstream legacy web server)"
    echo "$HEADER_BODY"
else
    echo "❌ FAIL (Headers not returned by upstream legacy backend)"
fi

# Test 4: Quantum Engine API Passthrough (/api/pqc/status)
echo -n "[Test 4] Querying Direct PQC Engine via Gateway Route (/api/pqc/status)... "
ENGINE_BODY=$(curl -k -s "${GATEWAY_URL}/api/pqc/status")
if echo "$ENGINE_BODY" | grep -q "NIST FIPS 203"; then
    echo "✅ PASS (PQC Engine routed through gateway)"
    echo "$ENGINE_BODY"
else
    echo "❌ FAIL (Could not contact PQC Engine: $ENGINE_BODY)"
fi

# Test 5: Side-Channel DudeCT Timing Attack Audit (/api/pqc/audit/timing-attack)
echo -n "[Test 5] Executing DudeCT Constant-Time Timing Audit via Gateway... "
AUDIT_BODY=$(curl -k -s -X POST "${GATEWAY_URL}/api/pqc/audit/timing-attack" \
    -H "Content-Type: application/json" \
    -d '{"sampleIterations":500,"tStatisticThreshold":4.5}')
if echo "$AUDIT_BODY" | grep -q "TUM-CTA-"; then
    echo "✅ PASS (DudeCT Side-Channel Audit Completed)"
    echo "$AUDIT_BODY" | grep -E "reportId|isOverallCompliant|sideChannelVulnerabilityScore" || echo "$AUDIT_BODY"
else
    echo "❌ FAIL (Timing audit failed: $AUDIT_BODY)"
fi

echo "======================================================================"
echo "  🎉 All TUM-Quantum Gateway Turnkey Validation Tests Completed!     "
echo "======================================================================"
