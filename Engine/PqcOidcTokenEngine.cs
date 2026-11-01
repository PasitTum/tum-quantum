// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Quantum.Core.Interfaces;
using Tum.Quantum.Core.Models;
using Tum.Trust.Security.Core.Interfaces;
using Tum.Trust.Security.Core.Models.QuantumSafe;
using Tum.Trust.Security.Infrastructure.Security;

namespace Tum.Quantum.Engine
{
    /// <summary>
    /// Production implementation of Quantum-Safe OpenID Connect (PQC-OIDC) Token Engine.
    /// Signs and verifies compact JWT ID Tokens using NIST FIPS 204 (ML-DSA-65) lattice cryptography.
    /// </summary>
    public class PqcOidcTokenEngine : IPqcOidcTokenEngine
    {
        private readonly IQuantumSafeTrustEngine _quantumEngine;
        private readonly ILogger<PqcOidcTokenEngine> _logger;

        private PqcKeyPair? _signingKey;
        private string? _keyId;
        private readonly SemaphoreSlim _keyLock = new(1, 1);

        /// <summary>
        /// Initializes a new instance of the <see cref="PqcOidcTokenEngine"/> class.
        /// </summary>
        public PqcOidcTokenEngine(
            IQuantumSafeTrustEngine? quantumEngine = null,
            ILogger<PqcOidcTokenEngine>? logger = null)
        {
            _quantumEngine = quantumEngine ?? new QuantumSafeTrustEngine();
            _logger = logger ?? NullLogger<PqcOidcTokenEngine>.Instance;
        }

        /// <inheritdoc />
        public async Task<PqcOidcTokenPackage> IssueIdTokenAsync(
            string subject,
            string audience,
            string issuer = "https://identity.tum.co.th/oauth2/v1",
            IDictionary<string, object>? customClaims = null,
            TimeSpan? lifetime = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(subject)) throw new ArgumentException("Subject cannot be empty.", nameof(subject));
            if (string.IsNullOrWhiteSpace(audience)) throw new ArgumentException("Audience cannot be empty.", nameof(audience));

            await EnsureSigningKeyAsync(cancellationToken).ConfigureAwait(false);

            var now = DateTimeOffset.UtcNow;
            var validity = lifetime ?? TimeSpan.FromHours(1);
            var expires = now.Add(validity);

            var claims = new PqcOidcClaims
            {
                Iss = issuer,
                Sub = subject,
                Aud = audience,
                Iat = now.ToUnixTimeSeconds(),
                Nbf = now.ToUnixTimeSeconds(),
                Exp = expires.ToUnixTimeSeconds(),
                Jti = Guid.NewGuid().ToString("D"),
                CustomClaims = customClaims != null ? new Dictionary<string, object>(customClaims) : new Dictionary<string, object>()
            };

            // 1. Build JOSE Header
            var header = new Dictionary<string, string>
            {
                ["alg"] = "ML-DSA-65",
                ["typ"] = "JWT",
                ["kid"] = _keyId!
            };

            string headerJson = JsonSerializer.Serialize(header);
            string headerBase64Url = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));

            // 2. Build Payload
            var payloadMap = new Dictionary<string, object>
            {
                ["iss"] = claims.Iss,
                ["sub"] = claims.Sub,
                ["aud"] = claims.Aud,
                ["iat"] = claims.Iat,
                ["nbf"] = claims.Nbf,
                ["exp"] = claims.Exp,
                ["jti"] = claims.Jti,
                ["acr"] = claims.Acr,
                ["amr"] = claims.Amr
            };

            foreach (var kvp in claims.CustomClaims)
            {
                payloadMap[kvp.Key] = kvp.Value;
            }

            string payloadJson = JsonSerializer.Serialize(payloadMap);
            string payloadBase64Url = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

            // 3. Signing Input: Header.Payload
            string signingInput = $"{headerBase64Url}.{payloadBase64Url}";
            byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

            // 4. Lattice Signature: NIST FIPS 204 ML-DSA-65
            byte[] signature = await _quantumEngine.SignQuantumSafeAsync(
                signingInputBytes,
                _signingKey!.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                cancellationToken).ConfigureAwait(false);

            string signatureBase64Url = Base64UrlEncode(signature);
            string rawToken = $"{signingInput}.{signatureBase64Url}";

            _logger.LogInformation("PQC-OIDC Token issued: Sub={Sub}, Aud={Aud}, Kid={Kid}", subject, audience, _keyId);

            return new PqcOidcTokenPackage
            {
                RawToken = rawToken,
                KeyId = _keyId!,
                Subject = subject,
                ExpiresAtUtc = expires,
                Claims = claims
            };
        }

        /// <inheritdoc />
        public async Task<PqcOidcValidationResult> ValidateIdTokenAsync(
            string rawToken,
            string expectedAudience,
            string expectedIssuer = "https://identity.tum.co.th/oauth2/v1",
            CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();

            if (string.IsNullOrWhiteSpace(rawToken))
            {
                return new PqcOidcValidationResult { IsValid = false, ErrorMessage = "Token string cannot be empty." };
            }

            string[] parts = rawToken.Split('.');
            if (parts.Length != 3)
            {
                return new PqcOidcValidationResult { IsValid = false, ErrorMessage = "Malformed compact JWT: expected 3 dot-separated parts." };
            }

            try
            {
                await EnsureSigningKeyAsync(cancellationToken).ConfigureAwait(false);

                // Decode Header
                byte[] headerBytes = Base64UrlDecode(parts[0]);
                using var headerDoc = JsonDocument.Parse(headerBytes);
                string alg = headerDoc.RootElement.GetProperty("alg").GetString() ?? string.Empty;

                if (!alg.Equals("ML-DSA-65", StringComparison.OrdinalIgnoreCase))
                {
                    return new PqcOidcValidationResult { IsValid = false, ErrorMessage = $"Unsupported PQC algorithm: {alg}" };
                }

                // Decode Payload
                byte[] payloadBytes = Base64UrlDecode(parts[1]);
                using var payloadDoc = JsonDocument.Parse(payloadBytes);
                var root = payloadDoc.RootElement;

                string iss = root.TryGetProperty("iss", out var issProp) ? issProp.GetString() ?? string.Empty : string.Empty;
                string sub = root.TryGetProperty("sub", out var subProp) ? subProp.GetString() ?? string.Empty : string.Empty;
                string aud = root.TryGetProperty("aud", out var audProp) ? audProp.GetString() ?? string.Empty : string.Empty;
                long exp = root.TryGetProperty("exp", out var expProp) ? expProp.GetInt64() : 0;
                long nbf = root.TryGetProperty("nbf", out var nbfProp) ? nbfProp.GetInt64() : 0;
                long iat = root.TryGetProperty("iat", out var iatProp) ? iatProp.GetInt64() : 0;

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                // Validate Lifetime and Claims
                if (!string.Equals(iss, expectedIssuer, StringComparison.Ordinal))
                {
                    return new PqcOidcValidationResult { IsValid = false, ErrorMessage = $"Issuer mismatch: expected '{expectedIssuer}', got '{iss}'." };
                }

                if (!string.Equals(aud, expectedAudience, StringComparison.Ordinal))
                {
                    return new PqcOidcValidationResult { IsValid = false, ErrorMessage = $"Audience mismatch: expected '{expectedAudience}', got '{aud}'." };
                }

                if (now > exp)
                {
                    return new PqcOidcValidationResult { IsValid = false, ErrorMessage = "Token has expired." };
                }

                if (now < (nbf - 30)) // 30s clock skew tolerance
                {
                    return new PqcOidcValidationResult { IsValid = false, ErrorMessage = "Token not yet valid (nbf check failed)." };
                }

                // Verify Lattice Signature
                string signingInput = $"{parts[0]}.{parts[1]}";
                byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);
                byte[] signatureBytes = Base64UrlDecode(parts[2]);

                var verifyReq = new PqcVerificationRequest
                {
                    Payload = signingInputBytes,
                    PqcSignature = signatureBytes,
                    PqcPublicKey = _signingKey!.PublicKey,
                    Algorithm = PqcSignatureAlgorithm.MlDsa65
                };

                var verifyRes = await _quantumEngine.VerifyQuantumSafeSignatureAsync(verifyReq, cancellationToken).ConfigureAwait(false);

                sw.Stop();

                if (!verifyRes.IsValid)
                {
                    return new PqcOidcValidationResult
                    {
                        IsValid = false,
                        IsQuantumSafe = false,
                        ErrorMessage = "Cryptographic signature verification failed: invalid ML-DSA-65 signature.",
                        LatencyMs = sw.Elapsed.TotalMilliseconds
                    };
                }

                var claims = new PqcOidcClaims
                {
                    Iss = iss,
                    Sub = sub,
                    Aud = aud,
                    Exp = exp,
                    Nbf = nbf,
                    Iat = iat
                };

                return new PqcOidcValidationResult
                {
                    IsValid = true,
                    IsQuantumSafe = true,
                    Subject = sub,
                    Claims = claims,
                    LatencyMs = sw.Elapsed.TotalMilliseconds
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new PqcOidcValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Token parsing error: {ex.Message}",
                    LatencyMs = sw.Elapsed.TotalMilliseconds
                };
            }
        }

        /// <inheritdoc />
        public async Task<IList<PqcOidcJwksKey>> GetJwksKeysAsync(CancellationToken cancellationToken = default)
        {
            await EnsureSigningKeyAsync(cancellationToken).ConfigureAwait(false);

            return new List<PqcOidcJwksKey>
            {
                new()
                {
                    Kty = "PQC",
                    Use = "sig",
                    Alg = "ML-DSA-65",
                    Kid = _keyId!,
                    X = Base64UrlEncode(_signingKey!.PublicKey)
                }
            };
        }

        private async Task EnsureSigningKeyAsync(CancellationToken ct)
        {
            if (_signingKey != null) return;

            await _keyLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_signingKey == null)
                {
                    _signingKey = await _quantumEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65, ct).ConfigureAwait(false);
                    using var sha256 = SHA256.Create();
                    byte[] hash = sha256.ComputeHash(_signingKey.PublicKey);
                    _keyId = Base64UrlEncode(hash)[..16];
                }
            }
            finally
            {
                _keyLock.Release();
            }
        }

        private static string Base64UrlEncode(byte[] input)
        {
            string base64 = Convert.ToBase64String(input);
            return base64.Replace("+", "-").Replace("/", "_").Replace("=", "");
        }

        private static byte[] Base64UrlDecode(string input)
        {
            string base64 = input.Replace("-", "+").Replace("_", "/");
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }
}
