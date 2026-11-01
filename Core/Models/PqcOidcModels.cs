// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Quantum-Safe OpenID Connect (PQC-OIDC) JSON Web Key (JWK) conforming to JOSE specifications.
    /// </summary>
    public class PqcOidcJwksKey
    {
        /// <summary>
        /// Key Type ("PQC").
        /// </summary>
        public string Kty { get; set; } = "PQC";

        /// <summary>
        /// Key Use ("sig").
        /// </summary>
        public string Use { get; set; } = "sig";

        /// <summary>
        /// Algorithm ("ML-DSA-65" or "ML-DSA-44").
        /// </summary>
        public string Alg { get; set; } = "ML-DSA-65";

        /// <summary>
        /// Key ID (Key Fingerprint SHA-256).
        /// </summary>
        public string Kid { get; set; } = string.Empty;

        /// <summary>
        /// Base64Url-encoded Post-Quantum Public Key.
        /// </summary>
        public string X { get; set; } = string.Empty;
    }

    /// <summary>
    /// OpenID Connect standard claims payload with Sovereign Identity extensions.
    /// </summary>
    public class PqcOidcClaims
    {
        /// <summary>
        /// Issuer identifier URL.
        /// </summary>
        public string Iss { get; set; } = string.Empty;

        /// <summary>
        /// Subject identifier (DID or Citizen Identifier).
        /// </summary>
        public string Sub { get; set; } = string.Empty;

        /// <summary>
        /// Audience (client ID or relying party).
        /// </summary>
        public string Aud { get; set; } = string.Empty;

        /// <summary>
        /// Expiration time in Unix seconds.
        /// </summary>
        public long Exp { get; set; }

        /// <summary>
        /// Issued at time in Unix seconds.
        /// </summary>
        public long Iat { get; set; }

        /// <summary>
        /// Not before time in Unix seconds.
        /// </summary>
        public long Nbf { get; set; }

        /// <summary>
        /// Unique token identifier (JTI UUID).
        /// </summary>
        public string Jti { get; set; } = string.Empty;

        /// <summary>
        /// Authentication Context Class Reference (e.g. "https://identity.tum.co.th/assurance/ial3/aal3").
        /// </summary>
        public string Acr { get; set; } = "https://identity.tum.co.th/assurance/ial3/aal3";

        /// <summary>
        /// Authentication Methods References.
        /// </summary>
        public IList<string> Amr { get; set; } = new List<string> { "pqc_smartcard", "biometric_3d" };

        /// <summary>
        /// Custom user or organization claims.
        /// </summary>
        public IDictionary<string, object> CustomClaims { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// Complete signed PQC-OIDC ID Token package.
    /// </summary>
    public class PqcOidcTokenPackage
    {
        /// <summary>
        /// Compact serialized token (Header.Payload.PqcSignature).
        /// </summary>
        public string RawToken { get; set; } = string.Empty;

        /// <summary>
        /// Key ID used for signing.
        /// </summary>
        public string KeyId { get; set; } = string.Empty;

        /// <summary>
        /// Target subject.
        /// </summary>
        public string Subject { get; set; } = string.Empty;

        /// <summary>
        /// Token expiration in UTC.
        /// </summary>
        public DateTimeOffset ExpiresAtUtc { get; set; }

        /// <summary>
        /// Claims embedded within the token.
        /// </summary>
        public PqcOidcClaims Claims { get; set; } = new();
    }

    /// <summary>
    /// Outcome of validating a PQC-OIDC Token.
    /// </summary>
    public class PqcOidcValidationResult
    {
        /// <summary>
        /// Gets or sets whether the token is valid, active, and cryptographically untampered.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets whether the signature is verified using post-quantum lattice cryptography.
        /// </summary>
        public bool IsQuantumSafe { get; set; }

        /// <summary>
        /// Gets or sets authenticated subject identifier.
        /// </summary>
        public string Subject { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets verified claims dictionary.
        /// </summary>
        public PqcOidcClaims? Claims { get; set; }

        /// <summary>
        /// Gets or sets error message if validation failed.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets validation latency in milliseconds.
        /// </summary>
        public double LatencyMs { get; set; }
    }
}
