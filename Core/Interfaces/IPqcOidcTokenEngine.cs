// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;

namespace Tum.Quantum.Core.Interfaces
{
    /// <summary>
    /// Quantum-Safe OpenID Connect (PQC-OIDC) Token Engine.
    /// Issues and verifies ID Tokens and Access Tokens signed with NIST FIPS 204 (ML-DSA-65) lattice cryptography.
    /// </summary>
    public interface IPqcOidcTokenEngine
    {
        /// <summary>
        /// Issues a signed Post-Quantum ID Token in compact JWT format.
        /// </summary>
        /// <param name="subject">Subject identifier (e.g. did:tum:citizen:1234).</param>
        /// <param name="audience">Target audience / Client ID.</param>
        /// <param name="issuer">Issuer URL.</param>
        /// <param name="customClaims">Optional custom claims (name, role, citizen_id, scopes).</param>
        /// <param name="lifetime">Token validity lifetime (defaults to 1 hour).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Signed PQC-OIDC token package.</returns>
        Task<PqcOidcTokenPackage> IssueIdTokenAsync(
            string subject,
            string audience,
            string issuer = "https://identity.tum.co.th/oauth2/v1",
            IDictionary<string, object>? customClaims = null,
            TimeSpan? lifetime = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates a compact PQC-OIDC token, checking expiry, audience, issuer, and ML-DSA-65 lattice signature.
        /// </summary>
        /// <param name="rawToken">Compact JWT string.</param>
        /// <param name="expectedAudience">Expected audience.</param>
        /// <param name="expectedIssuer">Expected issuer URL.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Validation result.</returns>
        Task<PqcOidcValidationResult> ValidateIdTokenAsync(
            string rawToken,
            string expectedAudience,
            string expectedIssuer = "https://identity.tum.co.th/oauth2/v1",
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the public JWKS keys for public verification of PQC-OIDC tokens.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>List of JWK objects.</returns>
        Task<IList<PqcOidcJwksKey>> GetJwksKeysAsync(CancellationToken cancellationToken = default);
    }
}
