// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.QuantumSafe;

namespace Tum.Trust.Security.Core.Interfaces
{
    /// <summary>
    /// Post-Quantum Cryptography (PQC) Trust Engine for NIST FIPS 204 ML-DSA, CRYSTALS-Dilithium,
    /// and hybrid post-quantum sovereign identity verification.
    /// </summary>
    public interface IQuantumSafeTrustEngine
    {
        /// <summary>
        /// Verifies a post-quantum or hybrid cryptographic signature against a data payload.
        /// </summary>
        /// <param name="request">The verification request containing payload, signatures, and public keys.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A result indicating validity, quantum immunity, and latency metrics.</returns>
        Task<PqcVerificationResult> VerifyQuantumSafeSignatureAsync(PqcVerificationRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// Generates a post-quantum or hybrid key pair according to the specified algorithm.
        /// </summary>
        /// <param name="algorithm">The target PQC algorithm.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A newly generated key pair with public and private components.</returns>
        Task<PqcKeyPair> GeneratePqcKeyPairAsync(PqcSignatureAlgorithm algorithm, CancellationToken cancellationToken = default);

        /// <summary>
        /// Signs a payload using a post-quantum private key.
        /// </summary>
        /// <param name="data">The payload bytes to sign.</param>
        /// <param name="privateKey">The private key bytes.</param>
        /// <param name="algorithm">The PQC algorithm to use.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>The signature bytes.</returns>
        Task<byte[]> SignQuantumSafeAsync(byte[] data, byte[] privateKey, PqcSignatureAlgorithm algorithm, CancellationToken cancellationToken = default);

        /// <summary>
        /// Determines whether a legacy algorithm is vulnerable to Shor's algorithm on quantum computing systems.
        /// </summary>
        /// <param name="algorithmName">The algorithm name (e.g., 'RSA-2048', 'ECDSA-P256', 'ML-DSA-65').</param>
        /// <returns><c>true</c> if vulnerable to quantum cryptanalysis; otherwise <c>false</c>.</returns>
        bool IsAlgorithmDeprecatedByQuantum(string algorithmName);

        /// <summary>
        /// Gets the quantum security strength in bits for the specified algorithm.
        /// </summary>
        /// <param name="algorithm">The PQC algorithm.</param>
        /// <returns>Estimated post-quantum security strength in bits.</returns>
        int GetQuantumSecurityLevelBits(PqcSignatureAlgorithm algorithm);
    }
}
