// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.QuantumSafe;

namespace Tum.Trust.Security.Core.Interfaces
{
    /// <summary>
    /// Hybrid Permissive Migration Adapter interface for transitioning Classical PKI (RSA / ECDSA)
    /// to Post-Quantum Cryptography conforming to NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium).
    /// Enforces the TUM "No One Left Behind" zero-disruption hybrid migration strategy.
    /// </summary>
    public interface IHybridMigrationAdapter
    {
        /// <summary>
        /// Gets the default migration enforcement mode configured on this adapter instance.
        /// </summary>
        HybridMigrationMode DefaultMode { get; }

        /// <summary>
        /// Verifies a hybrid dual-envelope according to the specified migration policy.
        /// </summary>
        /// <param name="envelope">The dual-envelope containing classical and/or PQC signatures.</param>
        /// <param name="policy">Optional migration policy. If null, uses the adapter's default permissive policy.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A detailed verification and migration compliance result.</returns>
        Task<HybridMigrationResult> VerifyEnvelopeAsync(
            HybridDualEnvelope envelope,
            HybridMigrationPolicy? policy = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Verifies signature components with permissive or strict hybrid rules.
        /// </summary>
        /// <param name="payload">The original data payload that was signed.</param>
        /// <param name="classicSignature">Optional classical signature bytes (RSA or ECDSA).</param>
        /// <param name="classicPublicKey">Optional classical public key bytes.</param>
        /// <param name="classicAlgorithm">Optional classical algorithm name (e.g., 'RSA-4096', 'ECDSA-P256').</param>
        /// <param name="pqcSignature">Optional post-quantum signature bytes (NIST FIPS 204 ML-DSA).</param>
        /// <param name="pqcPublicKey">Optional post-quantum public key bytes.</param>
        /// <param name="pqcAlgorithm">The post-quantum algorithm used.</param>
        /// <param name="mode">Optional migration mode override.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A detailed verification and migration compliance result.</returns>
        Task<HybridMigrationResult> VerifyDualEnvelopeAsync(
            byte[] payload,
            byte[]? classicSignature,
            byte[]? classicPublicKey,
            string? classicAlgorithm,
            byte[]? pqcSignature,
            byte[]? pqcPublicKey,
            PqcSignatureAlgorithm pqcAlgorithm,
            HybridMigrationMode? mode = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a signed dual-envelope containing both Classical (RSA/ECDSA) and PQC (ML-DSA) signatures.
        /// </summary>
        /// <param name="payload">The data payload to sign.</param>
        /// <param name="classicPrivateKey">The classical private key bytes.</param>
        /// <param name="classicAlgorithm">The classical algorithm name (e.g. 'RSA-2048', 'ECDSA-P256').</param>
        /// <param name="classicPublicKey">The classical public key bytes.</param>
        /// <param name="pqcPrivateKey">The post-quantum private key bytes.</param>
        /// <param name="pqcAlgorithm">The post-quantum algorithm (e.g. ML-DSA-65).</param>
        /// <param name="pqcPublicKey">The post-quantum public key bytes.</param>
        /// <param name="contextId">Optional context or transaction ID.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>The generated hybrid dual-envelope.</returns>
        Task<HybridDualEnvelope> CreateDualEnvelopeAsync(
            byte[] payload,
            byte[] classicPrivateKey,
            string classicAlgorithm,
            byte[] classicPublicKey,
            byte[] pqcPrivateKey,
            PqcSignatureAlgorithm pqcAlgorithm,
            byte[] pqcPublicKey,
            string? contextId = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Augments an existing legacy classical signature by appending a post-quantum ML-DSA signature,
        /// elevating a legacy transaction to a quantum-resistant dual-envelope.
        /// </summary>
        /// <param name="payload">The original data payload that was signed.</param>
        /// <param name="classicSignature">The existing classical signature bytes.</param>
        /// <param name="classicPublicKey">The existing classical public key bytes.</param>
        /// <param name="classicAlgorithm">The existing classical algorithm name.</param>
        /// <param name="pqcPrivateKey">The post-quantum private key bytes.</param>
        /// <param name="pqcAlgorithm">The post-quantum algorithm to sign with.</param>
        /// <param name="pqcPublicKey">The post-quantum public key bytes.</param>
        /// <param name="contextId">Optional context or transaction ID.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>The elevated hybrid dual-envelope.</returns>
        Task<HybridDualEnvelope> UpgradeLegacyToDualEnvelopeAsync(
            byte[] payload,
            byte[] classicSignature,
            byte[] classicPublicKey,
            string classicAlgorithm,
            byte[] pqcPrivateKey,
            PqcSignatureAlgorithm pqcAlgorithm,
            byte[] pqcPublicKey,
            string? contextId = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Extracts classical legacy components from a dual-envelope for backward compatibility with older clients.
        /// </summary>
        /// <param name="envelope">The dual-envelope.</param>
        /// <returns>The extracted legacy signature package.</returns>
        LegacySignaturePackage ExtractLegacyPackage(HybridDualEnvelope envelope);

        /// <summary>
        /// Evaluates the quantum vulnerability and migration risk of a cryptographic algorithm.
        /// </summary>
        /// <param name="algorithmName">The algorithm name to assess.</param>
        /// <returns>A quantum risk assessment report.</returns>
        QuantumRiskAssessment AssessAlgorithmRisk(string algorithmName);
    }
}
