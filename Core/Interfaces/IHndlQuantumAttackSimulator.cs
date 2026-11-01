// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;

namespace Tum.Quantum.Core.Interfaces
{
    /// <summary>
    /// Evaluates and simulates Harvest Now, Decrypt Later (HNDL) quantum cryptanalytic attacks
    /// against classical public-key infrastructure (RSA / ECC) vs NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).
    /// </summary>
    public interface IHndlQuantumAttackSimulator
    {
        /// <summary>
        /// Executes an HNDL attack simulation against a targeted cryptographic asset or intercepted session.
        /// </summary>
        /// <param name="request">Parameters describing the harvested asset, algorithm, cipher, and adversary hardware.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Comprehensive simulation result with forward secrecy status and vulnerability metrics.</returns>
        Task<HndlSimulationResult> SimulateAttackAsync(HndlSimulationRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// Evaluates a batch of intercepted network sessions, cryptographic certificates, or archival stores.
        /// </summary>
        /// <param name="request">Batch harvest analysis parameters.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Consolidated scorecard and quantum readiness percentage.</returns>
        Task<HndlHarvestBatchResult> SimulateBatchHarvestAsync(HndlHarvestBatchRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// Calculates theoretical quantum cryptanalysis complexity metrics (logical/physical qubits, circuit depth)
        /// using Shor's and Grover's algorithm formulas.
        /// </summary>
        /// <param name="algorithmName">The algorithm name (e.g., 'RSA-2048', 'ECDSA-P256', 'ML-KEM-768').</param>
        /// <returns>Theoretical complexity metrics.</returns>
        QuantumCryptanalysisMetrics CalculateTheoreticalComplexity(string algorithmName);

        /// <summary>
        /// Determines whether a given combination of key exchange and bulk encryption is vulnerable to retroactive decryption.
        /// </summary>
        /// <param name="keyExchangeAlgorithm">The key exchange or encapsulation scheme (e.g., 'ECDHE-P256', 'RSA-2048', 'ML-KEM-768').</param>
        /// <param name="bulkEncryptionAlgorithm">The bulk cipher (e.g., 'AES-128-GCM', 'AES-256-GCM').</param>
        /// <returns><c>true</c> if vulnerable to HNDL attack; otherwise <c>false</c>.</returns>
        bool EvaluateForwardSecrecyVulnerability(string keyExchangeAlgorithm, string bulkEncryptionAlgorithm);
    }
}
