// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;

namespace Tum.Quantum.Core.Interfaces
{
    /// <summary>
    /// Executes automated validation and compliance audits against NIST FIPS 140-3
    /// (Security Requirements for Cryptographic Modules) for post-quantum primitives.
    /// </summary>
    public interface IFips140AuditRunner
    {
        /// <summary>
        /// Executes full FIPS 140-3 readiness audit across all 11 operational sections for the target security level.
        /// </summary>
        /// <param name="targetLevel">Target FIPS 140-3 Security Level (Level 1 to 4).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Comprehensive readiness report with KAT results and entropy score.</returns>
        Task<Fips140AuditReport> RunFips140ReadinessAuditAsync(Fips140SecurityLevel targetLevel = Fips140SecurityLevel.Level3, CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes power-up cryptographic self-tests (POST) on all approved algorithms (ML-DSA, ML-KEM, SHA-384, AES-256).
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><c>true</c> if all KAT tests pass; otherwise <c>false</c>.</returns>
        Task<bool> RunPowerUpSelfTestsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Verifies Critical Security Parameter (CSP) zeroization mechanism.
        /// Ensures sensitive key buffers are overwritten with zeros immediately upon command or tamper event.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><c>true</c> if memory scrub and zeroization verified; otherwise <c>false</c>.</returns>
        Task<bool> VerifyCspZeroizationAsync(CancellationToken cancellationToken = default);
    }
}
