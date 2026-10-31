// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Specifies the migration enforcement mode for evaluating hybrid and legacy cryptographic signatures.
    /// Implements the TUM zero-disruption hybrid migration philosophy ("No One Left Behind").
    /// </summary>
    public enum HybridMigrationMode
    {
        /// <summary>
        /// Permissive migration window. Accepts valid Classical signatures (with quantum deprecation warning),
        /// valid PQC signatures, and Dual-Envelope signatures. Ideal for phased sovereign enterprise rollout.
        /// </summary>
        Permissive = 1,

        /// <summary>
        /// Strict hybrid enforcement. Both Classical (RSA/ECDSA) and PQC (NIST FIPS 204 ML-DSA) signatures
        /// must be present and pass cryptographic verification independently.
        /// </summary>
        StrictHybrid = 2,

        /// <summary>
        /// Enforce Post-Quantum Cryptography only. Classical-only signatures are rejected.
        /// Requires valid NIST FIPS 204 ML-DSA verification.
        /// </summary>
        EnforcePqcOnly = 3,

        /// <summary>
        /// Non-blocking audit mode. Records telemetry and diagnostics on quantum readiness
        /// without failing incoming transactions.
        /// </summary>
        AuditOnly = 4
    }
}
