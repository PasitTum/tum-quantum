// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Granular outcome status for hybrid cryptographic and migration compliance evaluation.
    /// </summary>
    public enum HybridMigrationStatus
    {
        /// <summary>
        /// Both Classical (RSA/ECDSA) and Post-Quantum (ML-DSA) signatures verified successfully. Full quantum immunity.
        /// </summary>
        QuantumSafeHybrid = 1,

        /// <summary>
        /// Classical signature is valid, but Post-Quantum signature is absent. Permitted under Permissive mode,
        /// but vulnerable to Shor's algorithm on quantum systems.
        /// </summary>
        PermittedLegacyWarning = 2,

        /// <summary>
        /// Post-Quantum ML-DSA signature is valid, Classical signature is absent. Quantum immune.
        /// </summary>
        QuantumSafePqcOnly = 3,

        /// <summary>
        /// Classical signature is valid, but the Post-Quantum signature failed verification.
        /// </summary>
        ClassicValidPqcFailed = 4,

        /// <summary>
        /// Post-Quantum signature is valid, but Classical signature failed verification.
        /// </summary>
        PqcValidClassicFailed = 5,

        /// <summary>
        /// Classical-only signature rejected because current policy requires PQC or Strict Hybrid.
        /// </summary>
        RejectedLegacy = 6,

        /// <summary>
        /// Cryptographic signature verification failed (mismatch or corrupted signature).
        /// </summary>
        SignatureInvalid = 7,

        /// <summary>
        /// Request or envelope payload is empty, null, or corrupted.
        /// </summary>
        InvalidPayload = 8
    }
}
