// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Post-Quantum Cryptography (PQC) signature algorithms conforming to NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium)
    /// and hybrid quantum-resistant envelopes.
    /// </summary>
    public enum PqcSignatureAlgorithm
    {
        /// <summary>
        /// NIST FIPS 204 ML-DSA-44 (CRYSTALS-Dilithium Level 2). Equivalent to ~128-bit quantum security.
        /// </summary>
        MlDsa44 = 1,

        /// <summary>
        /// NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium Level 3 - Enterprise Standard). Equivalent to ~192-bit quantum security.
        /// </summary>
        MlDsa65 = 2,

        /// <summary>
        /// NIST FIPS 204 ML-DSA-87 (CRYSTALS-Dilithium Level 5 - Military Grade). Equivalent to ~256-bit quantum security.
        /// </summary>
        MlDsa87 = 3,

        /// <summary>
        /// NIST FIPS 203 ML-KEM-512 (CRYSTALS-Kyber Level 1 Key Encapsulation).
        /// </summary>
        MlKem512 = 4,

        /// <summary>
        /// NIST FIPS 203 ML-KEM-768 (CRYSTALS-Kyber Level 3 Key Encapsulation).
        /// </summary>
        MlKem768 = 5,

        /// <summary>
        /// NIST FIPS 203 ML-KEM-1024 (CRYSTALS-Kyber Level 5 Key Encapsulation).
        /// </summary>
        MlKem1024 = 6,

        /// <summary>
        /// Hybrid Dual Envelope: RSA-4096 (Classic) + ML-DSA-65 (Post-Quantum Lattice).
        /// </summary>
        HybridRsa4096Dilithium = 10,

        /// <summary>
        /// Hybrid Dual Envelope: ECDSA P-384 (Classic) + ML-DSA-65 (Post-Quantum Lattice).
        /// </summary>
        HybridEcdsaDilithium = 11
    }
}
