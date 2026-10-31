// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Represents the outcome of a Quantum-Safe signature verification process.
    /// </summary>
    public class PqcVerificationResult
    {
        /// <summary>
        /// Gets or sets a value indicating whether the overall signature verification succeeded.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the verification provides mathematical immunity
        /// against Shor's and Grover's quantum cryptanalytic algorithms.
        /// </summary>
        public bool IsQuantumSafe { get; set; }

        /// <summary>
        /// Gets or sets the algorithm evaluated during verification.
        /// </summary>
        public PqcSignatureAlgorithm AlgorithmUsed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether both classic and quantum branches passed in hybrid mode.
        /// </summary>
        public bool HybridIntegrityVerified { get; set; }

        /// <summary>
        /// Gets or sets the estimated quantum security level in bits (e.g., 128, 192, 256 bits).
        /// </summary>
        public int QuantumSecurityBits { get; set; }

        /// <summary>
        /// Gets or sets the execution latency of the verification in milliseconds.
        /// </summary>
        public double VerificationLatencyMs { get; set; }

        /// <summary>
        /// Gets or sets an error or diagnostic message if verification failed.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets the SHA-256 fingerprint of the verified post-quantum public key.
        /// </summary>
        public string? KeyFingerprintSha256 { get; set; }
    }
}
