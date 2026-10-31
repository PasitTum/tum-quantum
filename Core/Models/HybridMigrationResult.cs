// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Detailed evaluation result returned by the Hybrid Permissive Migration Adapter.
    /// Provides audit telemetry, quantum immunity status, and migration guidance.
    /// </summary>
    public class HybridMigrationResult
    {
        /// <summary>
        /// Gets or sets a value indicating whether the signature evaluation passed under the active policy.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the verified signature provides mathematical immunity
        /// against Shor's and Grover's quantum cryptanalysis.
        /// </summary>
        public bool IsQuantumSafe { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether both Classical and PQC branches were verified.
        /// </summary>
        public bool HybridIntegrityVerified { get; set; }

        /// <summary>
        /// Gets or sets the migration mode evaluated.
        /// </summary>
        public HybridMigrationMode ModeEvaluated { get; set; }

        /// <summary>
        /// Gets or sets the granular migration status.
        /// </summary>
        public HybridMigrationStatus Status { get; set; }

        /// <summary>
        /// Gets or sets whether the classical signature branch passed.
        /// </summary>
        public bool ClassicVerified { get; set; }

        /// <summary>
        /// Gets or sets whether the PQC signature branch passed.
        /// </summary>
        public bool PqcVerified { get; set; }

        /// <summary>
        /// Gets or sets the estimated quantum security level in bits.
        /// </summary>
        public int QuantumSecurityBits { get; set; }

        /// <summary>
        /// Gets or sets the execution latency of the verification process in milliseconds.
        /// </summary>
        public double VerificationLatencyMs { get; set; }

        /// <summary>
        /// Gets or sets an error message if verification failed.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets actionable migration guidance and warnings for audit logs and operators.
        /// </summary>
        public string? MigrationGuidance { get; set; }

        /// <summary>
        /// Gets or sets the SHA-256 fingerprint of the PQC public key if verified.
        /// </summary>
        public string? PqcKeyFingerprintSha256 { get; set; }

        /// <summary>
        /// Gets or sets the SHA-256 fingerprint of the Classical public key if verified.
        /// </summary>
        public string? ClassicKeyFingerprintSha256 { get; set; }
    }
}
