// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Quantum risk audit and vulnerability assessment for cryptographic algorithms.
    /// </summary>
    public class QuantumRiskAssessment
    {
        /// <summary>
        /// Gets or sets the algorithm evaluated.
        /// </summary>
        public string AlgorithmName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets whether the algorithm is deprecated by quantum computers (Shor's algorithm).
        /// </summary>
        public bool IsDeprecatedByQuantum { get; set; }

        /// <summary>
        /// Gets or sets the assessed risk level (Critical, High, Medium, Low, QuantumSafe).
        /// </summary>
        public string RiskLevel { get; set; } = "Unknown";

        /// <summary>
        /// Gets or sets description of the cryptographic threat vector (e.g., Shor's factoring, Discrete Log).
        /// </summary>
        public string ThreatVector { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the recommended post-quantum migration target (e.g., NIST FIPS 204 ML-DSA-65).
        /// </summary>
        public string RecommendedMigrationTarget { get; set; } = "NIST FIPS 204 ML-DSA-65";

        /// <summary>
        /// Gets or sets the estimated quantum break horizon.
        /// </summary>
        public string EstimatedHorizon { get; set; } = string.Empty;
    }
}
