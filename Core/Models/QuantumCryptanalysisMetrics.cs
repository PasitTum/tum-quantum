// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Theoretical quantum cryptanalysis complexity metrics calculated from NIST &amp; scientific literature.
    /// </summary>
    public class QuantumCryptanalysisMetrics
    {
        /// <summary>
        /// Gets or sets the target cryptographic algorithm name.
        /// </summary>
        public string AlgorithmName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the cryptographic category (e.g., ClassicalAsymmetric, ClassicalSymmetric, LatticePqc).
        /// </summary>
        public string CryptographicFamily { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the classical key size or security parameter in bits.
        /// </summary>
        public int KeySizeBits { get; set; }

        /// <summary>
        /// Gets or sets the theoretical minimum logical qubits required to execute Shor's algorithm.
        /// Returns 0 if immune to Shor's algorithm (e.g., Lattice PQC or symmetric ciphers).
        /// </summary>
        public int ShorLogicalQubitsRequired { get; set; }

        /// <summary>
        /// Gets or sets the estimated physical qubits required using surface-code error correction.
        /// </summary>
        public long EstimatedPhysicalQubitsRequired { get; set; }

        /// <summary>
        /// Gets or sets the estimated Toffoli gate depth or quantum circuit runtime.
        /// </summary>
        public string QuantumCircuitDepth { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the post-quantum effective security margin in bits against all known quantum attacks.
        /// </summary>
        public int PostQuantumSecurityBits { get; set; }

        /// <summary>
        /// Gets or sets whether this algorithm is mathematically immune to polynomial-time quantum cryptanalysis.
        /// </summary>
        public bool IsQuantumImmune { get; set; }

        /// <summary>
        /// Gets or sets the primary mathematical problem underlying security (e.g., Prime Factorization, Discrete Logarithm, M-LWE, M-SIS).
        /// </summary>
        public string MathematicalHardnessAssumption { get; set; } = string.Empty;
    }
}
