// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Outcome of a simulated Harvest Now, Decrypt Later (HNDL) quantum attack.
    /// </summary>
    public class HndlSimulationResult
    {
        /// <summary>
        /// Gets or sets the target algorithm evaluated.
        /// </summary>
        public string TargetAlgorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets whether the harvested data is vulnerable to retroactive quantum decryption or signature forging.
        /// </summary>
        public bool IsHarvestVulnerable { get; set; }

        /// <summary>
        /// Gets or sets whether the mathematical secret was successfully derived using Shor's or Grover's algorithm.
        /// </summary>
        public bool IsDecryptedByShor { get; set; }

        /// <summary>
        /// Gets or sets the forward secrecy status under quantum cryptanalysis.
        /// </summary>
        public HndlForwardSecrecyStatus ForwardSecrecyStatus { get; set; }

        /// <summary>
        /// Gets or sets the assessed risk severity level.
        /// </summary>
        public HndlRiskSeverity VulnerabilitySeverity { get; set; }

        /// <summary>
        /// Gets or sets the quantitative risk score from 0.0 (Quantum Immune) to 100.0 (Completely Broken).
        /// </summary>
        public double VulnerabilityScore { get; set; }

        /// <summary>
        /// Gets or sets theoretical cryptanalysis metrics for the target algorithm.
        /// </summary>
        public QuantumCryptanalysisMetrics CryptanalysisMetrics { get; set; } = new();

        /// <summary>
        /// Gets or sets the estimated time required for the adversary's quantum hardware to break this session.
        /// </summary>
        public string EstimatedBreakTimeDescription { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the primary attack vector used against this cryptographic primitive.
        /// </summary>
        public string PrimaryAttackVector { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets comprehensive architectural and security analysis from the quantum simulator.
        /// </summary>
        public string SimulationAnalysis { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets actionable remediation guidance according to NIST FIPS PQC standards.
        /// </summary>
        public string RecommendedMitigation { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the decrypted plaintext bytes if the cipher was successfully broken in simulation.
        /// </summary>
        public byte[]? SimulatedDecryptedPayload { get; set; }

        /// <summary>
        /// Gets or sets simulation execution latency in milliseconds.
        /// </summary>
        public double SimulationDurationMs { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the simulation was executed.
        /// </summary>
        public DateTimeOffset SimulatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
