// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Threat scenario for Harvest Now, Decrypt Later (HNDL) attacks.
    /// </summary>
    public enum HndlAttackScenario
    {
        /// <summary>
        /// Intercepted TLS session handshake where session keys are encrypted with classical asymmetric algorithms.
        /// </summary>
        HarvestedTlsHandshake,

        /// <summary>
        /// Encrypted archival storage, backups, or databases stored using classical asymmetric envelopes.
        /// </summary>
        ArchivalStorageBreach,

        /// <summary>
        /// Long-term identity assertions or certificates forged retroactively by cracking the root CA or signer key.
        /// </summary>
        DigitalSignatureForging,

        /// <summary>
        /// Handshake protected by NIST FIPS 203 ML-KEM or dual-envelope hybrid key encapsulation.
        /// </summary>
        PqcHybridEncapsulation
    }

    /// <summary>
    /// Forward secrecy status evaluated under quantum cryptanalysis.
    /// </summary>
    public enum HndlForwardSecrecyStatus
    {
        /// <summary>
        /// Compromised: Classical key exchange permits future full plaintext recovery via Shor's algorithm.
        /// </summary>
        Compromised,

        /// <summary>
        /// Protected: Protected by NIST FIPS 203 (ML-KEM) lattice encapsulation; immune to Shor's algorithm.
        /// </summary>
        PqcProtected,

        /// <summary>
        /// Immune: Quantum-safe symmetric cipher with adequate key length (>= 256 bits) or pure lattice PQC.
        /// </summary>
        Immune,

        /// <summary>
        /// Degraded: Classical signature component broken, but payload remains confidential via PQC KEM.
        /// </summary>
        Degraded
    }

    /// <summary>
    /// Severity level of the quantum exposure.
    /// </summary>
    public enum HndlRiskSeverity
    {
        /// <summary>
        /// Critical: Immediately breakable upon CRQC arrival; high-value archival data compromised retroactively.
        /// </summary>
        Critical,

        /// <summary>
        /// High: Vulnerable classical algorithm; session key derivation breaks forward secrecy.
        /// </summary>
        High,

        /// <summary>
        /// Medium: Symmetric cipher vulnerable to Grover speedup (e.g., AES-128 reduced to 64-bit security).
        /// </summary>
        Medium,

        /// <summary>
        /// Low: Hybrid scheme with weak classical parameter but strong PQC component.
        /// </summary>
        Low,

        /// <summary>
        /// Immune: Fully compliant with NIST FIPS 203/204 with >= 128 bits post-quantum security margin.
        /// </summary>
        Immune
    }

    /// <summary>
    /// Hardware generation and capability assumptions for the simulated quantum adversary.
    /// </summary>
    public class QuantumHardwareProfile
    {
        /// <summary>
        /// Gets or sets the name or generation of the quantum architecture.
        /// </summary>
        public string ArchitectureName { get; set; } = "Fault-Tolerant Superconducting CRQC";

        /// <summary>
        /// Gets or sets the total number of physical qubits available to the adversary.
        /// </summary>
        public long PhysicalQubits { get; set; } = 20_000_000;

        /// <summary>
        /// Gets or sets the number of logical fault-tolerant qubits achievable after error correction.
        /// </summary>
        public int LogicalQubits { get; set; } = 10_000;

        /// <summary>
        /// Gets or sets the physical gate error rate (e.g. 1e-4).
        /// </summary>
        public double PhysicalErrorRate { get; set; } = 1e-4;

        /// <summary>
        /// Gets or sets the surface code distance for quantum error correction.
        /// </summary>
        public int SurfaceCodeDistance { get; set; } = 27;

        /// <summary>
        /// Gets or sets the simulated year when this quantum hardware becomes operational.
        /// </summary>
        public int OperationalYear { get; set; } = 2030;

        /// <summary>
        /// Returns a default profile simulating an adversary with an early CRQC (Cryptanalytically Relevant Quantum Computer).
        /// </summary>
        public static QuantumHardwareProfile CreateStandardAdversary() => new()
        {
            ArchitectureName = "State-Sponsored Early CRQC (Surface Code)",
            PhysicalQubits = 15_000_000,
            LogicalQubits = 6_000,
            PhysicalErrorRate = 1e-4,
            SurfaceCodeDistance = 25,
            OperationalYear = 2030
        };

        /// <summary>
        /// Returns a profile simulating modern NISQ hardware (incapable of running Shor's algorithm on enterprise keys).
        /// </summary>
        public static QuantumHardwareProfile CreateNisqEra() => new()
        {
            ArchitectureName = "NISQ Intermediate Scale (No Logical Error Correction)",
            PhysicalQubits = 1_121,
            LogicalQubits = 0,
            PhysicalErrorRate = 1e-3,
            SurfaceCodeDistance = 0,
            OperationalYear = 2026
        };
    }
}
