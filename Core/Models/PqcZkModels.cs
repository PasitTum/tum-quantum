// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Type of attribute predicate proven in zero knowledge.
    /// </summary>
    public enum PqcZkProofType
    {
        /// <summary>
        /// Proves age >= threshold without disclosing exact date of birth or age.
        /// </summary>
        AgeVerification,

        /// <summary>
        /// Proves valid citizenship or sovereign jurisdiction clearance without disclosing citizen ID.
        /// </summary>
        CitizenshipAffirmation,

        /// <summary>
        /// Proves financial solvency >= threshold without revealing bank account balance.
        /// </summary>
        SolvencyThreshold,

        /// <summary>
        /// Proves authorized AI agent permission scope without disclosing agent secrets.
        /// </summary>
        AgentCapabilityGrant
    }

    /// <summary>
    /// Non-interactive zero-knowledge proof package based on post-quantum lattice commitments.
    /// </summary>
    public class PqcZkProofPackage
    {
        /// <summary>
        /// Gets or sets the predicate proof type.
        /// </summary>
        public PqcZkProofType ProofType { get; set; }

        /// <summary>
        /// Gets or sets the public claim or predicate verified (e.g. "AGE_GE_20").
        /// </summary>
        public string PublicClaim { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the lattice commitment bytes (C = A*s + e mod q).
        /// </summary>
        public byte[] Commitment { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the Fiat-Shamir challenge bytes derived from random oracle.
        /// </summary>
        public byte[] Challenge { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the response vector proving the relation within norm bounds.
        /// </summary>
        public byte[] ResponseVector { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets public parameter context binding the proof to a specific session or verifier nonce.
        /// </summary>
        public string VerifierNonce { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets timestamp when the zero-knowledge proof was issued.
        /// </summary>
        public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets whether the underlying commitment scheme is immune to quantum cryptanalysis (Lattice M-LWE/SIS).
        /// </summary>
        public bool IsQuantumImmune { get; set; } = true;
    }

    /// <summary>
    /// Verification result of a zero-knowledge attribute proof.
    /// </summary>
    public class PqcZkVerificationResult
    {
        /// <summary>
        /// Gets or sets whether the zero-knowledge proof is cryptographically valid.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets whether zero-knowledge privacy was preserved (no private witness disclosed).
        /// </summary>
        public bool IsZeroKnowledgePreserved { get; set; }

        /// <summary>
        /// Gets or sets the attribute predicate that was proven.
        /// </summary>
        public string ProvenClaim { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets error message if verification fails.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets execution latency in milliseconds.
        /// </summary>
        public double LatencyMs { get; set; }
    }
}
