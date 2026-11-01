// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// NIST FIPS 140-3 Security Levels (ISO/IEC 19790:2012).
    /// </summary>
    public enum Fips140SecurityLevel
    {
        /// <summary>
        /// Level 1: Basic security requirements; software-only boundary; production-grade components.
        /// </summary>
        Level1 = 1,

        /// <summary>
        /// Level 2: Role-based authentication; tamper-evidence coatings; operating environment isolation.
        /// </summary>
        Level2 = 2,

        /// <summary>
        /// Level 3: Identity-based authentication; tamper-detection and automatic zeroization circuitry; environmental failure protection.
        /// </summary>
        Level3 = 3,

        /// <summary>
        /// Level 4: Complete physical protection envelope; immediate zeroization upon breach; fault-injection immunity.
        /// </summary>
        Level4 = 4
    }

    /// <summary>
    /// Known Answer Test (KAT) vector execution result.
    /// </summary>
    public class Fips140KatResult
    {
        /// <summary>
        /// Gets or sets cryptographic algorithm name under test.
        /// </summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets test vector identifier (e.g. NIST CAVP Vector #104).
        /// </summary>
        public string TestVectorId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets whether the actual algorithm output matched the expected cryptographic answer.
        /// </summary>
        public bool IsPassed { get; set; }

        /// <summary>
        /// Gets or sets execution latency in microseconds.
        /// </summary>
        public double LatencyUs { get; set; }
    }

    /// <summary>
    /// Comprehensive audit scorecard for NIST FIPS 140-3 Cryptographic Module Readiness.
    /// </summary>
    public class Fips140AuditReport
    {
        /// <summary>
        /// Gets or sets the audited cryptographic module name.
        /// </summary>
        public string ModuleName { get; set; } = "TUM Sovereign Post-Quantum Cryptographic Core Module";

        /// <summary>
        /// Gets or sets firmware and software version.
        /// </summary>
        public string Version { get; set; } = "v1.5.0-FIPS";

        /// <summary>
        /// Gets or sets evaluated FIPS 140-3 target security level.
        /// </summary>
        public Fips140SecurityLevel TargetLevel { get; set; }

        /// <summary>
        /// Gets or sets whether the module is fully compliant with all 11 FIPS 140-3 operational areas.
        /// </summary>
        public bool IsCompliant { get; set; }

        /// <summary>
        /// Gets or sets whether power-up cryptographic self-tests passed.
        /// </summary>
        public bool PowerUpSelfTestsPassed { get; set; }

        /// <summary>
        /// Gets or sets whether Critical Security Parameter (CSP) zeroization verified.
        /// </summary>
        public bool CspZeroizationVerified { get; set; }

        /// <summary>
        /// Gets or sets SP 800-90B min-entropy health estimate (bits per byte, max 8.0).
        /// </summary>
        public double EntropyHealthScore { get; set; }

        /// <summary>
        /// Gets or sets list of Known Answer Test (KAT) verification results.
        /// </summary>
        public IList<Fips140KatResult> KatResults { get; set; } = new List<Fips140KatResult>();

        /// <summary>
        /// Gets or sets compliance checklist across all 11 FIPS 140-3 sections.
        /// </summary>
        public IDictionary<string, bool> SectionChecklist { get; set; } = new Dictionary<string, bool>();

        /// <summary>
        /// Gets or sets timestamp when the readiness audit was completed.
        /// </summary>
        public DateTimeOffset AuditedAtUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets executive certification summary.
        /// </summary>
        public string ExecutiveSummary { get; set; } = string.Empty;
    }
}
