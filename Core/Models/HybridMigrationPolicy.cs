// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Configuration policy governing how the Hybrid Permissive Migration Adapter validates signatures.
    /// </summary>
    public class HybridMigrationPolicy
    {
        /// <summary>
        /// Migration enforcement mode (default: Permissive).
        /// </summary>
        public HybridMigrationMode Mode { get; set; } = HybridMigrationMode.Permissive;

        /// <summary>
        /// Allows legacy RSA signatures during the migration window.
        /// </summary>
        public bool AllowLegacyRsa { get; set; } = true;

        /// <summary>
        /// Allows legacy ECDSA signatures during the migration window.
        /// </summary>
        public bool AllowLegacyEcdsa { get; set; } = true;

        /// <summary>
        /// Minimum quantum security bits required when PQC is present (default: 128 bits).
        /// </summary>
        public int MinimumPqcSecurityBits { get; set; } = 128;

        /// <summary>
        /// When both Classical and PQC signatures are present in the envelope, require both to be cryptographically valid,
        /// even under Permissive mode (prevents corrupted dual-envelopes). Default: true.
        /// </summary>
        public bool EnforceDualIntegrityWhenPresent { get; set; } = true;

        /// <summary>
        /// Maximum allowed timestamp age or clock skew for the envelope (default: 1 hour). Set null to disable.
        /// </summary>
        public TimeSpan? MaxEnvelopeAge { get; set; } = TimeSpan.FromHours(1);
    }
}
