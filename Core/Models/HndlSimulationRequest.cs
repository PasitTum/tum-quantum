// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Parameters for executing a simulated Harvest Now, Decrypt Later (HNDL) attack.
    /// </summary>
    public class HndlSimulationRequest
    {
        /// <summary>
        /// Gets or sets the attack scenario to simulate.
        /// </summary>
        public HndlAttackScenario Scenario { get; set; } = HndlAttackScenario.HarvestedTlsHandshake;

        /// <summary>
        /// Gets or sets the target cryptographic algorithm under evaluation (e.g. RSA-2048, ECDSA-P256, ML-KEM-768, ML-DSA-65).
        /// </summary>
        public string TargetAlgorithm { get; set; } = "RSA-2048";

        /// <summary>
        /// Gets or sets the captured payload or ciphertext bytes harvested by the adversary.
        /// If omitted or empty, the simulator will automatically synthesize a realistic sample payload.
        /// </summary>
        public byte[]? CapturedPayload { get; set; }

        /// <summary>
        /// Gets or sets the symmetric bulk encryption cipher used to seal the payload (e.g., AES-256-GCM, ChaCha20-Poly1305, AES-128-CBC).
        /// </summary>
        public string BulkCipherAlgorithm { get; set; } = "AES-256-GCM";

        /// <summary>
        /// Gets or sets optional recorded metadata from the harvested session (e.g., ClientHello, ServerCertFingerprint).
        /// </summary>
        public IDictionary<string, string> HarvestMetadata { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Gets or sets the adversary's quantum hardware profile. If null, the standard early CRQC profile will be used.
        /// </summary>
        public QuantumHardwareProfile? AdversaryHardware { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the traffic was intercepted or data was harvested.
        /// </summary>
        public DateTimeOffset HarvestedAtUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets the simulated future year when the adversary attempts quantum decryption with CRQC.
        /// Defaults to 2030 (standard NIST / NSA commercial quantum projection).
        /// </summary>
        public int SimulationDecryptionYear { get; set; } = 2030;
    }
}
