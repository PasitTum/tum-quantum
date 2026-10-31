// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Represents a Dual-Envelope container combining a Classical signature (RSA or ECDSA)
    /// and a NIST FIPS 204 ML-DSA Post-Quantum Cryptography signature over a common payload.
    /// Supports the "Permissive Migration Adapter" for transitioning legacy PKI to quantum resilience.
    /// </summary>
    public class HybridDualEnvelope
    {
        /// <summary>
        /// Gets or sets the data payload that is signed.
        /// </summary>
        public byte[] Payload { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the Classical signature algorithm (e.g., 'RSA-2048', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384').
        /// </summary>
        public string? ClassicAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the Classical signature bytes (RSA PKCS#1/PSS or ECDSA).
        /// </summary>
        public byte[]? ClassicSignature { get; set; }

        /// <summary>
        /// Gets or sets the Classical public key bytes (SubjectPublicKeyInfo DER, PEM or raw format).
        /// </summary>
        public byte[]? ClassicPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the Post-Quantum signature algorithm conforming to NIST FIPS 204 (ML-DSA-44, ML-DSA-65, ML-DSA-87).
        /// </summary>
        public PqcSignatureAlgorithm PqcAlgorithm { get; set; } = PqcSignatureAlgorithm.MlDsa65;

        /// <summary>
        /// Gets or sets the Post-Quantum signature bytes.
        /// </summary>
        public byte[]? PqcSignature { get; set; }

        /// <summary>
        /// Gets or sets the Post-Quantum public key bytes.
        /// </summary>
        public byte[]? PqcPublicKey { get; set; }

        /// <summary>
        /// Gets or sets an optional unique identifier or context for audit tracing.
        /// </summary>
        public string? ContextId { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the envelope was created.
        /// </summary>
        public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets additional metadata tags for governance, telemetry, or PKI tracking.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Gets a value indicating whether classical signature bytes and public key are present.
        /// </summary>
        public bool HasClassicSignature =>
            ClassicSignature is { Length: > 0 } && ClassicPublicKey is { Length: > 0 };

        /// <summary>
        /// Gets a value indicating whether PQC signature bytes and public key are present.
        /// </summary>
        public bool HasPqcSignature =>
            PqcSignature is { Length: > 0 } && PqcPublicKey is { Length: > 0 };

        /// <summary>
        /// Gets a value indicating whether both Classical and PQC components are present (True Dual-Envelope).
        /// </summary>
        public bool IsDualEnvelope => HasClassicSignature && HasPqcSignature;

        /// <summary>
        /// Serializes the hybrid dual-envelope to a JSON formatted string.
        /// </summary>
        public string ToJson()
        {
            return System.Text.Json.JsonSerializer.Serialize(this, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = false
            });
        }

        /// <summary>
        /// Deserializes a hybrid dual-envelope from a JSON formatted string.
        /// </summary>
        public static HybridDualEnvelope? FromJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            return System.Text.Json.JsonSerializer.Deserialize<HybridDualEnvelope>(json);
        }
    }
}
