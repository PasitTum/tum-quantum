// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Represents a signature verification request to be evaluated by the Quantum-Safe Trust Engine.
    /// </summary>
    public class PqcVerificationRequest
    {
        /// <summary>
        /// Gets or sets the data payload that was signed.
        /// </summary>
        public byte[] Payload { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the primary post-quantum signature bytes (e.g. NIST ML-DSA / Dilithium).
        /// </summary>
        public byte[] PqcSignature { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the post-quantum public key bytes.
        /// </summary>
        public byte[] PqcPublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the optional classic signature bytes (RSA / ECDSA) for dual hybrid envelopes.
        /// </summary>
        public byte[]? ClassicSignature { get; set; }

        /// <summary>
        /// Gets or sets the optional classic public key bytes (RSA / ECDSA) for dual hybrid envelopes.
        /// </summary>
        public byte[]? ClassicPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the cryptographic algorithm used.
        /// </summary>
        public PqcSignatureAlgorithm Algorithm { get; set; } = PqcSignatureAlgorithm.MlDsa65;

        /// <summary>
        /// Gets or sets a value indicating whether hybrid verification is strictly enforced.
        /// If true, both classic and post-quantum signatures must pass independently.
        /// </summary>
        public bool RequireHybridProof { get; set; }

        /// <summary>
        /// Gets or sets an identifier or context string for audit and logging.
        /// </summary>
        public string? ContextId { get; set; }
    }
}
