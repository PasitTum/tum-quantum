// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Represents a cryptographic key pair for Post-Quantum Cryptography (PQC).
    /// </summary>
    public class PqcKeyPair
    {
        /// <summary>
        /// Gets or sets the algorithm used by this key pair.
        /// </summary>
        public PqcSignatureAlgorithm Algorithm { get; set; }

        /// <summary>
        /// Gets or sets the raw public key bytes.
        /// </summary>
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the raw private/secret key bytes.
        /// </summary>
        public byte[] PrivateKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the optional classic public key bytes when used in hybrid mode (e.g. RSA-4096 / ECDSA-P384).
        /// </summary>
        public byte[]? ClassicPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the optional classic private key bytes when used in hybrid mode.
        /// </summary>
        public byte[]? ClassicPrivateKey { get; set; }

        /// <summary>
        /// Gets or sets the estimated quantum security level in bits (e.g., 128, 192, 256).
        /// </summary>
        public int QuantumSecurityBits { get; set; }

        /// <summary>
        /// Gets or sets the creation timestamp (UTC).
        /// </summary>
        public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets the base64-encoded representation of the public key.
        /// </summary>
        public string PublicKeyBase64 => PublicKey.Length > 0 ? Convert.ToBase64String(PublicKey) : string.Empty;
    }
}
