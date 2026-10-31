// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Trust.Security.Core.Models.QuantumSafe
{
    /// <summary>
    /// Extracted classical legacy signature package for transmission to legacy-only PKI systems.
    /// </summary>
    public class LegacySignaturePackage
    {
        /// <summary>
        /// Gets or sets the data payload.
        /// </summary>
        public byte[] Payload { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the Classical signature bytes.
        /// </summary>
        public byte[] Signature { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the Classical public key bytes.
        /// </summary>
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the Classical algorithm name.
        /// </summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the creation timestamp.
        /// </summary>
        public DateTimeOffset TimestampUtc { get; set; }

        /// <summary>
        /// Gets or sets optional context identifier.
        /// </summary>
        public string? ContextId { get; set; }
    }
}
