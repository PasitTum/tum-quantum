// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Supported TLS 1.3 Post-Quantum and Hybrid Named Groups (IETF Draft Compliant).
    /// </summary>
    public enum PqcTlsNamedGroup : ushort
    {
        /// <summary>
        /// Hybrid X25519 + NIST FIPS 203 ML-KEM-768 (IETF CodePoint 0x11EC).
        /// </summary>
        X25519MLKEM768 = 0x11EC,

        /// <summary>
        /// Hybrid SecP256r1 + NIST FIPS 203 ML-KEM-768 (IETF CodePoint 0x11ED).
        /// </summary>
        SecP256r1MLKEM768 = 0x11ED,

        /// <summary>
        /// Pure NIST FIPS 203 ML-KEM-768 (CodePoint 0x0200).
        /// </summary>
        MLKEM768 = 0x0200,

        /// <summary>
        /// Pure NIST FIPS 203 ML-KEM-1024 (CodePoint 0x0201).
        /// </summary>
        MLKEM1024 = 0x0201
    }

    /// <summary>
    /// ClientHello message representation for Post-Quantum TLS 1.3 handshake.
    /// </summary>
    public class PqcTlsClientHello
    {
        /// <summary>
        /// Protocol version (TLS 1.3 legacy_version 0x0303).
        /// </summary>
        public ushort ProtocolVersion { get; set; } = 0x0303;

        /// <summary>
        /// 32-byte cryptographic random nonce.
        /// </summary>
        public byte[] ClientRandom { get; set; } = new byte[32];

        /// <summary>
        /// Ephemeral session identifier.
        /// </summary>
        public byte[] SessionId { get; set; } = new byte[32];

        /// <summary>
        /// Negotiated cipher suites (e.g. TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256).
        /// </summary>
        public IList<string> CipherSuites { get; set; } = new List<string>
        {
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256"
        };

        /// <summary>
        /// Selected named group for key exchange.
        /// </summary>
        public PqcTlsNamedGroup NamedGroup { get; set; } = PqcTlsNamedGroup.X25519MLKEM768;

        /// <summary>
        /// Client Key Share payload containing classical ephemeral public key + ML-KEM encapsulation key.
        /// </summary>
        public byte[] ClientKeyShare { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Ephemeral client private key component (held strictly in client memory, not sent over wire).
        /// </summary>
        public byte[] EphemeralClientSecret { get; set; } = Array.Empty<byte>();
    }

    /// <summary>
    /// ServerHello message representation for Post-Quantum TLS 1.3 handshake.
    /// </summary>
    public class PqcTlsServerHello
    {
        /// <summary>
        /// Protocol version (0x0303).
        /// </summary>
        public ushort ProtocolVersion { get; set; } = 0x0303;

        /// <summary>
        /// 32-byte server cryptographic random nonce.
        /// </summary>
        public byte[] ServerRandom { get; set; } = new byte[32];

        /// <summary>
        /// Echoed session identifier.
        /// </summary>
        public byte[] SessionId { get; set; } = new byte[32];

        /// <summary>
        /// Selected cipher suite (e.g. TLS_AES_256_GCM_SHA384).
        /// </summary>
        public string SelectedCipherSuite { get; set; } = "TLS_AES_256_GCM_SHA384";

        /// <summary>
        /// Agreed named group.
        /// </summary>
        public PqcTlsNamedGroup SelectedGroup { get; set; } = PqcTlsNamedGroup.X25519MLKEM768;

        /// <summary>
        /// Server Key Share payload (server ephemeral public key + ML-KEM ciphertext).
        /// </summary>
        public byte[] ServerKeyShare { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Derived server shared secret component.
        /// </summary>
        public byte[] DerivedSharedSecret { get; set; } = Array.Empty<byte>();
    }

    /// <summary>
    /// Handshake negotiation outcome with derived TLS 1.3 traffic secrets and cryptographic audit trail.
    /// </summary>
    public class PqcTlsHandshakeResult
    {
        /// <summary>
        /// Gets or sets whether the handshake was negotiated successfully.
        /// </summary>
        public bool IsSuccessful { get; set; }

        /// <summary>
        /// Gets or sets whether the session possesses post-quantum forward secrecy.
        /// </summary>
        public bool HasQuantumForwardSecrecy { get; set; }

        /// <summary>
        /// Gets or sets the agreed key exchange group.
        /// </summary>
        public PqcTlsNamedGroup NegotiatedGroup { get; set; }

        /// <summary>
        /// Gets or sets the agreed cipher suite.
        /// </summary>
        public string NegotiatedCipherSuite { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the composite hybrid shared secret (SHA-384 digest).
        /// </summary>
        public byte[] HybridSharedSecret { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the TLS 1.3 Handshake Secret derived via HKDF-Extract.
        /// </summary>
        public byte[] HandshakeSecret { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the TLS 1.3 Master Secret derived via HKDF-Extract.
        /// </summary>
        public byte[] MasterSecret { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the client application traffic encryption key (256 bits).
        /// </summary>
        public byte[] ClientApplicationTrafficKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the server application traffic encryption key (256 bits).
        /// </summary>
        public byte[] ServerApplicationTrafficKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the client application traffic initialization vector (96 bits).
        /// </summary>
        public byte[] ClientApplicationIv { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the server application traffic initialization vector (96 bits).
        /// </summary>
        public byte[] ServerApplicationIv { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the SHA-384 handshake transcript hash.
        /// </summary>
        public byte[] TranscriptHash { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets handshake latency in milliseconds.
        /// </summary>
        public double HandshakeLatencyMs { get; set; }

        /// <summary>
        /// Gets or sets audit description of the post-quantum protection tier.
        /// </summary>
        public string SecurityAuditDescription { get; set; } = string.Empty;
    }
}
