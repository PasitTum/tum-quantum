// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Status code of the Time-Stamp Authority response (RFC 3161 PKIStatus).
    /// </summary>
    public enum PkiStatus
    {
        /// <summary>
        /// Time-stamp token was granted successfully.
        /// </summary>
        Granted = 0,

        /// <summary>
        /// Time-stamp token granted with modifications.
        /// </summary>
        GrantedWithMods = 1,

        /// <summary>
        /// Request was rejected.
        /// </summary>
        Rejection = 2,

        /// <summary>
        /// Request is waiting for authorization.
        /// </summary>
        Waiting = 3
    }

    /// <summary>
    /// RFC 3161 TimeStampReq structure containing the document message imprint and nonce.
    /// </summary>
    public class PqcTimeStampRequest
    {
        /// <summary>
        /// Version of the Time-Stamp Request (v1).
        /// </summary>
        public int Version { get; set; } = 1;

        /// <summary>
        /// Hash algorithm used to digest the document (e.g. SHA-384, SHA-512).
        /// </summary>
        public string HashAlgorithm { get; set; } = "SHA-384";

        /// <summary>
        /// Cryptographic digest of the document or transaction payload.
        /// </summary>
        public byte[] MessageImprint { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Optional Policy OID requested by the client.
        /// </summary>
        public string PolicyOid { get; set; } = "1.3.6.1.4.1.61440.1.1";

        /// <summary>
        /// Optional 64-bit client nonce to protect against replay attacks.
        /// </summary>
        public ulong? Nonce { get; set; }

        /// <summary>
        /// Whether the TSA should include its signer certificate / public key in the response.
        /// </summary>
        public bool CertReq { get; set; } = true;
    }

    /// <summary>
    /// RFC 3161 TSTInfo data structure signed by the Post-Quantum Time-Stamp Authority.
    /// </summary>
    public class PqcTstInfo
    {
        /// <summary>
        /// Version (1).
        /// </summary>
        public int Version { get; set; } = 1;

        /// <summary>
        /// TSA Policy OID.
        /// </summary>
        public string PolicyOid { get; set; } = "1.3.6.1.4.1.61440.1.1";

        /// <summary>
        /// Echoed message imprint.
        /// </summary>
        public byte[] MessageImprint { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Hash algorithm identifier.
        /// </summary>
        public string HashAlgorithm { get; set; } = "SHA-384";

        /// <summary>
        /// Monotonically increasing unique serial number assigned by the TSA.
        /// </summary>
        public ulong SerialNumber { get; set; }

        /// <summary>
        /// Verified atomic time when the timestamp token was generated.
        /// </summary>
        public DateTimeOffset GenTimeUtc { get; set; }

        /// <summary>
        /// Echoed client nonce if requested.
        /// </summary>
        public ulong? Nonce { get; set; }

        /// <summary>
        /// Distinguished Name of the issuing TSA.
        /// </summary>
        public string TsaName { get; set; } = "CN=TUM Sovereign Post-Quantum Time-Stamp Authority, O=TUM Group Holdings, C=TH";
    }

    /// <summary>
    /// Complete RFC 3161 Time-Stamp Token (TST) sealed with NIST FIPS 204 ML-DSA-87.
    /// </summary>
    public class PqcTimeStampToken
    {
        /// <summary>
        /// Status of the request.
        /// </summary>
        public PkiStatus Status { get; set; } = PkiStatus.Granted;

        /// <summary>
        /// Descriptive failure info if status is rejected.
        /// </summary>
        public string? StatusString { get; set; }

        /// <summary>
        /// Certified timestamp information envelope.
        /// </summary>
        public PqcTstInfo TstInfo { get; set; } = new();

        /// <summary>
        /// Post-quantum digital signature generated using NIST FIPS 204 ML-DSA-87 (Category 5, 256 bits).
        /// </summary>
        public byte[] PqcSignature { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// TSA public key bytes used to verify the signature.
        /// </summary>
        public byte[] TsaPublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Canonical SHA-384 fingerprint of the timestamp token.
        /// </summary>
        public string TokenFingerprintSha384 { get; set; } = string.Empty;

        /// <summary>
        /// Whether this token is guaranteed immune to quantum forgery under Shor's algorithm.
        /// </summary>
        public bool IsQuantumImmune { get; set; } = true;
    }
}
