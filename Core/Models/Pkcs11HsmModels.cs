// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using Tum.Trust.Security.Core.Models.QuantumSafe;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// PKCS#11 cryptoki session state.
    /// </summary>
    public enum Pkcs11SessionState
    {
        /// <summary>
        /// Read-only public session (no user PIN logged in).
        /// </summary>
        ReadOnlyPublic,

        /// <summary>
        /// Read-write public session.
        /// </summary>
        ReadWritePublic,

        /// <summary>
        /// Read-write user session (authenticated with user PIN).
        /// </summary>
        ReadWriteUser,

        /// <summary>
        /// Security Officer (Admin) session.
        /// </summary>
        SecurityOfficer,

        /// <summary>
        /// Session has been closed or invalidated.
        /// </summary>
        Closed
    }

    /// <summary>
    /// Hardware Security Module (HSM) Token Information and Physical Security Profile.
    /// </summary>
    public class Pkcs11TokenInfo
    {
        /// <summary>
        /// Gets or sets the manufacturer identifier.
        /// </summary>
        public string ManufacturerId { get; set; } = "TUM Group Holdings Sovereign Lab";

        /// <summary>
        /// Gets or sets hardware model name.
        /// </summary>
        public string Model { get; set; } = "TUM-QVAULT-9000-PQC-HSM";

        /// <summary>
        /// Gets or sets hardware serial number.
        /// </summary>
        public string SerialNumber { get; set; } = "TH-HSM-2026-FIPS-001";

        /// <summary>
        /// Gets or sets FIPS 140-3 physical security assurance level (Level 3 or Level 4).
        /// </summary>
        public string PhysicalSecurityLevel { get; set; } = "FIPS 140-3 Level 4 (Tamper-Response Physical Enclave)";

        /// <summary>
        /// Gets or sets supported post-quantum and classical cryptoki mechanisms.
        /// </summary>
        public IList<string> SupportedMechanisms { get; set; } = new List<string>
        {
            "CKM_ML_DSA_44",
            "CKM_ML_DSA_65",
            "CKM_ML_DSA_87",
            "CKM_ML_KEM_768",
            "CKM_ML_KEM_1024",
            "CKM_HYBRID_X25519_MLKEM768"
        };

        /// <summary>
        /// Gets or sets total on-chip non-volatile cryptographic storage in bytes.
        /// </summary>
        public long TotalMemoryBytes { get; set; } = 32 * 1024 * 1024; // 32MB Secure Enclave

        /// <summary>
        /// Gets or sets available free storage in bytes.
        /// </summary>
        public long FreeMemoryBytes { get; set; } = 28 * 1024 * 1024;
    }

    /// <summary>
    /// Active PKCS#11 session handle.
    /// </summary>
    public class Pkcs11SessionHandle
    {
        /// <summary>
        /// Gets or sets the 64-bit session handle identifier.
        /// </summary>
        public ulong SessionId { get; set; }

        /// <summary>
        /// Gets or sets the target slot ID.
        /// </summary>
        public int SlotId { get; set; }

        /// <summary>
        /// Gets or sets session authentication state.
        /// </summary>
        public Pkcs11SessionState State { get; set; }

        /// <summary>
        /// Gets or sets session creation timestamp.
        /// </summary>
        public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Handle referencing a private or public post-quantum key object stored securely within the HSM.
    /// Private key material never leaves the hardware boundary.
    /// </summary>
    public class Pkcs11ObjectHandle
    {
        /// <summary>
        /// Gets or sets unique object handle within the HSM storage.
        /// </summary>
        public ulong ObjectHandleId { get; set; }

        /// <summary>
        /// Gets or sets human-readable label (CKA_LABEL).
        /// </summary>
        public string Label { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets target post-quantum algorithm.
        /// </summary>
        public PqcSignatureAlgorithm Algorithm { get; set; }

        /// <summary>
        /// Gets or sets whether this key is marked CKA_SENSITIVE (true).
        /// </summary>
        public bool IsSensitive { get; set; } = true;

        /// <summary>
        /// Gets or sets whether this key is marked CKA_NEVER_EXTRACTABLE (true).
        /// </summary>
        public bool IsNeverExtractable { get; set; } = true;

        /// <summary>
        /// Gets or sets public key component (exportable for verification).
        /// </summary>
        public byte[] PublicKeyBytes { get; set; } = Array.Empty<byte>();
    }
}
