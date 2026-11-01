// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;
using Tum.Trust.Security.Core.Models.QuantumSafe;

namespace Tum.Quantum.Core.Interfaces
{
    /// <summary>
    /// Driver interface for Quantum Hardware Security Modules (HSM) conforming to OASIS PKCS#11 standard.
    /// Enforces zero key leakage, on-chip key generation, and hardware-accelerated lattice operations.
    /// </summary>
    public interface IPkcs11QuantumHsmDriver
    {
        /// <summary>
        /// Queries hardware token info and security capabilities for the given slot.
        /// </summary>
        /// <param name="slotId">Hardware slot identifier.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Token security and mechanism metadata.</returns>
        Task<Pkcs11TokenInfo> GetTokenInfoAsync(int slotId = 1, CancellationToken cancellationToken = default);

        /// <summary>
        /// Opens a cryptoki session and authenticates using the user PIN (C_OpenSession + C_Login).
        /// </summary>
        /// <param name="slotId">Target hardware slot.</param>
        /// <param name="userPin">User PIN for authentication.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Authenticated session handle.</returns>
        Task<Pkcs11SessionHandle> OpenSessionAsync(int slotId, string userPin, CancellationToken cancellationToken = default);

        /// <summary>
        /// Generates a post-quantum key pair directly inside the HSM enclave (C_GenerateKeyPair).
        /// Private key is strictly non-extractable (CKA_NEVER_EXTRACTABLE).
        /// </summary>
        /// <param name="session">Authenticated session handle.</param>
        /// <param name="algorithm">Target post-quantum algorithm.</param>
        /// <param name="keyLabel">Human-readable label for key indexing.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Handle referencing the on-chip key object.</returns>
        Task<Pkcs11ObjectHandle> GeneratePqcKeyInHsmAsync(Pkcs11SessionHandle session, PqcSignatureAlgorithm algorithm, string keyLabel, CancellationToken cancellationToken = default);

        /// <summary>
        /// Performs on-chip post-quantum digital signature without private key leaving the HSM (C_SignInit + C_Sign).
        /// </summary>
        /// <param name="session">Active session handle.</param>
        /// <param name="keyHandle">Handle referencing the on-chip private key.</param>
        /// <param name="data">Payload bytes to sign.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Hardware-generated post-quantum digital signature.</returns>
        Task<byte[]> SignOnHsmAsync(Pkcs11SessionHandle session, Pkcs11ObjectHandle keyHandle, byte[] data, CancellationToken cancellationToken = default);

        /// <summary>
        /// Performs signature verification on the HSM (C_VerifyInit + C_Verify).
        /// </summary>
        /// <param name="session">Active session handle.</param>
        /// <param name="keyHandle">Handle referencing the key object.</param>
        /// <param name="data">Original data.</param>
        /// <param name="signature">Signature bytes to verify.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><c>true</c> if valid; otherwise <c>false</c>.</returns>
        Task<bool> VerifyOnHsmAsync(Pkcs11SessionHandle session, Pkcs11ObjectHandle keyHandle, byte[] data, byte[] signature, CancellationToken cancellationToken = default);

        /// <summary>
        /// Closes and terminates a cryptoki session (C_CloseSession).
        /// </summary>
        /// <param name="session">Session handle to terminate.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        Task CloseSessionAsync(Pkcs11SessionHandle session, CancellationToken cancellationToken = default);
    }
}
