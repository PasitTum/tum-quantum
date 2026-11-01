// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;

namespace Tum.Quantum.Core.Interfaces
{
    /// <summary>
    /// Post-Quantum Time-Stamp Authority (PQC-TSA) conforming to RFC 3161 and Thailand ETA B.E. 2544 Sections 26 &amp; 28.
    /// Issues and verifies immutable timestamp tokens sealed with NIST FIPS 204 (ML-DSA-87) lattice signatures.
    /// </summary>
    public interface ITimeStampAuthorityEngine
    {
        /// <summary>
        /// Creates a valid RFC 3161 TimeStampReq from an input document or payload.
        /// </summary>
        /// <param name="documentBytes">Payload bytes to timestamp.</param>
        /// <param name="hashAlgorithm">Hash algorithm (SHA-384 or SHA-512).</param>
        /// <param name="nonce">Optional 64-bit client nonce.</param>
        /// <returns>A well-formed TimeStampReq object.</returns>
        PqcTimeStampRequest CreateRequest(byte[] documentBytes, string hashAlgorithm = "SHA-384", ulong? nonce = null);

        /// <summary>
        /// Processes a TimeStampReq and issues a certified, signed PqcTimeStampToken.
        /// </summary>
        /// <param name="request">The incoming timestamp request.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Issued TimeStampToken sealed with ML-DSA-87 signature.</returns>
        Task<PqcTimeStampToken> IssueTimeStampTokenAsync(PqcTimeStampRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// Verifies an issued TimeStampToken against the original document payload and validates TSA signature.
        /// </summary>
        /// <param name="token">The timestamp token to verify.</param>
        /// <param name="originalDocumentBytes">Original unhashed document bytes.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><c>true</c> if valid and untampered; otherwise <c>false</c>.</returns>
        Task<bool> VerifyTimeStampTokenAsync(PqcTimeStampToken token, byte[] originalDocumentBytes, CancellationToken cancellationToken = default);
    }
}
