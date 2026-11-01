// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Quantum.Core.Interfaces;
using Tum.Quantum.Core.Models;
using Tum.Trust.Security.Core.Interfaces;
using Tum.Trust.Security.Core.Models.QuantumSafe;
using Tum.Trust.Security.Infrastructure.Security;

namespace Tum.Quantum.Engine
{
    /// <summary>
    /// Production implementation of RFC 3161 Post-Quantum Time-Stamp Authority (PQC-TSA).
    /// Seals legal documents and digital records using NIST FIPS 204 (ML-DSA-87) lattice signatures.
    /// </summary>
    public class TimeStampAuthorityEngine : ITimeStampAuthorityEngine
    {
        private readonly IQuantumSafeTrustEngine _quantumEngine;
        private readonly ILogger<TimeStampAuthorityEngine> _logger;

        private PqcKeyPair? _tsaKeyPair;
        private ulong _serialCounter = 1000000;
        private readonly SemaphoreSlim _keyLock = new(1, 1);

        /// <summary>
        /// Initializes a new instance of the <see cref="TimeStampAuthorityEngine"/> class.
        /// </summary>
        public TimeStampAuthorityEngine(
            IQuantumSafeTrustEngine? quantumEngine = null,
            ILogger<TimeStampAuthorityEngine>? logger = null)
        {
            _quantumEngine = quantumEngine ?? new QuantumSafeTrustEngine();
            _logger = logger ?? NullLogger<TimeStampAuthorityEngine>.Instance;
        }

        /// <inheritdoc />
        public PqcTimeStampRequest CreateRequest(byte[] documentBytes, string hashAlgorithm = "SHA-384", ulong? nonce = null)
        {
            if (documentBytes == null || documentBytes.Length == 0)
            {
                throw new ArgumentException("Document bytes cannot be null or empty.", nameof(documentBytes));
            }

            using var sha = hashAlgorithm.Equals("SHA-512", StringComparison.OrdinalIgnoreCase)
                ? (HashAlgorithm)SHA512.Create()
                : SHA384.Create();

            byte[] digest = sha.ComputeHash(documentBytes);

            return new PqcTimeStampRequest
            {
                Version = 1,
                HashAlgorithm = hashAlgorithm.ToUpperInvariant(),
                MessageImprint = digest,
                Nonce = nonce ?? (ulong)RandomNumberGenerator.GetInt32(1, int.MaxValue)
            };
        }

        /// <inheritdoc />
        public async Task<PqcTimeStampToken> IssueTimeStampTokenAsync(PqcTimeStampRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            if (request.MessageImprint == null || request.MessageImprint.Length < 32)
            {
                return new PqcTimeStampToken
                {
                    Status = PkiStatus.Rejection,
                    StatusString = "badAlg: Missing or invalid message imprint digest."
                };
            }

            await EnsureTsaKeyAsync(cancellationToken).ConfigureAwait(false);

            ulong serial = Interlocked.Increment(ref _serialCounter);
            var nowUtc = DateTimeOffset.UtcNow;

            var tstInfo = new PqcTstInfo
            {
                Version = 1,
                PolicyOid = request.PolicyOid,
                MessageImprint = request.MessageImprint,
                HashAlgorithm = request.HashAlgorithm,
                SerialNumber = serial,
                GenTimeUtc = nowUtc,
                Nonce = request.Nonce,
                TsaName = "CN=TUM Sovereign Post-Quantum Time-Stamp Authority, O=TUM Group Holdings, C=TH"
            };

            byte[] canonicalBytes = BuildCanonicalTstInfo(tstInfo);

            // Sign using NIST FIPS 204 ML-DSA-87 (Category 5 lattice signature)
            byte[] signature = await _quantumEngine.SignQuantumSafeAsync(
                canonicalBytes,
                _tsaKeyPair!.PrivateKey,
                PqcSignatureAlgorithm.MlDsa87,
                cancellationToken).ConfigureAwait(false);

            // Token Fingerprint
            using var sha384 = SHA384.Create();
            byte[] tokenDigest = sha384.ComputeHash(signature);
            string fingerprint = Convert.ToBase64String(tokenDigest);

            _logger.LogInformation("RFC 3161 PQC Timestamp Token issued: SerialNumber={SerialNumber}, Alg=ML-DSA-87", serial);

            return new PqcTimeStampToken
            {
                Status = PkiStatus.Granted,
                TstInfo = tstInfo,
                PqcSignature = signature,
                TsaPublicKey = _tsaKeyPair.PublicKey,
                TokenFingerprintSha384 = fingerprint,
                IsQuantumImmune = true
            };
        }

        /// <inheritdoc />
        public async Task<bool> VerifyTimeStampTokenAsync(PqcTimeStampToken token, byte[] originalDocumentBytes, CancellationToken cancellationToken = default)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (originalDocumentBytes == null) throw new ArgumentNullException(nameof(originalDocumentBytes));

            if (token.Status != PkiStatus.Granted || token.TstInfo == null || token.PqcSignature == null || token.TsaPublicKey == null)
            {
                return false;
            }

            // 1. Verify Message Imprint against original document
            using var sha = token.TstInfo.HashAlgorithm.Equals("SHA-512", StringComparison.OrdinalIgnoreCase)
                ? (HashAlgorithm)SHA512.Create()
                : SHA384.Create();

            byte[] computedDigest = sha.ComputeHash(originalDocumentBytes);

            if (!CryptographicEquals(token.TstInfo.MessageImprint, computedDigest))
            {
                _logger.LogWarning("TSA verification failed: Document digest does not match token message imprint.");
                return false;
            }

            // 2. Rebuild Canonical TSTInfo and verify ML-DSA-87 signature
            byte[] canonicalBytes = BuildCanonicalTstInfo(token.TstInfo);

            var verifyReq = new PqcVerificationRequest
            {
                Payload = canonicalBytes,
                PqcSignature = token.PqcSignature,
                PqcPublicKey = token.TsaPublicKey,
                Algorithm = PqcSignatureAlgorithm.MlDsa87
            };

            var verifyRes = await _quantumEngine.VerifyQuantumSafeSignatureAsync(verifyReq, cancellationToken).ConfigureAwait(false);
            return verifyRes.IsValid;
        }

        private async Task EnsureTsaKeyAsync(CancellationToken ct)
        {
            if (_tsaKeyPair != null) return;

            await _keyLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_tsaKeyPair == null)
                {
                    _tsaKeyPair = await _quantumEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa87, ct).ConfigureAwait(false);
                }
            }
            finally
            {
                _keyLock.Release();
            }
        }

        private static byte[] BuildCanonicalTstInfo(PqcTstInfo info)
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms, Encoding.UTF8);

            writer.Write(info.Version);
            writer.Write(info.PolicyOid);
            writer.Write(info.HashAlgorithm);
            writer.Write(info.MessageImprint.Length);
            writer.Write(info.MessageImprint);
            writer.Write(info.SerialNumber);
            writer.Write(info.GenTimeUtc.ToUnixTimeMilliseconds());
            writer.Write(info.Nonce.HasValue);
            if (info.Nonce.HasValue)
            {
                writer.Write(info.Nonce.Value);
            }
            writer.Write(info.TsaName);

            return ms.ToArray();
        }

        private static bool CryptographicEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}
