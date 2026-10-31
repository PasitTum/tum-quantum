// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Text;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Interfaces;
using Tum.Trust.Security.Core.Models.QuantumSafe;
using Tum.Trust.Security.Infrastructure.Security;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class HybridPermissiveMigrationAdapterTests
    {
        private readonly IQuantumSafeTrustEngine _trustEngine;
        private readonly HybridPermissiveMigrationAdapter _adapter;

        public HybridPermissiveMigrationAdapterTests()
        {
            _trustEngine = new QuantumSafeTrustEngine();
            _adapter = new HybridPermissiveMigrationAdapter(_trustEngine);
        }

        [Fact]
        public async Task CreateAndVerify_DualEnvelope_RsaAndMlDsa65_Succeeds()
        {
            // Arrange
            byte[] payload = Encoding.UTF8.GetBytes("SOVEREIGN-ENTERPRISE-PAYLOAD-SCRUM-18");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            // Act: Create Dual Envelope
            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey,
                contextId: "CTX-RSA-MLDSA");

            // Assert Envelope Structure
            Assert.True(envelope.IsDualEnvelope);
            Assert.True(envelope.HasClassicSignature);
            Assert.True(envelope.HasPqcSignature);
            Assert.Equal("RSA-2048", envelope.ClassicAlgorithm);
            Assert.Equal(PqcSignatureAlgorithm.MlDsa65, envelope.PqcAlgorithm);

            // Act: Verify Dual Envelope
            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            // Assert Verification Result
            Assert.True(result.IsValid);
            Assert.True(result.IsQuantumSafe);
            Assert.True(result.HybridIntegrityVerified);
            Assert.True(result.ClassicVerified);
            Assert.True(result.PqcVerified);
            Assert.Equal(HybridMigrationStatus.QuantumSafeHybrid, result.Status);
            Assert.Equal(192, result.QuantumSecurityBits);
            Assert.NotNull(result.ClassicKeyFingerprintSha256);
            Assert.NotNull(result.PqcKeyFingerprintSha256);
            Assert.Null(result.ErrorMessage);
        }

        [Fact]
        public async Task CreateAndVerify_DualEnvelope_EcdsaAndMlDsa65_Succeeds()
        {
            // Arrange
            byte[] payload = Encoding.UTF8.GetBytes("ECDSA-HYBRID-AUTHENTICATION-TOKEN");
            var (ecPriv, ecPub) = HybridPermissiveMigrationAdapter.GenerateClassicEcdsaKeyPair();
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            // Act
            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                ecPriv,
                "ECDSA-P256",
                ecPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey,
                contextId: "CTX-ECDSA-MLDSA");

            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            // Assert
            Assert.True(result.IsValid);
            Assert.True(result.IsQuantumSafe);
            Assert.True(result.HybridIntegrityVerified);
            Assert.True(result.ClassicVerified);
            Assert.True(result.PqcVerified);
            Assert.Equal(HybridMigrationStatus.QuantumSafeHybrid, result.Status);
        }

        [Fact]
        public async Task PermissiveMode_LegacyClassicOnly_ValidSignature_PermittedWithWarning()
        {
            // Arrange: Legacy client only sends RSA signature, no PQC component
            byte[] payload = Encoding.UTF8.GetBytes("LEGACY-ONLY-CLASSICAL-PAYLOAD");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);

            // Create classic signature
            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcPrivateKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PrivateKey,
                pqcAlgorithm: PqcSignatureAlgorithm.MlDsa65,
                pqcPublicKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PublicKey);

            // Strip PQC component to simulate legacy-only client
            envelope.PqcSignature = null;
            envelope.PqcPublicKey = null;

            // Act: Evaluate under default Permissive mode
            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            // Assert: Permissive mode accepts legacy signature without breaking production, but flags warning
            Assert.True(result.IsValid);
            Assert.False(result.IsQuantumSafe);
            Assert.False(result.HybridIntegrityVerified);
            Assert.True(result.ClassicVerified);
            Assert.False(result.PqcVerified);
            Assert.Equal(HybridMigrationStatus.PermittedLegacyWarning, result.Status);
            Assert.Equal(0, result.QuantumSecurityBits);
            Assert.Contains("VULNERABLE", result.MigrationGuidance ?? "");
        }

        [Fact]
        public async Task PermissiveMode_PurePqcOnly_ValidSignature_SucceedsWithQuantumImmunity()
        {
            // Arrange: Modern PQC-native client sends only ML-DSA
            byte[] payload = Encoding.UTF8.GetBytes("PQC-NATIVE-SOVEREIGN-CREDENTIAL");
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa87);
            byte[] pqcSig = await _trustEngine.SignQuantumSafeAsync(payload, pqcKey.PrivateKey, PqcSignatureAlgorithm.MlDsa87);

            var envelope = new HybridDualEnvelope
            {
                Payload = payload,
                PqcSignature = pqcSig,
                PqcPublicKey = pqcKey.PublicKey,
                PqcAlgorithm = PqcSignatureAlgorithm.MlDsa87
            };

            // Act
            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            // Assert
            Assert.True(result.IsValid);
            Assert.True(result.IsQuantumSafe);
            Assert.False(result.HybridIntegrityVerified);
            Assert.False(result.ClassicVerified);
            Assert.True(result.PqcVerified);
            Assert.Equal(HybridMigrationStatus.QuantumSafePqcOnly, result.Status);
            Assert.Equal(256, result.QuantumSecurityBits);
        }

        [Fact]
        public async Task DualEnvelope_CorruptedPqcSignature_FailsUnderEnforceDualIntegrity()
        {
            // Arrange
            byte[] payload = Encoding.UTF8.GetBytes("INTEGRITY-TAMPER-TEST");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey);

            // Corrupt the PQC signature
            envelope.PqcSignature![0] ^= 0xFF;

            // Act
            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            // Assert: Dual envelope with corrupted PQC branch must fail
            Assert.False(result.IsValid);
            Assert.False(result.IsQuantumSafe);
            Assert.True(result.ClassicVerified);
            Assert.False(result.PqcVerified);
            Assert.Equal(HybridMigrationStatus.ClassicValidPqcFailed, result.Status);
            Assert.NotNull(result.ErrorMessage);
        }

        [Fact]
        public async Task DualEnvelope_CorruptedClassicSignature_FailsUnderEnforceDualIntegrity()
        {
            // Arrange
            byte[] payload = Encoding.UTF8.GetBytes("INTEGRITY-CLASSIC-TAMPER");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey);

            // Corrupt the classic signature
            envelope.ClassicSignature![0] ^= 0xFF;

            // Act
            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            // Assert
            Assert.False(result.IsValid);
            Assert.False(result.ClassicVerified);
            Assert.True(result.PqcVerified);
            Assert.Equal(HybridMigrationStatus.PqcValidClassicFailed, result.Status);
        }

        [Fact]
        public async Task StrictHybridMode_LegacyOnly_Rejected()
        {
            // Arrange
            byte[] payload = Encoding.UTF8.GetBytes("STRICT-MODE-TEST");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcPrivateKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PrivateKey,
                pqcAlgorithm: PqcSignatureAlgorithm.MlDsa65,
                pqcPublicKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PublicKey);

            // Strip PQC
            envelope.PqcSignature = null;
            envelope.PqcPublicKey = null;

            var policy = new HybridMigrationPolicy { Mode = HybridMigrationMode.StrictHybrid };

            // Act
            var result = await _adapter.VerifyEnvelopeAsync(envelope, policy);

            // Assert: StrictHybrid rejects classical-only
            Assert.False(result.IsValid);
            Assert.Equal(HybridMigrationStatus.RejectedLegacy, result.Status);
            Assert.NotNull(result.ErrorMessage);
        }

        [Fact]
        public async Task EnforcePqcOnlyMode_LegacyOnly_Rejected()
        {
            // Arrange
            byte[] payload = Encoding.UTF8.GetBytes("ENFORCE-PQC-TEST");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcPrivateKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PrivateKey,
                pqcAlgorithm: PqcSignatureAlgorithm.MlDsa65,
                pqcPublicKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PublicKey);

            envelope.PqcSignature = null;
            envelope.PqcPublicKey = null;

            var policy = new HybridMigrationPolicy { Mode = HybridMigrationMode.EnforcePqcOnly };

            // Act
            var result = await _adapter.VerifyEnvelopeAsync(envelope, policy);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal(HybridMigrationStatus.RejectedLegacy, result.Status);
        }

        [Fact]
        public async Task UpgradeLegacyToDualEnvelope_ElevatesExistingClassicSignature()
        {
            // Arrange: Existing legacy classical package
            byte[] payload = Encoding.UTF8.GetBytes("LEGACY-TRANSACTION-RECORD-2024");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);

            var legacyEnvelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcPrivateKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PrivateKey,
                pqcAlgorithm: PqcSignatureAlgorithm.MlDsa65,
                pqcPublicKey: (await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65)).PublicKey);

            byte[] legacySig = legacyEnvelope.ClassicSignature!;

            // Act: Upgrade legacy signature by attaching PQC ML-DSA signature
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);
            var upgradedEnvelope = await _adapter.UpgradeLegacyToDualEnvelopeAsync(
                payload,
                legacySig,
                rsaPub,
                "RSA-2048",
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey,
                contextId: "UPGRADED-TRANSACTION");

            // Assert
            Assert.True(upgradedEnvelope.IsDualEnvelope);
            var verifyResult = await _adapter.VerifyEnvelopeAsync(upgradedEnvelope);
            Assert.True(verifyResult.IsValid);
            Assert.True(verifyResult.IsQuantumSafe);
            Assert.True(verifyResult.HybridIntegrityVerified);
            Assert.Equal(HybridMigrationStatus.QuantumSafeHybrid, verifyResult.Status);
        }

        [Fact]
        public async Task ExtractLegacyPackage_ValidDualEnvelope_ReturnsLegacyPackage()
        {
            // Arrange
            byte[] payload = Encoding.UTF8.GetBytes("EXTRACT-LEGACY-TEST");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey,
                contextId: "CTX-EXTRACT");

            // Act
            var legacyPkg = _adapter.ExtractLegacyPackage(envelope);

            // Assert
            Assert.NotNull(legacyPkg);
            Assert.Equal(payload, legacyPkg.Payload);
            Assert.Equal(envelope.ClassicSignature, legacyPkg.Signature);
            Assert.Equal(rsaPub, legacyPkg.PublicKey);
            Assert.Equal("RSA-2048", legacyPkg.Algorithm);
            Assert.Equal("CTX-EXTRACT", legacyPkg.ContextId);
        }

        [Fact]
        public void ExtractLegacyPackage_NoClassicSignature_ThrowsInvalidOperationException()
        {
            var envelope = new HybridDualEnvelope
            {
                Payload = Encoding.UTF8.GetBytes("NO-CLASSIC-DATA")
            };

            Assert.Throws<InvalidOperationException>(() => _adapter.ExtractLegacyPackage(envelope));
        }

        [Fact]
        public async Task VerifyEnvelope_EmptyPayload_ReturnsInvalidPayloadStatus()
        {
            var envelope = new HybridDualEnvelope
            {
                Payload = Array.Empty<byte>()
            };

            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            Assert.False(result.IsValid);
            Assert.Equal(HybridMigrationStatus.InvalidPayload, result.Status);
        }

        [Fact]
        public async Task VerifyEnvelope_NoSignatures_ReturnsSignatureInvalid()
        {
            var envelope = new HybridDualEnvelope
            {
                Payload = Encoding.UTF8.GetBytes("TEST-NO-SIGS")
            };

            var result = await _adapter.VerifyEnvelopeAsync(envelope);

            Assert.False(result.IsValid);
            Assert.Equal(HybridMigrationStatus.SignatureInvalid, result.Status);
        }

        [Fact]
        public async Task VerifyEnvelope_ExpiredTimestamp_FailsPolicy()
        {
            byte[] payload = Encoding.UTF8.GetBytes("EXPIRED-ENVELOPE-TEST");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey);

            // Set timestamp to 2 hours ago
            envelope.TimestampUtc = DateTimeOffset.UtcNow.AddHours(-2);

            var policy = new HybridMigrationPolicy
            {
                MaxEnvelopeAge = TimeSpan.FromMinutes(30)
            };

            var result = await _adapter.VerifyEnvelopeAsync(envelope, policy);

            Assert.False(result.IsValid);
            Assert.Equal(HybridMigrationStatus.SignatureInvalid, result.Status);
            Assert.Contains("timestamp is outside the allowed window", result.ErrorMessage ?? "");
        }

        [Theory]
        [InlineData("RSA-1024", true, "Critical")]
        [InlineData("RSA-2048", true, "Critical")]
        [InlineData("RSA-4096", true, "High")]
        [InlineData("ECDSA-P256", true, "Critical")]
        [InlineData("ECDSA-P384", true, "High")]
        [InlineData("ML-DSA-65", false, "QuantumSafe")]
        [InlineData("ML-KEM-768", false, "QuantumSafe")]
        public void AssessAlgorithmRisk_ReturnsCorrectRiskProfile(string algorithm, bool expectedDeprecated, string expectedRisk)
        {
            var assessment = _adapter.AssessAlgorithmRisk(algorithm);

            Assert.NotNull(assessment);
            Assert.Equal(algorithm, assessment.AlgorithmName);
            Assert.Equal(expectedDeprecated, assessment.IsDeprecatedByQuantum);
            Assert.Equal(expectedRisk, assessment.RiskLevel);
            Assert.NotEmpty(assessment.ThreatVector);
            Assert.NotEmpty(assessment.EstimatedHorizon);
        }

        [Fact]
        public async Task VerifyDualEnvelopeAsync_DirectParameters_Succeeds()
        {
            byte[] payload = Encoding.UTF8.GetBytes("DIRECT-PARAMETERS-TEST");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey);

            var result = await _adapter.VerifyDualEnvelopeAsync(
                payload,
                envelope.ClassicSignature,
                envelope.ClassicPublicKey,
                envelope.ClassicAlgorithm,
                envelope.PqcSignature,
                envelope.PqcPublicKey,
                envelope.PqcAlgorithm,
                HybridMigrationMode.Permissive);

            Assert.True(result.IsValid);
            Assert.True(result.IsQuantumSafe);
            Assert.True(result.HybridIntegrityVerified);
        }

        [Fact]
        public async Task AuditOnlyMode_DoesNotBlockLegacyTransactions()
        {
            byte[] payload = Encoding.UTF8.GetBytes("AUDIT-ONLY-PAYLOAD");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey);

            // Strip PQC
            envelope.PqcSignature = null;
            envelope.PqcPublicKey = null;

            var policy = new HybridMigrationPolicy { Mode = HybridMigrationMode.AuditOnly };

            var result = await _adapter.VerifyEnvelopeAsync(envelope, policy);

            Assert.True(result.IsValid);
            Assert.Equal(HybridMigrationMode.AuditOnly, result.ModeEvaluated);
            Assert.Equal(HybridMigrationStatus.PermittedLegacyWarning, result.Status);
        }

        [Fact]
        public async Task JsonSerialization_RoundTrip_PreservesIntegrityAndVerifies()
        {
            byte[] payload = Encoding.UTF8.GetBytes("JSON-SERIALIZATION-ROUNDTRIP");
            var (rsaPriv, rsaPub) = HybridPermissiveMigrationAdapter.GenerateClassicRsaKeyPair(2048);
            var pqcKey = await _trustEngine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);

            var envelope = await _adapter.CreateDualEnvelopeAsync(
                payload,
                rsaPriv,
                "RSA-2048",
                rsaPub,
                pqcKey.PrivateKey,
                PqcSignatureAlgorithm.MlDsa65,
                pqcKey.PublicKey,
                contextId: "JSON-SERIALIZE-CTX");

            envelope.Metadata["CustomTag"] = "QuantumSecurityAudit";

            // Serialize
            string json = envelope.ToJson();
            Assert.False(string.IsNullOrWhiteSpace(json));

            // Deserialize
            var deserialized = HybridDualEnvelope.FromJson(json);
            Assert.NotNull(deserialized);
            Assert.True(deserialized!.IsDualEnvelope);
            Assert.Equal("JSON-SERIALIZE-CTX", deserialized.ContextId);
            Assert.Equal("QuantumSecurityAudit", deserialized.Metadata["CustomTag"]);

            // Verify deserialized envelope
            var result = await _adapter.VerifyEnvelopeAsync(deserialized);
            Assert.True(result.IsValid);
            Assert.True(result.IsQuantumSafe);
            Assert.True(result.HybridIntegrityVerified);
        }
    }
}
