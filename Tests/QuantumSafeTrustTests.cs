// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Text;
using System.Threading.Tasks;
using Tum.Trust.Security.Core.Models.QuantumSafe;
using Tum.Trust.Security.Infrastructure.Security;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class QuantumSafeTrustTests
    {
        private readonly QuantumSafeTrustEngine _engine = new();

        [Theory]
        [InlineData(PqcSignatureAlgorithm.MlDsa44, 128)]
        [InlineData(PqcSignatureAlgorithm.MlDsa65, 192)]
        [InlineData(PqcSignatureAlgorithm.MlDsa87, 256)]
        [InlineData(PqcSignatureAlgorithm.HybridRsa4096Dilithium, 192)]
        [InlineData(PqcSignatureAlgorithm.HybridEcdsaDilithium, 192)]
        public async Task GenerateKeyPair_ProducesValidKeys_WithExpectedSecurityBits(PqcSignatureAlgorithm algorithm, int expectedBits)
        {
            var keyPair = await _engine.GeneratePqcKeyPairAsync(algorithm);

            Assert.NotNull(keyPair);
            Assert.Equal(algorithm, keyPair.Algorithm);
            Assert.Equal(expectedBits, keyPair.QuantumSecurityBits);
            Assert.True(keyPair.PublicKey.Length > 0);
            Assert.True(keyPair.PrivateKey.Length > 0);
            Assert.False(string.IsNullOrEmpty(keyPair.PublicKeyBase64));

            if (algorithm == PqcSignatureAlgorithm.HybridRsa4096Dilithium || algorithm == PqcSignatureAlgorithm.HybridEcdsaDilithium)
            {
                Assert.NotNull(keyPair.ClassicPublicKey);
                Assert.NotNull(keyPair.ClassicPrivateKey);
            }
        }

        [Fact]
        public async Task SignAndVerify_MlDsa65_ValidPayload_Succeeds()
        {
            var keyPair = await _engine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);
            byte[] payload = Encoding.UTF8.GetBytes("TUM-QUANTUM-RESEARCH-LAB-PAYLOAD-2026");

            byte[] signature = await _engine.SignQuantumSafeAsync(payload, keyPair.PrivateKey, PqcSignatureAlgorithm.MlDsa65);

            var req = new PqcVerificationRequest
            {
                Payload = payload,
                PqcSignature = signature,
                PqcPublicKey = keyPair.PublicKey,
                Algorithm = PqcSignatureAlgorithm.MlDsa65
            };

            var result = await _engine.VerifyQuantumSafeSignatureAsync(req);

            Assert.True(result.IsValid);
            Assert.True(result.IsQuantumSafe);
            Assert.Equal(192, result.QuantumSecurityBits);
            Assert.False(string.IsNullOrEmpty(result.KeyFingerprintSha256));
            Assert.Null(result.ErrorMessage);
        }

        [Fact]
        public async Task Verify_CorruptedSignature_FailsVerification()
        {
            var keyPair = await _engine.GeneratePqcKeyPairAsync(PqcSignatureAlgorithm.MlDsa65);
            byte[] payload = Encoding.UTF8.GetBytes("GENUINE-PAYLOAD");

            byte[] signature = await _engine.SignQuantumSafeAsync(payload, keyPair.PrivateKey, PqcSignatureAlgorithm.MlDsa65);

            // Corrupt the signature header
            signature[0] = (byte)(signature[0] ^ 0xFF);

            var req = new PqcVerificationRequest
            {
                Payload = payload,
                PqcSignature = signature,
                PqcPublicKey = keyPair.PublicKey,
                Algorithm = PqcSignatureAlgorithm.MlDsa65
            };

            var result = await _engine.VerifyQuantumSafeSignatureAsync(req);

            Assert.False(result.IsValid);
            Assert.False(result.IsQuantumSafe);
            Assert.NotNull(result.ErrorMessage);
        }

        [Theory]
        [InlineData("RSA-2048", true)]
        [InlineData("RSA-4096", true)]
        [InlineData("ECDSA-P256", true)]
        [InlineData("Ed25519", true)]
        [InlineData("ML-DSA-65", false)]
        [InlineData("CRYSTALS-Dilithium", false)]
        [InlineData("ML-KEM-768", false)]
        [InlineData("Kyber-1024", false)]
        public void IsAlgorithmDeprecatedByQuantum_CorrectlyIdentifiesVulnerabilities(string algo, bool expectedDeprecated)
        {
            bool deprecated = _engine.IsAlgorithmDeprecatedByQuantum(algo);
            Assert.Equal(expectedDeprecated, deprecated);
        }
    }
}
