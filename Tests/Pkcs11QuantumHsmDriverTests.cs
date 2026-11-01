// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Tum.Trust.Security.Core.Models.QuantumSafe;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class Pkcs11QuantumHsmDriverTests
    {
        private readonly Pkcs11QuantumHsmDriver _driver = new();

        [Fact]
        public async Task GetTokenInfo_ReturnsValidHsmMetadata()
        {
            var info = await _driver.GetTokenInfoAsync(slotId: 1);

            Assert.NotNull(info);
            Assert.Contains("TUM", info.ManufacturerId);
            Assert.Contains("QVAULT", info.Model);
            Assert.Contains("FIPS 140-3 Level 4", info.PhysicalSecurityLevel);
            Assert.Contains("CKM_ML_DSA_65", info.SupportedMechanisms);
            Assert.Contains("CKM_ML_KEM_768", info.SupportedMechanisms);
        }

        [Fact]
        public async Task OpenSession_WithCorrectPin_OpensReadWriteUserSession()
        {
            var session = await _driver.OpenSessionAsync(slotId: 1, userPin: Pkcs11QuantumHsmDriver.DefaultUserPin);

            Assert.NotNull(session);
            Assert.True(session.SessionId > 0);
            Assert.Equal(Pkcs11SessionState.ReadWriteUser, session.State);

            await _driver.CloseSessionAsync(session);
            Assert.Equal(Pkcs11SessionState.Closed, session.State);
        }

        [Fact]
        public async Task OpenSession_WithInvalidPin_ThrowsAuthenticationException()
        {
            await Assert.ThrowsAsync<AuthenticationException>(() =>
                _driver.OpenSessionAsync(slotId: 1, userPin: "WRONG_PIN_999"));
        }

        [Fact]
        public async Task GenerateKeyAndSign_OnChip_ExecutesWithoutExposingPrivateKey()
        {
            var session = await _driver.OpenSessionAsync(slotId: 1, userPin: Pkcs11QuantumHsmDriver.DefaultUserPin);

            var keyHandle = await _driver.GeneratePqcKeyInHsmAsync(
                session,
                PqcSignatureAlgorithm.MlDsa65,
                "NATIONAL_DIGITAL_PASSPORT_SIGNER_KEY");

            Assert.NotNull(keyHandle);
            Assert.True(keyHandle.ObjectHandleId > 0);
            Assert.True(keyHandle.IsSensitive);
            Assert.True(keyHandle.IsNeverExtractable);
            Assert.NotEmpty(keyHandle.PublicKeyBytes);

            byte[] payload = Encoding.UTF8.GetBytes("SOVEREIGN_PASSPORT_CHIP_PAYLOAD_DG1_DG2");

            // Sign on-chip
            byte[] signature = await _driver.SignOnHsmAsync(session, keyHandle, payload);
            Assert.NotNull(signature);
            Assert.NotEmpty(signature);

            // Verify on-chip
            bool isValid = await _driver.VerifyOnHsmAsync(session, keyHandle, payload, signature);
            Assert.True(isValid);

            await _driver.CloseSessionAsync(session);
        }

        [Fact]
        public async Task SignOnHsm_AfterSessionClosed_ThrowsInvalidOperationException()
        {
            var session = await _driver.OpenSessionAsync(slotId: 1, userPin: Pkcs11QuantumHsmDriver.DefaultUserPin);
            var keyHandle = await _driver.GeneratePqcKeyInHsmAsync(session, PqcSignatureAlgorithm.MlDsa44, "TEST_KEY");

            await _driver.CloseSessionAsync(session);

            byte[] payload = Encoding.UTF8.GetBytes("DATA");
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _driver.SignOnHsmAsync(session, keyHandle, payload));
        }
    }
}
