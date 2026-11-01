// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Tum.Quantum.Engine;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class PqcOidcTokenEngineTests
    {
        private readonly PqcOidcTokenEngine _oidcEngine = new();

        [Fact]
        public async Task IssueAndValidate_IdToken_ValidToken_Succeeds()
        {
            string sub = "did:tum:citizen:1100500123456";
            string aud = "tum-kiosk-portal-web";
            string iss = "https://identity.tum.co.th/oauth2/v1";

            var customClaims = new Dictionary<string, object>
            {
                ["thai_citizen_id"] = "1100500123456",
                ["title"] = "นาย",
                ["first_name"] = "ประสิทธิ์",
                ["last_name"] = "บุญปานเศรษฐ์"
            };

            var pkg = await _oidcEngine.IssueIdTokenAsync(
                subject: sub,
                audience: aud,
                issuer: iss,
                customClaims: customClaims,
                lifetime: TimeSpan.FromMinutes(30));

            Assert.NotNull(pkg);
            Assert.False(string.IsNullOrEmpty(pkg.RawToken));
            Assert.Equal(3, pkg.RawToken.Split('.').Length);
            Assert.Equal(sub, pkg.Subject);

            // Validate
            var valRes = await _oidcEngine.ValidateIdTokenAsync(
                rawToken: pkg.RawToken,
                expectedAudience: aud,
                expectedIssuer: iss);

            Assert.True(valRes.IsValid);
            Assert.True(valRes.IsQuantumSafe);
            Assert.Equal(sub, valRes.Subject);
            Assert.Null(valRes.ErrorMessage);
        }

        [Fact]
        public async Task ValidateIdToken_AudienceMismatch_FailsValidation()
        {
            var pkg = await _oidcEngine.IssueIdTokenAsync(
                subject: "user-123",
                audience: "expected-app-client");

            var valRes = await _oidcEngine.ValidateIdTokenAsync(
                rawToken: pkg.RawToken,
                expectedAudience: "wrong-app-client");

            Assert.False(valRes.IsValid);
            Assert.Contains("Audience mismatch", valRes.ErrorMessage);
        }

        [Fact]
        public async Task ValidateIdToken_TamperedPayload_FailsSignatureVerification()
        {
            var pkg = await _oidcEngine.IssueIdTokenAsync(
                subject: "user-authentic",
                audience: "app-client");

            // Tamper token signature segment
            string[] parts = pkg.RawToken.Split('.');
            char tamperedChar = parts[2][0] == 'A' ? 'B' : 'A';
            string tamperedSignature = tamperedChar + parts[2][1..];
            string tamperedToken = $"{parts[0]}.{parts[1]}.{tamperedSignature}";

            var valRes = await _oidcEngine.ValidateIdTokenAsync(
                rawToken: tamperedToken,
                expectedAudience: "app-client");

            Assert.False(valRes.IsValid);
            Assert.Contains("signature verification failed", valRes.ErrorMessage);
        }

        [Fact]
        public async Task GetJwksKeys_ReturnsValidPqcKey()
        {
            var keys = await _oidcEngine.GetJwksKeysAsync();

            Assert.NotNull(keys);
            Assert.NotEmpty(keys);
            var key = keys[0];
            Assert.Equal("PQC", key.Kty);
            Assert.Equal("ML-DSA-65", key.Alg);
            Assert.NotEmpty(key.Kid);
            Assert.NotEmpty(key.X);
        }
    }
}
