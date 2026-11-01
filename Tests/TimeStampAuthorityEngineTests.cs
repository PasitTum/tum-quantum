// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Text;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class TimeStampAuthorityEngineTests
    {
        private readonly TimeStampAuthorityEngine _tsaEngine = new();

        [Fact]
        public async Task IssueAndVerify_TimeStampToken_SucceedsWithUntamperedPayload()
        {
            byte[] doc = Encoding.UTF8.GetBytes("SOVEREIGN_LAND_TITLE_DEED_ELECTRONIC_TRANSACTION_ACT_BE2544");
            var req = _tsaEngine.CreateRequest(doc, "SHA-384", nonce: 994827104);

            var token = await _tsaEngine.IssueTimeStampTokenAsync(req);

            Assert.NotNull(token);
            Assert.Equal(PkiStatus.Granted, token.Status);
            Assert.True(token.TstInfo.SerialNumber >= 1000000);
            Assert.Equal((ulong)994827104, token.TstInfo.Nonce);
            Assert.True(token.IsQuantumImmune);
            Assert.NotEmpty(token.PqcSignature);
            Assert.NotEmpty(token.TsaPublicKey);
            Assert.False(string.IsNullOrEmpty(token.TokenFingerprintSha384));

            // Verify with untampered document
            bool isValid = await _tsaEngine.VerifyTimeStampTokenAsync(token, doc);
            Assert.True(isValid);
        }

        [Fact]
        public async Task Verify_TimeStampToken_TamperedDocument_ReturnsFalse()
        {
            byte[] doc = Encoding.UTF8.GetBytes("ORIGINAL_CONTRACT_TERMS");
            byte[] tamperedDoc = Encoding.UTF8.GetBytes("TAMPERED_CONTRACT_TERMS");

            var req = _tsaEngine.CreateRequest(doc);
            var token = await _tsaEngine.IssueTimeStampTokenAsync(req);

            bool isValid = await _tsaEngine.VerifyTimeStampTokenAsync(token, tamperedDoc);
            Assert.False(isValid);
        }

        [Fact]
        public async Task Issue_TimeStampToken_MissingImprint_ReturnsRejection()
        {
            var req = new PqcTimeStampRequest
            {
                MessageImprint = Array.Empty<byte>()
            };

            var token = await _tsaEngine.IssueTimeStampTokenAsync(req);
            Assert.Equal(PkiStatus.Rejection, token.Status);
            Assert.Contains("badAlg", token.StatusString);
        }
    }
}
