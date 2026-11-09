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
    public class ServerIntegrationTests
    {
        private readonly PqcTls13HandshakeEngine _tlsEngine = new();
        private readonly PqcZeroKnowledgeProver _zkProver = new();
        private readonly Pkcs11QuantumHsmDriver _hsmDriver = new();
        private readonly Fips140AuditRunner _fipsAuditor = new();
        private readonly TimeStampAuthorityEngine _tsaEngine = new();
        private readonly PqcOidcTokenEngine _oidcEngine = new();
        private readonly ConstantTimeAnalyzer _constantTimeAnalyzer = new();

        [Fact]
        public async Task EndToEnd_TlsAndOidcAndTsaPipeline_ExecutesCleanly()
        {
            // 1. TLS 1.3 Key Exchange
            var clientHello = await _tlsEngine.GenerateClientHelloAsync();
            var serverHello = await _tlsEngine.ProcessClientHelloAsync(clientHello);
            var tlsResult = await _tlsEngine.FinalizeClientHandshakeAsync(clientHello, serverHello);
            Assert.True(tlsResult.IsSuccessful);

            // 2. Issue PQC-OIDC Identity Token over TLS channel
            var tokenPkg = await _oidcEngine.IssueIdTokenAsync("did:tum:citizen:test", "kiosk-aud");
            var valResult = await _oidcEngine.ValidateIdTokenAsync(tokenPkg.RawToken, "kiosk-aud");
            Assert.True(valResult.IsValid);

            // 3. Issue RFC 3161 PQC Timestamp
            var tsaReq = _tsaEngine.CreateRequest(Encoding.UTF8.GetBytes(tokenPkg.RawToken));
            var tsaToken = await _tsaEngine.IssueTimeStampTokenAsync(tsaReq);
            Assert.Equal(PkiStatus.Granted, tsaToken.Status);

            // 4. Verify FIPS 140-3 Readiness
            var fipsReport = await _fipsAuditor.RunFips140ReadinessAuditAsync(Fips140SecurityLevel.Level3);
            Assert.True(fipsReport.IsCompliant);

            // 5. Query Quantum HSM
            var hsmInfo = await _hsmDriver.GetTokenInfoAsync(1);
            Assert.NotNull(hsmInfo);

            // 6. Execute Side-Channel Constant-Time Verification
            var ctaReport = await _constantTimeAnalyzer.RunFullVulnerabilityAnalysisAsync(new TimingAttackSimulationRequest
            {
                SampleIterations = 600,
                TStatisticThreshold = 4.5
            });
            Assert.True(ctaReport.IsOverallCompliant);
            Assert.True(ctaReport.PassedEvaluations >= 4);
        }
    }
}
