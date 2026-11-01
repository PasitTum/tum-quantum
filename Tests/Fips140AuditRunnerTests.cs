// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading.Tasks;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class Fips140AuditRunnerTests
    {
        private readonly Fips140AuditRunner _runner = new();

        [Fact]
        public async Task RunFips140ReadinessAudit_Level3_SucceedsWithAllChecks()
        {
            var report = await _runner.RunFips140ReadinessAuditAsync(Fips140SecurityLevel.Level3);

            Assert.NotNull(report);
            Assert.Equal(Fips140SecurityLevel.Level3, report.TargetLevel);
            Assert.True(report.IsCompliant);
            Assert.True(report.PowerUpSelfTestsPassed);
            Assert.True(report.CspZeroizationVerified);
            Assert.True(report.EntropyHealthScore >= 7.8, $"Entropy health score was {report.EntropyHealthScore}, expected >= 7.8");
            Assert.NotEmpty(report.KatResults);
            Assert.All(report.KatResults, kat => Assert.True(kat.IsPassed));
            Assert.Equal(11, report.SectionChecklist.Count);
            Assert.All(report.SectionChecklist.Values, Assert.True);
            Assert.Contains("PASSED", report.ExecutiveSummary);
        }

        [Fact]
        public async Task RunPowerUpSelfTests_Succeeds()
        {
            bool passed = await _runner.RunPowerUpSelfTestsAsync();
            Assert.True(passed);
        }

        [Fact]
        public async Task VerifyCspZeroization_Succeeds()
        {
            bool zeroized = await _runner.VerifyCspZeroizationAsync();
            Assert.True(zeroized);
        }
    }
}
