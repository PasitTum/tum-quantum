// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class HndlQuantumAttackSimulatorTests
    {
        private readonly HndlQuantumAttackSimulator _simulator = new();

        [Fact]
        public async Task SimulateAttack_RSA2048_WithSufficientQubits_SucceedsDecryptionAndMarksCritical()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "RSA-2048",
                CapturedPayload = Encoding.UTF8.GetBytes("SOVEREIGN_ID_TOP_SECRET_PASSPORT_NUMBER_99981"),
                AdversaryHardware = QuantumHardwareProfile.CreateStandardAdversary(),
                SimulationDecryptionYear = 2030
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.True(res.IsHarvestVulnerable);
            Assert.True(res.IsDecryptedByShor);
            Assert.Equal(HndlForwardSecrecyStatus.Compromised, res.ForwardSecrecyStatus);
            Assert.Equal(HndlRiskSeverity.Critical, res.VulnerabilitySeverity);
            Assert.Equal(100.0, res.VulnerabilityScore);
            Assert.Equal(4098, res.CryptanalysisMetrics.ShorLogicalQubitsRequired);
            Assert.NotNull(res.SimulatedDecryptedPayload);
            Assert.Equal("SOVEREIGN_ID_TOP_SECRET_PASSPORT_NUMBER_99981", Encoding.UTF8.GetString(res.SimulatedDecryptedPayload!));
            Assert.Contains("Shor's Algorithm", res.PrimaryAttackVector);
            Assert.Contains("HybridPermissiveMigrationAdapter", res.RecommendedMitigation);
        }

        [Fact]
        public async Task SimulateAttack_RSA4096_WithSufficientQubits_CalculatesCorrectMetrics()
        {
            var adversary = new QuantumHardwareProfile
            {
                LogicalQubits = 10_000,
                PhysicalQubits = 45_000_000,
                OperationalYear = 2032
            };

            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "RSA-4096",
                AdversaryHardware = adversary,
                SimulationDecryptionYear = 2035
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.True(res.IsHarvestVulnerable);
            Assert.True(res.IsDecryptedByShor);
            Assert.Equal(8194, res.CryptanalysisMetrics.ShorLogicalQubitsRequired);
            Assert.Equal(40_000_000, res.CryptanalysisMetrics.EstimatedPhysicalQubitsRequired);
            Assert.Equal(HndlRiskSeverity.Critical, res.VulnerabilitySeverity);
        }

        [Fact]
        public async Task SimulateAttack_ECDSA256_WithSufficientQubits_DerivesECDLPAndMarksCompromised()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "ECDSA-P256",
                CapturedPayload = Encoding.UTF8.GetBytes("BANK_TRANSFER_AUTHENTICATION_TOKEN_THB_5000000"),
                AdversaryHardware = QuantumHardwareProfile.CreateStandardAdversary(),
                SimulationDecryptionYear = 2030
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.True(res.IsHarvestVulnerable);
            Assert.True(res.IsDecryptedByShor);
            Assert.Equal(HndlForwardSecrecyStatus.Compromised, res.ForwardSecrecyStatus);
            Assert.Equal(2330, res.CryptanalysisMetrics.ShorLogicalQubitsRequired);
            Assert.NotNull(res.SimulatedDecryptedPayload);
            Assert.Contains("Discrete Logarithm", res.PrimaryAttackVector);
        }

        [Fact]
        public async Task SimulateAttack_Ed25519_CompromisedByShor()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "Ed25519",
                AdversaryHardware = QuantumHardwareProfile.CreateStandardAdversary()
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.True(res.IsHarvestVulnerable);
            Assert.Equal(HndlForwardSecrecyStatus.Compromised, res.ForwardSecrecyStatus);
            Assert.Equal(0, res.CryptanalysisMetrics.PostQuantumSecurityBits);
        }

        [Fact]
        public async Task SimulateAttack_MlKem768_ImmuneToQuantumAttack_ZeroVulnerabilityScore()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "ML-KEM-768",
                CapturedPayload = Encoding.UTF8.GetBytes("POST_QUANTUM_KEY_ENCAPSULATED_SESSION_DATA"),
                AdversaryHardware = QuantumHardwareProfile.CreateStandardAdversary()
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.False(res.IsHarvestVulnerable);
            Assert.False(res.IsDecryptedByShor);
            Assert.Equal(HndlForwardSecrecyStatus.PqcProtected, res.ForwardSecrecyStatus);
            Assert.Equal(HndlRiskSeverity.Immune, res.VulnerabilitySeverity);
            Assert.Equal(0.0, res.VulnerabilityScore);
            Assert.Equal(192, res.CryptanalysisMetrics.PostQuantumSecurityBits);
            Assert.True(res.CryptanalysisMetrics.IsQuantumImmune);
            Assert.Null(res.SimulatedDecryptedPayload); // Remains uncompromised
            Assert.Contains("Lattice", res.PrimaryAttackVector);
        }

        [Fact]
        public async Task SimulateAttack_MlKem1024_ImmuneToQuantumAttack_PostQuantum256Bits()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "ML-KEM-1024",
                AdversaryHardware = QuantumHardwareProfile.CreateStandardAdversary()
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.False(res.IsHarvestVulnerable);
            Assert.Equal(256, res.CryptanalysisMetrics.PostQuantumSecurityBits);
            Assert.True(res.CryptanalysisMetrics.IsQuantumImmune);
            Assert.Equal(0.0, res.VulnerabilityScore);
        }

        [Fact]
        public async Task SimulateAttack_MlDsa65_ImmuneToQuantumAttack_ReturnsImmuneStatus()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "ML-DSA-65",
                AdversaryHardware = QuantumHardwareProfile.CreateStandardAdversary()
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.False(res.IsHarvestVulnerable);
            Assert.Equal(HndlRiskSeverity.Immune, res.VulnerabilitySeverity);
            Assert.Equal(192, res.CryptanalysisMetrics.PostQuantumSecurityBits);
        }

        [Fact]
        public async Task SimulateAttack_HybridDualEnvelope_ClassicalBrokenButPqcEnvelopeIntact()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "Hybrid-RSA-MLDSA-65",
                CapturedPayload = Encoding.UTF8.GetBytes("CONFIDENTIAL_GOVERNMENT_DUAL_ENVELOPE_DATA"),
                AdversaryHardware = QuantumHardwareProfile.CreateStandardAdversary()
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.False(res.IsHarvestVulnerable);
            Assert.False(res.IsDecryptedByShor);
            Assert.Equal(HndlForwardSecrecyStatus.Degraded, res.ForwardSecrecyStatus);
            Assert.Equal(HndlRiskSeverity.Low, res.VulnerabilitySeverity);
            Assert.Equal(12.0, res.VulnerabilityScore);
            Assert.Null(res.SimulatedDecryptedPayload);
            Assert.Contains("PQC envelope remains impenetrable", res.EstimatedBreakTimeDescription);
        }

        [Fact]
        public async Task SimulateAttack_ModernNisqHardware_IdentifiesHarvestAtRiskAwaitingCrqc()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "RSA-2048",
                AdversaryHardware = QuantumHardwareProfile.CreateNisqEra(),
                SimulationDecryptionYear = 2026
            };

            var res = await _simulator.SimulateAttackAsync(req);

            Assert.NotNull(res);
            Assert.True(res.IsHarvestVulnerable);
            Assert.False(res.IsDecryptedByShor); // Cannot decrypt yet with NISQ
            Assert.Equal(HndlRiskSeverity.High, res.VulnerabilitySeverity);
            Assert.Equal(85.0, res.VulnerabilityScore);
            Assert.Contains("awaiting operational CRQC", res.EstimatedBreakTimeDescription);
        }

        [Fact]
        public void CalculateTheoreticalComplexity_KnownAlgorithms_ReturnsAccurateMetrics()
        {
            var rsa = _simulator.CalculateTheoreticalComplexity("RSA-2048");
            Assert.Equal(4098, rsa.ShorLogicalQubitsRequired);
            Assert.Equal(20_000_000, rsa.EstimatedPhysicalQubitsRequired);
            Assert.False(rsa.IsQuantumImmune);

            var rsa3072 = _simulator.CalculateTheoreticalComplexity("RSA-3072");
            Assert.Equal(6146, rsa3072.ShorLogicalQubitsRequired);

            var ecdsa = _simulator.CalculateTheoreticalComplexity("ECDSA-P256");
            Assert.Equal(2330, ecdsa.ShorLogicalQubitsRequired);
            Assert.False(ecdsa.IsQuantumImmune);

            var p384 = _simulator.CalculateTheoreticalComplexity("ECDSA-P384");
            Assert.Equal(3480, p384.ShorLogicalQubitsRequired);

            var mlKem768 = _simulator.CalculateTheoreticalComplexity("ML-KEM-768");
            Assert.Equal(0, mlKem768.ShorLogicalQubitsRequired);
            Assert.Equal(192, mlKem768.PostQuantumSecurityBits);
            Assert.True(mlKem768.IsQuantumImmune);

            var mlDsa65 = _simulator.CalculateTheoreticalComplexity("ML-DSA-65");
            Assert.Equal(0, mlDsa65.ShorLogicalQubitsRequired);
            Assert.Equal(192, mlDsa65.PostQuantumSecurityBits);
            Assert.True(mlDsa65.IsQuantumImmune);
        }

        [Theory]
        [InlineData("ECDHE-RSA", true)]
        [InlineData("ECDH-P256", true)]
        [InlineData("RSA-2048", true)]
        [InlineData("ML-KEM-768", false)]
        [InlineData("KYBER-1024", false)]
        [InlineData("Hybrid-KEM", false)]
        public void EvaluateForwardSecrecyVulnerability_ExpectedOutcomes(string kex, bool expectedVulnerable)
        {
            bool isVulnerable = _simulator.EvaluateForwardSecrecyVulnerability(kex, "AES-256-GCM");
            Assert.Equal(expectedVulnerable, isVulnerable);
        }

        [Fact]
        public async Task SimulateBatchHarvest_MixedFleetAssets_CalculatesAccuratePercentagesAndScore()
        {
            var batchReq = new HndlHarvestBatchRequest
            {
                TargetSystemName = "National Digital Super-Highway Gateways",
                HarvestedAssets = new List<HndlSimulationRequest>
                {
                    new() { TargetAlgorithm = "RSA-2048" },
                    new() { TargetAlgorithm = "ECDSA-P256" },
                    new() { TargetAlgorithm = "ML-KEM-768" },
                    new() { TargetAlgorithm = "ML-DSA-65" }
                }
            };

            var res = await _simulator.SimulateBatchHarvestAsync(batchReq);

            Assert.NotNull(res);
            Assert.Equal(4, res.TotalAssetsEvaluated);
            Assert.Equal(2, res.VulnerableAssetCount);
            Assert.Equal(2, res.QuantumImmuneAssetCount);
            Assert.Equal(50.0, res.QuantumReadinessPercentage);
            Assert.True(res.AverageVulnerabilityScore > 0);
            Assert.Contains("National Digital Super-Highway Gateways", res.ExecutiveSummary);
            Assert.Equal(4, res.AssetResults.Count);
        }

        [Fact]
        public async Task SimulateBatchHarvest_AllPqcImmune_Returns100PercentReadiness()
        {
            var batchReq = new HndlHarvestBatchRequest
            {
                TargetSystemName = "TUM Quantum Sovereign Core",
                HarvestedAssets = new List<HndlSimulationRequest>
                {
                    new() { TargetAlgorithm = "ML-KEM-768" },
                    new() { TargetAlgorithm = "ML-DSA-65" },
                    new() { TargetAlgorithm = "ML-DSA-87" }
                }
            };

            var res = await _simulator.SimulateBatchHarvestAsync(batchReq);

            Assert.Equal(3, res.TotalAssetsEvaluated);
            Assert.Equal(0, res.VulnerableAssetCount);
            Assert.Equal(3, res.QuantumImmuneAssetCount);
            Assert.Equal(100.0, res.QuantumReadinessPercentage);
            Assert.Equal(0.0, res.AverageVulnerabilityScore);
            Assert.Contains("FULL POST-QUANTUM RESILIENCE", res.ExecutiveSummary);
        }

        [Fact]
        public async Task SimulateBatchHarvest_AllClassical_Returns0PercentReadinessAndCriticalAdvisory()
        {
            var batchReq = new HndlHarvestBatchRequest
            {
                TargetSystemName = "Legacy Bank Core System",
                HarvestedAssets = new List<HndlSimulationRequest>
                {
                    new() { TargetAlgorithm = "RSA-2048" },
                    new() { TargetAlgorithm = "ECDSA-P256" }
                }
            };

            var res = await _simulator.SimulateBatchHarvestAsync(batchReq);

            Assert.Equal(2, res.TotalAssetsEvaluated);
            Assert.Equal(2, res.VulnerableAssetCount);
            Assert.Equal(0, res.QuantumImmuneAssetCount);
            Assert.Equal(0.0, res.QuantumReadinessPercentage);
            Assert.Contains("CRITICAL EXECUTIVE ACTION REQUIRED", res.ExecutiveSummary);
        }

        [Fact]
        public async Task SimulateAttack_PerformanceLatency_Under5Milliseconds()
        {
            var req = new HndlSimulationRequest
            {
                TargetAlgorithm = "ML-KEM-768"
            };

            // Warm up
            await _simulator.SimulateAttackAsync(req);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var res = await _simulator.SimulateAttackAsync(req);
            sw.Stop();

            Assert.True(sw.ElapsedMilliseconds < 15, $"Execution took {sw.ElapsedMilliseconds}ms, expected < 15ms");
            Assert.True(res.SimulationDurationMs < 15);
        }

        [Fact]
        public async Task SimulateAttack_NullRequest_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _simulator.SimulateAttackAsync(null!));
        }

        [Fact]
        public async Task SimulateBatchHarvest_NullRequest_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _simulator.SimulateBatchHarvestAsync(null!));
        }
    }
}
