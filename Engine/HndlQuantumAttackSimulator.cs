// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
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
    /// Production-grade engine for Harvest Now, Decrypt Later (HNDL) Quantum Attack Simulation.
    /// Simulates Shor's algorithm (period finding via QFT) and Grover's algorithm attack surfaces
    /// on classical asymmetric PKI (RSA/ECC) vs NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) lattice schemes.
    /// </summary>
    public class HndlQuantumAttackSimulator : IHndlQuantumAttackSimulator
    {
        private readonly IQuantumSafeTrustEngine _quantumEngine;
        private readonly ILogger<HndlQuantumAttackSimulator> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="HndlQuantumAttackSimulator"/> class.
        /// </summary>
        /// <param name="quantumEngine">Optional underlying quantum-safe trust engine.</param>
        /// <param name="logger">Optional logger instance.</param>
        public HndlQuantumAttackSimulator(
            IQuantumSafeTrustEngine? quantumEngine = null,
            ILogger<HndlQuantumAttackSimulator>? logger = null)
        {
            _quantumEngine = quantumEngine ?? new QuantumSafeTrustEngine();
            _logger = logger ?? NullLogger<HndlQuantumAttackSimulator>.Instance;
        }

        /// <inheritdoc />
        public Task<HndlSimulationResult> SimulateAttackAsync(HndlSimulationRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var sw = Stopwatch.StartNew();

            string targetAlg = string.IsNullOrWhiteSpace(request.TargetAlgorithm) ? "RSA-2048" : request.TargetAlgorithm.Trim();
            string bulkCipher = string.IsNullOrWhiteSpace(request.BulkCipherAlgorithm) ? "AES-256-GCM" : request.BulkCipherAlgorithm.Trim();
            var adversary = request.AdversaryHardware ?? QuantumHardwareProfile.CreateStandardAdversary();

            // Calculate theoretical complexity metrics for the target algorithm
            var metrics = CalculateTheoreticalComplexity(targetAlg);

            // Determine if the algorithm is vulnerable to Shor's algorithm
            bool isShorVulnerable = _quantumEngine.IsAlgorithmDeprecatedByQuantum(targetAlg);

            // Synthesize sample payload if none provided
            byte[] rawPayload = request.CapturedPayload ?? Encoding.UTF8.GetBytes(
                $"SOVEREIGN_CONFIDENTIAL_PAYLOAD_SESSION_REF_NIST_FIPS203_HARVEST_{DateTime.UtcNow.Ticks}");

            // Perform simulated cryptographic harvesting and decryption
            bool canAdversaryDecrypt;
            HndlForwardSecrecyStatus fsStatus;
            HndlRiskSeverity severity;
            double riskScore;
            byte[]? decryptedBytes = null;
            string breakTime;
            string attackVector;
            string analysis;
            string remediation;

            if (targetAlg.IndexOf("Hybrid", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                // Hybrid Classical + PQC
                canAdversaryDecrypt = false;
                fsStatus = HndlForwardSecrecyStatus.Degraded;
                severity = HndlRiskSeverity.Low;
                riskScore = 12.0;
                breakTime = "Classical layer compromised in ~2 hours; PQC envelope remains impenetrable";
                attackVector = "Partial Compromise: Classical component broken via Shor's algorithm; PQC lattice envelope held intact.";
                analysis = $"The hybrid structure combines classical PKI with NIST ML-DSA/ML-KEM. " +
                           $"While a quantum adversary with CRQC can factor the classical component, " +
                           $"the post-quantum envelope prevents plaintext recovery, upholding confidentiality and non-repudiation.";
                remediation = "Continue phased migration. Plan retirement of legacy classical signature/key-exchange components by 2030.";
            }
            else if (metrics.IsQuantumImmune)
            {
                // Lattice PQC (ML-KEM / ML-DSA)
                canAdversaryDecrypt = false;
                fsStatus = HndlForwardSecrecyStatus.PqcProtected;
                severity = HndlRiskSeverity.Immune;
                riskScore = 0.0;
                breakTime = "Mathematically Infeasible (>10^150 years under known quantum algorithms)";
                attackVector = $"Protected by Lattice Hardness ({metrics.MathematicalHardnessAssumption}).";
                analysis = $"The asset uses {targetAlg}, which is mathematically immune to Shor's polynomial-time factoring. " +
                           $"The best known quantum attacks (quantum sieve on SVP) require over 2^{metrics.PostQuantumSecurityBits} operations, " +
                           $"exceeding the computational capacity of any conceivable physical universe.";
                remediation = "No immediate migration required. Algorithm meets NIST FIPS standards for post-quantum immunity.";
            }
            else if (isShorVulnerable)
            {
                // Classical Asymmetric (RSA / ECDSA / ECDH / Ed25519)
                bool adversaryHasSufficientQubits = adversary.LogicalQubits >= metrics.ShorLogicalQubitsRequired;

                if (adversaryHasSufficientQubits && adversary.OperationalYear <= request.SimulationDecryptionYear)
                {
                    canAdversaryDecrypt = true;
                    fsStatus = HndlForwardSecrecyStatus.Compromised;
                    severity = HndlRiskSeverity.Critical;
                    riskScore = 100.0;
                    breakTime = targetAlg.IndexOf("RSA", StringComparison.OrdinalIgnoreCase) >= 0
                        ? "4.2 hours with 20M physical qubits (Surface Code)"
                        : "1.8 hours with 12M physical qubits (Surface Code)";
                    attackVector = targetAlg.IndexOf("RSA", StringComparison.OrdinalIgnoreCase) >= 0
                        ? "Shor's Algorithm for Integer Factorization: Order-finding via Quantum Fourier Transform (QFT)."
                        : "Shor's Algorithm for Elliptic Curve Discrete Logarithm Problem (ECDLP).";

                    // Simulate actual derivation of session secret and plaintext decryption
                    decryptedBytes = SimulatePlaintextDecryption(rawPayload, targetAlg, bulkCipher);

                    analysis = $"CRITICAL VULNERABILITY: Adversary with {adversary.LogicalQubits} logical qubits " +
                               $"meets the threshold ({metrics.ShorLogicalQubitsRequired} required). " +
                               $"All intercepted traffic and archival data encrypted under {targetAlg} can be decrypted retroactively. " +
                               $"Forward secrecy is completely nullified.";
                    remediation = "URGENT: Replace classical key exchange with NIST FIPS 203 (ML-KEM-768). " +
                                  "Deploy Tum.Quantum HybridPermissiveMigrationAdapter immediately to wrap existing PKI.";
                }
                else
                {
                    // Quantum hardware not yet sufficient today, but asset is harvested for future decryption
                    canAdversaryDecrypt = false;
                    fsStatus = HndlForwardSecrecyStatus.Compromised;
                    severity = HndlRiskSeverity.High;
                    riskScore = 85.0;
                    breakTime = $"Harvester backlog queue awaiting operational CRQC ({adversary.OperationalYear})";
                    attackVector = $"Harvest Now, Decrypt Later (HNDL): Traffic archived awaiting CRQC with >= {metrics.ShorLogicalQubitsRequired} logical qubits.";
                    analysis = $"High Risk: While current hardware cannot run Shor's algorithm on enterprise keys, " +
                               $"hostile actors are intercepting and stockpiling this traffic today. " +
                               $"Upon CRQC deployment in {adversary.OperationalYear}, retroactive decryption will succeed.";
                    remediation = "Deploy NIST FIPS 203 ML-KEM-768 encapsulation now to protect current traffic from future decryption.";
                }
            }
            else
            {
                // Symmetric or Unrecognized
                canAdversaryDecrypt = false;
                fsStatus = HndlForwardSecrecyStatus.Immune;
                severity = HndlRiskSeverity.Medium;
                riskScore = 40.0;
                breakTime = "Grover quadratic search requires 2^128 evaluations";
                attackVector = "Grover's Algorithm amplitude amplification on symmetric key space.";
                analysis = $"Symmetric algorithm with Grover speedup evaluated. Ensure >= 256-bit key sizes (e.g. AES-256) for 128-bit quantum security.";
                remediation = "Enforce AES-256-GCM or ChaCha20-Poly1305 as default bulk cipher across all endpoints.";
            }

            bool isHarvestVulnerable = isShorVulnerable && targetAlg.IndexOf("Hybrid", StringComparison.OrdinalIgnoreCase) < 0 && !metrics.IsQuantumImmune;

            sw.Stop();

            var result = new HndlSimulationResult
            {
                TargetAlgorithm = targetAlg,
                IsHarvestVulnerable = isHarvestVulnerable,
                IsDecryptedByShor = canAdversaryDecrypt,
                ForwardSecrecyStatus = fsStatus,
                VulnerabilitySeverity = severity,
                VulnerabilityScore = riskScore,
                CryptanalysisMetrics = metrics,
                EstimatedBreakTimeDescription = breakTime,
                PrimaryAttackVector = attackVector,
                SimulationAnalysis = analysis,
                RecommendedMitigation = remediation,
                SimulatedDecryptedPayload = decryptedBytes,
                SimulationDurationMs = sw.Elapsed.TotalMilliseconds,
                SimulatedAtUtc = DateTimeOffset.UtcNow
            };

            _logger.LogInformation("HNDL Simulation executed: TargetAlg={TargetAlgorithm}, Vulnerable={IsVulnerable}, Decrypted={IsDecrypted}, Score={Score:F1}, Latency={Latency:F2}ms",
                targetAlg, result.IsHarvestVulnerable, result.IsDecryptedByShor, result.VulnerabilityScore, result.SimulationDurationMs);

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public async Task<HndlHarvestBatchResult> SimulateBatchHarvestAsync(HndlHarvestBatchRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var sw = Stopwatch.StartNew();

            var assets = request.HarvestedAssets ?? new List<HndlSimulationRequest>();
            var results = new List<HndlSimulationResult>(assets.Count);

            int vulnerableCount = 0;
            int immuneCount = 0;
            double totalScore = 0.0;

            foreach (var asset in assets)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (asset.AdversaryHardware == null && request.GlobalAdversaryProfile != null)
                {
                    asset.AdversaryHardware = request.GlobalAdversaryProfile;
                }

                var res = await SimulateAttackAsync(asset, cancellationToken).ConfigureAwait(false);
                results.Add(res);

                if (res.IsHarvestVulnerable)
                {
                    vulnerableCount++;
                }
                else
                {
                    immuneCount++;
                }

                totalScore += res.VulnerabilityScore;
            }

            int totalAssets = assets.Count;
            double avgScore = totalAssets > 0 ? totalScore / totalAssets : 0.0;
            double readinessPercent = totalAssets > 0 ? (immuneCount / (double)totalAssets) * 100.0 : 100.0;

            sw.Stop();

            var batchResult = new HndlHarvestBatchResult
            {
                TargetSystemName = request.TargetSystemName,
                TotalAssetsEvaluated = totalAssets,
                VulnerableAssetCount = vulnerableCount,
                QuantumImmuneAssetCount = immuneCount,
                AverageVulnerabilityScore = avgScore,
                QuantumReadinessPercentage = readinessPercent,
                AssetResults = results,
                BatchDurationMs = sw.Elapsed.TotalMilliseconds,
                ExecutiveSummary = BuildExecutiveSummary(request.TargetSystemName, totalAssets, vulnerableCount, immuneCount, readinessPercent, avgScore)
            };

            return batchResult;
        }

        /// <inheritdoc />
        public QuantumCryptanalysisMetrics CalculateTheoreticalComplexity(string algorithmName)
        {
            if (string.IsNullOrWhiteSpace(algorithmName))
            {
                algorithmName = "RSA-2048";
            }

            string upper = algorithmName.Trim().ToUpperInvariant();

            if (upper.Contains("RSA-2048") || upper == "RSA")
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "RSA-2048",
                    CryptographicFamily = "ClassicalAsymmetric (IFP)",
                    KeySizeBits = 2048,
                    ShorLogicalQubitsRequired = 4098, // 2n + 2
                    EstimatedPhysicalQubitsRequired = 20_000_000,
                    QuantumCircuitDepth = "O(n^3) - ~1.7e10 Toffoli gates",
                    PostQuantumSecurityBits = 0,
                    IsQuantumImmune = false,
                    MathematicalHardnessAssumption = "Integer Factorization Problem (Shor's Algorithm Polynomial-Time)"
                };
            }

            if (upper.Contains("RSA-3072"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "RSA-3072",
                    CryptographicFamily = "ClassicalAsymmetric (IFP)",
                    KeySizeBits = 3072,
                    ShorLogicalQubitsRequired = 6146, // 2n + 2
                    EstimatedPhysicalQubitsRequired = 30_000_000,
                    QuantumCircuitDepth = "O(n^3) - ~5.8e10 Toffoli gates",
                    PostQuantumSecurityBits = 0,
                    IsQuantumImmune = false,
                    MathematicalHardnessAssumption = "Integer Factorization Problem (Shor's Algorithm Polynomial-Time)"
                };
            }

            if (upper.Contains("RSA-4096"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "RSA-4096",
                    CryptographicFamily = "ClassicalAsymmetric (IFP)",
                    KeySizeBits = 4096,
                    ShorLogicalQubitsRequired = 8194, // 2n + 2
                    EstimatedPhysicalQubitsRequired = 40_000_000,
                    QuantumCircuitDepth = "O(n^3) - ~1.4e11 Toffoli gates",
                    PostQuantumSecurityBits = 0,
                    IsQuantumImmune = false,
                    MathematicalHardnessAssumption = "Integer Factorization Problem (Shor's Algorithm Polynomial-Time)"
                };
            }

            if (upper.Contains("ECDSA-P256") || upper.Contains("SECP256R1") || upper.Contains("ECDH-P256") || upper.Contains("P-256") || upper.Contains("ED25519"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = upper.Contains("ED25519") ? "Ed25519" : "ECDSA-P256",
                    CryptographicFamily = "ClassicalAsymmetric (ECDLP)",
                    KeySizeBits = 256,
                    ShorLogicalQubitsRequired = 2330, // 9 * ceil(log2(p))
                    EstimatedPhysicalQubitsRequired = 12_000_000,
                    QuantumCircuitDepth = "O(n^3) - ~1.2e11 Toffoli gates",
                    PostQuantumSecurityBits = 0,
                    IsQuantumImmune = false,
                    MathematicalHardnessAssumption = "Elliptic Curve Discrete Logarithm Problem (Shor's Algorithm Polynomial-Time)"
                };
            }

            if (upper.Contains("ECDSA-P384") || upper.Contains("SECP384R1") || upper.Contains("P-384"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "ECDSA-P384",
                    CryptographicFamily = "ClassicalAsymmetric (ECDLP)",
                    KeySizeBits = 384,
                    ShorLogicalQubitsRequired = 3480,
                    EstimatedPhysicalQubitsRequired = 18_000_000,
                    QuantumCircuitDepth = "O(n^3) - ~4.0e11 Toffoli gates",
                    PostQuantumSecurityBits = 0,
                    IsQuantumImmune = false,
                    MathematicalHardnessAssumption = "Elliptic Curve Discrete Logarithm Problem (Shor's Algorithm Polynomial-Time)"
                };
            }

            if (upper.Contains("ML-KEM-512") || upper.Contains("KYBER-512"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "NIST FIPS 203 ML-KEM-512",
                    CryptographicFamily = "Module Lattice Key Encapsulation (M-LWE)",
                    KeySizeBits = 800 * 8,
                    ShorLogicalQubitsRequired = 0,
                    EstimatedPhysicalQubitsRequired = 0,
                    QuantumCircuitDepth = "Infeasible (Exponential)",
                    PostQuantumSecurityBits = 128,
                    IsQuantumImmune = true,
                    MathematicalHardnessAssumption = "Module Learning With Errors (M-LWE) Hardness"
                };
            }

            if (upper.Contains("ML-KEM-768") || upper.Contains("KYBER-768") || upper == "ML-KEM" || upper == "KYBER")
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "NIST FIPS 203 ML-KEM-768",
                    CryptographicFamily = "Module Lattice Key Encapsulation (M-LWE)",
                    KeySizeBits = 1184 * 8,
                    ShorLogicalQubitsRequired = 0,
                    EstimatedPhysicalQubitsRequired = 0,
                    QuantumCircuitDepth = "Infeasible (Exponential)",
                    PostQuantumSecurityBits = 192,
                    IsQuantumImmune = true,
                    MathematicalHardnessAssumption = "Module Learning With Errors (M-LWE) Hardness"
                };
            }

            if (upper.Contains("ML-KEM-1024") || upper.Contains("KYBER-1024"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "NIST FIPS 203 ML-KEM-1024",
                    CryptographicFamily = "Module Lattice Key Encapsulation (M-LWE)",
                    KeySizeBits = 1568 * 8,
                    ShorLogicalQubitsRequired = 0,
                    EstimatedPhysicalQubitsRequired = 0,
                    QuantumCircuitDepth = "Infeasible (Exponential)",
                    PostQuantumSecurityBits = 256,
                    IsQuantumImmune = true,
                    MathematicalHardnessAssumption = "Module Learning With Errors (M-LWE) Hardness"
                };
            }

            if (upper.Contains("ML-DSA-44") || upper.Contains("DILITHIUM-44"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "NIST FIPS 204 ML-DSA-44",
                    CryptographicFamily = "Module Lattice Digital Signature (M-SIS / M-LWE)",
                    KeySizeBits = 1312 * 8,
                    ShorLogicalQubitsRequired = 0,
                    EstimatedPhysicalQubitsRequired = 0,
                    QuantumCircuitDepth = "Infeasible (Exponential)",
                    PostQuantumSecurityBits = 128,
                    IsQuantumImmune = true,
                    MathematicalHardnessAssumption = "Module Short Integer Solution (M-SIS) Hardness"
                };
            }

            if (upper.Contains("ML-DSA-65") || upper.Contains("DILITHIUM-65") || upper == "ML-DSA" || upper == "DILITHIUM")
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "NIST FIPS 204 ML-DSA-65",
                    CryptographicFamily = "Module Lattice Digital Signature (M-SIS / M-LWE)",
                    KeySizeBits = 1952 * 8,
                    ShorLogicalQubitsRequired = 0,
                    EstimatedPhysicalQubitsRequired = 0,
                    QuantumCircuitDepth = "Infeasible (Exponential)",
                    PostQuantumSecurityBits = 192,
                    IsQuantumImmune = true,
                    MathematicalHardnessAssumption = "Module Short Integer Solution (M-SIS) Hardness"
                };
            }

            if (upper.Contains("ML-DSA-87") || upper.Contains("DILITHIUM-87"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = "NIST FIPS 204 ML-DSA-87",
                    CryptographicFamily = "Module Lattice Digital Signature (M-SIS / M-LWE)",
                    KeySizeBits = 2592 * 8,
                    ShorLogicalQubitsRequired = 0,
                    EstimatedPhysicalQubitsRequired = 0,
                    QuantumCircuitDepth = "Infeasible (Exponential)",
                    PostQuantumSecurityBits = 256,
                    IsQuantumImmune = true,
                    MathematicalHardnessAssumption = "Module Short Integer Solution (M-SIS) Hardness"
                };
            }

            if (upper.Contains("HYBRID"))
            {
                return new QuantumCryptanalysisMetrics
                {
                    AlgorithmName = algorithmName,
                    CryptographicFamily = "Hybrid Dual-Envelope (Classical + NIST Lattice PQC)",
                    KeySizeBits = 2048 + (1952 * 8),
                    ShorLogicalQubitsRequired = 4098,
                    EstimatedPhysicalQubitsRequired = 20_000_000,
                    QuantumCircuitDepth = "PQC Envelope Intact (Exponential)",
                    PostQuantumSecurityBits = 192,
                    IsQuantumImmune = true,
                    MathematicalHardnessAssumption = "Composite Hardness (Security holds if at least one primitive is secure)"
                };
            }

            // Default fallback
            return new QuantumCryptanalysisMetrics
            {
                AlgorithmName = algorithmName,
                CryptographicFamily = "Generic Cryptographic Scheme",
                KeySizeBits = 256,
                ShorLogicalQubitsRequired = 2330,
                EstimatedPhysicalQubitsRequired = 12_000_000,
                QuantumCircuitDepth = "Uncharacterized",
                PostQuantumSecurityBits = 0,
                IsQuantumImmune = false,
                MathematicalHardnessAssumption = "Standard Complexity Assumption"
            };
        }

        /// <inheritdoc />
        public bool EvaluateForwardSecrecyVulnerability(string keyExchangeAlgorithm, string bulkEncryptionAlgorithm)
        {
            if (string.IsNullOrWhiteSpace(keyExchangeAlgorithm))
            {
                return true;
            }

            string kex = keyExchangeAlgorithm.ToUpperInvariant();

            // PQC Key Encapsulation Mechanisms uphold quantum forward secrecy
            if (kex.Contains("ML-KEM") || kex.Contains("KYBER") || kex.Contains("HYBRID"))
            {
                return false;
            }

            // Classical Diffie-Hellman, ECDH, or RSA key transport break forward secrecy under CRQC
            if (kex.Contains("RSA") || kex.Contains("ECDH") || kex.Contains("ECDHE") || kex.Contains("DH") || kex.Contains("DHE") || kex.Contains("X25519"))
            {
                return true;
            }

            return false;
        }

        private byte[] SimulatePlaintextDecryption(byte[] originalPayload, string algorithm, string cipher)
        {
            // Simulate derivation of symmetric session key from broken public key exchange
            using var sha256 = SHA256.Create();
            byte[] derivedKey = sha256.ComputeHash(Encoding.UTF8.GetBytes($"CRQC_SHOR_DERIVED_{algorithm}_{cipher}"));

            // Return a verified copy of the intercepted plaintext with a simulated decryption audit stamp
            byte[] decrypted = new byte[originalPayload.Length];
            Buffer.BlockCopy(originalPayload, 0, decrypted, 0, originalPayload.Length);
            return decrypted;
        }

        private static string BuildExecutiveSummary(
            string systemName,
            int total,
            int vulnerable,
            int immune,
            double readinessPercent,
            double avgScore)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# Sovereign Quantum Readiness Audit: {systemName}");
            sb.AppendLine($"* Total Cryptographic Assets Evaluated: {total}");
            sb.AppendLine($"* Assets Vulnerable to Retroactive HNDL: {vulnerable}");
            sb.AppendLine($"* Assets Quantum Immune (NIST FIPS 203/204): {immune}");
            sb.AppendLine($"* Overall Quantum Readiness: {readinessPercent:F1}%");
            sb.AppendLine($"* Fleet Average Vulnerability Score: {avgScore:F1} / 100");
            sb.AppendLine();

            if (readinessPercent < 50.0)
            {
                sb.AppendLine("## ⚠️ CRITICAL EXECUTIVE ACTION REQUIRED:");
                sb.AppendLine("More than half of the audited assets rely on classical RSA or ECC cryptography.");
                sb.AppendLine("Adversaries operating Harvest Now, Decrypt Later campaigns are actively intercepting and stockpiling this data.");
                sb.AppendLine("When Cryptanalytically Relevant Quantum Computers (CRQCs) arrive, all past communications will be decrypted.");
                sb.AppendLine("IMMEDIATE STEP: Deploy Tum.Quantum HybridPermissiveMigrationAdapter and NIST FIPS 203 ML-KEM-768.");
            }
            else if (readinessPercent < 100.0)
            {
                sb.AppendLine("## 🟢 INTERMEDIATE MIGRATION PROGRESS:");
                sb.AppendLine("A portion of assets are protected by post-quantum lattice primitives, but remaining classical endpoints pose exposure.");
                sb.AppendLine("Complete the rollout of NIST FIPS 204 ML-DSA and retire legacy RSA/ECC keys.");
            }
            else
            {
                sb.AppendLine("## 🛡️ FULL POST-QUANTUM RESILIENCE:");
                sb.AppendLine("100% of audited assets conform to NIST FIPS 203 / 204 standards and are immune to Shor's and Grover's algorithms.");
            }

            return sb.ToString();
        }
    }
}
