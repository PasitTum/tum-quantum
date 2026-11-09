// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Identifies the post-quantum cryptographic operation evaluated for timing side-channel leaks.
    /// </summary>
    public enum ConstantTimeTarget
    {
        /// <summary>
        /// ML-KEM-768 (FIPS 203) Key Decapsulation and shared secret recovery.
        /// </summary>
        MlKem768Decapsulation = 1,

        /// <summary>
        /// ML-DSA-65 (FIPS 204) Lattice digital signature verification.
        /// </summary>
        MlDsa65SignatureVerification = 2,

        /// <summary>
        /// Constant-time memory and tag comparison primitives.
        /// </summary>
        SecretByteArrayComparison = 3,

        /// <summary>
        /// Lattice polynomial coefficient range evaluation and rejection sampling.
        /// </summary>
        PolynomialBoundCheck = 4
    }

    /// <summary>
    /// Verdict returned by the DudeCT statistical timing evaluation.
    /// </summary>
    public enum ConstantTimeVerdict
    {
        /// <summary>
        /// Null hypothesis of equal execution time distributions is accepted (|t| &lt; 4.5).
        /// </summary>
        Pass = 1,

        /// <summary>
        /// Statistically significant execution time divergence detected (|t| &gt;= 4.5).
        /// </summary>
        Fail = 2,

        /// <summary>
        /// Insufficient sample variance or sample count to establish significance.
        /// </summary>
        Inconclusive = 3
    }

    /// <summary>
    /// Holds the statistical outcome of a DudeCT (Welch's two-sample t-test) analysis.
    /// </summary>
    public class DudeCtStatisticalResult
    {
        /// <summary>Operation identifier.</summary>
        public string TargetName { get; set; } = string.Empty;

        /// <summary>Sample count for Class 0 (fixed/baseline).</summary>
        public int SampleCountClass0 { get; set; }

        /// <summary>Sample count for Class 1 (random/variance).</summary>
        public int SampleCountClass1 { get; set; }

        /// <summary>Mean execution time in nanoseconds for Class 0.</summary>
        public double MeanTimeClass0Ns { get; set; }

        /// <summary>Mean execution time in nanoseconds for Class 1.</summary>
        public double MeanTimeClass1Ns { get; set; }

        /// <summary>Sample variance for Class 0.</summary>
        public double VarianceClass0 { get; set; }

        /// <summary>Sample variance for Class 1.</summary>
        public double VarianceClass1 { get; set; }

        /// <summary>Calculated Welch's t-statistic.</summary>
        public double WelchTStatistic { get; set; }

        /// <summary>Rejection threshold (|t| &lt; Threshold).</summary>
        public double Threshold { get; set; } = 4.5;

        /// <summary>Effective degrees of freedom (Welch-Satterthwaite).</summary>
        public double DegreesOfFreedom { get; set; }

        /// <summary>Estimated p-value for the two-sample test.</summary>
        public double PValueEstimate { get; set; }

        /// <summary>True if operation meets constant-time invariant.</summary>
        public bool IsConstantTime { get; set; }

        /// <summary>Outcome verdict.</summary>
        public ConstantTimeVerdict Verdict { get; set; }

        /// <summary>Human-readable diagnostic summary.</summary>
        public string DiagnosticSummary { get; set; } = string.Empty;
    }

    /// <summary>
    /// Request to initiate a statistical timing attack vulnerability evaluation.
    /// </summary>
    public class TimingAttackSimulationRequest
    {
        /// <summary>Target cryptographic operation.</summary>
        public ConstantTimeTarget Target { get; set; } = ConstantTimeTarget.MlKem768Decapsulation;

        /// <summary>Number of samples per class (default 2000).</summary>
        public int SampleIterations { get; set; } = 2000;

        /// <summary>Welch t-statistic threshold (default 4.5).</summary>
        public double TStatisticThreshold { get; set; } = 4.5;

        /// <summary>Optionally include an intentionally vulnerable control to demonstrate detection.</summary>
        public bool IncludeSyntheticLeakageControl { get; set; } = false;
    }

    /// <summary>
    /// Comprehensive audit report detailing side-channel timing analysis results.
    /// </summary>
    public class ConstantTimeAnalysisReport
    {
        /// <summary>Unique report identifier.</summary>
        public string ReportId { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>Timestamp of report generation.</summary>
        public DateTimeOffset GeneratedAtUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>Runtime architecture description.</summary>
        public string Architecture { get; set; } = AppDomain.CurrentDomain.FriendlyName;

        /// <summary>Total targets evaluated.</summary>
        public int TotalEvaluations { get; set; }

        /// <summary>Passed evaluations.</summary>
        public int PassedEvaluations { get; set; }

        /// <summary>Failed evaluations.</summary>
        public int FailedEvaluations { get; set; }

        /// <summary>True if all production targets satisfy constant-time threshold.</summary>
        public bool IsOverallCompliant { get; set; }

        /// <summary>Maximum observed |t| statistic among evaluated targets.</summary>
        public double MaxObservedTStatistic { get; set; }

        /// <summary>Side-channel vulnerability score (0 = no leak, 100 = critical leak).</summary>
        public double SideChannelVulnerabilityScore { get; set; }

        /// <summary>Detailed statistical results per target.</summary>
        public List<DudeCtStatisticalResult> DetailedResults { get; set; } = new();

        /// <summary>Cryptographic hardening recommendations.</summary>
        public List<string> CryptographicRecommendations { get; set; } = new();
    }
}
