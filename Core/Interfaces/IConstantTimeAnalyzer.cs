// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;

namespace Tum.Quantum.Core.Interfaces
{
    /// <summary>
    /// Evaluates cryptographic implementations for timing side-channel leaks using constant-time
    /// primitives and empirical DudeCT (Welch's two-sample t-test) statistical analysis.
    /// </summary>
    public interface IConstantTimeAnalyzer
    {
        /// <summary>
        /// Performs constant-time equality check between two byte spans without early exit or branching.
        /// </summary>
        /// <param name="a">First byte span.</param>
        /// <param name="b">Second byte span.</param>
        /// <returns><c>true</c> if sequences are identical; otherwise <c>false</c>.</returns>
        bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b);

        /// <summary>
        /// Selects between two byte values in constant time based on a mask byte without branching.
        /// Returns <paramref name="a"/> when mask is 0xFF, or <paramref name="b"/> when mask is 0x00.
        /// </summary>
        /// <param name="mask">Mask byte (0xFF or 0x00).</param>
        /// <param name="a">First value.</param>
        /// <param name="b">Second value.</param>
        /// <returns>Selected byte.</returns>
        byte ConstantTimeSelect(byte mask, byte a, byte b);

        /// <summary>
        /// Executes a DudeCT statistical timing evaluation on a specified target operation
        /// comparing execution times between two classes of inputs (fixed vs random).
        /// </summary>
        /// <param name="operationName">Descriptive name of the evaluated operation.</param>
        /// <param name="operation">The cryptographic delegate taking an input byte array.</param>
        /// <param name="class0Generator">Generates class 0 (fixed/baseline) inputs.</param>
        /// <param name="class1Generator">Generates class 1 (random/variance) inputs.</param>
        /// <param name="sampleSize">Number of samples to evaluate per class.</param>
        /// <param name="threshold">Welch's t-statistic threshold (default 4.5).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Statistical result including Welch's t-statistic and verdict.</returns>
        Task<DudeCtStatisticalResult> RunDudeCtTestAsync(
            string operationName,
            Func<byte[], bool> operation,
            Func<byte[]> class0Generator,
            Func<byte[]> class1Generator,
            int sampleSize = 2000,
            double threshold = 4.5,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Runs a complete Constant-Time and Timing Attack Vulnerability Analysis suite across all
        /// supported NIST FIPS 203 and 204 lattice primitives.
        /// </summary>
        /// <param name="request">Simulation request configuration.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Consolidated audit report with side-channel metrics.</returns>
        Task<ConstantTimeAnalysisReport> RunFullVulnerabilityAnalysisAsync(
            TimingAttackSimulationRequest? request = null,
            CancellationToken cancellationToken = default);
    }
}
