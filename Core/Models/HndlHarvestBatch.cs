// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

namespace Tum.Quantum.Core.Models
{
    /// <summary>
    /// Request to analyze a batch of intercepted network sessions, cryptographic assets, or archival datasets.
    /// </summary>
    public class HndlHarvestBatchRequest
    {
        /// <summary>
        /// Gets or sets the organizational identifier or system name being assessed.
        /// </summary>
        public string TargetSystemName { get; set; } = "Enterprise Sovereign Core Infrastructure";

        /// <summary>
        /// Gets or sets the collection of individual simulation requests representing captured assets.
        /// </summary>
        public IList<HndlSimulationRequest> HarvestedAssets { get; set; } = new List<HndlSimulationRequest>();

        /// <summary>
        /// Gets or sets the default quantum adversary profile for assets that don't specify one.
        /// </summary>
        public QuantumHardwareProfile? GlobalAdversaryProfile { get; set; }
    }

    /// <summary>
    /// Aggregate audit scorecard and risk summary for an organization's harvested assets.
    /// </summary>
    public class HndlHarvestBatchResult
    {
        /// <summary>
        /// Gets or sets the system or organization assessed.
        /// </summary>
        public string TargetSystemName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the total number of assets evaluated.
        /// </summary>
        public int TotalAssetsEvaluated { get; set; }

        /// <summary>
        /// Gets or sets the count of assets vulnerable to retroactive HNDL compromise.
        /// </summary>
        public int VulnerableAssetCount { get; set; }

        /// <summary>
        /// Gets or sets the count of assets immune to quantum cryptanalysis.
        /// </summary>
        public int QuantumImmuneAssetCount { get; set; }

        /// <summary>
        /// Gets or sets the overall fleet/system quantum readiness percentage (0.0 to 100.0).
        /// </summary>
        public double QuantumReadinessPercentage { get; set; }

        /// <summary>
        /// Gets or sets the fleet average quantum vulnerability score (0.0 to 100.0).
        /// </summary>
        public double AverageVulnerabilityScore { get; set; }

        /// <summary>
        /// Gets or sets individual simulation outcomes for each harvested asset.
        /// </summary>
        public IList<HndlSimulationResult> AssetResults { get; set; } = new List<HndlSimulationResult>();

        /// <summary>
        /// Gets or sets executive migration recommendation and roadmap summary.
        /// </summary>
        public string ExecutiveSummary { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets total batch analysis execution time in milliseconds.
        /// </summary>
        public double BatchDurationMs { get; set; }
    }
}
