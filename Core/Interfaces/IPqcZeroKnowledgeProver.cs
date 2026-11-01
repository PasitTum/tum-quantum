// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;

namespace Tum.Quantum.Core.Interfaces
{
    /// <summary>
    /// Quantum-safe Zero-Knowledge attribute prover and verifier using lattice-based commitments.
    /// Preserves complete privacy against quantum cryptanalysis (Shor &amp; Grover).
    /// </summary>
    public interface IPqcZeroKnowledgeProver
    {
        /// <summary>
        /// Generates a zero-knowledge proof that the citizen's age meets or exceeds a threshold without revealing exact age or birthdate.
        /// </summary>
        /// <param name="actualAge">Private witness: the actual age.</param>
        /// <param name="minimumAgeThreshold">Public predicate: required minimum age (e.g. 20 for Thai adulthood).</param>
        /// <param name="verifierNonce">Unique session nonce from the verifier.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A non-interactive zero-knowledge proof package.</returns>
        Task<PqcZkProofPackage> GenerateAgeProofAsync(int actualAge, int minimumAgeThreshold, string verifierNonce, CancellationToken cancellationToken = default);

        /// <summary>
        /// Generates a zero-knowledge proof of financial solvency >= threshold without revealing net worth.
        /// </summary>
        /// <param name="actualBalance">Private witness: the actual account balance.</param>
        /// <param name="minimumSolvencyThreshold">Public predicate: required solvency (e.g. 100,000 THB).</param>
        /// <param name="verifierNonce">Unique session nonce from the verifier.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A non-interactive zero-knowledge proof package.</returns>
        Task<PqcZkProofPackage> GenerateSolvencyProofAsync(decimal actualBalance, decimal minimumSolvencyThreshold, string verifierNonce, CancellationToken cancellationToken = default);

        /// <summary>
        /// Verifies a quantum-safe zero-knowledge proof package.
        /// </summary>
        /// <param name="proofPackage">The proof package to evaluate.</param>
        /// <param name="expectedVerifierNonce">Expected session nonce to prevent replay attacks.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Verification result.</returns>
        Task<PqcZkVerificationResult> VerifyProofAsync(PqcZkProofPackage proofPackage, string expectedVerifierNonce, CancellationToken cancellationToken = default);
    }
}
