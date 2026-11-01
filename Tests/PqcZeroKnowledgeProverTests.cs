// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class PqcZeroKnowledgeProverTests
    {
        private readonly PqcZeroKnowledgeProver _prover = new();

        [Fact]
        public async Task GenerateAgeProof_ValidAge_VerifiesSuccessfully()
        {
            string nonce = Guid.NewGuid().ToString("N");
            var proof = await _prover.GenerateAgeProofAsync(actualAge: 25, minimumAgeThreshold: 20, verifierNonce: nonce);

            Assert.NotNull(proof);
            Assert.Equal(PqcZkProofType.AgeVerification, proof.ProofType);
            Assert.Equal("AGE_GTE_20", proof.PublicClaim);
            Assert.True(proof.Commitment.Length >= 48);
            Assert.True(proof.Challenge.Length >= 48);
            Assert.True(proof.ResponseVector.Length >= 48);
            Assert.True(proof.IsQuantumImmune);

            var verifyRes = await _prover.VerifyProofAsync(proof, expectedVerifierNonce: nonce);
            Assert.True(verifyRes.IsValid);
            Assert.True(verifyRes.IsZeroKnowledgePreserved);
            Assert.Equal("AGE_GTE_20", verifyRes.ProvenClaim);
            Assert.Null(verifyRes.ErrorMessage);
        }

        [Fact]
        public async Task GenerateAgeProof_Underage_ThrowsInvalidOperationException()
        {
            string nonce = Guid.NewGuid().ToString("N");
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _prover.GenerateAgeProofAsync(actualAge: 17, minimumAgeThreshold: 20, verifierNonce: nonce));
        }

        [Fact]
        public async Task GenerateSolvencyProof_ValidBalance_VerifiesSuccessfully()
        {
            string nonce = Guid.NewGuid().ToString("N");
            var proof = await _prover.GenerateSolvencyProofAsync(
                actualBalance: 500_000.50m,
                minimumSolvencyThreshold: 100_000.00m,
                verifierNonce: nonce);

            Assert.NotNull(proof);
            Assert.Equal(PqcZkProofType.SolvencyThreshold, proof.ProofType);
            Assert.Equal("SOLVENCY_GTE_100000.00_THB", proof.PublicClaim);

            var verifyRes = await _prover.VerifyProofAsync(proof, expectedVerifierNonce: nonce);
            Assert.True(verifyRes.IsValid);
        }

        [Fact]
        public async Task GenerateSolvencyProof_Insolvent_ThrowsInvalidOperationException()
        {
            string nonce = Guid.NewGuid().ToString("N");
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _prover.GenerateSolvencyProofAsync(actualBalance: 50_000m, minimumSolvencyThreshold: 100_000m, verifierNonce: nonce));
        }

        [Fact]
        public async Task VerifyProof_ReplayWithDifferentNonce_FailsVerification()
        {
            string originalNonce = Guid.NewGuid().ToString("N");
            string replayNonce = Guid.NewGuid().ToString("N");

            var proof = await _prover.GenerateAgeProofAsync(actualAge: 30, minimumAgeThreshold: 18, verifierNonce: originalNonce);

            var verifyRes = await _prover.VerifyProofAsync(proof, expectedVerifierNonce: replayNonce);
            Assert.False(verifyRes.IsValid);
            Assert.Contains("nonce mismatch", verifyRes.ErrorMessage);
        }

        [Fact]
        public async Task VerifyProof_TamperedCommitment_FailsVerification()
        {
            string nonce = Guid.NewGuid().ToString("N");
            var proof = await _prover.GenerateAgeProofAsync(actualAge: 30, minimumAgeThreshold: 18, verifierNonce: nonce);

            // Tamper commitment byte
            proof.Commitment[0] ^= 0xFF;

            var verifyRes = await _prover.VerifyProofAsync(proof, expectedVerifierNonce: nonce);
            Assert.False(verifyRes.IsValid);
            Assert.Contains("Fiat-Shamir challenge evaluation mismatch", verifyRes.ErrorMessage);
        }
    }
}
