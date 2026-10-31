using Tum.Quantum.Core.Models;
using Tum.Trust.Security.Core.Models.QuantumSafe;

namespace Tum.Quantum.Core.Interfaces;

/// <summary>
/// Sovereign Post-Quantum Identity Assertion Token Signer &amp; Verifier.
/// Issues tamper-proof, quantum-resistant digital identity tokens combining
/// NIST FIPS 204 (ML-DSA) and classical signatures.
/// </summary>
public interface IPqcAssertionSigner
{
    /// <summary>
    /// Issues a signed Post-Quantum Identity Assertion token with dual cryptographic proof.
    /// </summary>
    PqcIdentityAssertion IssueAssertion(
        string subjectId,
        string issuer,
        IDictionary<string, string> claims,
        TimeSpan validityDuration,
        byte[] classicalPrivateKey,
        PqcKeyPair pqcKeyPair);

    /// <summary>
    /// Verifies a Post-Quantum Identity Assertion against classical and PQC trust roots.
    /// </summary>
    PqcAssertionVerificationResult VerifyAssertion(
        PqcIdentityAssertion assertion,
        byte[] classicalPublicKey,
        byte[] pqcPublicKey);
}
