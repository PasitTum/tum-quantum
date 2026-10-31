using System.Text;
using Tum.Quantum.Core.Interfaces;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Tum.Trust.Security.Core.Models.QuantumSafe;
using Xunit;

namespace Tum.Quantum.Tests;

public class PqcAssertionSignerTests
{
    private readonly PqcAssertionSigner _signer = new();

    [Fact]
    public void IssueAssertion_ValidParameters_ProducesDualSignedToken()
    {
        byte[] secretKey = Encoding.UTF8.GetBytes("SovereignSuperSecretKeyForClassicalHMAC!");
        var pqcKeyPair = new PqcKeyPair
        {
            Algorithm = PqcSignatureAlgorithm.MlDsa44,
            PublicKey = new byte[1312],
            PrivateKey = new byte[2560]
        };
        pqcKeyPair.PrivateKey[0] = 0xAA;

        var claims = new Dictionary<string, string>
        {
            { "citizen_id", "1-1001-00001-11-1" },
            { "name_th", "นายสมชาย ใจดี" },
            { "thai_dopa_status", "ACTIVE" },
            { "assurance_level", "IAL2.3" }
        };

        var assertion = _signer.IssueAssertion(
            subjectId: "th-citizen-1100100001111",
            issuer: "https://identity.tumgroup.holdings",
            claims: claims,
            validityDuration: TimeSpan.FromMinutes(30),
            classicalPrivateKey: secretKey,
            pqcKeyPair: pqcKeyPair
        );

        Assert.NotNull(assertion);
        Assert.Equal("th-citizen-1100100001111", assertion.SubjectId);
        Assert.Equal(PqcSignatureAlgorithm.MlDsa44, assertion.SignatureEnvelope.PqcAlgorithm);
        Assert.Equal("HMAC-SHA256", assertion.SignatureEnvelope.ClassicAlgorithm);
        Assert.NotEmpty(assertion.CompactSerializedToken);
        Assert.Contains(".", assertion.CompactSerializedToken);

        // Verify assertion
        var verification = _signer.VerifyAssertion(
            assertion,
            classicalPublicKey: secretKey,
            pqcPublicKey: pqcKeyPair.PublicKey
        );

        Assert.True(verification.IsValid);
        Assert.True(verification.IsClassicalSignatureValid);
        Assert.True(verification.IsQuantumSignatureValid);
        Assert.False(verification.IsExpired);
        Assert.Equal("1-1001-00001-11-1", verification.VerifiedClaims["citizen_id"]);
    }

    [Fact]
    public void VerifyAssertion_TamperedClaims_FailsClassicalVerification()
    {
        byte[] secretKey = Encoding.UTF8.GetBytes("SovereignSuperSecretKeyForClassicalHMAC!");
        var pqcKeyPair = new PqcKeyPair
        {
            Algorithm = PqcSignatureAlgorithm.MlDsa44,
            PublicKey = new byte[1312],
            PrivateKey = new byte[2560]
        };

        var assertion = _signer.IssueAssertion(
            subjectId: "th-citizen-1100100001111",
            issuer: "https://identity.tumgroup.holdings",
            claims: new Dictionary<string, string> { { "role", "Citizen" } },
            validityDuration: TimeSpan.FromMinutes(10),
            classicalPrivateKey: secretKey,
            pqcKeyPair: pqcKeyPair
        );

        // Attacker tampers with claim to escalate role
        assertion.Claims["role"] = "Administrator";

        var verification = _signer.VerifyAssertion(
            assertion,
            classicalPublicKey: secretKey,
            pqcPublicKey: pqcKeyPair.PublicKey
        );

        Assert.False(verification.IsValid);
        Assert.False(verification.IsClassicalSignatureValid);
        Assert.Contains(verification.ValidationErrors, e => e.Contains("Classical signature"));
    }

    [Fact]
    public void VerifyAssertion_ExpiredToken_FlagsExpired()
    {
        byte[] secretKey = Encoding.UTF8.GetBytes("SovereignSuperSecretKeyForClassicalHMAC!");
        var pqcKeyPair = new PqcKeyPair
        {
            Algorithm = PqcSignatureAlgorithm.MlDsa44,
            PublicKey = new byte[1312],
            PrivateKey = new byte[2560]
        };

        var assertion = _signer.IssueAssertion(
            subjectId: "th-citizen-1100100001111",
            issuer: "https://identity.tumgroup.holdings",
            claims: new Dictionary<string, string>(),
            validityDuration: TimeSpan.FromSeconds(-5), // Already expired
            classicalPrivateKey: secretKey,
            pqcKeyPair: pqcKeyPair
        );

        var verification = _signer.VerifyAssertion(
            assertion,
            classicalPublicKey: secretKey,
            pqcPublicKey: pqcKeyPair.PublicKey
        );

        Assert.False(verification.IsValid);
        Assert.True(verification.IsExpired);
        Assert.Contains(verification.ValidationErrors, e => e.Contains("expired"));
    }
}
