using Tum.Trust.Security.Core.Models.QuantumSafe;

namespace Tum.Quantum.Core.Models;

/// <summary>
/// Quantum-resilient Sovereign Identity Assertion token.
/// </summary>
public class PqcIdentityAssertion
{
    /// <summary>
    /// Unique identifier of the issued assertion token.
    /// </summary>
    public string TokenId { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>
    /// Subject identifier (e.g. National Citizen ID or DID).
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Token issuer trust anchor URL.
    /// </summary>
    public string Issuer { get; set; } = "https://identity.tumgroup.holdings";

    /// <summary>
    /// UTC timestamp of issue.
    /// </summary>
    public DateTime IssuedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// UTC timestamp of expiration.
    /// </summary>
    public DateTime ExpiresAtUtc { get; set; } = DateTime.UtcNow.AddHours(1);

    /// <summary>
    /// Attested claims dictionary.
    /// </summary>
    public IDictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();

    /// <summary>
    /// Dual cryptographic signature envelope (Classical + NIST PQC).
    /// </summary>
    public HybridDualEnvelope SignatureEnvelope { get; set; } = new();

    /// <summary>
    /// Compact Base64-encoded token string.
    /// </summary>
    public string CompactSerializedToken { get; set; } = string.Empty;
}

/// <summary>
/// Outcome of verifying a PQC Identity Assertion.
/// </summary>
public class PqcAssertionVerificationResult
{
    /// <summary>
    /// Indicates whether overall token validity succeeded.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Indicates whether classical signature verified.
    /// </summary>
    public bool IsClassicalSignatureValid { get; set; }

    /// <summary>
    /// Indicates whether NIST ML-DSA lattice signature verified.
    /// </summary>
    public bool IsQuantumSignatureValid { get; set; }

    /// <summary>
    /// Indicates whether token has expired.
    /// </summary>
    public bool IsExpired { get; set; }

    /// <summary>
    /// Attested subject identifier.
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Verified claims extracted from payload.
    /// </summary>
    public IDictionary<string, string> VerifiedClaims { get; set; } = new Dictionary<string, string>();

    /// <summary>
    /// Errors encountered during verification.
    /// </summary>
    public IList<string> ValidationErrors { get; set; } = new List<string>();
}
