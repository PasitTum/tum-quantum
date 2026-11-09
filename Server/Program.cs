// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using Microsoft.AspNetCore.Mvc;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Tum.Trust.Security.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var quantumEngine = new QuantumSafeTrustEngine();
var assertionSigner = new PqcAssertionSigner(quantumEngine);
var hndlSimulator = new HndlQuantumAttackSimulator(quantumEngine);
var tlsEngine = new PqcTls13HandshakeEngine(quantumEngine);
var zkProver = new PqcZeroKnowledgeProver();
var hsmDriver = new Pkcs11QuantumHsmDriver(quantumEngine);
var fipsAuditor = new Fips140AuditRunner(quantumEngine);
var tsaEngine = new TimeStampAuthorityEngine(quantumEngine);
var oidcEngine = new PqcOidcTokenEngine(quantumEngine);
var constantTimeAnalyzer = new ConstantTimeAnalyzer(quantumEngine);

app.MapGet("/health", () => Results.Ok(new
{
    status = "HEALTHY",
    service = "TUM Quantum Cryptography Service",
    standard = "NIST FIPS 203 (ML-KEM) & NIST FIPS 204 (ML-DSA)",
    sprintsCompleted = "Sprints 1-15 (Enterprise Milestone 3)",
    capabilities = new[]
    {
        "PQC Lattice Verification (FIPS 203/204)",
        "Hybrid Migration Adapter (SCRUM-18)",
        "Identity Assertion Token (SCRUM-25)",
        "HNDL Quantum Attack Simulator (SCRUM-35)",
        "Post-Quantum TLS 1.3 Handshake (Sprint 10)",
        "zk-SNARKs Lattice Attribute Proof (Sprint 11)",
        "PKCS#11 Quantum Hardware HSM Driver (Sprint 12)",
        "FIPS 140-3 Readiness Audit Suite (Sprint 13)",
        "RFC 3161 Post-Quantum TSA (Sprint 14)",
        "Quantum-Safe OpenID Connect (Sprint 15)",
        "Constant-Time & Timing Attack Analysis (DudeCT)"
    },
    timestamp = DateTime.UtcNow
}));

app.MapGet("/api/pqc/status", () => Results.Ok(new
{
    status = "READY",
    algorithms = new[] { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Hybrid Permissive", "HNDL Simulation Sandbox", "PQC-TLS-1.3", "PQC-ZKP", "PKCS#11 HSM", "FIPS 140-3", "PQC-TSA", "PQC-OIDC", "DudeCT-Timing-Analysis" },
    activeStandard = "NIST FIPS 203 / NIST FIPS 204",
    fipsCompliance = true,
    hndlHarnessOperational = true,
    timestamp = DateTime.UtcNow
}));

// HNDL Attack Simulator (SCRUM-35)
app.MapPost("/api/pqc/hndl/simulate", async ([FromBody] HndlSimulationRequest request, CancellationToken ct) =>
{
    if (request == null) return Results.BadRequest(new { error = "Request payload cannot be null." });
    var result = await hndlSimulator.SimulateAttackAsync(request, ct);
    return Results.Ok(result);
});

app.MapPost("/api/pqc/hndl/batch", async ([FromBody] HndlHarvestBatchRequest request, CancellationToken ct) =>
{
    if (request == null) return Results.BadRequest(new { error = "Batch request payload cannot be null." });
    var result = await hndlSimulator.SimulateBatchHarvestAsync(request, ct);
    return Results.Ok(result);
});

app.MapGet("/api/pqc/hndl/complexity", ([FromQuery] string? algorithm) =>
{
    var metrics = hndlSimulator.CalculateTheoreticalComplexity(algorithm ?? "RSA-2048");
    return Results.Ok(metrics);
});

// Post-Quantum TLS 1.3 Handshake (Sprint 10)
app.MapPost("/api/pqc/tls/client-hello", async (CancellationToken ct) =>
{
    var clientHello = await tlsEngine.GenerateClientHelloAsync(PqcTlsNamedGroup.X25519MLKEM768, ct);
    return Results.Ok(clientHello);
});

app.MapPost("/api/pqc/tls/process-hello", async ([FromBody] PqcTlsClientHello clientHello, CancellationToken ct) =>
{
    if (clientHello == null) return Results.BadRequest(new { error = "ClientHello cannot be null." });
    var serverHello = await tlsEngine.ProcessClientHelloAsync(clientHello, ct);
    return Results.Ok(serverHello);
});

// Quantum-Safe Zero-Knowledge Proofs (Sprint 11)
app.MapPost("/api/pqc/zkp/age-proof", async ([FromBody] AgeProofRequest req, CancellationToken ct) =>
{
    if (req == null) return Results.BadRequest(new { error = "Request cannot be null." });
    var proof = await zkProver.GenerateAgeProofAsync(req.ActualAge, req.MinimumAgeThreshold, req.VerifierNonce, ct);
    return Results.Ok(proof);
});

app.MapPost("/api/pqc/zkp/verify", async ([FromBody] ZkVerifyRequest req, CancellationToken ct) =>
{
    if (req == null || req.Proof == null) return Results.BadRequest(new { error = "Proof cannot be null." });
    var result = await zkProver.VerifyProofAsync(req.Proof, req.ExpectedNonce, ct);
    return Results.Ok(result);
});

// PKCS#11 Quantum HSM Driver (Sprint 12)
app.MapGet("/api/pqc/hsm/info", async ([FromQuery] int slotId, CancellationToken ct) =>
{
    var info = await hsmDriver.GetTokenInfoAsync(slotId > 0 ? slotId : 1, ct);
    return Results.Ok(info);
});

// FIPS 140-3 Readiness Audit (Sprint 13)
app.MapPost("/api/pqc/audit/fips140", async ([FromQuery] int level, CancellationToken ct) =>
{
    var targetLevel = (level >= 1 && level <= 4) ? (Fips140SecurityLevel)level : Fips140SecurityLevel.Level3;
    var report = await fipsAuditor.RunFips140ReadinessAuditAsync(targetLevel, ct);
    return Results.Ok(report);
});

// Constant-Time & Timing Attack Analysis (NIST FIPS 140-3 & DudeCT)
app.MapPost("/api/pqc/audit/timing-attack", async ([FromBody] TimingAttackSimulationRequest? req, CancellationToken ct) =>
{
    var report = await constantTimeAnalyzer.RunFullVulnerabilityAnalysisAsync(req, ct);
    return Results.Ok(report);
});

// RFC 3161 Post-Quantum TSA (Sprint 14)
app.MapPost("/api/pqc/tsa/issue", async ([FromBody] PqcTimeStampRequest req, CancellationToken ct) =>
{
    if (req == null) return Results.BadRequest(new { error = "TimeStampReq cannot be null." });
    var token = await tsaEngine.IssueTimeStampTokenAsync(req, ct);
    return Results.Ok(token);
});

// Quantum-Safe OpenID Connect (Sprint 15)
app.MapPost("/api/pqc/oidc/token", async ([FromBody] OidcIssueRequest req, CancellationToken ct) =>
{
    if (req == null) return Results.BadRequest(new { error = "OidcIssueRequest cannot be null." });
    var pkg = await oidcEngine.IssueIdTokenAsync(req.Subject, req.Audience, req.Issuer ?? "https://identity.tum.co.th/oauth2/v1", req.CustomClaims, null, ct);
    return Results.Ok(pkg);
});

app.MapPost("/api/pqc/oidc/validate", async ([FromBody] OidcValidateRequest req, CancellationToken ct) =>
{
    if (req == null) return Results.BadRequest(new { error = "OidcValidateRequest cannot be null." });
    var result = await oidcEngine.ValidateIdTokenAsync(req.RawToken, req.ExpectedAudience, req.ExpectedIssuer ?? "https://identity.tum.co.th/oauth2/v1", ct);
    return Results.Ok(result);
});

app.MapGet("/.well-known/jwks.json", async (CancellationToken ct) =>
{
    var keys = await oidcEngine.GetJwksKeysAsync(ct);
    return Results.Ok(new { keys });
});

app.Run();

public record AgeProofRequest(int ActualAge, int MinimumAgeThreshold, string VerifierNonce);
public record ZkVerifyRequest(PqcZkProofPackage Proof, string ExpectedNonce);
public record OidcIssueRequest(string Subject, string Audience, string? Issuer, Dictionary<string, object>? CustomClaims);
public record OidcValidateRequest(string RawToken, string ExpectedAudience, string? ExpectedIssuer);

public partial class Program { }
