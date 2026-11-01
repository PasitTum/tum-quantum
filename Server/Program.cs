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

app.MapGet("/health", () => Results.Ok(new
{
    status = "HEALTHY",
    service = "TUM Quantum Cryptography Service",
    standard = "NIST FIPS 203 (ML-KEM) & NIST FIPS 204 (ML-DSA)",
    capabilities = new[] { "PQC Lattice Verification", "Hybrid Migration Adapter", "Identity Assertion Token", "HNDL Attack Simulation" },
    timestamp = DateTime.UtcNow
}));

app.MapGet("/api/pqc/status", () => Results.Ok(new
{
    status = "READY",
    algorithms = new[] { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Hybrid Permissive", "HNDL Simulation Sandbox" },
    activeStandard = "NIST FIPS 203 / NIST FIPS 204",
    fipsCompliance = true,
    hndlHarnessOperational = true,
    timestamp = DateTime.UtcNow
}));

// HNDL Quantum Attack Simulation Endpoints (SCRUM-35)
app.MapPost("/api/pqc/hndl/simulate", async ([FromBody] HndlSimulationRequest request, CancellationToken ct) =>
{
    if (request == null)
    {
        return Results.BadRequest(new { error = "Request payload cannot be null." });
    }

    var result = await hndlSimulator.SimulateAttackAsync(request, ct);
    return Results.Ok(result);
});

app.MapPost("/api/pqc/hndl/batch", async ([FromBody] HndlHarvestBatchRequest request, CancellationToken ct) =>
{
    if (request == null)
    {
        return Results.BadRequest(new { error = "Batch request payload cannot be null." });
    }

    var result = await hndlSimulator.SimulateBatchHarvestAsync(request, ct);
    return Results.Ok(result);
});

app.MapGet("/api/pqc/hndl/complexity", ([FromQuery] string? algorithm) =>
{
    var metrics = hndlSimulator.CalculateTheoreticalComplexity(algorithm ?? "RSA-2048");
    return Results.Ok(metrics);
});

app.Run();

public partial class Program { }
