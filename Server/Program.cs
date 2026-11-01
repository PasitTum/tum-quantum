// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using Tum.Quantum.Engine;
using Tum.Trust.Security.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var quantumEngine = new QuantumSafeTrustEngine();
var assertionSigner = new PqcAssertionSigner(quantumEngine);

app.MapGet("/health", () => Results.Ok(new
{
    status = "HEALTHY",
    service = "TUM Quantum Cryptography Service",
    standard = "NIST FIPS 203 (ML-KEM) & NIST FIPS 204 (ML-DSA)",
    timestamp = DateTime.UtcNow
}));

app.MapGet("/api/pqc/status", () => Results.Ok(new
{
    status = "READY",
    algorithms = new[] { "ML-KEM-768", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Hybrid Permissive" },
    activeStandard = "NIST FIPS 203 / NIST FIPS 204",
    fipsCompliance = true,
    timestamp = DateTime.UtcNow
}));

app.Run();

public partial class Program { }
