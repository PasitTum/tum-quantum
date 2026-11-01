# Multi-stage Dockerfile for TUM Quantum Cryptography Service (NIST FIPS 203 & 204)
# Build Stage (.NET 8.0 SDK)
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src

COPY Tum.Quantum.csproj ./
COPY Server/Tum.Quantum.Server.csproj ./Server/
RUN dotnet restore Server/Tum.Quantum.Server.csproj

COPY . ./
RUN dotnet publish Server/Tum.Quantum.Server.csproj -c Release -o /app/publish /p:UseAppHost=false

# Runtime Image (.NET 8.0 ASP.NET Alpine)
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS final
WORKDIR /app

RUN apk add --no-cache curl wget

COPY --from=build /app/publish .

EXPOSE 5100
ENV ASPNETCORE_URLS=http://+:5100
ENV ASPNETCORE_ENVIRONMENT=Production
ENV DOTNET_EnableDiagnostics=0

HEALTHCHECK --interval=20s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:5100/health || exit 1

ENTRYPOINT ["dotnet", "Tum.Quantum.Server.dll"]
