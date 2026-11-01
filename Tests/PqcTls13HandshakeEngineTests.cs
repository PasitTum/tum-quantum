// Copyright (c) 2026 TUM Group Holdings. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading.Tasks;
using Tum.Quantum.Core.Models;
using Tum.Quantum.Engine;
using Xunit;

namespace Tum.Quantum.Tests
{
    public class PqcTls13HandshakeEngineTests
    {
        private readonly PqcTls13HandshakeEngine _engine = new();

        [Fact]
        public async Task GenerateClientHello_ProducesValidSharesAndRandoms()
        {
            var hello = await _engine.GenerateClientHelloAsync(PqcTlsNamedGroup.X25519MLKEM768);

            Assert.NotNull(hello);
            Assert.Equal((ushort)0x0303, hello.ProtocolVersion);
            Assert.Equal(32, hello.ClientRandom.Length);
            Assert.Equal(32, hello.SessionId.Length);
            Assert.Equal(PqcTlsNamedGroup.X25519MLKEM768, hello.NamedGroup);
            Assert.True(hello.ClientKeyShare.Length >= 32 + 1184); // X25519 (32) + ML-KEM-768 (1184)
            Assert.True(hello.EphemeralClientSecret.Length > 0);
        }

        [Fact]
        public async Task ProcessClientHello_ProducesValidServerHelloAndEncapsulatedShare()
        {
            var clientHello = await _engine.GenerateClientHelloAsync();
            var serverHello = await _engine.ProcessClientHelloAsync(clientHello);

            Assert.NotNull(serverHello);
            Assert.Equal(32, serverHello.ServerRandom.Length);
            Assert.Equal(clientHello.SessionId, serverHello.SessionId);
            Assert.Equal("TLS_AES_256_GCM_SHA384", serverHello.SelectedCipherSuite);
            Assert.Equal(PqcTlsNamedGroup.X25519MLKEM768, serverHello.SelectedGroup);
            Assert.True(serverHello.ServerKeyShare.Length >= 32 + 1088); // X25519 (32) + ML-KEM-768 ciphertext (1088)
            Assert.Equal(48, serverHello.DerivedSharedSecret.Length); // SHA-384
        }

        [Fact]
        public async Task CompleteHandshake_DerivesMatchingClientAndServerTrafficKeys()
        {
            var clientHello = await _engine.GenerateClientHelloAsync();
            var serverHello = await _engine.ProcessClientHelloAsync(clientHello);

            var clientRes = await _engine.FinalizeClientHandshakeAsync(clientHello, serverHello);
            var serverRes = await _engine.FinalizeServerHandshakeAsync(clientHello, serverHello);

            Assert.True(clientRes.IsSuccessful);
            Assert.True(serverRes.IsSuccessful);
            Assert.True(clientRes.HasQuantumForwardSecrecy);
            Assert.True(serverRes.HasQuantumForwardSecrecy);

            // Verify Client and Server derived identical master secrets and application keys
            Assert.Equal(clientRes.MasterSecret, serverRes.MasterSecret);
            Assert.Equal(clientRes.ClientApplicationTrafficKey, serverRes.ClientApplicationTrafficKey);
            Assert.Equal(clientRes.ServerApplicationTrafficKey, serverRes.ServerApplicationTrafficKey);
            Assert.Equal(clientRes.ClientApplicationIv, serverRes.ClientApplicationIv);
            Assert.Equal(clientRes.ServerApplicationIv, serverRes.ServerApplicationIv);
            Assert.Equal(clientRes.TranscriptHash, serverRes.TranscriptHash);

            Assert.Equal(32, clientRes.ClientApplicationTrafficKey.Length); // AES-256
            Assert.Equal(12, clientRes.ClientApplicationIv.Length); // GCM IV
        }

        [Fact]
        public async Task ProcessClientHello_NullOrInvalidKeyShare_ThrowsException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _engine.ProcessClientHelloAsync(null!));

            var badHello = new PqcTlsClientHello { ClientKeyShare = new byte[10] };
            await Assert.ThrowsAsync<ArgumentException>(() => _engine.ProcessClientHelloAsync(badHello));
        }
    }
}
