using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebPushDemo.Utilities
{
    public static class Encryptor
    {
        public static EncryptionResult Encrypt(string userKey, string userSecret, string payload)
        {
            var userKeyBytes = Base64UrlEncoder.DecodeBytes(userKey);
            var userSecretBytes = Base64UrlEncoder.DecodeBytes(userSecret);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);

            return Encrypt(userKeyBytes, userSecretBytes, payloadBytes);
        }

        public static EncryptionResult Encrypt(byte[] userKey, byte[] userSecret, byte[] payload)
        {
            var salt = GenerateSalt(16);

            // DiffieHelman instance for creating server public/private key pair
            using var diffieHellmanBob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

            // Extract server private key
            var serverPrivateKey = diffieHellmanBob.ExportECPrivateKey();

            // Export server public key
            var serverEcParams = diffieHellmanBob.ExportParameters(true);
            var serverX = new BigInteger(serverEcParams.Q.X, true).ToByteArray(true);
            byte[] serverY = new BigInteger(serverEcParams.Q.Y, true).ToByteArray(true);

            var serverPublicKey = new byte[serverX.Length + serverY.Length + 1];
            serverPublicKey[0] = 0x4;
            Array.Copy(serverX, 0, serverPublicKey, 1, serverX.Length);
            Array.Copy(serverY, 0, serverPublicKey, serverX.Length + 1, serverY.Length);

            // Re-create EC curve params from user public key
            var publicKeyX = new byte[userKey.Length / 2];
            var publicKeyY = new byte[publicKeyX.Length];
            Buffer.BlockCopy(userKey, 1, publicKeyX, 0, publicKeyX.Length);
            Buffer.BlockCopy(userKey, 1 + publicKeyX.Length, publicKeyY, 0, publicKeyY.Length);

            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q =
                    {
                        X = publicKeyX,
                        Y = publicKeyY,
                    },
            };

            // Derive key material (does the HKDF extract which is expanded later to get the prk)
            using var diffieHellmanAlice = ECDiffieHellman.Create(ecParams);
            var keyMaterial = diffieHellmanBob.DeriveKeyFromHmac(diffieHellmanAlice.PublicKey, HashAlgorithmName.SHA256, userSecret);

            var prk = HKDF.Expand(HashAlgorithmName.SHA256, keyMaterial, 32, Encoding.UTF8.GetBytes("Content-Encoding: auth\0"));

            // HKDF extract + expand to get the cek and nonce
            var cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, prk, 16, salt, CreateInfoChunk("aesgcm", userKey, serverPublicKey));
            var nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, prk, 12, salt, CreateInfoChunk("nonce", userKey, serverPublicKey));

            var input = AddPaddingToInput(payload);

            var encryptedMessage = EncryptAesGcm(nonce, cek, input);

            return new EncryptionResult
            {
                Salt = salt,
                Payload = encryptedMessage,
                PublicKey = serverPublicKey,
            };
        }

        private static byte[] GenerateSalt(int length)
        {
            var salt = new byte[length];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        private static byte[] AddPaddingToInput(byte[] data)
        {
            var input = new byte[0 + 2 + data.Length];
            Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
            return input;
        }

        private static byte[] EncryptAesGcm(byte[] nonce, byte[] cek, byte[] message)
        {
            // Message length + tag length of 16 (maximum tag length)
            var ciphertextWithTag = new byte[message.Length + 16];

            using (var aesgcm = new AesGcm(cek))
            {
                aesgcm.Encrypt(
                    nonce,
                    message,
                    ciphertextWithTag.AsSpan(0, message.Length),
                    ciphertextWithTag.AsSpan(message.Length));
            }

            return ciphertextWithTag;
        }

        private static byte[] ConvertInt(int number)
        {
            var output = new byte[sizeof(ushort)];
            BinaryPrimitives.WriteUInt16BigEndian(output, (ushort)number);
            return output;
        }

        private static byte[] CreateInfoChunk(string type, byte[] recipientPublicKey, byte[] senderPublicKey)
        {
            var output = new List<byte>();
            output.AddRange(Encoding.UTF8.GetBytes($"Content-Encoding: {type}\0P-256\0"));
            output.AddRange(ConvertInt(recipientPublicKey.Length));
            output.AddRange(recipientPublicKey);
            output.AddRange(ConvertInt(senderPublicKey.Length));
            output.AddRange(senderPublicKey);
            return output.ToArray();
        }
    }
}

