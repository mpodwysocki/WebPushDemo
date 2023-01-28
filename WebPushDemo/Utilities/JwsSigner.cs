using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WebPushDemo.Utilities
{
    internal class JwsSigner
    {
        private readonly byte[] _privateKey;

        public JwsSigner(byte[] privateKey)
        {
            _privateKey = privateKey;
        }

        public string GenerateSignature(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var securedInput = SecureInput(header, payload);
            var message = Encoding.UTF8.GetBytes(securedInput);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = _privateKey,
            });

            var signatureData = ecdsa.SignData(message, HashAlgorithmName.SHA256);

            var signature = Base64UrlEncoder.Encode(signatureData);
            return $"{securedInput}.{signature}";
        }

        private static string SecureInput(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var encodeHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
            var encodePayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

            return $"{encodeHeader}.{encodePayload}";
        }
    }
}

