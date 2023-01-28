using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace WebPushDemo.Utilities
{
    public static class VapidUtilities
    {
        /// <summary>
        /// Generate vapid keys
        /// </summary>
        public static VapidDetails GenerateVapidKeys()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ecdsa.GenerateKey(ECCurve.NamedCurves.nistP256);

            var ecParams = ecdsa.ExportParameters(true);
            var x = ecParams.Q.X!;
            var y = ecParams.Q.Y!;

            var publicKey = new byte[x.Length + y.Length + 1];
            publicKey[0] = 0x4;
            Array.Copy(x, 0, publicKey, 1, x.Length);
            Array.Copy(y, 0, publicKey, x.Length + 1, y.Length);

            var privateKey = ecParams.D;

            return new VapidDetails
            {
                PublicKey = Base64UrlEncoder.Encode(publicKey),
                PrivateKey = Base64UrlEncoder.Encode(privateKey),
            };
        }

        /// <summary>
        /// This method takes the required VAPID parameters and returns the required
        /// header to be added to a Web Push Protocol Request.
        /// </summary>
        /// <param name="audience">This must be the origin of the push service.</param>
        /// <param name="subject">This should be a URL or a 'mailto:' email address</param>
        /// <param name="publicKey">The VAPID public key as a base64 encoded string</param>
        /// <param name="privateKey">The VAPID private key as a base64 encoded string</param>
        /// <param name="expiration">The expiration of the VAPID JWT.</param>
        /// <returns>A dictionary of header key/value pairs.</returns>
        public static (string AuthHeader, string CryptoKeyHeader) GetVapidHeaders(string audience, string subject, string publicKey,
            string privateKey, long expiration = -1)
        {
            ValidateAudience(audience);
            ValidateSubject(subject);
            ValidatePublicKey(publicKey);
            ValidatePrivateKey(privateKey);

            var privateKeyData = Base64UrlEncoder.DecodeBytes(privateKey);
            if (privateKeyData.Length != 32)
            {
                throw new ArgumentException("Vapid private key should be 32 bytes long when decoded.", nameof(privateKey));
            }

            if (expiration == -1)
            {
                expiration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 43200;
            }
            else
            {
                ValidateExpiration(expiration);
            }

            var header = new Dictionary<string, object>
            {
                { "typ", "JWT" },
                { "alg", "ES256" },
            };

            var jwtPayload = new Dictionary<string, object>
            {
                { "aud", audience },
                { "exp", expiration },
                { "sub", subject },
            };

            var signer = new JwsSigner(privateKeyData);
            var token = signer.GenerateSignature(header, jwtPayload);

            var authHeader = $"WebPush {token}";
            var crytpoKeyHeader = $"p256ecdsa={publicKey}";

            return (authHeader, crytpoKeyHeader);
        }

        private static void ValidateAudience(string audience)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentException("No audience could be generated for VAPID.", nameof(audience));
            }

            if (audience.Length == 0)
            {
                throw new ArgumentException(
                    $"The audience value must be a string containing the origin of a push service. {audience}", nameof(audience));
            }

            if (!Uri.IsWellFormedUriString(audience, UriKind.Absolute))
            {
                throw new ArgumentException("VAPID audience is not a url.", nameof(audience));
            }
        }

        private static void ValidateSubject(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject))
            {
                throw new ArgumentNullException(nameof(subject), "A subject is required");
            }

            if (!Uri.IsWellFormedUriString(subject, UriKind.Absolute))
            {
                throw new ArgumentException("Subject is not a valid URL or mailto address");
            }
        }

        private static void ValidatePublicKey(string publicKey)
        {
            if (string.IsNullOrWhiteSpace(publicKey))
            {
                throw new ArgumentNullException(nameof(publicKey), "Valid public key not set");
            }
        }

        private static void ValidatePrivateKey(string privateKey)
        {
            if (string.IsNullOrWhiteSpace(privateKey))
            {
                throw new ArgumentNullException(nameof(privateKey), "Valid private key not set");
            }
        }

        private static void ValidateExpiration(long expiration)
        {
            if (expiration <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                throw new ArgumentException("Vapid expiration must be a unix timestamp in the future", nameof(expiration));
            }
        }
    }
}

