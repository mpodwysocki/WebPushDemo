﻿namespace WebPushDemo.Utilities
{
    public class VapidDetails
    {
        public VapidDetails()
        {
        }

        /// <param name="subject">This should be a URL or a 'mailto:' email address</param>
        /// <param name="publicKey">The VAPID public key as a base64 encoded string</param>
        /// <param name="privateKey">The VAPID private key as a base64 encoded string</param>
        public VapidDetails(string subject, string publicKey, string privateKey)
        {
            Subject = subject;
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        public string Subject { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
        public string PrivateKey { get; set; } = string.Empty;
        public long Expiration { get; set; } = -1;
    }
}

