using Microsoft.IdentityModel.Tokens;

namespace WebPushDemo.Utilities
{
    public class EncryptionResult
    {
        public byte[]? PublicKey { get; set; }
        public byte[]? Payload { get; set; }
        public byte[]? Salt { get; set; }

        public string Base64EncodePublicKey()
        {
            return Base64UrlEncoder.Encode(PublicKey);
        }

        public string Base64EncodeSalt()
        {
            return Base64UrlEncoder.Encode(Salt);
        }
    }
}

