using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace WebPushDemo.Utilities
{
	public class WebPushClient
	{
		private readonly HttpClient _httpClient;
        private readonly TimeSpan DefaultTtl = TimeSpan.FromDays(28);

        public WebPushClient()
		{
			_httpClient = new HttpClient();
		}


		public async Task<SendNotificationResponse> SendNotification(PushSubscription pushSubscription, string payload, VapidDetails vapidDetails)
		{
			var subscriptionEndpoint = pushSubscription.Endpoint;
            var uri = new Uri(subscriptionEndpoint);
            var audience = $"{uri.Scheme}://{uri.Host}";

            var (AuthHeader, CryptoKeyHeader) = VapidUtilities.GetVapidHeaders(audience, vapidDetails.Subject, vapidDetails.PublicKey, vapidDetails.PrivateKey);

            using var request = new HttpRequestMessage(HttpMethod.Post, subscriptionEndpoint);
            var encryptedPayload = Encryptor.Encrypt(pushSubscription.P256DH, pushSubscription.Auth, payload);


            request.Content = new ByteArrayContent(encryptedPayload.Payload!);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            request.Content.Headers.ContentLength = encryptedPayload.Payload?.Length;
            request.Content.Headers.ContentEncoding.Add("aesgcm");
            request.Headers.Add("Encryption", $"salt={encryptedPayload.Base64EncodeSalt()}");
            var cryptoKeyHeader = $"dh={encryptedPayload.Base64EncodePublicKey()}";

            request.Headers.Add("Authorization", AuthHeader);
            if (string.IsNullOrEmpty(cryptoKeyHeader))
            {
                cryptoKeyHeader = CryptoKeyHeader;
            }
            else
            {
                cryptoKeyHeader += $";{CryptoKeyHeader}";
            }

            request.Headers.Add("Crypto-Key", cryptoKeyHeader);
            request.Headers.Add("TTL", $"{(int)DefaultTtl.TotalSeconds}");

            var response = await _httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();
            var location = response.Headers.Location;

            return new SendNotificationResponse
            {
                PlatformStatusCode = (int)response.StatusCode,
                PlatformErrorReason = string.IsNullOrEmpty(responseBody) ? null : responseBody,
                PlatformMessageId = location?.ToString() ?? null,
            };
        }
	}
}

