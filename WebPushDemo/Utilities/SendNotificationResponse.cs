using System;
namespace WebPushDemo.Utilities
{
	public class SendNotificationResponse
	{
		public SendNotificationResponse()
		{
		}

		public int PlatformStatusCode { get; set; }
		public string? PlatformErrorReason { get; set; }
		public string? PlatformMessageId { get; set; }
    }
}

