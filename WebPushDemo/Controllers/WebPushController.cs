﻿using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using WebPushDemo.Models;
using WebPushDemo.Utilities;

namespace WebPushDemo.Controllers
{
    public class WebPushController : Controller
    {
        private readonly IConfiguration _configuration;

        private readonly WebPushDemoContext _context;

        public WebPushController(WebPushDemoContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public IActionResult Send(int? id)
        {
            return View();
        }

        [HttpPost, ActionName("Send")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Send(int id)
        {
            var payload = Request.Form["payload"];
            var device = await _context.Devices.SingleOrDefaultAsync(m => m.Id == id);

            string vapidPublicKey = _configuration.GetSection("VapidKeys")["PublicKey"];
            string vapidPrivateKey = _configuration.GetSection("VapidKeys")["PrivateKey"];

            var pushSubscription = new PushSubscription(device.PushEndpoint, device.PushP256DH, device.PushAuth);
            var vapidDetails = new VapidDetails("mailto:example@example.com", vapidPublicKey, vapidPrivateKey);

            var webPushClient = new WebPushClient();
            var response = await webPushClient.SendNotification(pushSubscription, payload, vapidDetails);
            Console.WriteLine($"Status Code: {response.PlatformStatusCode}");
            Console.WriteLine($"Error Reason: {response.PlatformErrorReason}");


            return View();
        }

        public IActionResult GenerateKeys()
        {
            var keys = VapidUtilities.GenerateVapidKeys();
            ViewBag.PublicKey = keys.PublicKey;
            ViewBag.PrivateKey = keys.PrivateKey;
            return View();
        }
    }
}