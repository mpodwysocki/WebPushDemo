//var applicationServerPublicKey = "";
const SERVICE_WORKER = "/sw.js";
let isSubscribed = false;

document.querySelector("#registerButton").addEventListener("click", async () => {
  // Application Server Public Key defined in Views/Device/Create.cshtml
  if (typeof applicationServerPublicKey === "undefined") {
    errorHandler("VAPID public key is undefined.");
    return;
  }

  const status = await Notification.requestPermission();
  if (status === "denied") {
    errorHandler("[Notification.requestPermission] Browser denied permissions to notification api.");
    return;
  } else if (status === "granted") {
    console.log("[Notification.requestPermission] Initializing service worker.");
    await initServiceWorker();
  }

  await subscribe();
});

async function initServiceWorker() {
  if ("serviceWorker" in navigator) {
    const registration = await navigator.serviceWorker.register(SERVICE_WORKER);
    await handleWorkerRegistration(registration);
  } else {
    errorHandler("[initServiceWorker] Service workers are not supported in this browser.");
  }
};

async function handleWorkerRegistration(registration) {
  if (registration.installing) {
    console.log("Service worker installing");
  } else if (registration.waiting) {
    console.log("Service worker installed");
  } else if (registration.active) {
    console.log("Service worker active");
  }

  await initState(registration);
}

// Once the service worker is registered set the initial state
async function initState(registration) {
  // Are Notifications supported in the service worker?
  if (!(registration.showNotification)) {
    errorHandler("[initState] Notifications are unsupported on service workers.");
    return;
  }

  // Check if push messaging is supported
  if (!("PushManager" in window)) {
    errorHandler("[initState] Push messaging is unsupported.");
    return;
  }

  // We need the service worker registration to check for a subscription
  registration = await navigator.serviceWorker.ready;
  const subscription = await registration.pushManager.getSubscription();
  if (subscription) {
    console.log("User is already subscribed to push notifications");
    await subscription.unsubscribe();
  }
}

async function subscribe() {
  const registration = await navigator.serviceWorker.ready;
  const subscribeParams = { userVisibleOnly: true };

  // Setting the public key of our VAPID key pair
  const applicationServerKey = urlB64ToUint8Array(applicationServerPublicKey);
  subscribeParams.applicationServerKey = applicationServerKey;

  try {
    const subscription = await registration.pushManager.subscribe(subscribeParams);
    const p256dh = base64Encode(subscription.getKey("p256dh"));
    const auth = base64Encode(subscription.getKey("auth"));

    document.getElementById("PushEndpoint").value = subscription.endpoint;
    document.getElementById("PushP256DH").value = p256dh;
    document.getElementById("PushAuth").value = auth;
  } catch (e) {
    errorHandler('[subscribe] Unable to subscribe to push', e.message);
  }
}

function errorHandler(message, e) {
  if (typeof e == "undefined") {
    e = null;
  }

  console.error(message, e);
  const errorMessage = document.getElementById("errorMessage");
  errorMessage.innerHTML = `<li>${message}: ${e}</li>`;
  errorMessage.parentElement.style.display = "block";
}

function urlB64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding)
    .replace(/\-/g, "+")
    .replace(/_/g, "/");

  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function base64Encode(arrayBuffer) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}
