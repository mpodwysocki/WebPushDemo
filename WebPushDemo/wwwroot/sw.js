self.addEventListener('push', function (event) {
  if (!(self.Notification && self.Notification.permission === 'granted')) {
    return;
  }

  const data = {};
  if (event.data) {
    data = event.data.json();
  }

  console.log('Notification Received:');
  console.log(data);

  const title = data.title ?? "Push Notification Title";
  const message = data.message ?? "Push Notification Body";
  const icon = "images/push-icon.jpg";

  event.waitUntil(self.registration.showNotification(title, {
    body: message,
    icon: icon,
    badge: icon
  }));
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
});
