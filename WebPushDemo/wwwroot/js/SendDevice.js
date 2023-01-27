document.addEventListener("DOMContentLoaded", () => {
  const handler = () => {
    const payload = document.getElementById("Payload");
    const title = document.getElementById("Title");
    const message = document.getElementById("Message");
    const payloadObject = {
      title: title.value,
      message: message.value
    };
    payload.value = JSON.stringify(payloadObject);
  };

  document.getElementById("Title").addEventListener("keyup", handler);
  document.getElementById("Message").addEventListener("keyup", handler);
});
