document.addEventListener("DOMContentLoaded", function () {
  const ec = new elliptic.ec("p256");

  document
    .getElementById("generate")
    .addEventListener("click", function () {
      let key = ec.genKeyPair();
      document.getElementById("publicKey").value = key.getPublic("hex");
      document.getElementById("privateKey").value = key.getPrivate("hex");
    });

  document
    .getElementById("encrypt")
    .addEventListener("click", function () {
      let privateKey = document.getElementById("privateKey").value;
      let message = document.getElementById("plainTextEncrypt").value;
      let encrypted = CryptoJS.AES.encrypt(message, privateKey).toString();
      document.getElementById("cipherText").value = encrypted;
    });

  document
    .getElementById("decrypt")
    .addEventListener("click", function () {
      let privateKey = document.getElementById("privateKeyDecrypt").value;
      let encryptedText = document.getElementById("cipherTextDecrypt").value;
      let bytes = CryptoJS.AES.decrypt(encryptedText, privateKey);
      let decryptedText = bytes.toString(CryptoJS.enc.Utf8);
      document.getElementById("plainTextDecrypt").value = decryptedText;
    });
});
