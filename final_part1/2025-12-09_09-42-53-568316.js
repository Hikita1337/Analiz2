// firebase-messaging-sw.js
importScripts("https://www.gstatic.com/firebasejs/9.2.0/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/9.2.0/firebase-messaging-compat.js");

const firebaseConfig = {
  apiKey: "AIzaSyB5Xh6ITwLWjnv_PFNn6e83__z5gRU-cNQ",
  authDomain: "csgorun-prod.firebaseapp.com",
  projectId: "csgorun-prod",
  storageBucket: "csgorun-prod.appspot.com",
  messagingSenderId: "860722030196",
  appId: "1:860722030196:web:9fc9060f35b6b67e7e5321",
  measurementId: "G-3M5CL91Q5K",
};

firebase.initializeApp(firebaseConfig);

const messaging = firebase.messaging();

// Обработка фоновых push-уведомлений
messaging.onBackgroundMessage(function (payload) {});
