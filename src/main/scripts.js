//const socket = new WebSocket('ws://158.220.105.209:8010');
const socket = new WebSocket('ws://localhost:8010');

var privateKey = null;
var publicKey = null;

// Function to convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Function to convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const binary = String.fromCharCode(...bytes);
    return btoa(binary);
}

// Import a private key (PKCS#8 format)
async function importPrivateKey(privateKeyBase64) {
    const privateKeyArrayBuffer = base64ToArrayBuffer(privateKeyBase64);
    return window.crypto.subtle.importKey(
        "pkcs8",
        privateKeyArrayBuffer,
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        ["deriveKey"]
    );
}

// Import a public key (SPKI format)
async function importPublicKey(publicKeyBase64) {
    const publicKeyArrayBuffer = base64ToArrayBuffer(publicKeyBase64);
    return window.crypto.subtle.importKey(
        "spki",
        publicKeyArrayBuffer,
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        []
    );
}

// Generate a shared secret
async function generateSharedSecret(privateKeyBase64, publicKeyBase64) {
    // Import the private and public keys
    const privateKey = await importPrivateKey(privateKeyBase64);
    const publicKey = await importPublicKey(publicKeyBase64);

    // Derive the shared secret
    const sharedSecretKey = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey
        },
        privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );

    // Export the derived key as raw bits (ArrayBuffer)
    const sharedSecretArrayBuffer = await window.crypto.subtle.exportKey("raw", sharedSecretKey);

    // Convert ArrayBuffer to Base64 string
    return arrayBufferToBase64(sharedSecretArrayBuffer);
}



async function exportPublicKey(publicKey) {
    // Export the public key as SPKI format
    const exportedKey = await window.crypto.subtle.exportKey(
        "spki", // Public key format
        publicKey
    );

    // Convert to Base64 string (to easily send over the network)
    return btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
}


async function exportPrivateKey(privateKey) {
    // Export the private key as PKCS#8 format
    const exportedKey = await window.crypto.subtle.exportKey(
        "pkcs8", // Private key format
        privateKey
    );

    // Convert to Base64 string (to easily inspect, but don't send over the network)
    return btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
}

async function init(){
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true, // Keys are extractable
        ["deriveKey"]
    );
    privateKey = await exportPrivateKey(keyPair.privateKey);
    publicKey = await exportPublicKey(keyPair.publicKey);
}

sharedSecret = null;

async function createSecret(serverKey) {
    sharedSecret = await generateSharedSecret(privateKey, serverKey);
    console.log(sharedSecret);
}

async function main(){
    await init();

    socket.onopen = () => {
        console.log('Connected to the WebSocket server');
        socket.send(publicKey);
    };

    socket.onmessage = (event) => {
        console.log("Recieved message");
        message = event.data;
        console.log(privateKey);
        console.log(message);
        createSecret(message);
    };

    socket.onclose = (event) => {
        console.log('Disconnected from the WebSocket server');
    };

    socket.onerror = (error) => {
        console.error('WebSocket error: ', error);
    };
}

main();



/*async function generateAndExportKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true, // Keys are extractable
        ["deriveKey"]
    );

    // Export public key to send to server
    const exportedPublicKey = await exportPublicKey(keyPair.publicKey);

    console.log("Public Key (Base64):", exportedPublicKey);

    // (Optional) Export private key
    const exportedPrivateKey = await exportPrivateKey(keyPair.privateKey);
    console.log("Private Key (Base64):", exportedPrivateKey);
}

generateAndExportKeys();*/






























/*
isSetup = false;
serverPublicKey = "";

clientKeyPair = generateRSAKeyPair();
clientPrivateKey = clientKeyPair.privateKey;
clientPublicKey = clientKeyPair.publicKey;

// Method to generate RSA key pair
async function generateRSAKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048, // Key size
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: { name: "SHA-256" },
        },
        true, // Whether the key is extractable
        ["encrypt", "decrypt"] // Key usage
    );
    return keyPair;
}

// Method to encrypt data using RSA public key
async function encrypt(plainText, publicKey) {
    const encoder = new TextEncoder();
    const encodedText = encoder.encode(plainText);
    
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        encodedText
    );
    
    // Convert ArrayBuffer to Base64 string
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

// Method to decrypt data using RSA private key
async function decrypt(encryptedText, privateKey) {
    // Convert Base64 string to ArrayBuffer
    const encryptedData = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
    
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        privateKey,
        encryptedData
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}


msg = {
    "header" : "create-account",
    "username" : "redstoner20192",
    "displayname" : "Redstoner_2019",
    "email" : "lukaspaepke2020@gmail.com",
    "password" : "test"
}

msglogin = {
    "header" : "login-2fa",
    "username" : "lukas",
    "password" : "test",
    "2fa-id" : "5ecfa271-b114-45af-8704-9b7fb05b1bc1",
    "2fa-code" : "305-554"
}

window.localStorage.setItem("token","xkldjfhlkjucxhglkjxfjhg");
window.localStorage.setItem("dennis","kitten");

socket.onopen = () => {
    console.log('Connected to the WebSocket server');
    //console.log(clientPublicKey.modulus);
};

socket.onmessage = (event) => {
    if(!isSetup){
        console.log(event.data);
        serverPublicKey = event.data;
        return;
    }
    console.log('Message from server: ', event.data);
    json = JSON.parse(event.data);
    if(json.value === 'OK'){
        if(json.result.data === '2fa-required'){
            loginForm.classList.add('hidden');
            twoFaForm.classList.remove('hidden');
            msg['2fa-id'] = json.result['2fa-id'];
            msg.header = 'create-account-2fa';
            console.log(msg);
        } else if(json.result.data === 'incorrect-password') {
            messageDiv.textContent = 'Invalid username or password';
        } else {
            messageDiv.textContent = 'Login successful!';
        }
        if(json.result.data === 'login-success'){
            messageDiv.textContent = 'Login successful!';
            twoFaForm.classList.add('hidden');
        }
    } else if(json.value === '2fa-incorrect'){
        messageDiv.textContent = 'Invalid 2FA code';
    }
};

socket.onclose = (event) => {
    console.log('Disconnected from the WebSocket server');
};

socket.onerror = (error) => {
    console.error('WebSocket error: ', error);
};


const loginForm = document.getElementById('loginForm');
const twoFaForm = document.getElementById('2faForm');
const messageDiv = document.getElementById('message');

// Event listener for login form submission
loginForm.addEventListener('submit', (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    //msg.username = username;
    //msg.password = password;

    //sendMessage(JSON.stringify(msg));
});

// Event listener for 2FA form submission
twoFaForm.addEventListener('submit', (e) => {
    e.preventDefault();

    const twoFaCode = document.getElementById('2faCode').value;

    msg['2fa-code'] = document.getElementById('2faCode').value;

    //sendMessage(JSON.stringify(msg));
});
*/
  