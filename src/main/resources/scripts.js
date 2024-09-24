function generateRandomNBitNumber(n) {
    const bytes = Math.ceil(n / 8);
    const array = new Uint8Array(bytes);
    window.crypto.getRandomValues(array);
    let bigInt = BigInt('0x' + Array.from(array).map(b => b.toString(16).padStart(2, '0')).join(''));
    const mask = (BigInt(1) << BigInt(n)) - BigInt(1);
    bigInt &= mask;
    return bigInt;
}

function isProbablePrime(n, k = 40) {
    if (n < 2n) return false;
    if (n === 2n) return true;
    if (n % 2n === 0n) return false;
    let d = n - 1n;
    let s = 0;
    while (d % 2n === 0n) {
        d /= 2n;
        s += 1;
    }
    for (let i = 0; i < k; i++) {
        let a = BigInt.asUintN(n.toString(2).length, generateRandomNBitNumber(n.toString(2).length - 1) + 1n);
        let x = modPow(a, d, n);
        if (x === 1n || x === n - 1n) continue;
        let flag = false;
        for (let r = 0; r < s; r++) {
            x = modPow(x, 2n, n);
            if (x === n - 1n) {
                flag = true;
                break;
            }
        }
        if (!flag) return false;
    }
    return true;
}

function generateNBitPrime(n) {
    if (n < 2) throw new Error('n must be at least 2');
    let prime;
    do {
        prime = generateRandomNBitNumber(n);
        prime |= (BigInt(1) << BigInt(n - 1));
    } while (!isProbablePrime(prime));
    return prime;
}

function modInverse(a, m) {
    a = BigInt(a);
    m = BigInt(m);

    let [g, x, y] = extendedGCD(a, m);
    if (g !== 1n) {
        throw new Error("Modular inverse does not exist");
    }
    return (x % m + m) % m;
}

function modPow(base, exponent, modulus) {
    if (modulus === BigInt(1)) return BigInt(0);

    base = base % modulus;
    let result = BigInt(1);
    let exp = exponent;

    while (exp > 0) {
        if (exp % BigInt(2) === BigInt(1)) {
            result = (result * base) % modulus;
        }
        exp = exp >> BigInt(1);
        base = (base * base) % modulus;
    }

    return result;
}

function extendedGCD(a, b) {
    if (b === 0n) {
        return [a, 1n, 0n];
    }
    let [g, x1, y1] = extendedGCD(b, a % b);
    let x = y1;
    let y = x1 - (a / b) * y1;
    return [g, x, y];
}

function decryptSessionKey(encryptedSessionKey, server_n, client_d){
    return modPow(encryptedSessionKey,client_d,server_n);
}

function generateRSAKeyPair(bitLength){
    p = generateNBitPrime(bitLength);
    q = generateNBitPrime(bitLength);

    n = p * q;

    phi = (p - BigInt(1)) * (q - BigInt(1));

    e = BigInt(65537);

    d = modInverse(e, phi);

    return [n, e, d];
}

function bigIntToBase64(bigInt) {
    const hexString = bigInt.toString(16);
    const paddedHexString = hexString.length % 2 === 1 ? '0' + hexString : hexString;

    const byteArray = new Uint8Array(paddedHexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const binaryString = String.fromCharCode.apply(null, byteArray);
    return btoa(binaryString);
}

async function encrypt(message, key) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        await window.crypto.subtle.digest("SHA-256", encoder.encode(key)),
        "AES-CBC",
        false,
        ["encrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        keyMaterial,
        encoder.encode(message)
    );

    return `${btoa(String.fromCharCode(...iv))}:${btoa(String.fromCharCode(...new Uint8Array(encrypted)))}`;
}

async function decrypt(encryptedData, key) {
    const [ivBase64, contentBase64] = encryptedData.split(":");
    const iv = new Uint8Array(atob(ivBase64).split("").map(char => char.charCodeAt(0)));
    const encryptedContent = new Uint8Array(atob(contentBase64).split("").map(char => char.charCodeAt(0)));

    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)),
        "AES-CBC",
        false,
        ["decrypt"]
    );

    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv },
        keyMaterial,
        encryptedContent
    );

    return new TextDecoder().decode(decrypted);
}

async function handleMessage(message){
    var recieved = JSON.parse(message);
    if(recieved.header === "server-info"){
        server_n = recieved.n;
        server_e = recieved.e;
        return recieved;
    } else if(recieved.header === "connection-result"){
        session_key = decryptSessionKey(BigInt(recieved.sessionKey),keyPair[0],keyPair[2]).toString();
        return recieved;
    } else if(recieved.header === "encrypted"){
        var encryption = recieved.encryption;
        if(encryption === "AES"){
            var decrypted = await decrypt(recieved.data, session_key);
            return JSON.parse(decrypted);
        } else if(encryption === "PLAIN") {
            return JSON.parse(recieved.data);
        } else {
            return;
        }
    } else {
        return recieved;
    }
}

function setup(){
    keyPair = generateRSAKeyPair(1024);
    let connectionMessage = {
        'header' : 'connection',
        'n' : keyPair[0].toString(),
        'e' : keyPair[1].toString()
    }
    socket.send(JSON.stringify(connectionMessage));
}

function sendMessage(message){
    (async () => {
        const key = session_key;

        const encryptedData = await encrypt(message, key);

        var carrier = {
            "header" : "encrypted",
            "encryption" : "AES",
            "data" : encryptedData
        }
        socket.send(JSON.stringify(carrier));
    })();
}

var keyPair = null;

var server_n = null;
var server_e = null;
var session_key = null;






//const socket = new WebSocket('ws://158.220.105.209:8010');
const socket = new WebSocket('ws:/localhost:99');

socket.onopen = () => {
    socket.send("Hello World");
    console.log('Connected to the WebSocket server');
    setup();
};

socket.onmessage = (event) => {
    handleMessage(event.data).then((result) => {
        console.log(result);
    });
};

socket.onclose = (event) => {
    console.log('Disconnected from the WebSocket server');
};

socket.onerror = (error) => {
    console.error('WebSocket error: ', error);
};

/*setTimeout(function(){
    var login = {
        "header" : "login",
        "username" : "lukas",
        "password" : "test"
    };
    socket.send(JSON.stringify(login));
    //sendMessage(JSON.stringify(login));
}, 1000);*/