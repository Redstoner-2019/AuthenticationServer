package me.redstoner2019.server;

import me.redstoner2019.util.Logger;
import org.java_websocket.WebSocket;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;

public class RSAUtil {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String AES = "AES";
    public static HashMap<String,String> sessionKeys = new HashMap<>();

    public static void sendInit(WebSocket ws){
        int bitLength = 1024;

        BigInteger[] serverKeyPair = generateRSAKeyPair(bitLength);
        BigInteger server_n = serverKeyPair[0];
        BigInteger server_e = serverKeyPair[1];
        BigInteger server_d = serverKeyPair[2];

        JSONObject data = new JSONObject();
        data.put("header","server-info");
        data.put("n", server_n.toString());
        data.put("e", server_e.toString());

        ws.send(data.toString());
    }

    public static JSONObject handleMessage(JSONObject request, WebSocket ws){
        if(request.has("header")){
            if(request.getString("header").equals("connection")){
                BigInteger sessionKey = new BigInteger(512, new SecureRandom());
                BigInteger encryptedSessionKey = encryptSessionKey(sessionKey, new BigInteger(request.getString("n")), new BigInteger(request.getString("e")));

                String sessionKeyString = sessionKey.toString();
                sessionKeys.put(ws.getRemoteSocketAddress().toString(), sessionKeyString);

                JSONObject result = new JSONObject();
                result.put("sessionKey", encryptedSessionKey.toString());
                result.put("header","connection-result");
                ws.send(result.toString());
                return null;
            } else if(request.getString("header").equals("encrypted")){
                String encryption = request.getString("encryption");
                if(encryption.equals("AES")){
                    try {
                        request = new JSONObject(RSAUtil.decrypt(request.getString("data"),sessionKeys.get(ws.getRemoteSocketAddress().toString())));
                        return request;
                    } catch (Exception e) {
                        JSONObject response = new JSONObject();
                        response.put("header","response");
                        response.put("code",501);
                        response.put("value","An internal error occured");
                        ws.send(response.toString());
                        System.err.println(request.toString(3));
                        System.err.println(response);
                        e.printStackTrace();
                        return null;
                    }
                } else if(encryption.equals("PLAIN")){
                    try{
                        return request.getJSONObject("data");
                    }catch (Exception e){
                        try{
                            return new JSONObject(request.getString("data"));
                        }catch (Exception ex){
                            return request;
                        }
                    }
                } else {
                    JSONObject response = new JSONObject();
                    response.put("header","response");
                    response.put("code",400);
                    response.put("value","Invalid Encryption");
                    ws.send(response.toString());
                    return null;
                }
            } else {
                return request;
            }
        } else {
            return request;
        }
    }

    public static String encrypt(String message, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(getKey(key), AES);
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // Generate a random IV
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv); // Use SecureRandom to generate IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] encrypted = cipher.doFinal(message.getBytes());

        // Encode both IV and encrypted message to Base64
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);

        return ivBase64 + ":" + encryptedBase64;
    }

    public static String decrypt(String encryptedMessage, String key) throws Exception {
        String[] parts = encryptedMessage.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);

        SecretKeySpec secretKey = new SecretKeySpec(getKey(key), AES);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] original = cipher.doFinal(encryptedBytes);
        return new String(original);
    }

    private static byte[] getKey(String key) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(key.getBytes("UTF-8"));
        return keyBytes;
    }

    public static BigInteger[] generateRSAKeyPair(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        return generateRSAKeyPair(p, q);
    }

    public static BigInteger[] generateRSAKeyPair(BigInteger p, BigInteger q) {
        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = BigInteger.valueOf(65537);
        BigInteger d = e.modInverse(phi);
        return new BigInteger[]{n, e, d};
    }

    public static BigInteger encryptSessionKey(BigInteger sessionKey, BigInteger n, BigInteger e) {
        return sessionKey.modPow(e, n);
    }

    public static BigInteger decryptSessionKey(BigInteger ciphertext, BigInteger n, BigInteger d) {
        return ciphertext.modPow(d, n);
    }

    public static void sendMessageSecure(WebSocket ws, String message){
        if(sessionKeys.containsKey(ws.getRemoteSocketAddress().toString())){
            JSONObject messageJSON = new JSONObject();
            messageJSON.put("header", "encrypted");
            messageJSON.put("encryption", "AES");
            try {
                messageJSON.put("data", encrypt(message,sessionKeys.get(ws.getRemoteSocketAddress().toString())));
                ws.send(messageJSON.toString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            ws.send(message);
        }
    }
}
