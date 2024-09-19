package me.redstoner2019.server;

import me.redstoner2019.util.Logger;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.json.JSONException;
import org.json.JSONObject;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;

import static me.redstoner2019.server.RSAUtil.encryptSessionKey;
import static me.redstoner2019.server.RSAUtil.generateRSAKeyPair;

public class WebServer extends WebSocketServer {
    public static HashMap<String,String> sessionKeys = new HashMap<>();

    public WebServer(InetSocketAddress inetSocketAddress) {
        super(inetSocketAddress);
    }

    @Override
    public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
        Logger.log(webSocket.getRemoteSocketAddress() + " connected");

        int bitLength = 1024;

        BigInteger[] serverKeyPair = generateRSAKeyPair(bitLength);
        BigInteger server_n = serverKeyPair[0];
        BigInteger server_e = serverKeyPair[1];
        BigInteger server_d = serverKeyPair[2];

        JSONObject data = new JSONObject();
        data.put("header","server-info");
        data.put("n", server_n.toString());
        data.put("e", server_e.toString());

        webSocket.send(data.toString());
    }

    @Override
    public void onClose(WebSocket webSocket, int i, String s, boolean b) {
        Logger.log(webSocket.getRemoteSocketAddress() + " disconnected");
        sessionKeys.remove(webSocket.getRemoteSocketAddress().toString());
    }

    @Override
    public void onMessage(WebSocket webSocket, String s) {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                Logger.log(webSocket.getRemoteSocketAddress() + " received message: " + s);
                JSONObject response;
                try{
                    JSONObject request = new JSONObject(s);
                    if(request.has("header")){
                        if(request.getString("header").equals("connection")){
                            BigInteger sessionKey = new BigInteger(512, new SecureRandom());
                            BigInteger encryptedSessionKey = encryptSessionKey(sessionKey, new BigInteger(request.getString("n")), new BigInteger(request.getString("e")));

                            String sessionKeyString = sessionKey.toString();
                            sessionKeys.put(webSocket.getRemoteSocketAddress().toString(), sessionKeyString);
                            System.out.println(sessionKeyString);

                            JSONObject result = new JSONObject();
                            result.put("sessionKey", encryptedSessionKey.toString());
                            result.put("header","connection-result");
                            webSocket.send(result.toString());
                            return;
                        }
                        if(request.getString("header").equals("encrypted")){
                            String encryption = request.getString("encryption");
                            if(encryption.equals("AES")){
                                try {
                                    request = new JSONObject(RSAUtil.decrypt(request.getString("data"),sessionKeys.get(webSocket.getRemoteSocketAddress().toString())));
                                    Logger.log("Decrypted data: " + request.toString(3));
                                } catch (Exception e) {
                                    response = new JSONObject();
                                    response.put("header","response");
                                    response.put("code",501);
                                    response.put("value","An internal error occured");
                                    webSocket.send(response.toString());
                                    System.out.println(request.toString(3));
                                    System.out.println(response);
                                    e.printStackTrace();
                                    return;
                                }
                            } else {
                                System.out.println("Invalid encryption");
                                return;
                            }
                        }
                    }
                    if(request.has("header")){
                        switch (request.getString("header")){
                            case "delete-account" : {
                                if(!request.has("username") || !request.has("password") ||!request.has("token")){
                                    String error = "Missing fields";
                                    error+="\nusername: " + request.has("username");
                                    error+="\npassword: " + request.has("password");
                                    error+="\ntoken: " + request.has("token");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String username = request.getString("username");
                                String password = request.getString("password");
                                String token = request.getString("token");

                                JSONObject loginResult = AuthServer.accountLogin(username,password,true);

                                if(loginResult.getString("data").equals("login-success")){
                                    if(loginResult.getString("token").equals(token)){
                                        loginResult = AuthServer.tokenInfo(token);
                                        if(username.equals(loginResult.getString("username"))){
                                            AuthServer.deleteAccount(username);
                                            response = new JSONObject();
                                            response.put("header","response");
                                            response.put("code",200);
                                            response.put("value","OK");
                                        } else {
                                            response = new JSONObject();
                                            response.put("header","response");
                                            response.put("code",401);
                                            response.put("value","Invlaid credentials");
                                        }
                                    } else {
                                        response = new JSONObject();
                                        response.put("header","response");
                                        response.put("code",401);
                                        response.put("value","Invlaid credentials");
                                    }
                                } else {
                                    response = new JSONObject();
                                    response.put("header","response");
                                    response.put("code",401);
                                    response.put("value","Invlaid credentials");
                                }
                                break;
                            }
                            case "create-account": {
                                if(!request.has("username") || !request.has("displayname") ||!request.has("password") ||!request.has("email")){
                                    String error = "Missing fields";
                                    error+="\nusername: " + request.has("username");
                                    error+="\ndisplayname: " + request.has("displayname");
                                    error+="\npassword: " + request.has("password");
                                    error+="\nemail: " + request.has("email");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String username = request.getString("username");
                                String displayname = request.getString("displayname");
                                String password = request.getString("password");
                                String email = request.getString("email");
                                response = new JSONObject();
                                response.put("header","response");
                                response.put("code",200);
                                response.put("value","OK");
                                response.put("result",AuthServer.createAccount(username,displayname,password,email,false));
                                break;
                            }
                            case "create-account-2fa": {
                                if(!request.has("username") || !request.has("displayname") ||!request.has("password") ||!request.has("email") || !request.has("2fa-id") || !request.has("2fa-code")){
                                    String error = "Missing fields";
                                    error+="\nusername: " + request.has("username");
                                    error+="\ndisplayname: " + request.has("displayname");
                                    error+="\npassword: " + request.has("password");
                                    error+="\nemail: " + request.has("email");
                                    error+="\n2fa-id: " + request.has("2fa-id");
                                    error+="\n2fa-code: " + request.has("2fa-code");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }

                                String username = request.getString("username");
                                String displayname = request.getString("displayname");
                                String password = request.getString("password");
                                String email = request.getString("email");
                                String id = request.getString("2fa-id");
                                String code = request.getString("2fa-code");

                                if(AuthServer.twoFactors.containsKey(id)){
                                    if(AuthServer.twoFactors.get(id).getCode().equals(code)){
                                        if(System.currentTimeMillis() > AuthServer.twoFactors.get(id).getExpires()){
                                            response = new JSONObject();
                                            response.put("header","response");
                                            response.put("code",405);
                                            response.put("value","The 2fa code is expired");
                                            AuthServer.twoFactors.remove(id);
                                        } else {
                                            response = new JSONObject();
                                            response.put("header","response");
                                            response.put("code",200);
                                            response.put("value","OK");
                                            response.put("result",AuthServer.createAccount(username,displayname,password,email,true));
                                        }
                                    } else {
                                        response = new JSONObject();
                                        response.put("header","response");
                                        response.put("code",403);
                                        response.put("value","2fa-incorrect");
                                    }
                                } else {
                                    response = getMalformedRequestObject("Invalid 2FA ID");
                                }
                                break;
                            }
                            case "login": {
                                if(!request.has("username") || !request.has("password")){
                                    String error = "Missing fields";
                                    error+="\nusername: " + request.has("username");
                                    error+="\npassword: " + request.has("password");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String username = request.getString("username");
                                String password = request.getString("password");

                                response = new JSONObject();
                                response.put("header","response");
                                response.put("code",200);
                                response.put("value","OK");
                                response.put("result",AuthServer.accountLogin(username,password,false));
                                break;
                            }
                            case "login-2fa": {
                                if(!request.has("username") || !request.has("password") || !request.has("2fa-id") || !request.has("2fa-code")){
                                    String error = "Missing fields";
                                    error+="\nusername: " + request.has("username");
                                    error+="\npassword: " + request.has("password");
                                    error+="\n2fa-id: " + request.has("2fa-id");
                                    error+="\n2fa-code: " + request.has("2fa-code");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String username = request.getString("username");
                                String password = request.getString("password");
                                String id = request.getString("2fa-id");
                                String code = request.getString("2fa-code");

                                if(AuthServer.twoFactors.containsKey(id)){
                                    if(AuthServer.twoFactors.get(id).getCode().equals(code)){
                                        if(System.currentTimeMillis() > AuthServer.twoFactors.get(id).getExpires()){
                                            response = new JSONObject();
                                            response.put("header","response");
                                            response.put("code",405);
                                            response.put("value","The 2fa code is expired");
                                            AuthServer.twoFactors.remove(id);
                                        } else {
                                            response = new JSONObject();
                                            response.put("header","response");
                                            response.put("code",200);
                                            response.put("value","OK");
                                            response.put("result",AuthServer.accountLogin(username,password,true));
                                        }
                                    } else {
                                        response = new JSONObject();
                                        response.put("header","response");
                                        response.put("code",403);
                                        response.put("value","2fa-incorrect");
                                    }
                                } else {
                                    response = getMalformedRequestObject("Invalid 2FA ID");
                                }
                                break;
                            }
                            case "token-info": {
                                if(!request.has("token")){
                                    String error = "Missing fields";
                                    error+="\ntoken: " + request.has("token");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String token = request.getString("token");
                                response = new JSONObject();
                                response.put("header","response");
                                response.put("code",200);
                                response.put("value","OK");
                                response.put("result",AuthServer.tokenInfo(token));
                                break;
                            }
                            case "update-password": {
                                if(!request.has("token") || !request.has("password")){
                                    String error = "Missing fields";
                                    error+="\ntoken: " + request.has("token");
                                    error+="\npassword: " + request.has("password");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String token = request.getString("token");
                                String newPassword = request.getString("password");
                                response = new JSONObject();
                                response.put("code",200);
                                response.put("value","OK");
                                response.put("value","Method not found.");
                                response.put("result",AuthServer.tokenInfo(token));
                                break;
                            }
                            case "update-displayname": {
                                if(!request.has("token") || !request.has("displayname")){
                                    String error = "Missing fields";
                                    error+="\ntoken: " + request.has("token");
                                    error+="\ndisplayname: " + request.has("displayname");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String token = request.getString("token");
                                String newDisplayname = request.getString("displayname");
                                response = new JSONObject();
                                response.put("header","response");
                                response.put("code",200);
                                response.put("value","OK");
                                response.put("result",AuthServer.tokenInfo(token));
                                break;
                            }
                            case "update-2fa" : {
                                if(!request.has("token") || !request.has("2fa")){
                                    String error = "Missing fields";
                                    error+="\ntoken: " + request.has("token");
                                    error+="\n2fa: " + request.has("2fa");
                                    response = getMalformedRequestObject(error);
                                    break;
                                }
                                String token = request.getString("token");
                                boolean has2fa = request.getBoolean("2fa");
                                AuthServer.set2fa(AuthServer.tokenInfo(token).getString("username"),has2fa);
                                response = new JSONObject();
                                response.put("header","response");
                                response.put("code",200);
                                response.put("value","OK");
                            }
                            default : {
                                response = new JSONObject();
                                response.put("header","response");
                                response.put("code",404);
                                response.put("value","Method not found.");
                            }
                        }
                    } else {
                        response = new JSONObject();
                        response.put("header","response");
                        response.put("code",404);
                        response.put("value","Request type not found.");
                    }
                }catch (JSONException e) {
                    response = new JSONObject();
                    response.put("header","response");
                    response.put("code",400);
                    response.put("value","Malformed request.");
                    response.put("error", e.getMessage());
                    e.printStackTrace();
                } catch (Exception e){
                    response = new JSONObject();
                    response.put("header","response");
                    response.put("code",400);
                    response.put("value","An error occurred.");
                    response.put("error", "An internal unexpected Exception occured: \n" + exceptionStackTraceToString(e));
                    e.printStackTrace();
                }
                Logger.log("Sending response: " + response.toString(3));
                if(sessionKeys.containsKey(webSocket.getRemoteSocketAddress().toString())) RSAUtil.sendMessageSecure(webSocket,response.toString(),sessionKeys.get(webSocket.getRemoteSocketAddress().toString()));
                else webSocket.send(response.toString());
            }
        });
        t.start();
    }

    @Override
    public void onError(WebSocket webSocket, Exception e) {
        e.printStackTrace();
    }

    @Override
    public void onStart() {
        Logger.log("Server started");
    }

    public static String exceptionStackTraceToString(Exception e){
        String ex = "";
        for (StackTraceElement element : e.getStackTrace()) {
            Logger.log(element.toString());
            ex+=element.toString()+"\n";
        }
        return ex;
    }

    public static JSONObject getMalformedRequestObject(String error){
        JSONObject response = new JSONObject();
        response.put("header","response");
        response.put("code",400);
        response.put("value","Malformed request.");
        response.put("error", error);
        return response;
    }
}
