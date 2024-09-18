package me.redstoner2019.server;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.InetSocketAddress;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;

public class WebServer extends WebSocketServer {
    public static HashMap<String, PrivateKey> privateKeys = new HashMap<>();
    public static HashMap<String, PublicKey> publicKeys = new HashMap<>();

    public WebServer(InetSocketAddress inetSocketAddress) {
        super(inetSocketAddress);
    }

    public static PrivateKey getPrivateKey(InetSocketAddress inetSocketAddress) {
        return privateKeys.get(inetSocketAddress.toString());
    }

    public static PublicKey getPublicKey(InetSocketAddress inetSocketAddress) {
        return publicKeys.get(inetSocketAddress.toString());
    }

    public static String getPublicKeyString(InetSocketAddress inetSocketAddress) {
        return Base64.getEncoder().encodeToString(getPublicKey(inetSocketAddress).getEncoded());
    }

    @Override
    public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
        System.out.println(webSocket.getRemoteSocketAddress() + " connected");
        try {
            KeyPair keyPair = Encryption.generateRSAKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            privateKeys.put(webSocket.getRemoteSocketAddress().toString(), privateKey);
            publicKeys.put(webSocket.getRemoteSocketAddress().toString(), publicKey);

            webSocket.send(publicKey.toString());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onClose(WebSocket webSocket, int i, String s, boolean b) {
        System.out.println(webSocket.getRemoteSocketAddress() + " disconnected");
    }

    @Override
    public void onMessage(WebSocket webSocket, String s) {
        System.out.println(s);
        if(true){
            return;
        }
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                System.out.println(webSocket.getRemoteSocketAddress() + " received message: " + s);
                JSONObject response;
                try{
                    JSONObject request = new JSONObject(s);
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
                System.out.println("Sending response: " + response.toString(3));
                webSocket.send(response.toString());
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
        System.out.println("Server started");
    }

    public static String exceptionStackTraceToString(Exception e){
        String ex = "";
        for (StackTraceElement element : e.getStackTrace()) {
            System.out.println(element);
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
