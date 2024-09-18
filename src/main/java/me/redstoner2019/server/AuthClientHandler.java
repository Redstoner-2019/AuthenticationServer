package me.redstoner2019.server;

import org.json.JSONObject;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class AuthClientHandler {
    private Socket socket;
    private ObjectOutputStream oos;
    private ObjectInputStream ois;
    public AuthClientHandler(Socket socket){
        try {
            this.socket = socket;
            this.oos = new ObjectOutputStream(socket.getOutputStream());
            this.ois = new ObjectInputStream(socket.getInputStream());
            start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    private void start(){
        while (!socket.isClosed()){
            try {
                JSONObject o = new JSONObject((String) ois.readObject());
                System.out.println(o.toString());
                if(o.has("header")){
                    switch (o.getString("header")){
                        case "create-account": {
                            String username = o.getString("username");
                            String displayname = o.getString("displayname");
                            String password = o.getString("password");
                            String email = o.getString("email");
                            sendJSON(AuthServer.createAccount(username,displayname,password,email,true));
                            break;
                        }
                        case "login": {
                            String username = o.getString("username");
                            String password = o.getString("password");
                            new Thread(new Runnable() {
                                @Override
                                public void run() {
                                    sendJSON(AuthServer.accountLogin(username,password,false));
                                }
                            }).start();
                            break;
                        }
                        case "token-info": {
                            String token = o.getString("token");
                            sendJSON(AuthServer.tokenInfo(token));
                            break;
                        }
                        case "update-password": {
                            String token = o.getString("token");
                            String newPassword = o.getString("password");
                            sendJSON(AuthServer.tokenInfo(token));
                            break;
                        }
                        case "update-displayname": {
                            String token = o.getString("token");
                            String newDisplayname = o.getString("displayname");
                            sendJSON(AuthServer.tokenInfo(token));
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Client disconnected");
                return;
            }
        }
    }
    private void sendJSON(JSONObject o){
        try {
            oos.writeObject(o.toString());
            oos.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
