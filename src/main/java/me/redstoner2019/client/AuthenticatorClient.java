package me.redstoner2019.client;

import org.json.JSONObject;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class AuthenticatorClient {
    private String address;
    private int port;
    private ObjectInputStream ois;
    private ObjectOutputStream oos;

    public AuthenticatorClient(){
        this("localhost",8009);
    }

    public AuthenticatorClient(String address, int port) {
        this.address = address;
        this.port = port;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setup(){
        try {
            Socket socket = new Socket(address,port);
            ois = new ObjectInputStream(socket.getInputStream());
            oos = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public JSONObject createAccount(String username, String displayname, String password){
        try {
            JSONObject o = new JSONObject();
            o.put("header","create-account");
            o.put("username",username);
            o.put("displayname",displayname);
            o.put("password",password);
            oos.writeObject(o.toString());
            return new JSONObject((String) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    public JSONObject loginAccount(String username, String password){
        try {
            JSONObject o = new JSONObject();
            o.put("header","login");
            o.put("username",username);
            o.put("password",password);
            oos.writeObject(o.toString());
            return new JSONObject((String) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    public JSONObject tokeninfo(String token){
        try {
            JSONObject o = new JSONObject();
            o.put("header","token-info");
            o.put("token",token);
            oos.writeObject(o.toString());
            return new JSONObject((String) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    public JSONObject updatePassword(String token, String newPassword){
        try {
            JSONObject o = new JSONObject();
            o.put("header","update-password");
            o.put("token",token);
            o.put("password",newPassword);
            oos.writeObject(o.toString());
            return new JSONObject((String) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    public JSONObject updateDisplayname(String token, String newDisplayname){
        try {
            JSONObject o = new JSONObject();
            o.put("header","update-displayname");
            o.put("token",token);
            o.put("displayname",newDisplayname);
            oos.writeObject(o.toString());
            return new JSONObject((String) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        AuthenticatorClient client = new AuthenticatorClient();
        client.setup();
        JSONObject accountResult = client.createAccount("lukas","Lukas","test");
        JSONObject loginResult = client.loginAccount("lukas","test");
        JSONObject tokenInfo = client.tokeninfo(loginResult.getString("token"));

        System.out.println(accountResult.toString());
        System.out.println(loginResult.toString());
        System.out.println(tokenInfo.toString());
    }
}
