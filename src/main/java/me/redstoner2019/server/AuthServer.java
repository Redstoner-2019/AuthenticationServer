package me.redstoner2019.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.redstoner2019.util.Token;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Files;

public class AuthServer {
    private static File userData = new File("userdata.json");
    private static JSONObject data = new JSONObject();
    public static void main(String[] args) {
        if(!userData.exists()){
            try {
                userData.createNewFile();
                writeStringToFile("{}",userData);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        reloadConfig();
        try {
            ServerSocket serverSocket = new ServerSocket(8009);
            System.out.println("Auth server started");
            while (!serverSocket.isClosed()){
                Socket socket = serverSocket.accept();
                System.out.println("Connection");
                Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        AuthClientHandler ach = new AuthClientHandler(socket);
                    }
                });
                t.start();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static JSONObject tokenInfo(String token){
        JSONObject result = new JSONObject();
        result.put("header","token-info-result");
        result.put("data","token-not-found");
        if(data.has("tokens")){
            JSONObject tokens = data.getJSONObject("tokens");
            if(tokens.has(token)){
                String username = data.getJSONObject("tokens").getString(token);
                result.put("data","success");
                result.put("username",username);
                result.put("displayname",data.getJSONObject(username).getString("displayname"));
            }
        }
        return result;
    }

    public static JSONObject accountLogin(String username, String password){
        reloadConfig();

        if(!accountExists(username)){
            JSONObject result = new JSONObject();
            result.put("header","login-result");
            result.put("data","account-doesnt-exist");
            return result;
        }

        JSONObject user = data.getJSONObject(username);

        if(!user.getString("password").equals(password)){
            JSONObject result = new JSONObject();
            result.put("header","login-result");
            result.put("data","incorrect-password");
            return result;
        }

        JSONObject tokens;
        if(data.has("tokens")){
            tokens = data.getJSONObject("tokens");
        } else {
            tokens = new JSONObject();
        }

        String token = Token.createToken(username,password);

        tokens.put(token,username);

        data.put("tokens",tokens);

        saveConfig();
        JSONObject result = new JSONObject();
        result.put("header","login-result");
        result.put("data","login-success");
        result.put("token",token);
        return result;
    }

    public static JSONObject createAccount(String username, String displayname, String password){
        reloadConfig();

        if(accountExists(username)){
            JSONObject result = new JSONObject();
            result.put("header","create-account-result");
            result.put("data","account-already-exists");
            return result;
        }

        JSONObject user = new JSONObject();
        user.put("displayname",displayname);
        user.put("password",password);
        user.put("creation-time",System.currentTimeMillis());
        data.put(username,user);


        saveConfig();
        JSONObject result = new JSONObject();
        result.put("header","create-account-result");
        result.put("data","account-created");
        return result;
    }

    public static boolean accountExists(String username){
        reloadConfig();
        return data.has(username);
    }

    public static void saveConfig(){
        try {
            writeStringToFile(prettyJSON(data.toString()),userData);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void reloadConfig(){
        try {
            data = new JSONObject(readFile(userData));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String prettyJSON(String uglyJsonString) {
        try{
            ObjectMapper objectMapper = new ObjectMapper();
            Object jsonObject = objectMapper.readValue(uglyJsonString, Object.class);
            String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
            return prettyJson;
        }catch (Exception e){
            return null;
        }
    }
    public static void writeStringToFile(String str, File file) throws IOException {
        FileOutputStream outputStream = new FileOutputStream(file);
        byte[] strToBytes = str.getBytes();
        outputStream.write(strToBytes);

        outputStream.close();
    }
    public static String readFile(File path) throws IOException {
        byte[] encoded = Files.readAllBytes(path.toPath());
        return new String(encoded, Charset.defaultCharset());
    }
}
