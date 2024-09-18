package me.redstoner2019.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.mail.SendFailedException;
import me.redstoner2019.util.Token;
import org.java_websocket.server.WebSocketServer;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;
import java.util.UUID;

import static me.redstoner2019.server.WebServer.exceptionStackTraceToString;

public class AuthServer {
    private static File userData = new File("userdata.json");
    private static JSONObject data = new JSONObject();
    public static HashMap<String, TwoFactor> twoFactors = new HashMap<>();
    public static void main(String[] args) {
        Email.init();
        Thread webServer = new Thread(new Runnable() {
            @Override
            public void run() {
                try{
                    System.out.println("Starting web server");
                    WebSocketServer server = new WebServer(new InetSocketAddress(8010));
                    System.out.println("Web server created");
                    server.start();
                    System.out.println("Web server started");
                    Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                server.stop();
                            } catch (InterruptedException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }));
                    Scanner scanner = new Scanner(System.in);
                    while (true) {
                        String in = scanner.next();
                        if(in.equals("exit")){
                            server.stop();
                            System.out.println("Exited");
                        }
                    }
                }catch (Exception e){
                    System.out.println("An error occurred while starting web server");
                    e.printStackTrace();
                }
            }
        });
        webServer.start();

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

    public static void deleteAccount(String username){
        reloadConfig();

        String email = data.getJSONObject(username).getString("email");
        data.remove(username);

        data.put("email",data.getJSONObject("email").remove(email));

        saveConfig();
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
                if(data.getJSONObject(username).has("uuid")) result.put("uuid",data.getJSONObject(username).getString("uuid"));
                result.put("displayname",data.getJSONObject(username).getString("displayname"));
                result.put("2fa",has2fa(username));
            }
        }
        return result;
    }

    public static JSONObject accountLogin(String username, String password, boolean twoaOverride){
        reloadConfig();

        if(!data.has("emails")){
            data.put("emails",new JSONObject());
        }

        if(data.getJSONObject("emails").has(username)){
            username = data.getJSONObject("emails").getString(username);
        }

        String email = getEmail(username);

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

        if(has2fa(username) && !twoaOverride && email != null){
            JSONObject result = new JSONObject();
            String id = UUID.randomUUID().toString();
            result.put("header","login-result");
            result.put("data","2fa-required");
            result.put("2fa-id",id);

            String code = "";
            String codeChars = "01234567489";
            Random r = new Random();

            for (int i = 0; i < 3; i++) {
                code+=codeChars.charAt(r.nextInt(codeChars.length()));
            }

            code+="-";

            for (int i = 0; i < 3; i++) {
                code+=codeChars.charAt(r.nextInt(codeChars.length()));
            }

            System.out.println("2FA-CODE: " + code);

            try{
                Email.send2faEmail(email,code);
                twoFactors.put(id, new TwoFactor(username, code, System.currentTimeMillis() + 1000 * 60 * 15));
            } catch (Exception e){
                result = new JSONObject();
                result.put("header","error");
                result.put("code",501);
                result.put("error", "An internal unexpected Exception occured: \n" + exceptionStackTraceToString(e));
                e.printStackTrace();
            }
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

    public static JSONObject createAccount(String username, String displayname, String password, String email, boolean towaOverride){
        reloadConfig();

        if(!data.has("emails")){
            data.put("emails",new JSONObject());
        }

        if(data.getJSONObject("emails").has(email)){
            JSONObject result = new JSONObject();
            result.put("header","create-account-result");
            result.put("data","email-already-exists");
            return result;
        }

        if(accountExists(username)){
            JSONObject result = new JSONObject();
            result.put("header","create-account-result");
            result.put("data","account-already-exists");
            return result;
        }

        if(username.length() < 3){
            JSONObject result = new JSONObject();
            result.put("header","create-account-result");
            result.put("data","account-username-too-short");
            return result;
        }

        if(username.length() > 32){
            JSONObject result = new JSONObject();
            result.put("header","create-account-result");
            result.put("data","account-username-too-long");
            return result;
        }

        if(!towaOverride){
            JSONObject result = new JSONObject();
            String id = UUID.randomUUID().toString();
            result.put("header","create-account-result");
            result.put("data","2fa-required");
            result.put("2fa-id",id);

            String code = "";
            String codeChars = "01234567489";
            Random r = new Random();

            for (int i = 0; i < 3; i++) {
                code+=codeChars.charAt(r.nextInt(codeChars.length()));
            }

            code+="-";

            for (int i = 0; i < 3; i++) {
                code+=codeChars.charAt(r.nextInt(codeChars.length()));
            }

            System.out.println("2FA-CODE: " + code);

            try{
                Email.sendCreateEmail(email,code,username,displayname);
                twoFactors.put(id, new TwoFactor(username, code, System.currentTimeMillis() + 1000 * 60 * 15));
            } catch (Exception e){
                if(e.getMessage().equals("Invalid Addresses")){
                    result = new JSONObject();
                    result.put("header","error");
                    result.put("code",400);
                    result.put("error", "Email invalid or doesnt exist");
                } else {
                    result = new JSONObject();
                    result.put("header","error");
                    result.put("code",501);
                    result.put("error", "An internal unexpected Exception occured: \n" + exceptionStackTraceToString(e));
                    e.printStackTrace();
                }
            }
            return result;
        }

        JSONObject user = new JSONObject();
        user.put("displayname",displayname);
        user.put("password",password);
        user.put("creation-time",System.currentTimeMillis());
        user.put("uuid", UUID.randomUUID());
        user.put("email",email);
        user.put("2fa",false);
        data.put(username,user);

        JSONObject emails = data.getJSONObject("emails");
        emails.put(email,username);
        data.put("emails",emails);

        JSONObject loginResult = accountLogin(username,password,true);


        saveConfig();
        JSONObject result = new JSONObject();
        result.put("header","create-account-result");
        result.put("data","account-created");
        result.put("token",loginResult.getString("token"));
        return result;
    }

    public static boolean accountExists(String username){
        reloadConfig();
        return data.has(username);
    }

    public static boolean has2fa(String username){
        reloadConfig();
        if(accountExists(username)){
            if(data.getJSONObject(username).has("2fa")){
                return data.getJSONObject(username).getBoolean("2fa");
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    public static String getEmail(String username){
        if(accountExists(username)){
            if(data.getJSONObject(username).has("email")){
                return data.getJSONObject(username).getString("email");
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    public static void set2fa(String username, boolean isEnabled){
        if(accountExists(username)){
            data.put(username,data.getJSONObject(username).put("2fa",isEnabled));
        }
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
