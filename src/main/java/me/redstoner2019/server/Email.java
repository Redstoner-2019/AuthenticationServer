package me.redstoner2019.server;

import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.Properties;

public class Email {

    public static void main(String[] args) {
        init();
        System.out.println("init done");
        sendCreateEmail("lukaspaepke2020gmail.com","1561531","redstoner-2019","Redstoner 2019");
    }

    final static String username = "sup.discordmot@gmail.com";
    final static String password = "fogx eszz zrdk gojt";
    static Properties props = new Properties();
    static Session session;

    public static void init(){
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");

        session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
    }

    public static void sendCreateEmail(String to, String code, String user, String displayname){
        try {
            // Create a default MimeMessage object
            Message message = new MimeMessage(session);
            // Set From: header field
            message.setFrom(new InternetAddress(username));
            // Set To: header field
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            // Set Subject: header field
            message.setSubject("Welcome to Discord mot!");
            // Set the actual message
            message.setText("Hello " + displayname + "!\n\n" +
                    "Welcome to Discord mot!\n\n" +
                    "Please enter the following code on the website to activate your account.\n\n" +
                    "```" + code + "```\n\n" +
                    "The code will expire in 15 Minutes.\n\n" +
                    "Have a nice day!");
            // Send message
            System.out.println("Sending email...");
            Transport.send(message);
            System.out.println("Email sent successfully!");
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public static void send2faEmail(String to, String code){
        try {
            // Create a default MimeMessage object
            Message message = new MimeMessage(session);
            // Set From: header field
            message.setFrom(new InternetAddress(username));
            // Set To: header field
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            // Set Subject: header field
            message.setSubject("Confirmation Email");
            // Set the actual message
            message.setText("A login into your Discord mot account has been detected.\n\nConfirmation-Code: " + code + "\n\nThis code expires in 15 Minutes.");
            // Send message
            Transport.send(message);
            System.out.println("Email sent successfully!");
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}
