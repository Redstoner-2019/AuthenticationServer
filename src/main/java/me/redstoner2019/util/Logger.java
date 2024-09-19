package me.redstoner2019.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss:SSS");

    /**
     * Writes a message to the console with a timestamp.
     *
     * @param message The message to be logged.
     */
    public static void log(String message) {
        LocalDateTime timestamp = LocalDateTime.now();
        String formattedTimestamp = timestamp.format(formatter);
        System.out.println("[" + formattedTimestamp + "] " + message);
    }

    public static void err(String message) {
        LocalDateTime timestamp = LocalDateTime.now();
        String formattedTimestamp = timestamp.format(formatter);
        System.err.println("[" + formattedTimestamp + "] " + message);
    }
}
