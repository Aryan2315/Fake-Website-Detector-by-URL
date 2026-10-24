import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure-Java storage (no drivers needed).
 *   users.txt         ->  email|name|salt|sha256(salt+password)
 *   scan_history.tsv  ->  email \t time \t score \t verdict \t url
 */
public class DataBaseConnection {

    private static final Path USERS = Paths.get("users.txt");
    private static final Path HISTORY = Paths.get("scan_history.tsv");
    private static final Object LOCK = new Object();

    // ------------------------------------------------------------------ users

    public static boolean userExists(String email) {
        return findUser(email) != null;
    }

    public static boolean registerUser(String name, String email, String password) {
        synchronized (LOCK) {
            email = email.trim().toLowerCase();
            if (findUser(email) != null) return false;
            String salt = randomSalt();
            String line = email + "|" + name.replace("|", " ").trim() + "|" + salt + "|" + hash(salt, password);
            try {
                Files.write(USERS, (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                return true;
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    /** Returns the user's name when the login is correct, otherwise null. */
    public static String login(String email, String password) {
        String[] u = findUser(email);
        if (u == null) return null;
        boolean ok = MessageDigest.isEqual(
                hash(u[2], password).getBytes(StandardCharsets.UTF_8),
                u[3].getBytes(StandardCharsets.UTF_8));
        return ok ? u[1] : null;
    }

    public static String getName(String email) {
        String[] u = findUser(email);
        return u == null ? "" : u[1];
    }

    private static String[] findUser(String email) {
        synchronized (LOCK) {
            if (!Files.exists(USERS)) return null;
            email = email.trim().toLowerCase();
            try {
                for (String line : Files.readAllLines(USERS, StandardCharsets.UTF_8)) {
                    String[] p = line.split("\\|", 4);
                    if (p.length == 4 && p[0].equals(email)) return p;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private static String randomSalt() {
        byte[] b = new byte[8];
        new SecureRandom().nextBytes(b);
        return toHex(b);
    }

    private static String hash(String salt, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return toHex(md.digest((salt + password).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ---------------------------------------------------------------- history

    public static void addHistory(ScanHistory h) {
        synchronized (LOCK) {
            String line = h.email + "\t" + h.time + "\t" + h.score + "\t" + h.verdict + "\t"
                    + h.url.replaceAll("[\\t\\r\\n]", " ");
            try {
                Files.write(HISTORY, (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static List<ScanHistory> loadHistory(String email) {
        synchronized (LOCK) {
            List<ScanHistory> out = new ArrayList<>();
            if (!Files.exists(HISTORY)) return out;
            email = email.trim().toLowerCase();
            try {
                for (String line : Files.readAllLines(HISTORY, StandardCharsets.UTF_8)) {
                    String[] p = line.split("\t", 5);
                    if (p.length == 5 && p[0].equals(email)) {
                        out.add(new ScanHistory(p[0], p[1], p[4], Integer.parseInt(p[2]), p[3]));
                    }
                }
            } catch (IOException | NumberFormatException e) {
                e.printStackTrace();
            }
            return out;
        }
    }

    public static void clearHistory(String email) {
        synchronized (LOCK) {
            if (!Files.exists(HISTORY)) return;
            email = email.trim().toLowerCase();
            try {
                List<String> keep = new ArrayList<>();
                for (String line : Files.readAllLines(HISTORY, StandardCharsets.UTF_8)) {
                    if (!line.startsWith(email + "\t")) keep.add(line);
                }
                Files.write(HISTORY, keep, StandardCharsets.UTF_8);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
