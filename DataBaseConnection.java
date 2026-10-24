import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DataBaseConnection {
    private static final String DB_URL = "jdbc:sqlite:phishing_detector.db";

    static {
        initializeDatabase();
    }

    public static Connection connect() {
        try {
            Class.forName("org.sqlite.JDBC");
            return DriverManager.getConnection(DB_URL);
        } catch (Exception e) {
            try {
                return DriverManager.getConnection(DB_URL);
            } catch (SQLException ex) {
                System.err.println("Database connection error: " + ex.getMessage());
                return null;
            }
        }
    }

    public static void initializeDatabase() {
        String sql = "CREATE TABLE IF NOT EXISTS scan_history (\n"
                 + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                 + " user_email TEXT NOT NULL,\n"
                 + " url TEXT NOT NULL,\n"
                 + " status TEXT NOT NULL,\n"
                 + " risk_score INTEGER NOT NULL,\n"
                 + " scan_time TEXT NOT NULL\n"
                 + ");";

        try (Connection conn = connect();
             Statement stmt = conn != null ? conn.createStatement() : null) {
            if (stmt != null) {
                stmt.execute(sql);
            }
        } catch (SQLException e) {
            System.err.println("Error initializing database table: " + e.getMessage());
        }
    }

    public static void saveScan(ScanHistory history) {
        String sql = "INSERT INTO scan_history(user_email, url, status, risk_score, scan_time) VALUES(?, ?, ?, ?, ?)";

        try (Connection conn = connect();
             PreparedStatement pstmt = conn != null ? conn.prepareStatement(sql) : null) {
            if (pstmt != null) {
                pstmt.setString(1, history.getUserEmail());
                pstmt.setString(2, history.getUrl());
                pstmt.setString(3, history.getStatus());
                pstmt.setInt(4, history.getRiskScore());
                pstmt.setString(5, history.getScanTime());
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("Error saving scan record: " + e.getMessage());
        }
    }

    public static List<ScanHistory> getHistoryForUser(String email) {
        List<ScanHistory> historyList = new ArrayList<>();
        String sql = "SELECT id, user_email, url, status, risk_score, scan_time FROM scan_history WHERE user_email = ? ORDER BY id DESC";

        try (Connection conn = connect();
             PreparedStatement pstmt = conn != null ? conn.prepareStatement(sql) : null) {
            if (pstmt != null) {
                pstmt.setString(1, email);
                ResultSet rs = pstmt.executeQuery();
                while (rs.next()) {
                    historyList.add(new ScanHistory(
                        rs.getInt("id"),
                        rs.getString("user_email"),
                        rs.getString("url"),
                        rs.getString("status"),
                        rs.getInt("risk_score"),
                        rs.getString("scan_time")
                    ));
                }
            }
        } catch (SQLException e) {
            System.err.println("Error fetching scan history: " + e.getMessage());
        }
        return historyList;
    }
}