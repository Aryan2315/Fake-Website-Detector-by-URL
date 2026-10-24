import java.time.LocalDateTime;

public class ScanHistory {
    private int id;
    private String userEmail;
    private String url;
    private String status;
    private int riskScore;
    private String scanTime;

    public ScanHistory(String userEmail, String url, String status, int riskScore) {
        this.userEmail = userEmail;
        this.url = url;
        this.status = status;
        this.riskScore = riskScore;
        this.scanTime = LocalDateTime.now().toString();
    }

    public ScanHistory(int id, String userEmail, String url, String status, int riskScore, String scanTime) {
        this.id = id;
        this.userEmail = userEmail;
        this.url = url;
        this.status = status;
        this.riskScore = riskScore;
        this.scanTime = scanTime;
    }

    public int getId() { return id; }
    public String getUserEmail() { return userEmail; }
    public String getUrl() { return url; }
    public String getStatus() { return status; }
    public int getRiskScore() { return riskScore; }
    public String getScanTime() { return scanTime; }

    @Override
    public String toString() {
        return String.format("[%s] URL: %s | Status: %s (Risk: %d%%) | Time: %s", 
                userEmail, url, status, riskScore, scanTime);
    }
}