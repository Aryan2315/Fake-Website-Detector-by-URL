public class ReportGenerator {

    public static String generateTextReport(String userEmail, String url, PhisingDetector.ScanResult result) {
        StringBuilder report = new StringBuilder();
        report.append("========================================\n");
        report.append("      FAKE WEBSITE SCAN REPORT          \n");
        report.append("========================================\n");
        report.append("Scanned By : ").append(userEmail).append("\n");
        report.append("Target URL : ").append(url).append("\n");
        report.append("Verdict    : ").append(result.getStatus()).append("\n");
        report.append("Risk Score : ").append(result.getRiskScore()).append("%\n");
        report.append("----------------------------------------\n");
        report.append("Analysis Details:\n");
        report.append(result.getDetails());
        report.append("========================================\n");
        return report.toString();
    }

    public static String generateHtmlReport(String userEmail, String url, PhisingDetector.ScanResult result) {
        String badgeColor = result.getStatus().equalsIgnoreCase("Phishing") ? "#dc3545" :
                            result.getStatus().equalsIgnoreCase("Suspicious") ? "#ffc107" : "#28a745";

        return "<div style='font-family: Arial; padding: 20px; background: #f8f9fa; border-radius: 8px;'>" +
               "<h2 style='color: #141e30;'>Fake Website Scan Report</h2>" +
               "<p><b>Scanned By:</b> " + userEmail + "</p>" +
               "<p><b>URL:</b> " + url + "</p>" +
               "<p><b>Verdict:</b> <span style='background: " + badgeColor + "; color: white; padding: 4px 10px; border-radius: 4px;'>" + result.getStatus() + "</span></p>" +
               "<p><b>Risk Score:</b> " + result.getRiskScore() + "%</p>" +
               "<h3>Analysis Details:</h3>" +
               "<pre style='background: white; padding: 10px; border: 1px solid #ddd;'>" + result.getDetails() + "</pre>" +
               "</div>";
    }
}