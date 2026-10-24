import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** Saves one scan result as a .html or .txt report. */
public class ReportGenerator {

    public static void save(File file, PhisingDetector.ScanResult r, String userEmail) throws IOException {
        boolean html = file.getName().toLowerCase().endsWith(".html");
        String content = html ? toHtml(r, userEmail) : toText(r, userEmail);
        Files.write(file.toPath(), content.getBytes(StandardCharsets.UTF_8));
    }

    public static String toText(PhisingDetector.ScanResult r, String userEmail) {
        StringBuilder sb = new StringBuilder();
        sb.append("FAKE WEBSITE DETECTOR - SCAN REPORT\n");
        sb.append("===================================\n");
        sb.append("Scanned by : ").append(userEmail).append("\n");
        sb.append("Date/time  : ").append(r.time).append("\n");
        sb.append("URL        : ").append(r.url).append("\n");
        sb.append("Risk score : ").append(r.score).append(" / 100\n");
        sb.append("Verdict    : ").append(r.verdict).append("\n\n");
        sb.append("CHECKS\n------\n");
        for (FeatureExtractor.Feature f : r.features) {
            sb.append(String.format("[%-7s] %-24s %+4d  %s%n",
                    f.triggered ? "FLAGGED" : "OK", f.name, f.points, f.description));
        }
        sb.append("\nADVICE\n------\n").append(PhisingDetector.advice(r.verdict)).append("\n");
        return sb.toString();
    }

    public static String toHtml(PhisingDetector.ScanResult r, String userEmail) {
        String color = r.verdict.equals("SAFE") ? "#2ecc71" : r.verdict.equals("SUSPICIOUS") ? "#f39c12" : "#e74c3c";
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Scan Report</title>")
          .append("<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:820px;margin:30px auto;color:#222}")
          .append("h1{margin-bottom:4px}.v{font-size:28px;font-weight:bold;color:").append(color).append("}")
          .append("table{border-collapse:collapse;width:100%;margin-top:14px}")
          .append("th,td{border:1px solid #ccc;padding:8px;text-align:left}th{background:#1e2c44;color:#fff}")
          .append(".f{color:#e74c3c;font-weight:bold}.o{color:#2ecc71;font-weight:bold}</style></head><body>");
        sb.append("<h1>Fake Website Detector - Scan Report</h1>");
        sb.append("<p>Scanned by ").append(esc(userEmail)).append(" on ").append(esc(r.time)).append("</p>");
        sb.append("<p><b>URL:</b> ").append(esc(r.url)).append("</p>");
        sb.append("<p class=\"v\">").append(r.verdict).append(" (risk ").append(r.score).append("/100)</p>");
        sb.append("<table><tr><th>Check</th><th>Status</th><th>Points</th><th>Details</th></tr>");
        for (FeatureExtractor.Feature f : r.features) {
            sb.append("<tr><td>").append(esc(f.name)).append("</td><td class=\"")
              .append(f.triggered ? "f\">FLAGGED" : "o\">OK").append("</td><td>")
              .append(f.points).append("</td><td>").append(esc(f.description)).append("</td></tr>");
        }
        sb.append("</table><h3>Advice</h3><p>").append(esc(PhisingDetector.advice(r.verdict))).append("</p>");
        sb.append("</body></html>");
        return sb.toString();
    }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
