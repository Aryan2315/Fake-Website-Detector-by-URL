import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Adds up the feature points and decides SAFE / SUSPICIOUS / PHISHING. */
public class PhisingDetector {

    public static class ScanResult {
        public final String url;
        public final int score;          // 0 - 100
        public final String verdict;     // SAFE, SUSPICIOUS or PHISHING
        public final String time;
        public final List<FeatureExtractor.Feature> features;

        public ScanResult(String url, int score, String verdict, List<FeatureExtractor.Feature> features) {
            this.url = url;
            this.score = score;
            this.verdict = verdict;
            this.features = features;
            this.time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        }
    }

    public static ScanResult analyze(String rawUrl) {
        List<FeatureExtractor.Feature> features = FeatureExtractor.extract(rawUrl);
        int total = 0;
        for (FeatureExtractor.Feature f : features) total += f.points;
        total = Math.max(0, Math.min(100, total));

        String verdict = total >= 60 ? "PHISHING" : total >= 30 ? "SUSPICIOUS" : "SAFE";
        return new ScanResult(rawUrl.trim(), total, verdict, features);
    }

    /** Quick sanity check before scanning. */
    public static boolean looksLikeUrl(String s) {
        if (s == null) return false;
        s = s.trim();
        return !s.isEmpty() && !s.contains(" ") && (s.contains(".") || s.contains("localhost"));
    }

    public static String advice(String verdict) {
        switch (verdict) {
            case "PHISHING":
                return "Do NOT open this link or enter any personal data. Report it to your IT team or the impersonated company.";
            case "SUSPICIOUS":
                return "Be careful. Do not enter passwords or payment details until you verify the site through its official app or website.";
            default:
                return "No strong phishing signs found. Still, always check the address bar before logging in.";
        }
    }
}
