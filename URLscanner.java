import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

public class URLscanner {

    private final FeatureExtractor extractor = new FeatureExtractor();
    private final PhisingDetector detector = new PhisingDetector();

    public PhisingDetector.ScanResult scanUrl(String userEmail, String url) {
        // 1. Extract URL features
        Map<String, Object> features = extractor.extractFeatures(url);

        // 2. Analyze against dataset_phishing.csv + heuristics
        PhisingDetector.ScanResult result = detector.analyze(url, features);

        // 3. Log scan to SQLite database
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        ScanHistory history = new ScanHistory(0, userEmail, url, result.getStatus(), result.getRiskScore(), timestamp);
        DataBaseConnection.saveScan(history);

        return result;
    }
}