import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class PhisingDetector {

    public static final String DATASET_FILE = "dataset_phishing.csv";
    private static final Map<String, String> DATASET_CACHE = new HashMap<>();
    private static boolean isDatasetLoaded = false;

    static {
        loadDataset();
    }

    public static class ScanResult {
        private final String status; // "Legitimate", "Suspicious", or "Phishing"
        private final int riskScore; // 0 to 100
        private final String details;

        public ScanResult(String status, int riskScore, String details) {
            this.status = status;
            this.riskScore = riskScore;
            this.details = details;
        }

        public String getStatus() { return status; }
        public int getRiskScore() { return riskScore; }
        public String getDetails() { return details; }
    }

    // Loads dataset_phishing.csv into memory
    public static synchronized void loadDataset() {
        if (isDatasetLoaded) return;

        File file = new File(DATASET_FILE);
        if (!file.exists()) {
            System.err.println("Dataset file not found: " + DATASET_FILE);
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            boolean isFirstLine = true;

            while ((line = br.readLine()) != null) {
                line = line.trim();
                // Skip empty lines or accidental Dockerfile instructions
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("FROM ") || line.startsWith("WORKDIR ") || line.startsWith("COPY ") || line.startsWith("RUN ") || line.startsWith("CMD ")) {
                    continue;
                }

                // Skip CSV header row
                if (isFirstLine && line.toLowerCase().startsWith("url,")) {
                    isFirstLine = false;
                    continue;
                }
                isFirstLine = false;

                String[] parts = line.split(",");
                if (parts.length >= 2) {
                    String rawUrl = parts[0].trim();
                    String rawStatus = parts[parts.length - 1].trim().toLowerCase(); // Reads status from the last column

                    String normalized = normalizeUrl(rawUrl);
                    if (!normalized.isEmpty()) {
                        DATASET_CACHE.put(normalized, rawStatus);
                    }
                }
            }
            isDatasetLoaded = true;
            System.out.println("Loaded " + DATASET_CACHE.size() + " records from " + DATASET_FILE);
        } catch (IOException e) {
            System.err.println("Error loading " + DATASET_FILE + ": " + e.getMessage());
        }
    }

    private static String normalizeUrl(String url) {
        String cleaned = url.trim().toLowerCase();
        if (cleaned.startsWith("https://")) {
            cleaned = cleaned.substring(8);
        } else if (cleaned.startsWith("http://")) {
            cleaned = cleaned.substring(7);
        }
        if (cleaned.startsWith("www.")) {
            cleaned = cleaned.substring(4);
        }
        if (cleaned.endsWith("/")) {
            cleaned = cleaned.substring(0, cleaned.length() - 1);
        }
        return cleaned;
    }

    // Main method that checks both the CSV dataset and URL features
    public ScanResult analyze(String url, Map<String, Object> features) {
        StringBuilder sb = new StringBuilder();
        int score = 0;

        String normalizedInput = normalizeUrl(url);
        String datasetMatch = DATASET_CACHE.get(normalizedInput);

        // Also check if the hostname alone matches an entry in the dataset
        if (datasetMatch == null) {
            try {
                URI uri = URI.create(url.contains("://") ? url : "https://" + url);
                if (uri.getHost() != null) {
                    datasetMatch = DATASET_CACHE.get(normalizeUrl(uri.getHost()));
                }
            } catch (Exception ignored) {}
        }

        if (datasetMatch != null) {
            if (datasetMatch.equals("phishing") || datasetMatch.equals("1") || datasetMatch.equals("bad")) {
                score = 95;
                sb.append("- [DATASET MATCH] URL found in dataset_phishing.csv marked as PHISHING.\n");
            } else if (datasetMatch.equals("legitimate") || datasetMatch.equals("0") || datasetMatch.equals("good")) {
                sb.append("- [DATASET MATCH] URL found in dataset_phishing.csv marked as LEGITIMATE.\n");
                return new ScanResult("Legitimate", 5, sb.toString());
            }
        }

        // Heuristic feature analysis
        int urlLength = (int) features.getOrDefault("url_length", 0);
        int hasIp = (int) features.getOrDefault("has_ip", 0);
        int nbDots = (int) features.getOrDefault("nb_dots", 0);
        int nbHyphens = (int) features.getOrDefault("nb_hyphens", 0);
        int nbAt = (int) features.getOrDefault("nb_at", 0);
        int shorteningService = (int) features.getOrDefault("shortening_service", 0);
        int suspiciousKeywords = (int) features.getOrDefault("suspicious_keywords_count", 0);

        if (urlLength > 75) {
            score += 20;
            sb.append("- URL length is unusually long (>75 characters).\n");
        }
        if (hasIp == 1) {
            score += 35;
            sb.append("- URL uses an IP address instead of a domain name.\n");
        }
        if (nbAt > 0) {
            score += 30;
            sb.append("- URL contains '@' symbol, often used to obscure real destination.\n");
        }
        if (shorteningService == 1) {
            score += 25;
            sb.append("- Uses a known URL shortening service.\n");
        }
        if (suspiciousKeywords > 0) {
            score += (suspiciousKeywords * 15);
            sb.append("- Contains suspicious security/login keywords (Count: ").append(suspiciousKeywords).append(").\n");
        }
        if (nbDots > 4) {
            score += 15;
            sb.append("- High number of subdomain dots.\n");
        }
        if (nbHyphens > 3) {
            score += 10;
            sb.append("- Multiple hyphens in domain/URL structure.\n");
        }

        if (score > 100) {
            score = 100;
        }

        String status;
        if (score >= 60) {
            status = "Phishing";
        } else if (score >= 30) {
            status = "Suspicious";
        } else {
            status = "Legitimate";
            if (sb.length() == 0) {
                sb.append("- No significant phishing indicators detected. URL appears safe.\n");
            }
        }

        return new ScanResult(status, score, sb.toString());
    }

    // Backwards-compatible method in case URLscanner calls analyze(features) without the URL string
    public ScanResult analyze(Map<String, Object> features) {
        return analyze("", features);
    }
}