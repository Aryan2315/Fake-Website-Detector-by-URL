import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FeatureExtractor {

    private static final String[] SHORTENING_SERVICES = {
        "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do"
    };

    private static final String[] SUSPICIOUS_KEYWORDS = {
        "login", "verify", "update", "account", "banking", "secure", "signin", "confirm", "password", "ebayisapi"
    };

    public Map<String, Object> extractFeatures(String urlString) {
        Map<String, Object> features = new HashMap<>();

        try {
            URI uri = URI.create(urlString.contains("://") ? urlString : "https://" + urlString);
            String hostName = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
            String fullUrl = urlString.toLowerCase();

            features.put("url_length", fullUrl.length());
            features.put("hostname_length", hostName.length());
            features.put("has_ip", isIpAddress(hostName) ? 1 : 0);
            features.put("nb_dots", countChar(fullUrl, '.'));
            features.put("nb_hyphens", countChar(fullUrl, '-'));
            features.put("nb_at", countChar(fullUrl, '@'));
            features.put("nb_qm", countChar(fullUrl, '?'));
            features.put("nb_eq", countChar(fullUrl, '='));
            features.put("nb_slash", countChar(fullUrl, '/'));
            features.put("nb_underscore", countChar(fullUrl, '_'));
            features.put("https_token", fullUrl.startsWith("https") ? 1 : 0);

            boolean isShortened = false;
            for (String service : SHORTENING_SERVICES) {
                if (hostName.contains(service)) {
                    isShortened = true;
                    break;
                }
            }
            features.put("shortening_service", isShortened ? 1 : 0);

            int suspiciousKeywordCount = 0;
            for (String keyword : SUSPICIOUS_KEYWORDS) {
                if (fullUrl.contains(keyword)) {
                    suspiciousKeywordCount++;
                }
            }
            features.put("suspicious_keywords_count", suspiciousKeywordCount);

        } catch (Exception e) {
            features.put("url_length", urlString.length());
            features.put("hostname_length", 0);
            features.put("has_ip", 0);
            features.put("nb_dots", countChar(urlString, '.'));
            features.put("nb_hyphens", 0);
            features.put("nb_at", 0);
            features.put("nb_qm", 0);
            features.put("nb_eq", 0);
            features.put("nb_slash", 0);
            features.put("nb_underscore", 0);
            features.put("https_token", 0);
            features.put("shortening_service", 0);
            features.put("suspicious_keywords_count", 0);
        }

        return features;
    }

    private boolean isIpAddress(String host) {
        String ipPattern = "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$";
        Pattern pattern = Pattern.compile(ipPattern);
        Matcher matcher = pattern.matcher(host);
        return matcher.matches();
    }

    private int countChar(String text, char c) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == c) {
                count++;
            }
        }
        return count;
    }
}