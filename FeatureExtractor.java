import java.util.*;
import java.util.regex.Pattern;

/**
 * Breaks a URL into parts and runs every phishing check on it.
 * Each check returns a Feature (name, flagged or not, risk points, explanation).
 */
public class FeatureExtractor {

    /** One check result. */
    public static class Feature {
        public final String name;
        public final boolean triggered;
        public final int points;          // 0 when not triggered
        public final String description;

        public Feature(String name, boolean triggered, int points, String description) {
            this.name = name;
            this.triggered = triggered;
            this.points = triggered ? points : 0;
            this.description = description;
        }
    }

    /** A URL split into its parts. */
    public static class ParsedUrl {
        public String original = "";
        public String scheme;             // null if user typed no scheme
        public String userInfo;           // text before '@' if present
        public String host = "";
        public int port = -1;
        public String path = "";
        public String query = "";
    }

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");

    private static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
            "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"));

    private static final Set<String> BAD_TLDS = new HashSet<>(Arrays.asList(
            "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "work", "icu", "buzz"));

    private static final String[] KEYWORDS = {
            "login", "signin", "verify", "secure", "account", "update", "confirm",
            "password", "banking", "wallet", "suspend", "unlock", "billing", "otp", "kyc"};

    private static final String[] BRANDS = {
            "paypal", "google", "facebook", "amazon", "apple", "microsoft", "netflix",
            "instagram", "whatsapp", "linkedin", "flipkart", "paytm", "sbi", "hdfc", "icici"};

    private static final Set<String> TRUSTED = new HashSet<>(Arrays.asList(
            "google.com", "youtube.com", "facebook.com", "amazon.com", "amazon.in",
            "microsoft.com", "apple.com", "github.com", "wikipedia.org", "linkedin.com",
            "twitter.com", "x.com", "instagram.com", "netflix.com", "paypal.com",
            "stackoverflow.com", "flipkart.com", "paytm.com", "sbi.co.in",
            "hdfcbank.com", "icicibank.com", "google.co.in"));

    // ---------------------------------------------------------------- parsing

    public static ParsedUrl parse(String raw) {
        ParsedUrl p = new ParsedUrl();
        p.original = raw == null ? "" : raw.trim();
        String s = p.original;

        int i = s.indexOf("://");
        if (i > 0 && s.substring(0, i).matches("[A-Za-z][A-Za-z0-9+.-]*")) {
            p.scheme = s.substring(0, i).toLowerCase();
            s = s.substring(i + 3);
        }

        int end = s.length();
        for (char c : new char[]{'/', '?', '#'}) {
            int k = s.indexOf(c);
            if (k >= 0 && k < end) end = k;
        }
        String authority = s.substring(0, end);
        String rest = s.substring(end);

        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            p.userInfo = authority.substring(0, at);
            authority = authority.substring(at + 1);
        }

        int colon = authority.lastIndexOf(':');
        if (colon >= 0 && authority.substring(colon + 1).matches("\\d{1,5}")) {
            p.port = Integer.parseInt(authority.substring(colon + 1));
            authority = authority.substring(0, colon);
        }
        p.host = authority.toLowerCase();

        int hash = rest.indexOf('#');
        if (hash >= 0) rest = rest.substring(0, hash);
        int q = rest.indexOf('?');
        p.path = q >= 0 ? rest.substring(0, q) : rest;
        p.query = q >= 0 ? rest.substring(q + 1) : "";
        return p;
    }

    public static boolean isIp(String host) {
        return IPV4.matcher(host).matches() || host.startsWith("[");
    }

    /** google.com for mail.google.com, bbc.co.uk for www.bbc.co.uk */
    public static String registeredDomain(String host) {
        String[] l = host.split("\\.");
        if (l.length <= 2) return host;
        String sld = l[l.length - 2], tld = l[l.length - 1];
        boolean cc = tld.length() == 2 && Arrays.asList("co", "com", "org", "net", "gov", "edu", "ac").contains(sld);
        int n = cc ? 3 : 2;
        if (l.length < n) return host;
        return String.join(".", Arrays.copyOfRange(l, l.length - n, l.length));
    }

    // ------------------------------------------------------------- the checks

    public static List<Feature> extract(String raw) {
        ParsedUrl p = parse(raw);
        String full = p.original.toLowerCase();
        String host = p.host;
        boolean ip = isIp(host);
        String reg = ip ? host : registeredDomain(host);
        String[] hostLabels = host.split("\\.");
        String tld = hostLabels.length > 0 ? hostLabels[hostLabels.length - 1] : "";
        List<Feature> f = new ArrayList<>();

        f.add(new Feature("Long URL", p.original.length() > 75, 10,
                "URL is " + p.original.length() + " characters (over 75 is suspicious)"));

        f.add(new Feature("IP address as host", ip, 25,
                "Real sites use domain names, not raw IP addresses"));

        f.add(new Feature("'@' symbol in URL", p.userInfo != null, 15,
                "Text before '@' is ignored by browsers and used to disguise the real host"));

        f.add(new Feature("No HTTPS", p.scheme != null && !p.scheme.equals("https"), 10,
                "Connection is not encrypted (scheme: " + p.scheme + ")"));

        int subs = ip ? 0 : hostLabels.length - reg.split("\\.").length;
        f.add(new Feature("Many subdomains", subs >= 3, 10,
                subs + " subdomain level(s); attackers stack them to hide the real domain"));

        int hyphens = host.length() - host.replace("-", "").length();
        f.add(new Feature("Hyphens in domain", hyphens >= 2, 8,
                hyphens + " hyphen(s) in the host name"));

        List<String> found = new ArrayList<>();
        for (String k : KEYWORDS) if (full.replaceFirst("^[a-z]+://", "").contains(k)) found.add(k);
        f.add(new Feature("Suspicious keywords", !found.isEmpty(), Math.min(15, 5 * found.size()),
                found.isEmpty() ? "No sensitive keywords" : "Found: " + found));

        f.add(new Feature("URL shortener", SHORTENERS.contains(reg), 15,
                "Shortened links hide the real destination"));

        f.add(new Feature("Risky TLD", !ip && BAD_TLDS.contains(tld), 12,
                "." + tld + " domains are frequently used for throw-away phishing sites"));

        f.add(new Feature("Double slash in path", p.path.contains("//"), 8,
                "'//' inside the path can be a redirect trick"));

        f.add(new Feature("Punycode (xn--)", host.contains("xn--"), 15,
                "Possible look-alike (homograph) domain using foreign characters"));

        f.add(new Feature("Non-standard port", p.port != -1 && p.port != 80 && p.port != 443, 8,
                "Port " + p.port + " is unusual for a public website"));

        int digits = 0;
        for (char c : host.toCharArray()) if (Character.isDigit(c)) digits++;
        f.add(new Feature("Many digits in host", !ip && digits >= 4, 6,
                digits + " digit(s) in the host name"));

        int pct = p.original.length() - p.original.replace("%", "").length();
        f.add(new Feature("Heavy URL encoding", pct >= 3, 5,
                pct + " percent-encoded characters"));

        String regLabel = reg.split("\\.")[0];
        String[] tokens = host.split("[.\\-]");
        String hit = null;
        if (!ip) {
            for (String b : BRANDS) {
                boolean inHost = Arrays.asList(tokens).contains(b) || (b.length() >= 6 && host.contains(b));
                if (inHost && !regLabel.equals(b)) { hit = b; break; }
            }
        }
        f.add(new Feature("Brand impersonation", hit != null, 20,
                hit == null ? "No famous brand misused in the host"
                        : "'" + hit + "' appears in the host but the real domain is " + reg));

        if (!ip && TRUSTED.contains(reg)) {
            f.add(new Feature("Trusted domain", true, -100,
                    reg + " is on the built-in trusted list"));
        }
        return f;
    }
}
