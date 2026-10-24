import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;


public class MLModel {

    public static final String MODEL_FILE = "model.txt";

    public static final String[] NAMES = {
            "url_length", "host_length", "path_length", "query_length", "dots", "hyphens_host",
            "digit_ratio", "digits_host", "slashes", "equals_signs", "ampersands", "at_symbol",
            "percent_signs", "underscores", "is_ip", "uses_https", "subdomains", "keyword_hits",
            "shortener", "risky_tld", "punycode", "odd_port", "brand_impersonation", "trusted_domain"};

    private static double[] w, mean, std;
    private static double bias;
    private static int trainedOn;
    private static int tp, tn, fp, fn;

    private MLModel() {}

    // ---------------------------------------------------------------- status

    public static boolean isTrained() { return w != null; }
    public static int trainedOn() { return trainedOn; }
    public static int tp() { return tp; }
    public static int tn() { return tn; }
    public static int fp() { return fp; }
    public static int fn() { return fn; }

    public static double accuracy() {
        int t = tp + tn + fp + fn;
        return t == 0 ? 0 : (double) (tp + tn) / t;
    }
    public static double precision() { return tp + fp == 0 ? 0 : (double) tp / (tp + fp); }
    public static double recall() { return tp + fn == 0 ? 0 : (double) tp / (tp + fn); }
    public static double f1() {
        double p = precision(), r = recall();
        return p + r == 0 ? 0 : 2 * p * r / (p + r);
    }

    // --------------------------------------------------------------- dataset

    public static class Dataset {
        public final List<String> urls = new ArrayList<>();
        public final List<Integer> labels = new ArrayList<>();   // 1 = phishing, 0 = legitimate
        public int phishing, legit, skipped;
        public String labelColumn = "";
    }

    public static Dataset loadCsv(File f) throws IOException {
        if (!f.exists()) throw new IOException("File not found: " + f.getAbsolutePath());
        List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
        if (lines.size() < 2) throw new IOException("The CSV file is empty.");

        String headerLine = lines.get(0);
        if (headerLine.startsWith("\uFEFF")) headerLine = headerLine.substring(1);
        String[] header = parseCsvLine(headerLine);

        int urlCol = -1, labelCol = -1;
        String[] labelNames = {"status", "label", "class", "type", "result", "phishing"};
        for (int i = 0; i < header.length; i++) {
            String h = header[i].trim().toLowerCase();
            if (h.equals("url")) urlCol = i;
            for (String ln : labelNames) if (h.equals(ln) && labelCol == -1) labelCol = i;
        }
        if (urlCol == -1) throw new IOException("No column named 'url' was found in the CSV header.");
        if (labelCol == -1) labelCol = header.length - 1;

        Dataset d = new Dataset();
        d.labelColumn = header[labelCol].trim();
        for (int i = 1; i < lines.size(); i++) {
            String[] c = parseCsvLine(lines.get(i));
            if (c.length <= Math.max(urlCol, labelCol)) { d.skipped++; continue; }
            String url = c[urlCol].trim();
            String lab = c[labelCol].trim().toLowerCase();
            int y;
            if (lab.equals("phishing") || lab.equals("1") || lab.equals("malicious") || lab.equals("bad")) y = 1;
            else if (lab.equals("legitimate") || lab.equals("0") || lab.equals("benign")
                    || lab.equals("good") || lab.equals("safe")) y = 0;
            else { d.skipped++; continue; }
            if (url.isEmpty()) { d.skipped++; continue; }
            d.urls.add(url);
            d.labels.add(y);
            if (y == 1) d.phishing++; else d.legit++;
        }
        return d;
    }

    static String[] parseCsvLine(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (quoted) {
                if (ch == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') { sb.append('"'); i++; }
                    else quoted = false;
                } else sb.append(ch);
            } else if (ch == '"') quoted = true;
            else if (ch == ',') { out.add(sb.toString()); sb.setLength(0); }
            else sb.append(ch);
        }
        out.add(sb.toString());
        return out.toArray(new String[0]);
    }

    // -------------------------------------------------------------- features

    public static double[] vector(String raw) {
        FeatureExtractor.ParsedUrl p = FeatureExtractor.parse(raw);
        String url = p.original;
        Map<String, FeatureExtractor.Feature> fm = new HashMap<>();
        for (FeatureExtractor.Feature f : FeatureExtractor.extract(raw)) fm.put(f.name, f);

        int digits = 0, hostDigits = 0;
        for (char c : url.toCharArray()) if (Character.isDigit(c)) digits++;
        for (char c : p.host.toCharArray()) if (Character.isDigit(c)) hostDigits++;

        boolean ip = FeatureExtractor.isIp(p.host);
        int subs = 0;
        if (!ip && !p.host.isEmpty()) {
            String reg = FeatureExtractor.registeredDomain(p.host);
            subs = Math.max(0, p.host.split("\\.").length - reg.split("\\.").length);
        }
        int kw = fm.containsKey("Suspicious keywords") ? fm.get("Suspicious keywords").points / 5 : 0;

        double[] x = new double[NAMES.length];
        int i = 0;
        x[i++] = url.length();
        x[i++] = p.host.length();
        x[i++] = p.path.length();
        x[i++] = p.query.length();
        x[i++] = count(url, '.');
        x[i++] = count(p.host, '-');
        x[i++] = digits / (double) Math.max(1, url.length());
        x[i++] = hostDigits;
        x[i++] = count(url, '/');
        x[i++] = count(url, '=');
        x[i++] = count(url, '&');
        x[i++] = p.userInfo != null ? 1 : 0;
        x[i++] = count(url, '%');
        x[i++] = count(url, '_');
        x[i++] = ip ? 1 : 0;
        x[i++] = p.scheme == null ? 0.5 : (p.scheme.equals("https") ? 1 : 0);
        x[i++] = subs;
        x[i++] = kw;
        x[i++] = flag(fm, "URL shortener");
        x[i++] = flag(fm, "Risky TLD");
        x[i++] = flag(fm, "Punycode (xn--)");
        x[i++] = flag(fm, "Non-standard port");
        x[i++] = flag(fm, "Brand impersonation");
        x[i++] = flag(fm, "Trusted domain");
        return x;
    }

    private static int count(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    private static double flag(Map<String, FeatureExtractor.Feature> fm, String name) {
        FeatureExtractor.Feature f = fm.get(name);
        return f != null && f.triggered ? 1 : 0;
    }

    // -------------------------------------------------------------- training

    /** Trains with an 80/20 train-test split and returns a readable report. */
    public static String train(Dataset d) {
        int n = d.urls.size(), k = NAMES.length;
        if (n < 50) throw new IllegalArgumentException("Need at least 50 usable rows, found " + n + ".");
        if (d.phishing == 0 || d.legit == 0) throw new IllegalArgumentException("The dataset has only one class.");

        double[][] X = new double[n][];
        int[] y = new int[n];
        for (int i = 0; i < n; i++) {
            X[i] = vector(d.urls.get(i));
            y[i] = d.labels.get(i);
        }

        List<Integer> idx = new ArrayList<>();
        for (int i = 0; i < n; i++) idx.add(i);
        Collections.shuffle(idx, new Random(42));
        int nTrain = (int) (n * 0.8), nTest = n - nTrain;

        double[] mu = new double[k], sd = new double[k];
        for (int j = 0; j < k; j++) {
            double s = 0;
            for (int t = 0; t < nTrain; t++) s += X[idx.get(t)][j];
            mu[j] = s / nTrain;
            double v = 0;
            for (int t = 0; t < nTrain; t++) { double dv = X[idx.get(t)][j] - mu[j]; v += dv * dv; }
            sd[j] = Math.sqrt(v / nTrain);
            if (sd[j] < 1e-9) sd[j] = 1;
        }
        double[][] Z = new double[n][k];
        for (int i = 0; i < n; i++) for (int j = 0; j < k; j++) Z[i][j] = (X[i][j] - mu[j]) / sd[j];

        double[] wt = new double[k];
        double b = 0, lr = 0.5, l2 = 0.001;
        for (int epoch = 0; epoch < 300; epoch++) {
            double[] gw = new double[k];
            double gb = 0;
            for (int t = 0; t < nTrain; t++) {
                int i = idx.get(t);
                double err = sigmoid(dot(wt, Z[i]) + b) - y[i];
                for (int j = 0; j < k; j++) gw[j] += err * Z[i][j];
                gb += err;
            }
            for (int j = 0; j < k; j++) wt[j] -= lr * (gw[j] / nTrain + l2 * wt[j]);
            b -= lr * gb / nTrain;
        }

        int a = 0, bb = 0, c = 0, e = 0;   // tp, tn, fp, fn
        for (int t = nTrain; t < n; t++) {
            int i = idx.get(t);
            int pred = sigmoid(dot(wt, Z[i]) + b) >= 0.5 ? 1 : 0;
            if (pred == 1 && y[i] == 1) a++;
            else if (pred == 0 && y[i] == 0) bb++;
            else if (pred == 1) c++;
            else e++;
        }

        w = wt; mean = mu; std = sd; bias = b; trainedOn = n;
        tp = a; tn = bb; fp = c; fn = e;
        save();
        return describe(nTrain, nTest);
    }

    private static double dot(double[] a, double[] b) {
        double s = 0;
        for (int i = 0; i < a.length; i++) s += a[i] * b[i];
        return s;
    }

    private static double sigmoid(double z) {
        z = Math.max(-30, Math.min(30, z));
        return 1.0 / (1.0 + Math.exp(-z));
    }

    /** Probability (0..1) that the URL is phishing. */
    public static double predict(String url) {
        if (w == null) return 0;
        double[] x = vector(url);
        double z = bias;
        for (int j = 0; j < w.length; j++) z += w[j] * (x[j] - mean[j]) / std[j];
        return sigmoid(z);
    }

    public static String describe(int nTrain, int nTest) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Trained on %d URLs (train %d / test %d)%n%n", trainedOn, nTrain, nTest));
        sb.append(String.format("Accuracy  : %.2f %%%n", accuracy() * 100));
        sb.append(String.format("Precision : %.2f %%%n", precision() * 100));
        sb.append(String.format("Recall    : %.2f %%%n", recall() * 100));
        sb.append(String.format("F1 score  : %.2f %%%n%n", f1() * 100));
        sb.append(String.format("Confusion matrix (test set)%n"));
        sb.append(String.format("  caught phishing (TP) : %d%n  legit passed (TN)    : %d%n", tp, tn));
        sb.append(String.format("  false alarms (FP)    : %d%n  missed phishing (FN) : %d%n%n", fp, fn));
        sb.append("Strongest signals learned from the data:\n");
        Integer[] order = new Integer[w.length];
        for (int i = 0; i < order.length; i++) order[i] = i;
        final double[] ww = w;
        Arrays.sort(order, (p, q) -> Double.compare(Math.abs(ww[q]), Math.abs(ww[p])));
        for (int r = 0; r < 8; r++) {
            int j = order[r];
            sb.append(String.format("  %-20s %+.2f  (%s phishing risk)%n", NAMES[j], w[j],
                    w[j] > 0 ? "raises" : "lowers"));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------ save / load

    private static void save() {
        try {
            List<String> out = new ArrayList<>();
            out.add(String.valueOf(trainedOn));
            out.add(String.valueOf(bias));
            out.add(join(w));
            out.add(join(mean));
            out.add(join(std));
            out.add(tp + "," + tn + "," + fp + "," + fn);
            Files.write(Paths.get(MODEL_FILE), out, StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean loadIfExists() {
        try {
            if (!Files.exists(Paths.get(MODEL_FILE))) return false;
            List<String> l = Files.readAllLines(Paths.get(MODEL_FILE), StandardCharsets.UTF_8);
            double[] nw = split(l.get(2)), nm = split(l.get(3)), ns = split(l.get(4));
            if (nw.length != NAMES.length || nm.length != NAMES.length || ns.length != NAMES.length) return false;
            trainedOn = Integer.parseInt(l.get(0).trim());
            bias = Double.parseDouble(l.get(1).trim());
            w = nw; mean = nm; std = ns;
            String[] m = l.get(5).split(",");
            tp = Integer.parseInt(m[0]); tn = Integer.parseInt(m[1]);
            fp = Integer.parseInt(m[2]); fn = Integer.parseInt(m[3]);
            return true;
        } catch (Exception e) {
            w = null;
            return false;
        }
    }

    private static String join(double[] a) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length; i++) sb.append(i > 0 ? "," : "").append(a[i]);
        return sb.toString();
    }

    private static double[] split(String s) {
        String[] p = s.split(",");
        double[] a = new double[p.length];
        for (int i = 0; i < p.length; i++) a[i] = Double.parseDouble(p[i].trim());
        return a;
    }
}
