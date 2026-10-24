import java.util.List;

/** One saved scan (a row in scan_history.tsv) plus helpers to save, load and count. */
public class ScanHistory {

    public final String email;
    public final String time;
    public final String url;
    public final int score;
    public final String verdict;

    public ScanHistory(String email, String time, String url, int score, String verdict) {
        this.email = email;
        this.time = time;
        this.url = url;
        this.score = score;
        this.verdict = verdict;
    }

    public static void add(String email, PhisingDetector.ScanResult r) {
        DataBaseConnection.addHistory(new ScanHistory(email, r.time, r.url, r.score, r.verdict));
    }

    public static List<ScanHistory> forUser(String email) {
        return DataBaseConnection.loadHistory(email);
    }

    public static void clear(String email) {
        DataBaseConnection.clearHistory(email);
    }

    /** Returns {safe, suspicious, phishing}. */
    public static int[] counts(List<ScanHistory> list) {
        int[] c = new int[3];
        for (ScanHistory h : list) {
            if (h.verdict.equals("SAFE")) c[0]++;
            else if (h.verdict.equals("SUSPICIOUS")) c[1]++;
            else c[2]++;
        }
        return c;
    }
}
