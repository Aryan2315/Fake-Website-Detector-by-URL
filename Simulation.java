import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Feature 9: live simulation.
 * A generator keeps creating random legitimate and phishing URLs (we know the truth),
 * the detector classifies each one in real time, and the panel shows how many it
 * caught, missed or wrongly flagged, plus a live accuracy chart.
 */
public class SimulationPanel extends JPanel {

    private static final String[] LEGIT = {"google.com", "wikipedia.org", "github.com", "amazon.in",
            "flipkart.com", "bbc.co.uk", "python.org", "stackoverflow.com", "nptel.ac.in", "iitd.ac.in",
            "microsoft.com", "apple.com", "linkedin.com", "coursera.org", "medium.com", "openai.com"};
    private static final String[] PATHS = {"", "/", "/about", "/search?q=java+swing", "/docs/index.html",
            "/courses/machine-learning", "/news/2026/10/ai-update", "/wiki/Genetics", "/login", "/account/settings"};
    private static final String[] BRANDS = {"paypal", "google", "facebook", "amazon", "apple", "microsoft",
            "netflix", "instagram", "whatsapp", "paytm", "sbi", "hdfc"};
    private static final String[] WORDS = {"login", "verify", "secure", "account", "update", "confirm",
            "signin", "banking", "wallet", "unlock", "billing", "kyc"};
    private static final String[] TLDS = {"tk", "ml", "xyz", "top", "click", "gq"};

    private final Random rnd = new Random();
    private final javax.swing.Timer timer;

    private final JButton startBtn = Theme.button("Start", Theme.SAFE);
    private final JSlider speed = new JSlider(1, 20, 5);
    private final JSlider share = new JSlider(5, 95, 40);
    private final JLabel speedLbl = Theme.label("Speed: 5 URLs/sec", Theme.BASE, Theme.TEXT);
    private final JLabel shareLbl = Theme.label("Phishing share: 40%", Theme.BASE, Theme.TEXT);
    private final JComboBox<String> mode = new JComboBox<>(new String[]{
            "Rules only", "ML model only", "Rules + ML (either flags)"});
    private final JLabel note = Theme.label(" ", Theme.BASE, Theme.WARN);

    private final DefaultTableModel model = Theme.tableModel("#", "Generated URL", "Truth", "Detector says", "Result");
    private final JLabel vGen = value(Theme.TEXT), vCaught = value(Theme.SAFE), vMissed = value(Theme.DANGER),
            vFalse = value(Theme.WARN), vAcc = value(Theme.ACCENT), vRecall = value(Theme.ACCENT);
    private final LineChart chart = new LineChart();

    private int generated, caught, missed, falseAlarms, okLegit;
    private final List<Integer> accHistory = new ArrayList<>();

    public SimulationPanel() {
        setLayout(new BorderLayout(0, 12));
        setBackground(Theme.BG);
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        timer = new javax.swing.Timer(200, e -> tick());

        startBtn.addActionListener(e -> toggle());
        JButton reset = Theme.button("Reset", new Color(90, 100, 120));
        reset.addActionListener(e -> reset());

        speed.setOpaque(false);
        share.setOpaque(false);
        speed.addChangeListener(e -> {
            speedLbl.setText("Speed: " + speed.getValue() + " URLs/sec");
            timer.setDelay(1000 / speed.getValue());
        });
        share.addChangeListener(e -> shareLbl.setText("Phishing share: " + share.getValue() + "%"));
        mode.setFont(Theme.BASE);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        controls.setOpaque(false);
        controls.add(startBtn);
        controls.add(reset);
        controls.add(speedLbl);
        controls.add(speed);
        controls.add(shareLbl);
        controls.add(share);
        controls.add(Theme.label("Detector:", Theme.BOLD, Theme.TEXT));
        controls.add(mode);

        JPanel north = new JPanel(new BorderLayout(0, 6));
        north.setOpaque(false);
        north.add(controls, BorderLayout.NORTH);
        north.add(note, BorderLayout.SOUTH);

        JPanel cards = new JPanel(new GridLayout(1, 6, 10, 0));
        cards.setOpaque(false);
        cards.add(card("URLs generated", vGen));
        cards.add(card("Phishing caught", vCaught));
        cards.add(card("Phishing missed", vMissed));
        cards.add(card("False alarms", vFalse));
        cards.add(card("Accuracy", vAcc));
        cards.add(card("Detection rate", vRecall));

        chart.setPreferredSize(new Dimension(100, 170));
        JPanel top = new JPanel(new BorderLayout(0, 10));
        top.setOpaque(false);
        top.add(cards, BorderLayout.NORTH);
        top.add(chart, BorderLayout.CENTER);

        JTable table = new JTable(model);
        Theme.styleTable(table, 4);
        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(1).setPreferredWidth(520);
        table.getColumnModel().getColumn(2).setPreferredWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(110);
        table.getColumnModel().getColumn(4).setPreferredWidth(110);

        JPanel center = new JPanel(new BorderLayout(0, 10));
        center.setOpaque(false);
        center.add(top, BorderLayout.NORTH);
        center.add(Theme.scroll(table), BorderLayout.CENTER);

        add(north, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
    }

    // -------------------------------------------------------------- controls

    private void toggle() {
        if (timer.isRunning()) {
            timer.stop();
            startBtn.setText("Start");
            startBtn.setBackground(Theme.SAFE);
        } else {
            timer.setDelay(1000 / speed.getValue());
            timer.start();
            startBtn.setText("Pause");
            startBtn.setBackground(Theme.WARN);
        }
    }

    private void reset() {
        timer.stop();
        startBtn.setText("Start");
        startBtn.setBackground(Theme.SAFE);
        generated = caught = missed = falseAlarms = okLegit = 0;
        accHistory.clear();
        model.setRowCount(0);
        note.setText(" ");
        updateCards();
        chart.setData(accHistory);
    }

    /** One simulation step: make a URL, classify it, record the result. */
    void tick() {
        boolean isPhish = rnd.nextInt(100) < share.getValue();
        String url = isPhish ? genPhish(rnd) : genLegit(rnd);

        int m = mode.getSelectedIndex();
        boolean needML = m != 0;
        boolean mlReady = MLModel.isTrained();
        note.setText(needML && !mlReady ? "ML model is not trained yet (see the ML Model tab) - using rules only." : " ");

        boolean rulesFlag = PhisingDetector.analyze(url).score >= 30;
        boolean mlFlag = mlReady && MLModel.predict(url) >= 0.5;
        boolean flagged;
        if (m == 1 && mlReady) flagged = mlFlag;
        else if (m == 2 && mlReady) flagged = rulesFlag || mlFlag;
        else flagged = rulesFlag;

        String result;
        if (isPhish && flagged) { caught++; result = "CAUGHT"; }
        else if (isPhish) { missed++; result = "MISSED"; }
        else if (flagged) { falseAlarms++; result = "FALSE ALARM"; }
        else { okLegit++; result = "OK"; }
        generated++;

        model.insertRow(0, new Object[]{String.valueOf(generated), url, isPhish ? "Phishing" : "Legit",
                flagged ? "Phishing" : "Safe", result});
        if (model.getRowCount() > 14) model.removeRow(model.getRowCount() - 1);

        accHistory.add((caught + okLegit) * 100 / generated);
        if (accHistory.size() > 200) accHistory.remove(0);
        updateCards();
        chart.setData(accHistory);
    }

    private void updateCards() {
        vGen.setText(String.valueOf(generated));
        vCaught.setText(String.valueOf(caught));
        vMissed.setText(String.valueOf(missed));
        vFalse.setText(String.valueOf(falseAlarms));
        vAcc.setText(generated == 0 ? "-" : (caught + okLegit) * 100 / generated + "%");
        vRecall.setText(caught + missed == 0 ? "-" : caught * 100 / (caught + missed) + "%");
    }

    // ------------------------------------------------------------ generators

    static String genLegit(Random r) {
        String host = LEGIT[r.nextInt(LEGIT.length)];
        if (r.nextInt(3) == 0) host = new String[]{"www.", "docs.", "mail.", "blog."}[r.nextInt(4)] + host;
        String scheme = r.nextInt(10) < 8 ? "https://" : "http://";
        return scheme + host + PATHS[r.nextInt(PATHS.length)];
    }

    static String genPhish(Random r) {
        String brand = BRANDS[r.nextInt(BRANDS.length)];
        String w1 = WORDS[r.nextInt(WORDS.length)], w2 = WORDS[r.nextInt(WORDS.length)];
        String tld = TLDS[r.nextInt(TLDS.length)];
        String scheme = r.nextInt(10) < 6 ? "http://" : "https://";
        switch (r.nextInt(7)) {
            case 0: return scheme + brand + "-" + w1 + "-" + w2 + "." + tld + "/" + w1 + ".php";
            case 1: return "http://" + (r.nextInt(223) + 1) + "." + r.nextInt(255) + "." + r.nextInt(255) + "."
                    + (r.nextInt(254) + 1) + "/" + w1 + "/" + brand + "/index.html";
            case 2: return scheme + "secure." + brand + ".com." + w1 + "-center." + tld + "/" + w2;
            case 3: return scheme + LEGIT[r.nextInt(LEGIT.length)] + "@" + rand(r, 8) + "." + tld + "/" + w1;
            case 4: return "https://bit.ly/" + rand(r, 6);
            case 5: return scheme + brand + (r.nextInt(9000) + 1000) + "." + tld + "/signin?id=" + rand(r, 10)
                    + "&session=" + rand(r, 12);
            default: return scheme + brand + "." + rand(r, 7) + ".com/" + w1 + "/" + rand(r, 5) + ".html";
        }
    }

    private static String rand(Random r, int n) {
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(chars.charAt(r.nextInt(chars.length())));
        return sb.toString();
    }

    // -------------------------------------------------------------- UI bits

    private static JLabel value(Color c) {
        JLabel l = Theme.label("0", new Font("Segoe UI", Font.BOLD, 26), c);
        l.setHorizontalAlignment(SwingConstants.CENTER);
        return l;
    }

    private static JPanel card(String title, JLabel value) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(Theme.PANEL);
        p.setBorder(BorderFactory.createEmptyBorder(10, 6, 8, 6));
        JLabel t = Theme.label(title, Theme.BASE, Theme.MUTED);
        t.setHorizontalAlignment(SwingConstants.CENTER);
        p.add(value, BorderLayout.CENTER);
        p.add(t, BorderLayout.SOUTH);
        return p;
    }

    /** Live line chart of accuracy (0-100 %). */
    private static class LineChart extends JPanel {
        private List<Integer> data = new ArrayList<>();

        LineChart() { setOpaque(false); }

        void setData(List<Integer> d) {
            data = d;
            repaint();
        }

        @Override protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();
            g.setColor(Theme.PANEL);
            g.fillRoundRect(0, 0, w, h, 16, 16);
            g.setFont(Theme.BOLD);
            g.setColor(Theme.TEXT);
            g.drawString("Detection accuracy over time (%)", 16, 24);

            int left = 46, right = 16, top = 38, bottom = 16;
            int pw = w - left - right, ph = h - top - bottom;
            g.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            for (int v = 0; v <= 100; v += 25) {
                int y = top + ph - ph * v / 100;
                g.setColor(new Color(50, 65, 95));
                g.drawLine(left, y, left + pw, y);
                g.setColor(Theme.MUTED);
                g.drawString(v + "", left - 28, y + 4);
            }
            if (data.size() < 2) {
                g.setColor(Theme.MUTED);
                g.drawString("Press Start to begin the simulation", left + 10, top + ph / 2);
                g.dispose();
                return;
            }
            g.setColor(Theme.ACCENT);
            g.setStroke(new BasicStroke(2.2f));
            int n = data.size();
            int px = left, py = top + ph - ph * data.get(0) / 100;
            for (int i = 1; i < n; i++) {
                int x = left + pw * i / (n - 1);
                int y = top + ph - ph * data.get(i) / 100;
                g.drawLine(px, py, x, y);
                px = x;
                py = y;
            }
            g.dispose();
        }
    }
}
