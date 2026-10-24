import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Main window. The 7 features:
 *  1. Login / Register (LoginFrame, RegisterFrame)
 *  2. Single URL scan with risk score and verdict
 *  3. Detailed feature breakdown table
 *  4. Live network check (DNS, HTTP, redirect, TLS)
 *  5. Batch scan from a .txt / .csv file
 *  6. Scan history + statistics chart
 *  7. Export report (HTML / TXT)
 *  8. Machine learning model trained from dataset_phishing.csv
 *  9. Live attack simulation
 */
public class DashboardFrame extends JFrame {

    private PhisingDetector.ScanResult lastScanResult;
    private String lastScannedUrl;
    private final String currentUserEmail;

    // scan tab
    private final JTextField urlField = new JTextField();
    private final RiskGauge gauge = new RiskGauge();
    private final DefaultTableModel featureModel = Theme.tableModel("Check", "Status", "Points", "Details");
    private final JTextArea liveArea = new JTextArea();

    // batch tab
    private final List<String> batchUrls = new ArrayList<>();
    private final List<PhisingDetector.ScanResult> batchResults = new ArrayList<>();
    private final DefaultTableModel batchModel = Theme.tableModel("URL", "Score", "Verdict");
    private final JLabel batchInfo = Theme.label("No file loaded", Theme.BASE, Theme.MUTED);

    // history tab
    private final DefaultTableModel historyModel = Theme.tableModel("Time", "URL", "Score", "Verdict");
    private final StatsPanel statsPanel = new StatsPanel();

    private final JTabbedPane tabs = new JTabbedPane();

    public DashboardFrame(String email) {
        this.currentUserEmail = email;

        setTitle("Fake Website Detector - Dashboard");
        setSize(1000, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        getContentPane().setBackground(Theme.BG);
        setLayout(new BorderLayout());

        add(buildHeader(), BorderLayout.NORTH);

        tabs.setFont(Theme.BOLD);
        tabs.addTab("Scan URL", buildScanTab());
        tabs.addTab("Batch Scan", buildBatchTab());
        tabs.addTab("History & Statistics", buildHistoryTab());
        tabs.addTab("ML Model (Dataset)", new MLPanel());
        tabs.addTab("Simulation", new SimulationPanel());
        tabs.addChangeListener(e -> {
            if (tabs.getSelectedIndex() == 2) refreshHistory();
        });
        add(tabs, BorderLayout.CENTER);

        refreshHistory();
    }

    // ================================================================ header

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(Theme.PANEL);
        header.setBorder(BorderFactory.createEmptyBorder(12, 20, 12, 20));

        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.add(Theme.label("Fake Website Detector", Theme.TITLE, Theme.TEXT));
        String name = DataBaseConnection.getName(currentUserEmail);
        left.add(Theme.label("Logged in as " + name + " (" + currentUserEmail + ")", Theme.BASE, Theme.MUTED));

        JButton logout = Theme.button("Logout", Theme.DANGER);
        logout.addActionListener(e -> {
            dispose();
            new LoginFrame().setVisible(true);
        });

        header.add(left, BorderLayout.WEST);
        header.add(logout, BorderLayout.EAST);
        return header;
    }

    // ============================================================ scan tab

    private JPanel buildScanTab() {
        JPanel p = new JPanel(new BorderLayout(0, 12));
        p.setBackground(Theme.BG);
        p.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        Theme.styleField(urlField);
        urlField.setFont(new Font("Consolas", Font.PLAIN, 15));
        urlField.setToolTipText("Example: http://paypal-login.verify-account.tk/signin");
        urlField.addActionListener(e -> doScan());

        JButton scan = Theme.button("Scan", Theme.ACCENT);
        JButton live = Theme.button("Live Check", new Color(142, 68, 173));
        JButton export = Theme.button("Export Report", new Color(39, 174, 96));
        JButton clear = Theme.button("Clear", new Color(90, 100, 120));
        scan.addActionListener(e -> doScan());
        live.addActionListener(e -> doLiveCheck());
        export.addActionListener(e -> doExport());
        clear.addActionListener(e -> doClear());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.setOpaque(false);
        buttons.add(scan);
        buttons.add(live);
        buttons.add(export);
        buttons.add(clear);

        JPanel top = new JPanel(new BorderLayout(10, 0));
        top.setOpaque(false);
        top.add(Theme.label("URL:", Theme.BOLD, Theme.TEXT), BorderLayout.WEST);
        top.add(urlField, BorderLayout.CENTER);
        top.add(buttons, BorderLayout.EAST);

        JTable table = new JTable(featureModel);
        Theme.styleTable(table, 1);
        table.getColumnModel().getColumn(0).setPreferredWidth(190);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(520);

        liveArea.setEditable(false);
        liveArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        liveArea.setBackground(new Color(12, 20, 36));
        liveArea.setForeground(new Color(120, 230, 160));
        liveArea.setMargin(new Insets(8, 10, 8, 10));
        liveArea.setText("Press \"Live Check\" to test DNS, HTTP status, redirects and TLS for this URL.");

        JScrollPane liveScroll = Theme.scroll(liveArea);
        liveScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(60, 80, 115)), "Live network check",
                0, 0, Theme.BOLD, Theme.MUTED));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, Theme.scroll(table), liveScroll);
        split.setResizeWeight(0.7);
        split.setDividerSize(6);
        split.setBorder(null);
        split.setBackground(Theme.BG);

        JPanel center = new JPanel(new BorderLayout(0, 10));
        center.setOpaque(false);
        center.add(gauge, BorderLayout.NORTH);
        center.add(split, BorderLayout.CENTER);

        p.add(top, BorderLayout.NORTH);
        p.add(center, BorderLayout.CENTER);
        return p;
    }

    private void doScan() {
        String url = urlField.getText().trim();
        if (!PhisingDetector.looksLikeUrl(url)) {
            JOptionPane.showMessageDialog(this,
                    "Please enter a valid URL, e.g. https://example.com/login",
                    "Invalid URL", JOptionPane.WARNING_MESSAGE);
            return;
        }
        PhisingDetector.ScanResult r = PhisingDetector.analyze(url);
        lastScanResult = r;
        lastScannedUrl = url;

        gauge.setResult(r.score, r.verdict);
        featureModel.setRowCount(0);
        for (FeatureExtractor.Feature f : r.features) {
            String pts = f.points == 0 ? "-" : (f.points > 0 ? "+" + f.points : String.valueOf(f.points));
            featureModel.addRow(new Object[]{f.name, f.triggered ? "FLAGGED" : "OK", pts, f.description});
        }
        if (MLModel.isTrained()) {
            double p = MLModel.predict(url);
            featureModel.addRow(new Object[]{"ML model (dataset)", p >= 0.5 ? "FLAGGED" : "OK", "-",
                    String.format("Phishing probability %.1f%% (model trained on %d URLs)", p * 100, MLModel.trainedOn())});
        }
        ScanHistory.add(currentUserEmail, r);
        refreshHistory();
    }

    private void doLiveCheck() {
        final String url = urlField.getText().trim();
        if (!PhisingDetector.looksLikeUrl(url)) {
            JOptionPane.showMessageDialog(this, "Enter a URL first.", "Invalid URL", JOptionPane.WARNING_MESSAGE);
            return;
        }
        liveArea.setText("Checking " + url + " ...");
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                return URLscanner.liveCheck(url);
            }
            @Override protected void done() {
                try {
                    liveArea.setText(get());
                } catch (Exception ex) {
                    liveArea.setText("Live check failed: " + ex.getMessage());
                }
                liveArea.setCaretPosition(0);
            }
        }.execute();
    }

    private void doExport() {
        if (lastScanResult == null) {
            JOptionPane.showMessageDialog(this, "Scan a URL first, then export its report.",
                    "Nothing to export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("scan_report.html"));
        fc.addChoosableFileFilter(new FileNameExtensionFilter("HTML report (*.html)", "html"));
        fc.addChoosableFileFilter(new FileNameExtensionFilter("Text report (*.txt)", "txt"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File f = fc.getSelectedFile();
        String n = f.getName().toLowerCase();
        if (!n.endsWith(".html") && !n.endsWith(".txt")) f = new File(f.getPath() + ".html");
        try {
            ReportGenerator.save(f, lastScanResult, currentUserEmail);
            JOptionPane.showMessageDialog(this, "Report saved to:\n" + f.getAbsolutePath(),
                    "Exported", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Could not save report: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void doClear() {
        urlField.setText("");
        featureModel.setRowCount(0);
        gauge.setResult(0, null);
        liveArea.setText("Press \"Live Check\" to test DNS, HTTP status, redirects and TLS for this URL.");
        lastScanResult = null;
        lastScannedUrl = null;
    }

    // =========================================================== batch tab

    private JPanel buildBatchTab() {
        JPanel p = new JPanel(new BorderLayout(0, 12));
        p.setBackground(Theme.BG);
        p.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JButton load = Theme.button("Load File (.txt / .csv)", Theme.ACCENT);
        JButton scanAll = Theme.button("Scan All", Theme.SAFE);
        JButton save = Theme.button("Save Results (CSV)", new Color(39, 174, 96));
        load.addActionListener(e -> loadBatchFile());
        scanAll.addActionListener(e -> scanAllBatch());
        save.addActionListener(e -> saveBatchCsv());

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        top.setOpaque(false);
        top.add(load);
        top.add(scanAll);
        top.add(save);
        top.add(Box.createHorizontalStrut(10));
        top.add(batchInfo);

        JTable table = new JTable(batchModel);
        Theme.styleTable(table, 2);
        table.getColumnModel().getColumn(0).setPreferredWidth(620);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(2).setPreferredWidth(120);

        p.add(top, BorderLayout.NORTH);
        p.add(Theme.scroll(table), BorderLayout.CENTER);
        p.add(Theme.label("File format: one URL per line (for CSV the first column is used). Lines starting with # are ignored.",
                Theme.BASE, Theme.MUTED), BorderLayout.SOUTH);
        return p;
    }

    private void loadBatchFile() {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new FileNameExtensionFilter("Text / CSV files", "txt", "csv"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File f = fc.getSelectedFile();
        try {
            List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
            batchUrls.clear();
            batchResults.clear();
            batchModel.setRowCount(0);
            for (String line : lines) {
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#")) continue;
                if (s.contains(",")) s = s.substring(0, s.indexOf(','));
                s = s.replace("\"", "").trim();
                if (s.equalsIgnoreCase("url")) continue;      // CSV header
                if (PhisingDetector.looksLikeUrl(s)) batchUrls.add(s);
            }
            batchInfo.setText(batchUrls.size() + " URL(s) loaded from " + f.getName());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Could not read file: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void scanAllBatch() {
        if (batchUrls.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Load a file with URLs first.",
                    "No URLs", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        batchModel.setRowCount(0);
        batchResults.clear();
        final List<String> urls = new ArrayList<>(batchUrls);

        new SwingWorker<Void, PhisingDetector.ScanResult>() {
            @Override protected Void doInBackground() {
                for (String u : urls) publish(PhisingDetector.analyze(u));
                return null;
            }
            @Override protected void process(List<PhisingDetector.ScanResult> chunks) {
                for (PhisingDetector.ScanResult r : chunks) {
                    batchResults.add(r);
                    batchModel.addRow(new Object[]{r.url, String.valueOf(r.score), r.verdict});
                    ScanHistory.add(currentUserEmail, r);
                }
                batchInfo.setText("Scanned " + batchResults.size() + " / " + urls.size());
            }
            @Override protected void done() {
                int bad = 0;
                for (PhisingDetector.ScanResult r : batchResults) if (!r.verdict.equals("SAFE")) bad++;
                batchInfo.setText("Done: " + batchResults.size() + " scanned, " + bad + " not safe");
                refreshHistory();
            }
        }.execute();
    }

    private void saveBatchCsv() {
        if (batchResults.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Run \"Scan All\" first.",
                    "Nothing to save", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("batch_results.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File f = fc.getSelectedFile();
        List<String> out = new ArrayList<>();
        out.add("url,score,verdict");
        for (PhisingDetector.ScanResult r : batchResults) {
            out.add("\"" + r.url.replace("\"", "\"\"") + "\"," + r.score + "," + r.verdict);
        }
        try {
            Files.write(f.toPath(), out, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Saved to:\n" + f.getAbsolutePath(),
                    "Saved", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Could not save: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ========================================================== history tab

    private JPanel buildHistoryTab() {
        JPanel p = new JPanel(new BorderLayout(15, 0));
        p.setBackground(Theme.BG);
        p.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JTable table = new JTable(historyModel);
        Theme.styleTable(table, 3);
        table.getColumnModel().getColumn(0).setPreferredWidth(140);
        table.getColumnModel().getColumn(1).setPreferredWidth(360);
        table.getColumnModel().getColumn(2).setPreferredWidth(50);
        table.getColumnModel().getColumn(3).setPreferredWidth(100);

        JButton refresh = Theme.button("Refresh", Theme.ACCENT);
        JButton clear = Theme.button("Clear History", Theme.DANGER);
        refresh.addActionListener(e -> refreshHistory());
        clear.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this, "Delete all your saved scans?",
                    "Clear history", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok == JOptionPane.YES_OPTION) {
                ScanHistory.clear(currentUserEmail);
                refreshHistory();
            }
        });

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 8));
        btns.setOpaque(false);
        btns.add(refresh);
        btns.add(clear);

        JPanel right = new JPanel(new BorderLayout());
        right.setOpaque(false);
        right.setPreferredSize(new Dimension(320, 100));
        right.add(statsPanel, BorderLayout.CENTER);
        right.add(btns, BorderLayout.SOUTH);

        p.add(Theme.scroll(table), BorderLayout.CENTER);
        p.add(right, BorderLayout.EAST);
        return p;
    }

    private void refreshHistory() {
        List<ScanHistory> list = ScanHistory.forUser(currentUserEmail);
        historyModel.setRowCount(0);
        for (int i = list.size() - 1; i >= 0; i--) {          // newest first
            ScanHistory h = list.get(i);
            historyModel.addRow(new Object[]{h.time, h.url, String.valueOf(h.score), h.verdict});
        }
        statsPanel.setCounts(ScanHistory.counts(list));
    }

    // ===================================================== custom AWT panels

    /** Coloured risk bar with the verdict text. */
    private static class RiskGauge extends JPanel {
        private int score;
        private String verdict;

        RiskGauge() {
            setOpaque(false);
            setPreferredSize(new Dimension(100, 72));
        }

        void setResult(int score, String verdict) {
            this.score = score;
            this.verdict = verdict;
            repaint();
        }

        @Override protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();

            g.setColor(Theme.PANEL);
            g.fillRoundRect(0, 0, w, h, 16, 16);

            int bx = 16, bh = 12, by = h - 24, bw = w - 32;
            g.setColor(new Color(50, 65, 95));
            g.fillRoundRect(bx, by, bw, bh, bh, bh);

            Color c = verdict == null ? Theme.MUTED : Theme.verdictColor(verdict);
            if (verdict != null && score > 0) {
                g.setColor(c);
                g.fillRoundRect(bx, by, Math.max(bh, bw * score / 100), bh, bh, bh);
            }
            g.setFont(new Font("Segoe UI", Font.BOLD, 20));
            g.setColor(c);
            String text = verdict == null ? "Enter a URL and press Scan"
                    : verdict + "   (risk " + score + " / 100)";
            g.drawString(text, 16, 30);
            g.dispose();
        }
    }

    /** Pie chart of SAFE / SUSPICIOUS / PHISHING counts. */
    private static class StatsPanel extends JPanel {
        private int[] counts = new int[3];

        StatsPanel() {
            setOpaque(false);
        }

        void setCounts(int[] c) {
            counts = c;
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
            g.drawString("Scan statistics", 16, 28);

            int total = counts[0] + counts[1] + counts[2];
            if (total == 0) {
                g.setColor(Theme.MUTED);
                g.drawString("No scans yet", w / 2 - 40, h / 2);
                g.dispose();
                return;
            }

            String[] names = {"Safe", "Suspicious", "Phishing"};
            Color[] cols = {Theme.SAFE, Theme.WARN, Theme.DANGER};

            int d = Math.max(60, Math.min(w - 60, h - 160));
            int x = (w - d) / 2, y = 45;
            int last = 2;
            while (last > 0 && counts[last] == 0) last--;

            int start = 90, used = 0;
            for (int i = 0; i < 3; i++) {
                if (counts[i] == 0) continue;
                int angle = (i == last) ? 360 - used : Math.round(360f * counts[i] / total);
                g.setColor(cols[i]);
                g.fillArc(x, y, d, d, start, -angle);
                start -= angle;
                used += angle;
            }

            int ly = y + d + 28;
            for (int i = 0; i < 3; i++) {
                g.setColor(cols[i]);
                g.fillRoundRect(24, ly - 12, 14, 14, 4, 4);
                g.setColor(Theme.TEXT);
                g.setFont(Theme.BASE);
                g.drawString(names[i] + ": " + counts[i] + "  (" + (100 * counts[i] / total) + "%)", 46, ly);
                ly += 24;
            }
            g.dispose();
        }
    }
}
