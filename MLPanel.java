import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;

/** Tab for feature 8: train a machine-learning model from the CSV dataset and test it. */
public class MLPanel extends JPanel {

    private final JTextField pathField = new JTextField("dataset_phishing.csv");
    private final JTextArea out = new JTextArea();
    private final JLabel status = Theme.label(" ", Theme.BASE, Theme.MUTED);
    private final MetricsChart chart = new MetricsChart();
    private final JTextField testField = new JTextField();
    private final JLabel testResult = Theme.label(" ", Theme.BOLD, Theme.TEXT);
    private final JButton trainBtn = Theme.button("Train Model", Theme.SAFE);

    public MLPanel() {
        setLayout(new BorderLayout(0, 12));
        setBackground(Theme.BG);
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // top: dataset path + buttons
        Theme.styleField(pathField);
        JButton browse = Theme.button("Browse...", Theme.ACCENT);
        browse.addActionListener(e -> browse());
        trainBtn.addActionListener(e -> train());
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btns.setOpaque(false);
        btns.add(browse);
        btns.add(trainBtn);
        JPanel top = new JPanel(new BorderLayout(10, 0));
        top.setOpaque(false);
        top.add(Theme.label("Dataset (CSV):", Theme.BOLD, Theme.TEXT), BorderLayout.WEST);
        top.add(pathField, BorderLayout.CENTER);
        top.add(btns, BorderLayout.EAST);

        JPanel north = new JPanel(new BorderLayout(0, 6));
        north.setOpaque(false);
        north.add(top, BorderLayout.NORTH);
        north.add(status, BorderLayout.SOUTH);

        // centre: report text + chart
        out.setEditable(false);
        out.setFont(new Font("Consolas", Font.PLAIN, 14));
        out.setBackground(new Color(12, 20, 36));
        out.setForeground(new Color(120, 230, 160));
        out.setMargin(new Insets(10, 12, 10, 12));
        chart.setPreferredSize(new Dimension(340, 100));
        JPanel center = new JPanel(new BorderLayout(12, 0));
        center.setOpaque(false);
        center.add(Theme.scroll(out), BorderLayout.CENTER);
        center.add(chart, BorderLayout.EAST);

        // bottom: quick test
        Theme.styleField(testField);
        testField.addActionListener(e -> predict());
        JButton predict = Theme.button("Predict", Theme.ACCENT);
        predict.addActionListener(e -> predict());
        JPanel row = new JPanel(new BorderLayout(10, 0));
        row.setOpaque(false);
        row.add(Theme.label("Test a URL:", Theme.BOLD, Theme.TEXT), BorderLayout.WEST);
        row.add(testField, BorderLayout.CENTER);
        row.add(predict, BorderLayout.EAST);
        JPanel south = new JPanel(new BorderLayout(0, 6));
        south.setOpaque(false);
        south.add(row, BorderLayout.NORTH);
        south.add(testResult, BorderLayout.SOUTH);

        add(north, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        if (MLModel.isTrained()) {
            out.setText(MLModel.describe((int) (MLModel.trainedOn() * 0.8),
                    MLModel.trainedOn() - (int) (MLModel.trainedOn() * 0.8)));
            status.setText("Saved model loaded from " + MLModel.MODEL_FILE);
        } else {
            out.setText("No model yet.\n\n1. Put dataset_phishing.csv in your project folder\n"
                    + "   (the CSV needs a 'url' column and a label column such as 'status').\n"
                    + "2. Click \"Train Model\".\n"
                    + "3. Test any URL below, or scan on the first tab.");
        }
    }

    private void browse() {
        JFileChooser fc = new JFileChooser(new File("."));
        fc.setFileFilter(new FileNameExtensionFilter("CSV files", "csv"));
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            pathField.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private void train() {
        final File f = new File(pathField.getText().trim());
        trainBtn.setEnabled(false);
        status.setText("Reading dataset and training... (can take a few seconds)");
        out.setText("Working...");

        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() throws Exception {
                MLModel.Dataset d = MLModel.loadCsv(f);
                String head = "Dataset : " + f.getName() + "\n"
                        + "Label   : column '" + d.labelColumn + "'\n"
                        + "Rows    : " + d.urls.size() + " used (" + d.phishing + " phishing, "
                        + d.legit + " legitimate), " + d.skipped + " skipped\n\n";
                return head + MLModel.train(d);
            }
            @Override protected void done() {
                try {
                    out.setText(get());
                    status.setText("Training finished. Model saved to " + MLModel.MODEL_FILE);
                } catch (Exception ex) {
                    Throwable t = ex.getCause() != null ? ex.getCause() : ex;
                    out.setText("Training failed:\n" + t.getMessage());
                    status.setText("Training failed.");
                }
                out.setCaretPosition(0);
                trainBtn.setEnabled(true);
                chart.repaint();
            }
        }.execute();
    }

    private void predict() {
        String url = testField.getText().trim();
        if (!MLModel.isTrained()) {
            testResult.setForeground(Theme.WARN);
            testResult.setText("Train the model first.");
            return;
        }
        if (!PhisingDetector.looksLikeUrl(url)) {
            testResult.setForeground(Theme.WARN);
            testResult.setText("Enter a valid URL.");
            return;
        }
        double p = MLModel.predict(url);
        boolean bad = p >= 0.5;
        testResult.setForeground(bad ? Theme.DANGER : Theme.SAFE);
        testResult.setText(String.format("ML says: %s  (phishing probability %.1f %%)",
                bad ? "PHISHING" : "LEGITIMATE", p * 100));
    }

    /** Bars for accuracy / precision / recall / F1 and the confusion matrix. */
    private static class MetricsChart extends JPanel {
        MetricsChart() { setOpaque(false); }

        @Override protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();
            g.setColor(Theme.PANEL);
            g.fillRoundRect(0, 0, w, h, 16, 16);
            g.setFont(Theme.BOLD);
            g.setColor(Theme.TEXT);
            g.drawString("Model performance", 16, 28);

            if (!MLModel.isTrained()) {
                g.setColor(Theme.MUTED);
                g.setFont(Theme.BASE);
                g.drawString("Not trained yet", 16, 60);
                g.dispose();
                return;
            }
            String[] names = {"Accuracy", "Precision", "Recall", "F1"};
            double[] vals = {MLModel.accuracy(), MLModel.precision(), MLModel.recall(), MLModel.f1()};
            int y = 48, bw = w - 32;
            for (int i = 0; i < 4; i++) {
                g.setFont(Theme.BASE);
                g.setColor(Theme.MUTED);
                g.drawString(names[i], 16, y + 12);
                g.setColor(new Color(50, 65, 95));
                g.fillRoundRect(16, y + 18, bw, 12, 12, 12);
                g.setColor(Theme.ACCENT);
                g.fillRoundRect(16, y + 18, Math.max(12, (int) (bw * vals[i])), 12, 12, 12);
                g.setColor(Theme.TEXT);
                g.drawString(String.format("%.1f%%", vals[i] * 100), w - 70, y + 12);
                y += 44;
            }

            // confusion matrix
            y += 14;
            g.setFont(Theme.BOLD);
            g.setColor(Theme.TEXT);
            g.drawString("Confusion matrix", 16, y);
            int cw = (w - 48) / 2, ch = 52, x0 = 16, y0 = y + 12;
            int[][] v = {{MLModel.tn(), MLModel.fp()}, {MLModel.fn(), MLModel.tp()}};
            String[][] t = {{"Legit OK", "False alarm"}, {"Missed", "Caught"}};
            Color[][] c = {{Theme.SAFE, Theme.WARN}, {Theme.DANGER, Theme.SAFE}};
            for (int r = 0; r < 2; r++) {
                for (int q = 0; q < 2; q++) {
                    int x = x0 + q * (cw + 16), yy = y0 + r * (ch + 8);
                    g.setColor(new Color(c[r][q].getRed(), c[r][q].getGreen(), c[r][q].getBlue(), 70));
                    g.fillRoundRect(x, yy, cw, ch, 10, 10);
                    g.setColor(Theme.TEXT);
                    g.setFont(new Font("Segoe UI", Font.BOLD, 18));
                    g.drawString(String.valueOf(v[r][q]), x + 10, yy + 24);
                    g.setFont(new Font("Segoe UI", Font.PLAIN, 12));
                    g.setColor(Theme.MUTED);
                    g.drawString(t[r][q], x + 10, yy + 42);
                }
            }
            g.dispose();
        }
    }
}
