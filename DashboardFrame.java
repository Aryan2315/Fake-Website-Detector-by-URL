import javax.swing.*;
import java.awt.*;
import java.net.URI;

public class DashboardFrame extends JFrame {

    private PhisingDetector.ScanResult lastScanResult;
    private String lastScannedUrl;
    private final String currentUserEmail;

    public DashboardFrame(String email) {
        this.currentUserEmail = email;

        setTitle("Fake Website Detector - Dashboard");
        setSize(780, 560);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(null);
        panel.setBackground(new Color(20, 30, 48));

        JLabel title = new JLabel("Fake Website Detector Using URL");
        title.setBounds(40, 25, 700, 40);
        title.setFont(new Font("Arial", Font.BOLD, 28));
        title.setForeground(Color.WHITE);
        panel.add(title);

        JLabel welcome = new JLabel("Welcome, " + email + "!");
        welcome.setBounds(40, 75, 500, 30);
        welcome.setFont(new Font("Arial", Font.PLAIN, 17));
        welcome.setForeground(Color.LIGHT_GRAY);
        panel.add(welcome);

        JLabel urlLabel = new JLabel("Enter website URL to check:");
        urlLabel.setBounds(40, 130, 400, 30);
        urlLabel.setForeground(Color.WHITE);
        panel.add(urlLabel);

        JTextField urlField = new JTextField();
        urlField.setBounds(40, 170, 480, 40);
        panel.add(urlField);

        JButton checkButton = new JButton("Check URL");
        checkButton.setBounds(535, 170, 185, 40);
        panel.add(checkButton);

        // Result and Status Display Area
        JLabel resultLabel = new JLabel("Status: Ready to scan.");
        resultLabel.setBounds(40, 230, 680, 30);
        resultLabel.setForeground(Color.WHITE);
        resultLabel.setFont(new Font("Arial", Font.BOLD, 15));
        panel.add(resultLabel);

        JTextArea detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        detailsArea.setBackground(new Color(30, 42, 64));
        detailsArea.setForeground(Color.WHITE);
        
        JScrollPane scrollPane = new JScrollPane(detailsArea);
        scrollPane.setBounds(40, 270, 680, 150);
        panel.add(scrollPane);

        // Action Buttons
        JButton reportButton = new JButton("View Full Report");
        reportButton.setBounds(40, 440, 170, 38);
        reportButton.setEnabled(false); // Disabled until a scan is run
        panel.add(reportButton);

        JButton logoutButton = new JButton("Logout");
        logoutButton.setBounds(230, 440, 120, 38);
        panel.add(logoutButton);

        // Check URL Button Logic
        checkButton.addActionListener(e -> {
            String input = urlField.getText().trim();

            if (input.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter a website URL.", "Input Required", JOptionPane.WARNING_MESSAGE);
                return;
            }

            String candidate = input.contains("://") ? input : "https://" + input;
            try {
                URI uri = URI.create(candidate);
                String scheme = uri.getScheme();
                String host = uri.getHost();

                if (host == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                    resultLabel.setForeground(new Color(255, 180, 100));
                    resultLabel.setText("Invalid URL format. Please enter a valid web address.");
                    detailsArea.setText("");
                    reportButton.setEnabled(false);
                    return;
                }

                // Run Phishing Scanner & Database Logging
                URLscanner scanner = new URLscanner();
                lastScannedUrl = candidate;
                lastScanResult = scanner.scanUrl(currentUserEmail, candidate);

                // Update UI based on scan verdict
                String status = lastScanResult.getStatus();
                int risk = lastScanResult.getRiskScore();

                if (status.equalsIgnoreCase("Phishing")) {
                    resultLabel.setForeground(new Color(255, 100, 100));
                } else if (status.equalsIgnoreCase("Suspicious")) {
                    resultLabel.setForeground(new Color(255, 200, 100));
                } else {
                    resultLabel.setForeground(new Color(100, 255, 150));
                }

                resultLabel.setText("Verdict: " + status + " | Risk Score: " + risk + "% (Saved to database)");
                detailsArea.setText(lastScanResult.getDetails());
                reportButton.setEnabled(true);

            } catch (IllegalArgumentException ex) {
                resultLabel.setForeground(new Color(255, 120, 120));
                resultLabel.setText("Invalid URL. Please check what you entered.");
                detailsArea.setText("");
                reportButton.setEnabled(false);
            }
        });

        // View Full Report Button Logic
        reportButton.addActionListener(e -> {
            if (lastScanResult != null) {
                String textReport = ReportGenerator.generateTextReport(currentUserEmail, lastScannedUrl, lastScanResult);
                
                JTextArea reportText = new JTextArea(textReport);
                reportText.setEditable(false);
                reportText.setFont(new Font("Monospaced", Font.PLAIN, 13));

                JOptionPane.showMessageDialog(
                    this,
                    new JScrollPane(reportText),
                    "Detailed Phishing Scan Report",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        });

        // Logout Button Logic
        logoutButton.addActionListener(e -> {
            new LoginFrame().setVisible(true);
            dispose();
        });

        add(panel);
    }
}