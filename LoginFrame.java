import javax.swing.*;
import java.awt.*;

public class LoginFrame extends JFrame {

    private final JTextField emailField = new JTextField(20);
    private final JPasswordField passField = new JPasswordField(20);
    private int row = 0;

    public LoginFrame() {
        setTitle("Fake Website Detector - Login");
        setSize(440, 480);
        setResizable(false);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel root = new JPanel(new GridBagLayout());
        root.setBackground(Theme.BG);
        root.setBorder(BorderFactory.createEmptyBorder(30, 45, 30, 45));
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 0, 5, 0);

        JLabel title = Theme.label("Fake Website Detector", Theme.TITLE, Theme.TEXT);
        title.setHorizontalAlignment(SwingConstants.CENTER);
        addRow(root, c, title);
        JLabel sub = Theme.label("Sign in to scan URLs", Theme.BASE, Theme.MUTED);
        sub.setHorizontalAlignment(SwingConstants.CENTER);
        c.insets = new Insets(0, 0, 25, 0);
        addRow(root, c, sub);

        c.insets = new Insets(5, 0, 2, 0);
        addRow(root, c, Theme.label("Email", Theme.BOLD, Theme.TEXT));
        Theme.styleField(emailField);
        c.insets = new Insets(0, 0, 10, 0);
        addRow(root, c, emailField);

        c.insets = new Insets(5, 0, 2, 0);
        addRow(root, c, Theme.label("Password", Theme.BOLD, Theme.TEXT));
        Theme.styleField(passField);
        c.insets = new Insets(0, 0, 20, 0);
        addRow(root, c, passField);

        JButton login = Theme.button("Login", Theme.ACCENT);
        login.addActionListener(e -> doLogin());
        c.insets = new Insets(5, 0, 5, 0);
        addRow(root, c, login);

        JButton register = Theme.button("Create new account", new Color(90, 100, 120));
        register.addActionListener(e -> {
            dispose();
            new RegisterFrame().setVisible(true);
        });
        addRow(root, c, register);

        passField.addActionListener(e -> doLogin());
        setContentPane(root);
    }

    private void addRow(JPanel p, GridBagConstraints c, JComponent comp) {
        c.gridy = row++;
        p.add(comp, c);
    }

    private void doLogin() {
        String email = emailField.getText().trim().toLowerCase();
        String pass = new String(passField.getPassword());

        if (email.isEmpty() || pass.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter email and password.",
                    "Missing details", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String name = DataBaseConnection.login(email, pass);
        if (name == null) {
            JOptionPane.showMessageDialog(this, "Wrong email or password.",
                    "Login failed", JOptionPane.ERROR_MESSAGE);
            passField.setText("");
            return;
        }
        dispose();
        new DashboardFrame(email).setVisible(true);
    }
}
