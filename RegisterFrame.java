import javax.swing.*;
import java.awt.*;

public class RegisterFrame extends JFrame {

    private final JTextField nameField = new JTextField(20);
    private final JTextField emailField = new JTextField(20);
    private final JPasswordField passField = new JPasswordField(20);
    private final JPasswordField confirmField = new JPasswordField(20);
    private int row = 0;

    public RegisterFrame() {
        setTitle("Fake Website Detector - Register");
        setSize(440, 590);
        setResizable(false);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel root = new JPanel(new GridBagLayout());
        root.setBackground(Theme.BG);
        root.setBorder(BorderFactory.createEmptyBorder(25, 45, 25, 45));
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;

        JLabel title = Theme.label("Create Account", Theme.TITLE, Theme.TEXT);
        title.setHorizontalAlignment(SwingConstants.CENTER);
        c.insets = new Insets(0, 0, 20, 0);
        addRow(root, c, title);

        addField(root, c, "Full name", nameField);
        addField(root, c, "Email", emailField);
        addField(root, c, "Password (min 6 characters)", passField);
        addField(root, c, "Confirm password", confirmField);

        JButton register = Theme.button("Register", Theme.SAFE);
        register.addActionListener(e -> doRegister());
        c.insets = new Insets(15, 0, 5, 0);
        addRow(root, c, register);

        JButton back = Theme.button("Back to login", new Color(90, 100, 120));
        back.addActionListener(e -> {
            dispose();
            new LoginFrame().setVisible(true);
        });
        c.insets = new Insets(5, 0, 5, 0);
        addRow(root, c, back);

        confirmField.addActionListener(e -> doRegister());
        setContentPane(root);
    }

    private void addField(JPanel p, GridBagConstraints c, String label, JTextField f) {
        Theme.styleField(f);
        c.insets = new Insets(5, 0, 2, 0);
        addRow(p, c, Theme.label(label, Theme.BOLD, Theme.TEXT));
        c.insets = new Insets(0, 0, 8, 0);
        addRow(p, c, f);
    }

    private void addRow(JPanel p, GridBagConstraints c, JComponent comp) {
        c.gridy = row++;
        p.add(comp, c);
    }

    private void doRegister() {
        String name = nameField.getText().trim();
        String email = emailField.getText().trim().toLowerCase();
        String pass = new String(passField.getPassword());
        String confirm = new String(confirmField.getPassword());

        String error = null;
        if (name.isEmpty()) error = "Please enter your name.";
        else if (!email.matches("^[\\w.+-]+@[\\w-]+(\\.[\\w-]+)+$")) error = "Please enter a valid email address.";
        else if (pass.length() < 6) error = "Password must be at least 6 characters.";
        else if (!pass.equals(confirm)) error = "Passwords do not match.";
        else if (DataBaseConnection.userExists(email)) error = "This email is already registered.";

        if (error != null) {
            JOptionPane.showMessageDialog(this, error, "Cannot register", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (DataBaseConnection.registerUser(name, email, pass)) {
            JOptionPane.showMessageDialog(this, "Account created! You can log in now.",
                    "Success", JOptionPane.INFORMATION_MESSAGE);
            dispose();
            new LoginFrame().setVisible(true);
        } else {
            JOptionPane.showMessageDialog(this, "Could not save the account. Check file permissions.",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
