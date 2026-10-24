import javax.swing.*;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class RegisterFrame extends JFrame {

    public RegisterFrame() {
        setTitle("Fake Website Detector - Register");
        setSize(450, 450);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(null);
        panel.setBackground(new Color(20, 30, 48));

        JLabel title = new JLabel("Create Account");
        title.setBounds(105, 25, 260, 35);
        title.setForeground(Color.WHITE);
        title.setFont(new Font("Arial", Font.BOLD, 25));
        panel.add(title);

        JLabel userLabel = new JLabel("Username");
        userLabel.setBounds(50, 80, 120, 25);
        userLabel.setForeground(Color.WHITE);
        panel.add(userLabel);

        JTextField usernameField = new JTextField();
        usernameField.setBounds(50, 107, 330, 35);
        panel.add(usernameField);

        JLabel emailLabel = new JLabel("Email");
        emailLabel.setBounds(50, 150, 120, 25);
        emailLabel.setForeground(Color.WHITE);
        panel.add(emailLabel);

        JTextField emailField = new JTextField();
        emailField.setBounds(50, 177, 330, 35);
        panel.add(emailField);

        JLabel passwordLabel = new JLabel("Password");
        passwordLabel.setBounds(50, 220, 120, 25);
        passwordLabel.setForeground(Color.WHITE);
        panel.add(passwordLabel);

        JPasswordField passwordField = new JPasswordField();
        passwordField.setBounds(50, 247, 330, 35);
        panel.add(passwordField);

        JButton registerButton = new JButton("Register");
        registerButton.setBounds(50, 300, 155, 38);
        panel.add(registerButton);

        JButton backButton = new JButton("Back to Login");
        backButton.setBounds(215, 300, 165, 38);
        panel.add(backButton);

        registerButton.addActionListener(e -> {
            String username = usernameField.getText().trim();
            String email = emailField.getText().trim();
            String password = new String(passwordField.getPassword());

            if (username.isEmpty() || email.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please fill in all fields.");
                return;
            }
            if (!email.contains("@") || !email.contains(".")) {
                JOptionPane.showMessageDialog(this, "Enter a valid email address.");
                return;
            }
            if (password.length() < 6) {
                JOptionPane.showMessageDialog(this, "Password must be at least 6 characters.");
                return;
            }
            if (LoginFrame.USERS.containsKey(email)) {
                JOptionPane.showMessageDialog(this, "An account with this email already exists.");
                return;
            }

            // Save user in memory
            LoginFrame.USERS.put(email, password);

            // Append user details to users.txt
            saveUserToFile(email, password);

            JOptionPane.showMessageDialog(this, "Account created. Please log in.");
            new LoginFrame().setVisible(true);
            dispose();
        });

        backButton.addActionListener(e -> {
            new LoginFrame().setVisible(true);
            dispose();
        });

        add(panel);
    }

    private void saveUserToFile(String email, String password) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LoginFrame.FILE_PATH, true))) {
            writer.write(email + "," + password);
            writer.newLine();
        } catch (IOException e) {
            JOptionPane.showMessageDialog(
                this,
                "Error saving account data to file: " + e.getMessage(),
                "Storage Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }
}