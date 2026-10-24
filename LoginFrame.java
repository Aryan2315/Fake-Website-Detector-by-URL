import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class LoginFrame extends JFrame {
    // In-memory user map (Email -> Password)
    public static final Map<String, String> USERS = new HashMap<>();
    public static final String FILE_PATH = "users.txt";

    public LoginFrame() {
        // Load existing users from users.txt into memory
        loadUsersFromFile();

        setTitle("Fake Website Detector Using URL - Login");
        setSize(450, 390);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(null);
        panel.setBackground(new Color(20, 30, 48));

        JLabel title = new JLabel("Welcome Back");
        title.setBounds(110, 25, 260, 35);
        title.setForeground(Color.WHITE);
        title.setFont(new Font("Arial", Font.BOLD, 26));
        panel.add(title);

        JLabel emailLabel = new JLabel("Email");
        emailLabel.setBounds(50, 85, 120, 25);
        emailLabel.setForeground(Color.WHITE);
        panel.add(emailLabel);

        JTextField emailField = new JTextField();
        emailField.setBounds(50, 112, 330, 35);
        panel.add(emailField);

        JLabel passwordLabel = new JLabel("Password");
        passwordLabel.setBounds(50, 158, 120, 25);
        passwordLabel.setForeground(Color.WHITE);
        panel.add(passwordLabel);

        JPasswordField passwordField = new JPasswordField();
        passwordField.setBounds(50, 185, 330, 35);
        panel.add(passwordField);

        JButton loginButton = new JButton("Login");
        loginButton.setBounds(50, 240, 155, 38);
        panel.add(loginButton);

        JButton registerButton = new JButton("Create Account");
        registerButton.setBounds(215, 240, 165, 38);
        panel.add(registerButton);

        JLabel note = new JLabel("New users: create an account first.");
        note.setBounds(50, 292, 330, 25);
        note.setForeground(Color.LIGHT_GRAY);
        panel.add(note);

        loginButton.addActionListener(e -> {
            String email = emailField.getText().trim();
            String password = new String(passwordField.getPassword());

            if (email.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Enter email and password.");
                return;
            }

            String savedPassword = USERS.get(email);
            if (savedPassword != null && savedPassword.equals(password)) {
                new DashboardFrame(email).setVisible(true);
                dispose();
            } else {
                JOptionPane.showMessageDialog(
                    this,
                    "Login failed. Check your details or create an account first.",
                    "Login Failed",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        });

        registerButton.addActionListener(e -> {
            new RegisterFrame().setVisible(true);
            dispose();
        });

        add(panel);
    }

    // Reads users from users.txt (Format: email,password)
    private void loadUsersFromFile() {
        USERS.clear();
        File file = new File(FILE_PATH);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                System.err.println("Could not create users.txt file: " + e.getMessage());
            }
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 2) {
                    USERS.put(parts[0].trim(), parts[1].trim());
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading users.txt: " + e.getMessage());
        }
    }
}