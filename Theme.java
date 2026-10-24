import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.JTextComponent;
import java.awt.*;

/** Shared colours, fonts and small UI helpers so every screen looks the same. */
public final class Theme {

    public static final Color BG     = new Color(20, 30, 48);
    public static final Color PANEL  = new Color(30, 44, 68);
    public static final Color ACCENT = new Color(0, 150, 230);
    public static final Color TEXT   = new Color(235, 240, 250);
    public static final Color MUTED  = new Color(150, 165, 190);
    public static final Color SAFE   = new Color(46, 204, 113);
    public static final Color WARN   = new Color(243, 156, 18);
    public static final Color DANGER = new Color(231, 76, 60);

    public static final Font BASE = new Font("Segoe UI", Font.PLAIN, 14);
    public static final Font BOLD = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font TITLE = new Font("Segoe UI", Font.BOLD, 24);

    private Theme() {}

    public static JButton button(String text, Color bg) {
        JButton b = new JButton(text);
        b.setBackground(bg);
        b.setForeground(Color.WHITE);
        b.setFont(BOLD);
        b.setOpaque(true);
        b.setFocusPainted(false);
        b.setBorderPainted(false);
        b.setBorder(BorderFactory.createEmptyBorder(9, 18, 9, 18));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return b;
    }

    public static JLabel label(String text, Font font, Color color) {
        JLabel l = new JLabel(text);
        l.setFont(font);
        l.setForeground(color);
        return l;
    }

    public static void styleField(JTextComponent f) {
        f.setBackground(new Color(36, 52, 80));
        f.setForeground(TEXT);
        f.setCaretColor(TEXT);
        f.setFont(BASE);
        f.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(60, 80, 115)),
                BorderFactory.createEmptyBorder(7, 10, 7, 10)));
    }

    public static JScrollPane scroll(Component c) {
        JScrollPane sp = new JScrollPane(c);
        sp.setBorder(BorderFactory.createLineBorder(new Color(60, 80, 115)));
        sp.getViewport().setBackground(PANEL);
        return sp;
    }

    public static Color verdictColor(String v) {
        if (v == null) return TEXT;
        switch (v) {
            case "SAFE": case "OK": case "CAUGHT": return SAFE;
            case "SUSPICIOUS": case "FALSE ALARM": return WARN;
            case "PHISHING": case "FLAGGED": case "MISSED": return DANGER;
            default: return TEXT;
        }
    }

    /** Read-only table model. */
    public static javax.swing.table.DefaultTableModel tableModel(String... cols) {
        return new javax.swing.table.DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
    }

    /** Dark table; the text in column statusCol is coloured by verdict / status. */
    public static void styleTable(JTable t, final int statusCol) {
        t.setBackground(PANEL);
        t.setForeground(TEXT);
        t.setFont(BASE);
        t.setRowHeight(28);
        t.setGridColor(new Color(45, 60, 90));
        t.setShowVerticalLines(false);
        t.setFillsViewportHeight(true);
        t.setSelectionBackground(new Color(0, 120, 190));
        t.setSelectionForeground(Color.WHITE);

        JTableHeader h = t.getTableHeader();
        h.setBackground(new Color(12, 20, 36));
        h.setForeground(TEXT);
        h.setFont(BOLD);
        h.setReorderingAllowed(false);

        t.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tb, Object v, boolean sel,
                                                           boolean foc, int row, int col) {
                super.getTableCellRendererComponent(tb, v, sel, foc, row, col);
                setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                setToolTipText(v == null ? null : v.toString());
                setFont(col == statusCol ? BOLD : BASE);
                if (!sel) {
                    setBackground(row % 2 == 0 ? PANEL : new Color(36, 52, 80));
                    setForeground(col == statusCol ? verdictColor(String.valueOf(v)) : TEXT);
                }
                return this;
            }
        });
    }
}
