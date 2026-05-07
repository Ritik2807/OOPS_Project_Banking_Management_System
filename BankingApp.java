import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.sql.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

// ================================================================
//   HERA PHERI BANK - GUI Version (Java Swing + MySQL)
//   OOP Concepts: Classes, Objects, Encapsulation, Inheritance,
//                 JDBC, ArrayList, Event Handling
//   Features: Sign Up, Login, Deposit, Withdraw, Balance Enquiry,
//             Fund Transfer, Mini Statement, Profile Page,
//             Change Password, Admin Panel, Password Hashing (SHA-256)
// ================================================================

// ------------------------------------------------------------------
// CLASS 0: Transaction
// ------------------------------------------------------------------
class Transaction {
    private String type, description, timestamp;
    private double amount, balanceAfter;

    public Transaction(String type, double amount, double balanceAfter,
                       String description, String timestamp) {
        this.type = type; this.amount = amount; this.balanceAfter = balanceAfter;
        this.description = description; this.timestamp = timestamp;
    }
    public String getType()         { return type; }
    public double getAmount()       { return amount; }
    public double getBalanceAfter() { return balanceAfter; }
    public String getDescription()  { return description; }
    public String getTimestamp()    { return timestamp; }
}

// ------------------------------------------------------------------
// CLASS 1: PasswordUtil — SHA-256 Hashing
// Concept: Utility class, static methods
// ------------------------------------------------------------------
class PasswordUtil {
    // Converts plain text password to SHA-256 hash (64 hex characters)
    public static String hash(String plainText) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(plainText.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes)
                sb.append(String.format("%02x", b));  // convert each byte to hex
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available: " + e.getMessage());
        }
    }

    // Checks if plain password matches stored hash
    public static boolean verify(String plainText, String storedHash) {
        return hash(plainText).equals(storedHash);
    }
}

// ------------------------------------------------------------------
// CLASS 2: DBHelper — all SQL queries
// ------------------------------------------------------------------
class DBHelper {

    // ── CONFIGURE THESE ───────────────────────────────────────────
    static final String DB_URL  = "jdbc:mysql://localhost:3306/banking_db"
            + "?useSSL=false&serverTimezone=Asia/Kolkata"
            + "&allowPublicKeyRetrieval=true";
    static final String DB_USER = "root";
    static final String DB_PASS = "1234";   //  MySQL password
    // ─────────────────────────────────────────────────────────────

    private Connection conn;

    public DBHelper() throws SQLException {
        try { Class.forName("com.mysql.cj.jdbc.Driver"); }
        catch (ClassNotFoundException ex) {
            throw new SQLException("MySQL JDBC Driver not found.\n"
                    + "Add mysql-connector-j-*.jar to your classpath.\n" + ex.getMessage());
        }
        conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        createTables();
    }

    private void createTables() throws SQLException {
        Statement st = conn.createStatement();

        // accounts table — password column stores SHA-256 hash (64 chars)
        st.execute(
                "CREATE TABLE IF NOT EXISTS accounts (" +
                        "  id             INT AUTO_INCREMENT PRIMARY KEY," +
                        "  username       VARCHAR(50)  NOT NULL UNIQUE," +
                        "  password       VARCHAR(64)  NOT NULL," +   // SHA-256 hex = 64 chars
                        "  account_number VARCHAR(20)  NOT NULL UNIQUE," +
                        "  balance        DOUBLE       NOT NULL DEFAULT 0.0," +
                        "  created_at     TIMESTAMP    DEFAULT CURRENT_TIMESTAMP" +
                        ")"
        );

        // transactions table
        st.execute(
                "CREATE TABLE IF NOT EXISTS transactions (" +
                        "  id             INT AUTO_INCREMENT PRIMARY KEY," +
                        "  account_number VARCHAR(20)  NOT NULL," +
                        "  type           CHAR(2)      NOT NULL," +
                        "  amount         DOUBLE       NOT NULL," +
                        "  balance_after  DOUBLE       NOT NULL," +
                        "  description    VARCHAR(255) NOT NULL," +
                        "  txn_time       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP," +
                        "  FOREIGN KEY (account_number)" +
                        "      REFERENCES accounts(account_number) ON DELETE CASCADE" +
                        ")"
        );

        // account number counter
        st.execute(
                "CREATE TABLE IF NOT EXISTS acc_counter (" +
                        "  id      INT PRIMARY KEY DEFAULT 1," +
                        "  counter INT NOT NULL DEFAULT 1001" +
                        ")"
        );
        st.execute("INSERT IGNORE INTO acc_counter (id, counter) VALUES (1, 1001)");

        // admin table — stores admin credentials (also hashed)
        st.execute(
                "CREATE TABLE IF NOT EXISTS admins (" +
                        "  id       INT AUTO_INCREMENT PRIMARY KEY," +
                        "  username VARCHAR(50)  NOT NULL UNIQUE," +
                        "  password VARCHAR(64)  NOT NULL" +
                        ")"
        );

        // Insert default admin: username=admin, password=admin123 (hashed)
        String adminHash = PasswordUtil.hash("admin123");
        st.execute("INSERT IGNORE INTO admins (username, password) VALUES ('admin', '" + adminHash + "')");

        st.close();
    }

    // ── Account number generator ──────────────────────────────────
    public synchronized String nextAccountNumber() throws SQLException {
        PreparedStatement rd = conn.prepareStatement("SELECT counter FROM acc_counter WHERE id=1");
        ResultSet rs = rd.executeQuery(); rs.next();
        int n = rs.getInt("counter"); rs.close(); rd.close();
        PreparedStatement up = conn.prepareStatement("UPDATE acc_counter SET counter=counter+1 WHERE id=1");
        up.executeUpdate(); up.close();
        return "ACC" + n;
    }

    // ── Account helpers ───────────────────────────────────────────
    public boolean usernameExists(String username) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT id FROM accounts WHERE username=?");
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();
        boolean e = rs.next(); rs.close(); ps.close(); return e;
    }

    public boolean accountNumberExists(String accNo) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT id FROM accounts WHERE account_number=?");
        ps.setString(1, accNo);
        ResultSet rs = ps.executeQuery();
        boolean e = rs.next(); rs.close(); ps.close(); return e;
    }

    public String createAccount(String username, String password) throws SQLException {
        String accNo = nextAccountNumber();
        String hashed = PasswordUtil.hash(password);   // hash before storing
        PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO accounts (username, password, account_number, balance) VALUES (?,?,?,0.0)");
        ps.setString(1, username); ps.setString(2, hashed); ps.setString(3, accNo);
        ps.executeUpdate(); ps.close();
        return accNo;
    }

    public Account login(String username, String password) throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
                "SELECT username, password, account_number, balance, created_at FROM accounts WHERE username=?");
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();
        Account acc = null;
        if (rs.next() && PasswordUtil.verify(password, rs.getString("password"))) {
            acc = new Account(rs.getString("username"), rs.getString("password"),
                    rs.getString("account_number"), rs.getDouble("balance"),
                    rs.getString("created_at"));
        }
        rs.close(); ps.close(); return acc;
    }

    public void updateBalance(String accNo, double bal) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("UPDATE accounts SET balance=? WHERE account_number=?");
        ps.setDouble(1, bal); ps.setString(2, accNo); ps.executeUpdate(); ps.close();
    }

    public double getBalance(String accNo) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT balance FROM accounts WHERE account_number=?");
        ps.setString(1, accNo);
        ResultSet rs = ps.executeQuery();
        double bal = 0; if (rs.next()) bal = rs.getDouble("balance");
        rs.close(); ps.close(); return bal;
    }

    // Change password — verifies old password first, then updates hash
    public String changePassword(String accNo, String oldPass, String newPass) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT password FROM accounts WHERE account_number=?");
        ps.setString(1, accNo);
        ResultSet rs = ps.executeQuery();
        if (!rs.next()) { rs.close(); ps.close(); return "ERROR:Account not found."; }
        String storedHash = rs.getString("password"); rs.close(); ps.close();
        if (!PasswordUtil.verify(oldPass, storedHash)) return "ERROR:Current password is incorrect.";
        if (newPass.length() < 4) return "ERROR:New password must be at least 4 characters.";
        PreparedStatement up = conn.prepareStatement("UPDATE accounts SET password=? WHERE account_number=?");
        up.setString(1, PasswordUtil.hash(newPass)); up.setString(2, accNo);
        up.executeUpdate(); up.close();
        return "SUCCESS:Password changed successfully!";
    }

    public void logTransaction(String accNo, String type, double amount,
                               double balAfter, String desc) throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO transactions (account_number,type,amount,balance_after,description) VALUES(?,?,?,?,?)");
        ps.setString(1, accNo); ps.setString(2, type); ps.setDouble(3, amount);
        ps.setDouble(4, balAfter); ps.setString(5, desc);
        ps.executeUpdate(); ps.close();
    }

    public ArrayList<Transaction> getMiniStatement(String accNo, int limit) throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
                "SELECT type,amount,balance_after,description," +
                        "DATE_FORMAT(txn_time,'%d-%b-%Y  %H:%i:%s') AS ts" +
                        " FROM transactions WHERE account_number=? ORDER BY id DESC LIMIT ?");
        ps.setString(1, accNo); ps.setInt(2, limit);
        ResultSet rs = ps.executeQuery();
        ArrayList<Transaction> list = new ArrayList<>();
        while (rs.next()) list.add(new Transaction(rs.getString("type"), rs.getDouble("amount"),
                rs.getDouble("balance_after"), rs.getString("description"), rs.getString("ts")));
        rs.close(); ps.close(); return list;
    }

    // Atomic fund transfer wrapped in DB transaction
    public String transfer(Account sender, String recipientAccNo, double amount) throws SQLException {
        if (sender.getAccountNumber().equalsIgnoreCase(recipientAccNo))
            return "ERROR:You cannot transfer to your own account.";
        if (amount <= 0) return "ERROR:Transfer amount must be greater than 0.";
        if (!accountNumberExists(recipientAccNo)) return "ERROR:Recipient account not found.";
        double senderBal = getBalance(sender.getAccountNumber());
        if (senderBal < amount) return "ERROR:Insufficient balance! Available: Rs." + String.format("%.2f", senderBal);
        PreparedStatement ps2 = conn.prepareStatement("SELECT username FROM accounts WHERE account_number=?");
        ps2.setString(1, recipientAccNo);
        ResultSet rs2 = ps2.executeQuery();
        String rName = rs2.next() ? rs2.getString("username") : recipientAccNo;
        rs2.close(); ps2.close();
        conn.setAutoCommit(false);
        try {
            double nSBal = senderBal - amount;
            double nRBal = getBalance(recipientAccNo) + amount;
            updateBalance(sender.getAccountNumber(), nSBal);
            updateBalance(recipientAccNo, nRBal);
            logTransaction(sender.getAccountNumber(), "DR", amount, nSBal,
                    "Transfer to " + rName + " (" + recipientAccNo.toUpperCase() + ")");
            logTransaction(recipientAccNo, "CR", amount, nRBal,
                    "Transfer from " + sender.getUsername() + " (" + sender.getAccountNumber() + ")");
            conn.commit(); sender.setBalance(nSBal);
            return "SUCCESS:Rs." + String.format("%.2f", amount) + " transferred to " + rName + " successfully!";
        } catch (SQLException ex) { conn.rollback(); throw ex; }
        finally { conn.setAutoCommit(true); }
    }

    // ── Admin helpers ─────────────────────────────────────────────
    public boolean adminLogin(String username, String password) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT password FROM admins WHERE username=?");
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();
        boolean ok = rs.next() && PasswordUtil.verify(password, rs.getString("password"));
        rs.close(); ps.close(); return ok;
    }

    // Returns all accounts for admin view
    public ArrayList<String[]> getAllAccounts() throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
                "SELECT username, account_number, balance," +
                        " DATE_FORMAT(created_at,'%d-%b-%Y') AS joined" +
                        " FROM accounts ORDER BY id");
        ResultSet rs = ps.executeQuery();
        ArrayList<String[]> list = new ArrayList<>();
        while (rs.next()) list.add(new String[]{
                rs.getString("username"), rs.getString("account_number"),
                String.format("%.2f", rs.getDouble("balance")), rs.getString("joined")
        });
        rs.close(); ps.close(); return list;
    }

    // Returns total accounts, total balance stats
    public String[] getStats() throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
                "SELECT COUNT(*) AS total, SUM(balance) AS totalBal FROM accounts");
        ResultSet rs = ps.executeQuery(); rs.next();
        int total = rs.getInt("total");
        double totalBal = rs.getDouble("totalBal");
        rs.close(); ps.close();
        PreparedStatement ps2 = conn.prepareStatement("SELECT COUNT(*) AS txns FROM transactions");
        ResultSet rs2 = ps2.executeQuery(); rs2.next();
        int txns = rs2.getInt("txns"); rs2.close(); ps2.close();
        return new String[]{String.valueOf(total), String.format("%.2f", totalBal), String.valueOf(txns)};
    }

    public void close() {
        try { if (conn != null && !conn.isClosed()) conn.close(); } catch (SQLException ignored) {}
    }
}

// ------------------------------------------------------------------
// CLASS 3: Account — in-memory logged-in user
// ------------------------------------------------------------------
class Account {
    private String username, password, accountNumber, createdAt;
    private double balance;

    public Account(String username, String password, String accountNumber,
                   double balance, String createdAt) {
        this.username = username; this.password = password;
        this.accountNumber = accountNumber; this.balance = balance;
        this.createdAt = createdAt;
    }
    public String getUsername()      { return username; }
    public String getAccountNumber() { return accountNumber; }
    public double getBalance()       { return balance; }
    public String getCreatedAt()     { return createdAt != null ? createdAt : "N/A"; }
    public void   setBalance(double b) { this.balance = b; }
    public boolean checkPassword(String pwd) { return PasswordUtil.verify(pwd, this.password); }
}

// ------------------------------------------------------------------
// CLASS 4: Bank — business logic layer
// ------------------------------------------------------------------
class Bank {
    private DBHelper db;
    public Bank(DBHelper db) { this.db = db; }

    public String signUp(String username, String password) {
        try {
            if (username.isEmpty() || password.isEmpty()) return "ERROR:Fields cannot be empty.";
            if (password.length() < 4) return "ERROR:Password must be at least 4 characters.";
            if (db.usernameExists(username)) return "ERROR:Username already taken.";
            return "SUCCESS:Account created! Account No: " + db.createAccount(username, password);
        } catch (SQLException e) { return "ERROR:DB error: " + e.getMessage(); }
    }

    public Account login(String u, String p) {
        try { return db.login(u, p); } catch (SQLException e) { return null; }
    }

    public boolean userExists(String u) {
        try { return db.usernameExists(u); } catch (SQLException e) { return false; }
    }

    public String deposit(Account acc, double amount) {
        try {
            if (amount <= 0) return "ERROR:Amount must be greater than 0.";
            double newBal = acc.getBalance() + amount;
            db.updateBalance(acc.getAccountNumber(), newBal);
            db.logTransaction(acc.getAccountNumber(), "CR", amount, newBal, "Deposit");
            acc.setBalance(newBal);
            return "SUCCESS:Rs." + String.format("%.2f", amount) + " deposited!";
        } catch (SQLException e) { return "ERROR:" + e.getMessage(); }
    }

    public String withdraw(Account acc, double amount) {
        try {
            if (amount <= 0) return "ERROR:Amount must be greater than 0.";
            if (amount > acc.getBalance()) return "ERROR:Insufficient balance! Available: Rs." + String.format("%.2f", acc.getBalance());
            double newBal = acc.getBalance() - amount;
            db.updateBalance(acc.getAccountNumber(), newBal);
            db.logTransaction(acc.getAccountNumber(), "DR", amount, newBal, "Withdrawal");
            acc.setBalance(newBal);
            return "SUCCESS:Rs." + String.format("%.2f", amount) + " withdrawn!";
        } catch (SQLException e) { return "ERROR:" + e.getMessage(); }
    }

    public String transferFunds(Account sender, String recipientAccNo, double amount) {
        try { return db.transfer(sender, recipientAccNo, amount); }
        catch (SQLException e) { return "ERROR:" + e.getMessage(); }
    }

    public String changePassword(String accNo, String oldPass, String newPass) {
        try { return db.changePassword(accNo, oldPass, newPass); }
        catch (SQLException e) { return "ERROR:" + e.getMessage(); }
    }

    public ArrayList<Transaction> getMiniStatement(String accNo) {
        try { return db.getMiniStatement(accNo, 5); } catch (SQLException e) { return new ArrayList<>(); }
    }

    public boolean adminLogin(String u, String p) {
        try { return db.adminLogin(u, p); } catch (SQLException e) { return false; }
    }

    public ArrayList<String[]> getAllAccounts() {
        try { return db.getAllAccounts(); } catch (SQLException e) { return new ArrayList<>(); }
    }

    public String[] getStats() {
        try { return db.getStats(); } catch (SQLException e) { return new String[]{"0","0","0"}; }
    }
}

// ------------------------------------------------------------------
// CLASS 5: BankingApp — Main GUI
// ------------------------------------------------------------------
public class BankingApp extends JFrame {

    // Colors
    static final Color BG       = new Color(245,247,252);
    static final Color CARD     = Color.WHITE;
    static final Color PRIMARY  = new Color(37,99,235);
    static final Color PRIM_D   = new Color(29,78,216);
    static final Color SUCCESS  = new Color(22,163,74);
    static final Color DANGER   = new Color(220,38,38);
    static final Color TEXT     = new Color(15,23,42);
    static final Color MUTED    = new Color(100,116,139);
    static final Color BORDER   = new Color(226,232,240);
    static final Color PURPLE   = new Color(109,40,217);
    static final Color TEAL     = new Color(13,148,136);
    static final Color TEAL_D   = new Color(15,118,110);
    static final Color ORANGE   = new Color(234,88,12);
    static final Color CR_COL   = new Color(22,163,74);
    static final Color DR_COL   = new Color(220,38,38);

    DBHelper   db;
    Bank       bank;
    Account    currentAccount = null;
    JPanel     mainPanel;
    CardLayout cardLayout;
    JLabel     dashGreet, dashAccNo, dashBalance, txnMsg;

    public BankingApp() {
        setTitle("Hera Pheri Bank \uD83C\uDFE6");
        setSize(460, 760);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(true);

        try { db = new DBHelper(); bank = new Bank(db); }
        catch (SQLException e) {
            JOptionPane.showMessageDialog(null,
                    "Cannot connect to MySQL.\n\n" + e.getMessage() +
                            "\n\nCheck:\n 1. MySQL running\n 2. DB_PASS in DBHelper\n 3. banking_db exists\n 4. JDBC JAR on classpath",
                    "DB Connection Failed", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }

        cardLayout = new CardLayout();
        mainPanel  = new JPanel(cardLayout);
        mainPanel.setBackground(BG);

        mainPanel.add(buildWelcomeScreen(), "WELCOME");
        mainPanel.add(buildSignUpScreen(),  "SIGNUP");
        mainPanel.add(buildLoginScreen(),   "LOGIN");
        mainPanel.add(buildAdminLogin(),    "ADMIN_LOGIN");

        JScrollPane dashScroll = new JScrollPane(buildDashboard());
        dashScroll.setBorder(null);
        dashScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        dashScroll.getVerticalScrollBar().setUnitIncrement(16);
        mainPanel.add(dashScroll, "DASHBOARD");

        add(mainPanel);
        cardLayout.show(mainPanel, "WELCOME");
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) { db.close(); }
        });
        setVisible(true);
    }

    // ================================================================
    //  SCREEN 1: Welcome
    // ================================================================
    JPanel buildWelcomeScreen() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBackground(BG);
        GridBagConstraints g = new GridBagConstraints();
        g.fill = GridBagConstraints.HORIZONTAL; g.gridx = 0;

        g.gridy=0; g.insets=new Insets(0,40,8,40);
        JLabel icon = new JLabel("\uD83C\uDFE6", SwingConstants.CENTER);
        icon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 56));
        p.add(icon, g);

        g.gridy=1; g.insets=new Insets(0,40,4,40);
        JLabel title = label("Hera Pheri Bank", 24, Font.BOLD, TEXT);
        title.setHorizontalAlignment(SwingConstants.CENTER); p.add(title, g);

        g.gridy=2; g.insets=new Insets(0,40,30,40);
        JLabel sub = label("Secure  •  Simple  •  Reliable", 13, Font.PLAIN, MUTED);
        sub.setHorizontalAlignment(SwingConstants.CENTER); p.add(sub, g);

        g.gridy=3; g.insets=new Insets(6,50,6,50);
        JButton b1 = primaryBtn("Create New Account");
        b1.addActionListener(e -> cardLayout.show(mainPanel, "SIGNUP")); p.add(b1, g);

        g.gridy=4;
        JButton b2 = outlineBtn("Log In to Existing Account");
        b2.addActionListener(e -> cardLayout.show(mainPanel, "LOGIN")); p.add(b2, g);

        g.gridy=5; g.insets=new Insets(8,50,6,50);
        JButton b3 = makeBtn("Admin Panel", new Color(30,41,59), new Color(15,23,42));
        b3.addActionListener(e -> cardLayout.show(mainPanel, "ADMIN_LOGIN")); p.add(b3, g);

        g.gridy=6; g.insets=new Insets(28,40,0,40);
        JLabel footer = label("B.Tech CSE Project  •  OOPs in Java  •  MySQL", 11, Font.PLAIN, MUTED);
        footer.setHorizontalAlignment(SwingConstants.CENTER); p.add(footer, g);

        return p;
    }

    // ================================================================
    //  SCREEN 2: Sign Up
    // ================================================================
    JPanel buildSignUpScreen() {
        JPanel outer = centeredOuter();
        JPanel card  = card(380, 440);

        card.add(label("Create Account", 22, Font.BOLD, TEXT)); card.add(vGap(4));
        card.add(label("Register a new bank account", 13, Font.PLAIN, MUTED)); card.add(vGap(20));
        card.add(formLabel("Username")); card.add(vGap(6));
        JTextField uField = textField("Choose a username"); card.add(uField); card.add(vGap(14));
        card.add(formLabel("Password")); card.add(vGap(6));
        JPasswordField pField = passwordField("Min. 4 characters"); card.add(pField); card.add(vGap(6));

        // Password strength hint
        JLabel hint = label("Password is stored securely using SHA-256 hashing", 11, Font.PLAIN, MUTED);
        card.add(hint); card.add(vGap(18));

        JButton btn = primaryBtn("Sign Up");
        btn.setAlignmentX(LEFT_ALIGNMENT); btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        JLabel msg = msgLabel();
        btn.addActionListener(e -> {
            String u = uField.getText().trim();
            String pw = new String(pField.getPassword()).trim();
            String r = bank.signUp(u, pw);
            showMsg(msg, r);
            if (r.startsWith("SUCCESS:")) { uField.setText(""); pField.setText(""); }
        });
        card.add(btn); card.add(vGap(10)); card.add(msg); card.add(vGap(12));
        JButton back = linkBtn("← Back to Home");
        back.addActionListener(e -> { msg.setText(""); cardLayout.show(mainPanel, "WELCOME"); });
        card.add(back);
        outer.add(card); return outer;
    }

    // ================================================================
    //  SCREEN 3: Login
    // ================================================================
    JPanel buildLoginScreen() {
        JPanel outer = centeredOuter();
        JPanel card  = card(380, 390);

        card.add(label("Welcome Back", 22, Font.BOLD, TEXT)); card.add(vGap(4));
        card.add(label("Enter your credentials to log in", 13, Font.PLAIN, MUTED)); card.add(vGap(22));
        card.add(formLabel("Username")); card.add(vGap(6));
        JTextField uField = textField("Enter username"); card.add(uField); card.add(vGap(16));
        card.add(formLabel("Password")); card.add(vGap(6));
        JPasswordField pField = passwordField("Enter password"); card.add(pField); card.add(vGap(22));

        JButton btn = primaryBtn("Log In");
        btn.setAlignmentX(LEFT_ALIGNMENT); btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        JLabel msg = msgLabel();
        btn.addActionListener(e -> {
            String u = uField.getText().trim();
            String pw = new String(pField.getPassword()).trim();
            if (u.isEmpty() || pw.isEmpty()) { showMsg(msg, "ERROR:Please fill in both fields."); return; }
            if (!bank.userExists(u)) { showMsg(msg, "ERROR:Username not found. Sign up first."); return; }
            Account acc = bank.login(u, pw);
            if (acc != null) {
                currentAccount = acc; msg.setText(""); uField.setText(""); pField.setText("");
                refreshDashboard(); cardLayout.show(mainPanel, "DASHBOARD");
            } else showMsg(msg, "ERROR:Incorrect password. Try again.");
        });
        card.add(btn); card.add(vGap(10)); card.add(msg); card.add(vGap(12));
        JButton back = linkBtn("← Back to Home");
        back.addActionListener(e -> { msg.setText(""); cardLayout.show(mainPanel, "WELCOME"); });
        card.add(back); outer.add(card); return outer;
    }

    // ================================================================
    //  SCREEN 4: Dashboard
    // ================================================================
    JPanel buildDashboard() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBackground(BG); p.setBorder(new EmptyBorder(20,24,20,24));

        // Top bar
        JPanel topBar = new JPanel(new BorderLayout());
        topBar.setBackground(BG); topBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        dashGreet = label("Hello, User!", 15, Font.BOLD, TEXT);

        // Top bar right — Profile + Logout buttons
        JPanel topRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        topRight.setBackground(BG);
        JButton profileBtn = linkBtn("👤 Profile");
        profileBtn.addActionListener(e -> showProfileDialog());
        JButton logoutBtn = linkBtn("Logout →");
        logoutBtn.addActionListener(e -> { currentAccount=null; txnMsg.setText(""); cardLayout.show(mainPanel,"WELCOME"); });
        topRight.add(profileBtn); topRight.add(logoutBtn);
        topBar.add(dashGreet, BorderLayout.WEST); topBar.add(topRight, BorderLayout.EAST);
        p.add(topBar); p.add(vGap(16));

        // Balance card
        JPanel balCard = new JPanel();
        balCard.setLayout(new BoxLayout(balCard, BoxLayout.Y_AXIS));
        balCard.setBackground(PRIMARY); balCard.setBorder(new EmptyBorder(20,22,20,22));
        balCard.setMaximumSize(new Dimension(Integer.MAX_VALUE, 115));
        JLabel balLbl = label("Current Balance", 12, Font.PLAIN, new Color(191,219,254));
        balLbl.setAlignmentX(LEFT_ALIGNMENT); balCard.add(balLbl); balCard.add(vGap(6));
        dashBalance = label("Rs. 0.00", 30, Font.BOLD, Color.WHITE);
        dashBalance.setAlignmentX(LEFT_ALIGNMENT); balCard.add(dashBalance); balCard.add(vGap(8));
        dashAccNo = label("Account No: ---", 12, Font.PLAIN, new Color(147,197,253));
        dashAccNo.setAlignmentX(LEFT_ALIGNMENT); balCard.add(dashAccNo);
        p.add(balCard); p.add(vGap(12));

        // Message area
        txnMsg = new JLabel(" ");
        txnMsg.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        txnMsg.setAlignmentX(LEFT_ALIGNMENT); txnMsg.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        p.add(txnMsg); p.add(vGap(4));

        // Deposit
        p.add(sectionLabel("Deposit Money")); p.add(vGap(7));
        JTextField depF = textField("Enter amount");
        JButton depBtn = primaryBtn("Deposit"); depBtn.setPreferredSize(new Dimension(110,42));
        depBtn.addActionListener(e -> {
            try { showMsg(txnMsg, bank.deposit(currentAccount, Double.parseDouble(depF.getText().trim()))); refreshBalance(); depF.setText(""); }
            catch (NumberFormatException ex) { showMsg(txnMsg, "ERROR:Enter a valid number."); }
        });
        p.add(inputRow(depF, depBtn)); p.add(vGap(14));

        // Withdraw
        p.add(sectionLabel("Withdraw Money")); p.add(vGap(7));
        JTextField withF = textField("Enter amount");
        JButton withBtn = outlineBtn("Withdraw"); withBtn.setPreferredSize(new Dimension(110,42));
        withBtn.addActionListener(e -> {
            try { showMsg(txnMsg, bank.withdraw(currentAccount, Double.parseDouble(withF.getText().trim()))); refreshBalance(); withF.setText(""); }
            catch (NumberFormatException ex) { showMsg(txnMsg, "ERROR:Enter a valid number."); }
        });
        p.add(inputRow(withF, withBtn)); p.add(vGap(14));

        // Balance Enquiry
        p.add(sectionLabel("Balance Enquiry")); p.add(vGap(7));
        JButton eBtn = outlineBtn("Check My Balance");
        eBtn.setAlignmentX(LEFT_ALIGNMENT); eBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        eBtn.addActionListener(e -> { if(currentAccount!=null) showMsg(txnMsg, "SUCCESS:Account: "
                + currentAccount.getAccountNumber() + "  |  Balance: Rs." + String.format("%.2f", currentAccount.getBalance())); });
        p.add(eBtn); p.add(vGap(16));

        p.add(divider()); p.add(vGap(14));

        // Fund Transfer
        p.add(sectionLabel("Fund Transfer")); p.add(vGap(7));
        JTextField recF = textField("Recipient account no.  (e.g. ACC1002)");
        recF.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42)); p.add(recF); p.add(vGap(8));
        JTextField trAmtF = textField("Amount to transfer");
        JButton trBtn = makeBtn("Transfer", PURPLE, new Color(91,33,182)); trBtn.setPreferredSize(new Dimension(110,42));
        trBtn.addActionListener(e -> {
            String rec = recF.getText().trim(); if(rec.startsWith("Recipient")) rec="";
            String amt = trAmtF.getText().trim(); if(amt.equals("Amount to transfer")) amt="";
            if(rec.isEmpty()) { showMsg(txnMsg,"ERROR:Enter recipient account number."); return; }
            if(amt.isEmpty()) { showMsg(txnMsg,"ERROR:Enter transfer amount."); return; }
            try {
                String res = bank.transferFunds(currentAccount, rec, Double.parseDouble(amt));
                showMsg(txnMsg, res); refreshBalance();
                if(res.startsWith("SUCCESS:")) { recF.setText(""); trAmtF.setText(""); }
            } catch(NumberFormatException ex) { showMsg(txnMsg,"ERROR:Enter a valid amount."); }
        });
        p.add(inputRow(trAmtF, trBtn)); p.add(vGap(6));
        JLabel hint = label("Your account no: ---  (share to receive money)", 11, Font.PLAIN, MUTED);
        hint.setAlignmentX(LEFT_ALIGNMENT); p.add(hint);
        dashAccNo.addPropertyChangeListener("text", evt ->
                hint.setText("Your account no: " + (currentAccount!=null ? currentAccount.getAccountNumber() : "---") + "  (share to receive money)"));

        p.add(vGap(14)); p.add(divider()); p.add(vGap(14));

        // Mini Statement
        p.add(sectionLabel("Mini Statement")); p.add(vGap(7));
        JButton stmtBtn = makeBtn("View Last 5 Transactions", TEAL, TEAL_D);
        stmtBtn.setAlignmentX(LEFT_ALIGNMENT); stmtBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        stmtBtn.addActionListener(e -> showMiniStatement());
        p.add(stmtBtn); p.add(vGap(14));

        p.add(divider()); p.add(vGap(14));

        // Change Password
        p.add(sectionLabel("Change Password")); p.add(vGap(7));
        JButton cpBtn = makeBtn("Change My Password", ORANGE, new Color(194,65,12));
        cpBtn.setAlignmentX(LEFT_ALIGNMENT); cpBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        cpBtn.addActionListener(e -> showChangePasswordDialog());
        p.add(cpBtn); p.add(vGap(20));

        return p;
    }

    // ================================================================
    //  DIALOG: Profile Page
    // ================================================================
    void showProfileDialog() {
        if (currentAccount == null) return;

        JDialog d = new JDialog(this, "My Profile", true);
        d.setSize(400, 380); d.setLocationRelativeTo(this); d.setResizable(false);

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG);

        // Header
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(PRIMARY); header.setBorder(new EmptyBorder(24,24,24,24));

        // Avatar circle
        JLabel avatar = new JLabel(currentAccount.getUsername().substring(0,1).toUpperCase(), SwingConstants.CENTER);
        avatar.setFont(new Font("Segoe UI", Font.BOLD, 28));
        avatar.setForeground(PRIMARY); avatar.setBackground(Color.WHITE); avatar.setOpaque(true);
        avatar.setPreferredSize(new Dimension(60,60)); avatar.setMaximumSize(new Dimension(60,60));
        avatar.setBorder(new EmptyBorder(5,5,5,5));
        JPanel avatarWrap = new JPanel(new FlowLayout(FlowLayout.LEFT,0,0));
        avatarWrap.setBackground(PRIMARY); avatarWrap.add(avatar);
        header.add(avatarWrap); header.add(vGap(10));

        JLabel nm = label(currentAccount.getUsername(), 20, Font.BOLD, Color.WHITE);
        nm.setAlignmentX(LEFT_ALIGNMENT); header.add(nm);
        JLabel accLbl = label("Account No: " + currentAccount.getAccountNumber(), 12, Font.PLAIN, new Color(191,219,254));
        accLbl.setAlignmentX(LEFT_ALIGNMENT); header.add(accLbl);
        root.add(header, BorderLayout.NORTH);

        // Body
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setBackground(BG); body.setBorder(new EmptyBorder(20,24,20,24));

        body.add(profileRow("👤  Full Name", currentAccount.getUsername()));
        body.add(vGap(12));
        body.add(profileRow("🏦  Account Number", currentAccount.getAccountNumber()));
        body.add(vGap(12));
        body.add(profileRow("💰  Current Balance", "Rs. " + String.format("%.2f", currentAccount.getBalance())));
        body.add(vGap(12));
        body.add(profileRow("📅  Member Since", currentAccount.getCreatedAt().split(" ")[0]));
        body.add(vGap(12));
        body.add(profileRow("🔐  Password Security", "SHA-256 Encrypted"));

        root.add(body, BorderLayout.CENTER);

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        footer.setBackground(BG); footer.setBorder(new EmptyBorder(4,16,14,16));
        JButton closeBtn = outlineBtn("Close");
        closeBtn.addActionListener(e -> d.dispose());
        footer.add(closeBtn);
        root.add(footer, BorderLayout.SOUTH);

        d.setContentPane(root); d.setVisible(true);
    }

    JPanel profileRow(String label, String value) {
        JPanel row = new JPanel(new BorderLayout(12,0));
        row.setBackground(CARD);
        row.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(BORDER,1,true), new EmptyBorder(10,14,10,14)));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 48));
        JLabel lbl = new JLabel(label); lbl.setFont(new Font("Segoe UI",Font.PLAIN,12)); lbl.setForeground(MUTED);
        JLabel val = new JLabel(value); val.setFont(new Font("Segoe UI",Font.BOLD,13)); val.setForeground(TEXT);
        row.add(lbl, BorderLayout.WEST); row.add(val, BorderLayout.EAST);
        return row;
    }

    // ================================================================
    //  DIALOG: Change Password
    // ================================================================
    void showChangePasswordDialog() {
        if (currentAccount == null) return;

        JDialog d = new JDialog(this, "Change Password", true);
        d.setSize(380, 360); d.setLocationRelativeTo(this); d.setResizable(false);

        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBackground(BG); root.setBorder(new EmptyBorder(28,30,28,30));

        root.add(label("Change Password", 20, Font.BOLD, TEXT)); root.add(vGap(4));
        root.add(label("Enter current and new password below", 12, Font.PLAIN, MUTED)); root.add(vGap(22));

        root.add(formLabel("Current Password")); root.add(vGap(6));
        JPasswordField oldF = passwordField("Enter current password"); root.add(oldF); root.add(vGap(14));

        root.add(formLabel("New Password")); root.add(vGap(6));
        JPasswordField newF = passwordField("Min. 4 characters"); root.add(newF); root.add(vGap(14));

        root.add(formLabel("Confirm New Password")); root.add(vGap(6));
        JPasswordField confF = passwordField("Re-enter new password"); root.add(confF); root.add(vGap(20));

        JLabel msg = msgLabel(); root.add(msg); root.add(vGap(10));

        JButton btn = primaryBtn("Update Password");
        btn.setAlignmentX(LEFT_ALIGNMENT); btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        btn.addActionListener(e -> {
            String oldP  = new String(oldF.getPassword()).trim();
            String newP  = new String(newF.getPassword()).trim();
            String confP = new String(confF.getPassword()).trim();
            if (oldP.isEmpty() || newP.isEmpty() || confP.isEmpty()) {
                showMsg(msg, "ERROR:All fields are required."); return;
            }
            if (!newP.equals(confP)) { showMsg(msg, "ERROR:New passwords do not match."); return; }
            String result = bank.changePassword(currentAccount.getAccountNumber(), oldP, newP);
            showMsg(msg, result);
            if (result.startsWith("SUCCESS:")) {
                oldF.setText(""); newF.setText(""); confF.setText("");
                // Close dialog after 1.5 seconds
                new Timer(1500, ev -> d.dispose()).start();
            }
        });
        root.add(btn);

        d.setContentPane(root); d.setVisible(true);
    }

    // ================================================================
    //  SCREEN 5: Admin Login
    // ================================================================
    JPanel buildAdminLogin() {
        JPanel outer = centeredOuter();
        JPanel card  = card(380, 400);

        // Admin badge
        JLabel badge = new JLabel("🔑  ADMIN ACCESS", SwingConstants.CENTER);
        badge.setFont(new Font("Segoe UI Emoji", Font.BOLD, 13));
        badge.setForeground(Color.WHITE); badge.setBackground(new Color(30,41,59));
        badge.setOpaque(true); badge.setBorder(new EmptyBorder(6,14,6,14));
        badge.setAlignmentX(LEFT_ALIGNMENT); badge.setMaximumSize(new Dimension(Integer.MAX_VALUE,36));
        card.add(badge); card.add(vGap(16));

        card.add(label("Admin Panel Login", 20, Font.BOLD, TEXT)); card.add(vGap(4));
        card.add(label("Default: admin / admin123", 12, Font.PLAIN, MUTED)); card.add(vGap(22));

        card.add(formLabel("Admin Username")); card.add(vGap(6));
        JTextField uF = textField("Enter admin username"); card.add(uF); card.add(vGap(16));
        card.add(formLabel("Admin Password")); card.add(vGap(6));
        JPasswordField pF = passwordField("Enter admin password"); card.add(pF); card.add(vGap(22));

        JButton btn = makeBtn("Login as Admin", new Color(30,41,59), new Color(15,23,42));
        btn.setAlignmentX(LEFT_ALIGNMENT); btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        JLabel msg = msgLabel();
        btn.addActionListener(e -> {
            String u = uF.getText().trim();
            String pw = new String(pF.getPassword()).trim();
            if (u.isEmpty() || pw.isEmpty()) { showMsg(msg,"ERROR:Enter both fields."); return; }
            if (bank.adminLogin(u, pw)) {
                uF.setText(""); pF.setText(""); msg.setText("");
                showAdminPanel();
            } else showMsg(msg, "ERROR:Invalid admin credentials.");
        });
        card.add(btn); card.add(vGap(10)); card.add(msg); card.add(vGap(12));
        JButton back = linkBtn("← Back to Home");
        back.addActionListener(e -> { msg.setText(""); cardLayout.show(mainPanel,"WELCOME"); });
        card.add(back); outer.add(card); return outer;
    }


    // ================================================================
    //  DIALOG: Admin Panel
    // ================================================================
    void showAdminPanel() {
        JDialog d = new JDialog(this, "Admin Panel", true);
        d.setSize(600, 540); d.setLocationRelativeTo(this); d.setResizable(true);

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG);

        // Header
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(new Color(30,41,59)); header.setBorder(new EmptyBorder(18,22,18,22));
        JPanel hl = new JPanel(); hl.setLayout(new BoxLayout(hl, BoxLayout.Y_AXIS)); hl.setBackground(new Color(30,41,59));
        JLabel htitle = label("Admin Panel", 18, Font.BOLD, Color.WHITE);
        JLabel hsub   = label("Hera Pheri Bank  •  All Accounts Overview", 12, Font.PLAIN, new Color(148,163,184));
        htitle.setAlignmentX(LEFT_ALIGNMENT); hsub.setAlignmentX(LEFT_ALIGNMENT);
        hl.add(htitle); hl.add(Box.createVerticalStrut(3)); hl.add(hsub);
        header.add(hl, BorderLayout.WEST);
        root.add(header, BorderLayout.NORTH);

        // Stats bar
        String[] stats = bank.getStats();
        JPanel statsBar = new JPanel(new GridLayout(1,3,1,0));
        statsBar.setBackground(new Color(15,23,42));
        statsBar.add(statCard("Total Accounts", stats[0], new Color(59,130,246)));
        statsBar.add(statCard("Total Balance", "Rs." + stats[1], new Color(16,185,129)));
        statsBar.add(statCard("Total Transactions", stats[2], new Color(245,158,11)));
        root.add(statsBar, BorderLayout.NORTH);

        // Put header and stats together
        JPanel topSection = new JPanel(new BorderLayout());
        topSection.add(header, BorderLayout.NORTH);
        topSection.add(statsBar, BorderLayout.SOUTH);
        root.add(topSection, BorderLayout.NORTH);

        // Accounts table
        ArrayList<String[]> accounts = bank.getAllAccounts();
        String[] cols = {"Username", "Account No", "Balance (Rs.)", "Joined"};
        String[][] data = accounts.toArray(new String[0][]);
        JTable table = new JTable(data, cols) {
            public boolean isCellEditable(int r, int c) { return false; }
        };
        table.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        table.setRowHeight(32);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        table.getTableHeader().setBackground(new Color(226,232,240));
        table.getTableHeader().setForeground(MUTED);
        table.setSelectionBackground(new Color(219,234,254));
        table.setGridColor(BORDER);
        table.setShowGrid(true);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(new EmptyBorder(0,0,0,0));
        root.add(tableScroll, BorderLayout.CENTER);

        // Footer
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        footer.setBackground(BG); footer.setBorder(new EmptyBorder(8,16,14,16));
        JLabel note = new JLabel("Logged in as: admin  •  Read-only access");
        note.setFont(new Font("Segoe UI", Font.PLAIN, 11)); note.setForeground(MUTED);
        JButton closeBtn = outlineBtn("Close");
        closeBtn.addActionListener(e -> d.dispose());
        footer.add(note); footer.add(closeBtn);
        root.add(footer, BorderLayout.SOUTH);

        d.setContentPane(root); d.setVisible(true);
    }

    JPanel statCard(String label, String value, Color accent) {
        JPanel p = new JPanel(); p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBackground(new Color(30,41,59)); p.setBorder(new EmptyBorder(12,16,12,16));
        JLabel lbl = new JLabel(label); lbl.setFont(new Font("Segoe UI",Font.PLAIN,11)); lbl.setForeground(new Color(148,163,184));
        JLabel val = new JLabel(value); val.setFont(new Font("Segoe UI",Font.BOLD,18)); val.setForeground(accent);
        p.add(lbl); p.add(Box.createVerticalStrut(4)); p.add(val);
        return p;
    }


    // ================================================================
    //  Mini Statement Dialog
    // ================================================================
    void showMiniStatement() {
        if (currentAccount == null) return;
        ArrayList<Transaction> txns = bank.getMiniStatement(currentAccount.getAccountNumber());

        JDialog d = new JDialog(this, "Mini Statement", true);
        d.setSize(500, 460); d.setLocationRelativeTo(this); d.setResizable(false);

        JPanel root = new JPanel(new BorderLayout()); root.setBackground(BG);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(PRIMARY); header.setBorder(new EmptyBorder(18,22,18,22));
        JPanel hl = new JPanel(); hl.setLayout(new BoxLayout(hl,BoxLayout.Y_AXIS)); hl.setBackground(PRIMARY);
        JLabel hTitle = label("Mini Statement",18,Font.BOLD,Color.WHITE);
        JLabel hInfo  = label(currentAccount.getAccountNumber()+"  •  "+currentAccount.getUsername(),12,Font.PLAIN,new Color(191,219,254));
        hTitle.setAlignmentX(LEFT_ALIGNMENT); hInfo.setAlignmentX(LEFT_ALIGNMENT);
        hl.add(hTitle); hl.add(Box.createVerticalStrut(4)); hl.add(hInfo);
        JLabel hBal = label("Rs."+String.format("%.2f",currentAccount.getBalance()),20,Font.BOLD,Color.WHITE);
        hBal.setHorizontalAlignment(SwingConstants.RIGHT);
        header.add(hl,BorderLayout.WEST); header.add(hBal,BorderLayout.EAST);
        root.add(header,BorderLayout.NORTH);

        JPanel body = new JPanel(); body.setLayout(new BoxLayout(body,BoxLayout.Y_AXIS));
        body.setBackground(BG); body.setBorder(new EmptyBorder(14,16,14,16));

        if (txns.isEmpty()) {
            JPanel ep = new JPanel(new GridBagLayout()); ep.setBackground(BG);
            ep.add(label("No transactions yet.",14,Font.PLAIN,MUTED)); body.add(ep);
        } else {
            JPanel colHdr = new JPanel(new GridLayout(1,4,8,0));
            colHdr.setBackground(new Color(226,232,240)); colHdr.setBorder(new EmptyBorder(6,10,6,10));
            colHdr.setMaximumSize(new Dimension(Integer.MAX_VALUE,32));
            colHdr.add(colHdLbl("Date & Time")); colHdr.add(colHdLbl("Description"));
            colHdr.add(colHdLbl("Type")); colHdr.add(colHdLbl("Amount / Balance"));
            body.add(colHdr); body.add(Box.createVerticalStrut(4));
            for (Transaction t : txns) { body.add(buildTxnRow(t)); body.add(Box.createVerticalStrut(6)); }
            body.add(Box.createVerticalStrut(8));
            body.add(label("Last "+txns.size()+" transaction(s) — stored in MySQL.",11,Font.PLAIN,MUTED));
        }

        JScrollPane scroll = new JScrollPane(body); scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(12);
        root.add(scroll,BorderLayout.CENTER);

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        footer.setBackground(BG); footer.setBorder(new EmptyBorder(8,16,14,16));
        JButton closeBtn = outlineBtn("Close"); closeBtn.addActionListener(e -> d.dispose());
        footer.add(closeBtn); root.add(footer,BorderLayout.SOUTH);
        d.setContentPane(root); d.setVisible(true);
    }

    JPanel buildTxnRow(Transaction t) {
        JPanel row = new JPanel(new GridLayout(1,4,8,0));
        row.setBackground(CARD);
        row.setBorder(BorderFactory.createCompoundBorder(new LineBorder(BORDER,1,true),new EmptyBorder(10,10,10,10)));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE,62));
        String[] parts = t.getTimestamp().split("  ");
        JPanel dp = new JPanel(); dp.setLayout(new BoxLayout(dp,BoxLayout.Y_AXIS)); dp.setBackground(CARD);
        JLabel dl = new JLabel(parts.length>0?parts[0]:t.getTimestamp()); dl.setFont(new Font("Segoe UI",Font.BOLD,11)); dl.setForeground(TEXT);
        JLabel tl = new JLabel(parts.length>1?parts[1]:""); tl.setFont(new Font("Segoe UI",Font.PLAIN,11)); tl.setForeground(MUTED);
        dp.add(dl); dp.add(tl); row.add(dp);
        JLabel desc = new JLabel("<html><body style='width:90px'>"+t.getDescription()+"</body></html>");
        desc.setFont(new Font("Segoe UI",Font.PLAIN,12)); desc.setForeground(TEXT); row.add(desc);
        boolean cr = t.getType().equals("CR");
        JLabel badge = new JLabel(cr?"CR":"DR",SwingConstants.CENTER);
        badge.setFont(new Font("Segoe UI",Font.BOLD,12)); badge.setForeground(cr?CR_COL:DR_COL); badge.setOpaque(true);
        badge.setBackground(cr?new Color(220,252,231):new Color(254,226,226)); badge.setBorder(new EmptyBorder(3,8,3,8));
        JPanel bw = new JPanel(new FlowLayout(FlowLayout.LEFT,0,8)); bw.setBackground(CARD); bw.add(badge); row.add(bw);
        JPanel ap = new JPanel(); ap.setLayout(new BoxLayout(ap,BoxLayout.Y_AXIS)); ap.setBackground(CARD);
        JLabel al = new JLabel("Rs."+String.format("%.2f",t.getAmount())); al.setFont(new Font("Segoe UI",Font.BOLD,13)); al.setForeground(cr?CR_COL:DR_COL);
        JLabel bl = new JLabel("Bal: Rs."+String.format("%.2f",t.getBalanceAfter())); bl.setFont(new Font("Segoe UI",Font.PLAIN,11)); bl.setForeground(MUTED);
        ap.add(al); ap.add(bl); row.add(ap);
        return row;
    }

    JLabel colHdLbl(String t) {
        JLabel l = new JLabel(t); l.setFont(new Font("Segoe UI",Font.BOLD,11)); l.setForeground(MUTED); return l;
    }

    JSeparator divider() {
        JSeparator s = new JSeparator(); s.setMaximumSize(new Dimension(Integer.MAX_VALUE,1)); s.setForeground(BORDER); return s;
    }


    // ================================================================
    //  Dashboard helpers
    // ================================================================
    void refreshDashboard() {
        if (currentAccount==null) return;
        dashGreet.setText("Hello, "+currentAccount.getUsername()+"!");
        dashAccNo.setText("Account No: "+currentAccount.getAccountNumber());
        refreshBalance(); txnMsg.setText(" ");
    }

    void refreshBalance() {
        if (currentAccount==null) return;
        dashBalance.setText("Rs. "+String.format("%.2f",currentAccount.getBalance()));
    }

    void showMsg(JLabel lbl, String result) {
        if (result.startsWith("SUCCESS:")) { lbl.setForeground(SUCCESS); lbl.setText("✔  "+result.substring(8)); }
        else { lbl.setForeground(DANGER); lbl.setText("✘  "+result.substring(6)); }
    }


    // ================================================================
    //  UI helpers
    // ================================================================
    JPanel centeredOuter() { JPanel p=new JPanel(new GridBagLayout()); p.setBackground(BG); return p; }

    JPanel card(int w, int h) {
        JPanel c=new JPanel(); c.setLayout(new BoxLayout(c,BoxLayout.Y_AXIS)); c.setBackground(CARD);
        c.setBorder(BorderFactory.createCompoundBorder(new LineBorder(BORDER,1,true),new EmptyBorder(28,32,28,32)));
        c.setPreferredSize(new Dimension(w,h)); return c;
    }

    JPanel inputRow(JTextField f, JButton b) {
        JPanel row=new JPanel(new BorderLayout(10,0)); row.setBackground(BG);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE,44));
        row.add(f,BorderLayout.CENTER); row.add(b,BorderLayout.EAST); return row;
    }

    JLabel label(String t, int sz, int st, Color c) {
        JLabel l=new JLabel(t); l.setFont(new Font("Segoe UI",st,sz)); l.setForeground(c); l.setAlignmentX(LEFT_ALIGNMENT); return l;
    }

    JLabel formLabel(String t)    { return label(t,13,Font.BOLD,TEXT); }
    JLabel sectionLabel(String t) { return label(t,13,Font.BOLD,MUTED); }

    JLabel msgLabel() {
        JLabel l=new JLabel(" "); l.setFont(new Font("Segoe UI",Font.PLAIN,13)); l.setAlignmentX(LEFT_ALIGNMENT);
        l.setMaximumSize(new Dimension(Integer.MAX_VALUE,30)); return l;
    }

    Component vGap(int h) { return Box.createVerticalStrut(h); }

    JTextField textField(String ph) {
        JTextField f=new JTextField(); f.setFont(new Font("Segoe UI",Font.PLAIN,14));
        f.setBorder(BorderFactory.createCompoundBorder(new LineBorder(BORDER,1,true),new EmptyBorder(8,12,8,12)));
        f.setMaximumSize(new Dimension(Integer.MAX_VALUE,42)); f.setAlignmentX(LEFT_ALIGNMENT);
        f.setForeground(MUTED); f.setText(ph);
        f.addFocusListener(new FocusAdapter() {
            public void focusGained(FocusEvent e) { if(f.getText().equals(ph)){f.setText("");f.setForeground(TEXT);} }
            public void focusLost(FocusEvent e)   { if(f.getText().isEmpty()){f.setText(ph);f.setForeground(MUTED);} }
        });
        return f;
    }

    JPasswordField passwordField(String ph) {
        JPasswordField f=new JPasswordField(); f.setFont(new Font("Segoe UI",Font.PLAIN,14));
        f.setBorder(BorderFactory.createCompoundBorder(new LineBorder(BORDER,1,true),new EmptyBorder(8,12,8,12)));
        f.setMaximumSize(new Dimension(Integer.MAX_VALUE,42)); f.setAlignmentX(LEFT_ALIGNMENT);
        f.setEchoChar((char)0); f.setForeground(MUTED); f.setText(ph);
        f.addFocusListener(new FocusAdapter() {
            public void focusGained(FocusEvent e) { if(new String(f.getPassword()).equals(ph)){f.setText("");f.setEchoChar('●');f.setForeground(TEXT);} }
            public void focusLost(FocusEvent e)   { if(f.getPassword().length==0){f.setEchoChar((char)0);f.setText(ph);f.setForeground(MUTED);} }
        });
        return f;
    }

    // Generic colored button factory
    JButton makeBtn(String text, Color bg, Color hover) {
        JButton b=new JButton(text); b.setFont(new Font("Segoe UI",Font.BOLD,14));
        b.setBackground(bg); b.setForeground(Color.WHITE); b.setFocusPainted(false); b.setOpaque(true);
        b.setBorder(new EmptyBorder(10,20,10,20)); b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e){b.setBackground(hover);}
            public void mouseExited(MouseEvent e){b.setBackground(bg);}
        });
        return b;
    }

    JButton primaryBtn(String t) { return makeBtn(t, PRIMARY, PRIM_D); }

    JButton outlineBtn(String text) {
        JButton b=new JButton(text); b.setFont(new Font("Segoe UI",Font.BOLD,14));
        b.setBackground(CARD); b.setForeground(PRIMARY); b.setFocusPainted(false); b.setOpaque(true);
        b.setBorder(BorderFactory.createCompoundBorder(new LineBorder(PRIMARY,1,true),new EmptyBorder(9,20,9,20)));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e){b.setBackground(new Color(239,246,255));}
            public void mouseExited(MouseEvent e){b.setBackground(CARD);}
        });
        return b;
    }

    JButton linkBtn(String text) {
        JButton b=new JButton(text); b.setFont(new Font("Segoe UI",Font.PLAIN,13));
        b.setForeground(PRIMARY); b.setBackground(null); b.setContentAreaFilled(false);
        b.setBorderPainted(false); b.setFocusPainted(false);
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); return b;
    }


    // ================================================================
    //  MAIN
    // ================================================================
    public static void main(String[] args) {
        SwingUtilities.invokeLater(BankingApp::new);
    }
}
