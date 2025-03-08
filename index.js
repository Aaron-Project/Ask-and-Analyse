const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise"); // Use mysql2/promise for async/await
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// 📌 MySQL Database Connection
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};

// Create a connection pool
const pool = mysql.createPool(dbConfig);

// Test the database connection
pool.getConnection()
  .then((connection) => {
    console.log("✅ MySQL Connected!");
    connection.release();
  })
  .catch((err) => {
    console.error("❌ MySQL Connection Error:", err);
    process.exit(1);
  });

// 📌 Middleware: Verify Token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    // Decode the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach decoded user info (email) to request
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token has expired." });
    }
    return res.status(400).json({ error: "Invalid token." });
  }
};

// 📌 User Registration
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const [existingUser] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ error: "Email already registered!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);

    res.json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("❌ Registration Error:", err);
    res.status(500).json({ error: "An error occurred during registration." });
  }
});

// 📌 User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    const [user] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (user.length === 0) {
      return res.status(400).json({ error: "User not found!" });
    }

    const isMatch = await bcrypt.compare(password, user[0].password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials." });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user[0].id, email: user[0].email, name: user[0].name },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful!",
      token,
      user: {
        id: user[0].id,
        name: user[0].name,
        email: user[0].email,
      },
    });
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).json({ error: "An error occurred during login." });
  }
});

// 📌 Save Query Execution History
app.post("/save-history", verifyToken, async (req, res) => {
  try {
    const { query_searched, response_status, filename } = req.body;
    const email = req.user.email; // Authenticated user's email

    console.log("✅ Saving History:", { query_searched, response_status, filename, email });

    // Get the username based on email from `users` table
    const [user] = await pool.query("SELECT name FROM users WHERE email = ?", [email]);
    if (user.length === 0) {
      return res.status(400).json({ error: "User not found." });
    }

    const username = user[0].name;

    // Insert query history into `history` table
    await pool.query(
      "INSERT INTO history (email, username, query_searched, response_status, filename, query_done_time) VALUES (?, ?, ?, ?, ?, NOW())",
      [email, username, query_searched, response_status, filename]
    );

    console.log("✅ History saved successfully!");
    res.json({ message: "History saved successfully." });
  } catch (error) {
    console.error("❌ Error saving history:", error);
    res.status(500).json({ error: "An error occurred while saving history." });
  }
});

// 📌 Get Query History for Logged-in User
app.get("/get-history", verifyToken, async (req, res) => {
  try {
    const email = req.user.email; // Get email from token

    console.log(`📌 Fetching history for email: ${email}`);

    // Fetch history for this email from `history` table
    const [history] = await pool.query(
      "SELECT query_searched, response_status, filename, query_done_time FROM history WHERE email = ? ORDER BY query_done_time DESC",
      [email]
    );

    console.log(`✅ History fetched: ${history.length} records found.`);
    res.json({ history });
  } catch (error) {
    console.error("❌ Error fetching history:", error);
    res.status(500).json({ error: "An error occurred while fetching history." });
  }
});

// 📌 Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});