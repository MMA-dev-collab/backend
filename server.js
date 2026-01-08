const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");

const app = express();

/* ======================
   CONFIG
====================== */
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

/*
  IMPORTANT:
  These MUST be set in Back4App → Environment Variables
*/
const DB_CONFIG = {
  host: process.env.DB_HOST,       // ❗ NOT localhost
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

/* ======================
   MIDDLEWARE
====================== */
app.use(cors());
app.use(express.json());

/* ======================
   HEALTH CHECK (MANDATORY)
====================== */
app.get("/", (req, res) => {
  res.status(200).json({ status: "OK" });
});

/* ======================
   DATABASE (NON-BLOCKING)
====================== */
let pool = null;

async function connectDatabase() {
  try {
    if (!DB_CONFIG.host) {
      console.warn("⚠️ DB env vars not set. Running without DB.");
      return;
    }

    pool = mysql.createPool(DB_CONFIG);
    await pool.query("SELECT 1");
    console.log("✅ Database connected");
  } catch (err) {
    console.error("❌ Database connection failed:", err.message);
    console.log("⚠️ Server will keep running without DB");
  }
}

// Connect AFTER server starts
connectDatabase();

/* ======================
   AUTH MIDDLEWARE
====================== */
function authMiddleware(requiredRole) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ message: "Missing token" });

    try {
      const token = header.split(" ")[1];
      const payload = jwt.verify(token, JWT_SECRET);

      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ message: "Forbidden" });
      }

      req.user = payload;
      next();
    } catch {
      return res.status(401).json({ message: "Invalid token" });
    }
  };
}

/* ======================
   AUTH ROUTES
====================== */
app.post("/api/auth/register", async (req, res) => {
  if (!pool) return res.status(503).json({ message: "DB unavailable" });

  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    const passwordHash = bcrypt.hashSync(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (email, passwordHash, role) VALUES (?, ?, 'student')",
      [email, passwordHash]
    );

    const token = jwt.sign(
      { id: result.insertId, email, role: "student" },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ message: "Email already exists" });
    }
    console.error(err);
    res.status(500).json({ message: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  if (!pool) return res.status(503).json({ message: "DB unavailable" });

  const { email, password } = req.body;

  try {
    const [rows] = await pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];
    const match = bcrypt.compareSync(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* ======================
   SERVER START (CRITICAL)
====================== */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
