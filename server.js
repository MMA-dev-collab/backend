require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const helmet = require("helmet");
const { z } = require("zod");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { sendVerificationEmail } = require('./utils/mailer-resend');
const { getClientIP, getDeviceFingerprint, getDeviceType, matchDevice, isValidIP, findAvailableSlot } = require('./utils/ip-helper');
const { calculateEndDate, convertToDays, getUserMembership, checkCaseAccess, formatDuration, getPlanHierarchy } = require('./utils/subscription-helper');
const { uploadImage } = require('./services/uploadService');
const { uploadMiddleware, validateImageDimensions } = require('./middleware/uploadMiddleware');

const app = express();

/* ======================
   CONFIG
====================== */
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key";

/* ======================
   TRUSTED PROXY CONFIG (SECURITY)
====================== */
// Configure trusted proxies for secure IP detection
// Railway uses a dynamic edge layer, so we trust the first upstream proxy (hop count = 1)
if (process.env.RAILWAY_ENVIRONMENT) {
  app.set('trust proxy', 1);
  console.log('✅ Railway environment detected: Trusting first proxy hop');
} else if (process.env.TRUSTED_PROXIES) {
  // Manual configuration for self-hosted/other environments
  const trustedProxies = process.env.TRUSTED_PROXIES.split(',').map(ip => ip.trim());
  app.set('trust proxy', trustedProxies);
  console.log('✅ Trusted proxies configured:', trustedProxies);
} else {
  console.warn('⚠️  No trusted proxies configured. Client IPs may be incorrect behind a proxy.');
}

// In-memory cache for token version validation (performance optimization)
const tokenVersionCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/* ======================
   MIDDLEWARE
====================== */
// Security headers
// Security headers
app.use(helmet({
  crossOriginResourcePolicy: false,
}));

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:3000', 'http://localhost:5173'];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.) in dev
    if (!origin && process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`[CORS] Blocked request from origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Serve static files from 'uploads' directory
app.use('/uploads', express.static('uploads'));

/* ======================
   RATE LIMITING
====================== */
// Global rate limiter: 100 requests per 15 minutes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.warn(`[RATE LIMIT] Global limit exceeded for IP: ${req.ip}`);
    res.status(429).json(options.message);
  }
});
app.use(globalLimiter);

// NEW: Burst rate limiter: 50 requests per 1 minute (DoS protection)
const burstLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 50,
  message: { message: 'Too many requests, please slow down.' },
  standardHeaders: true, // Return RateLimit headers
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.warn(`[RATE LIMIT] Burst limit exceeded for IP: ${req.ip}`);
    res.status(429).json(options.message);
  },
  // Redis Scalability Note:
  // In a multi-instance environment, replace MemoryStore with RedisStore (rate-limit-redis)
  // to share rate limit state across all server instances.
});
app.use(burstLimiter);

// Auth rate limiter: 5 requests per minute (brute-force protection)
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: { message: 'Too many authentication attempts, please try again in a minute.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.warn(`[RATE LIMIT] Auth limit exceeded for IP: ${req.ip}`);
    res.status(429).json(options.message);
  }
});

// Search rate limiter: 30 requests per minute
const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { message: 'Too many search requests, please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.warn(`[RATE LIMIT] Search limit exceeded for IP: ${req.ip}`);
    res.status(429).json(options.message);
  }
});

/* ======================
   INPUT VALIDATION SCHEMAS
====================== */
const searchQuerySchema = z.object({
  search: z.string().max(200).regex(/^[a-zA-Z0-9\u0600-\u06FF\s\-_]*$/, 'Invalid search characters').optional().default(''),
  category: z.string().optional().default('all'),
  difficulty: z.enum(['Beginner', 'Intermediate', 'Advanced', 'all']).optional().default('all'),
  duration: z.enum(['short', 'medium', 'long', 'all']).optional().default('all'),
  page: z.coerce.number().int().min(1).max(1000).optional().default(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(9)
});


/* ======================
   HEALTH CHECK (REQUIRED)
====================== */
app.get("/", (req, res) => {
  res.json({ status: "OK" });
});

// Upload rate limiter: 10 requests per 10 minutes
const uploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { message: 'Upload limit exceeded. Please wait 10 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

/* ======================
   UPLOAD ROUTES
====================== */
app.post('/api/upload', authMiddleware('admin'), uploadLimiter, uploadMiddleware, validateImageDimensions, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file provided' });
    }

    const type = req.body.type;
    let folder = 'physiosim/misc';

    if (type === 'case-cover') {
      folder = 'physiosim/case-covers';
    } else if (type === 'step-image') {
      folder = 'physiosim/steps/info-images';
    } else {
      // Optional: Reject unknown types or default to misc
      // return res.status(400).json({ message: 'Invalid upload type' });
    }

    // Upload to Cloudinary
    const result = await uploadImage(req.file.buffer, folder);

    res.json({
      message: 'Upload successful',
      url: result.url,
      publicId: result.publicId
    });

  } catch (error) {
    console.error('Upload Endpoint Error:', error);
    res.status(500).json({ message: 'Upload failed', error: error.message });
  }
});



/* ======================
   DATABASE CONFIG (AIVEN)
====================== */
const DB_CONFIG = {
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 26324),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,

  ssl: {
    rejectUnauthorized: false, // REQUIRED for Aiven
  },
};

let pool = null;

/* ======================
   NON-BLOCKING DB INIT
====================== */
async function connectDatabase() {
  try {
    if (!DB_CONFIG.host) {
      console.warn("⚠️ DB env vars missing. Running without DB.");
      return;
    }

    pool = mysql.createPool(DB_CONFIG);
    await pool.query("SELECT 1");
    console.log("✅ Database connected");

    // Run migrations
    await runMigrations();
  } catch (err) {
    console.error("❌ Database connection failed:", err.message);
    console.log("⚠️ Server will keep running without DB");
  }
}

async function runMigrations() {
  if (!pool) return;

  try {
    // Migration: Add status column to cases table
    const [columns] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cases' AND COLUMN_NAME = 'status'`,
      [DB_CONFIG.database]
    );

    if (columns.length === 0) {
      await pool.query(
        `ALTER TABLE cases 
         ADD COLUMN status ENUM('draft', 'published') NOT NULL DEFAULT 'draft'`
      );
      console.log("✅ Migration: Added status column to cases table");
    }

    // Migration: Add created_at column if missing
    const [createdAtColumns] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cases' AND COLUMN_NAME = 'created_at'`,
      [DB_CONFIG.database]
    );

    if (createdAtColumns.length === 0) {
      await pool.query(
        `ALTER TABLE cases 
         ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
      );
      console.log("✅ Migration: Added created_at column to cases table");
    }

    // Migration: Create essay_questions table
    const [essayTableExists] = await pool.query(
      `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES 
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'essay_questions'`,
      [DB_CONFIG.database]
    );

    if (essayTableExists.length === 0) {
      await pool.query(
        `CREATE TABLE essay_questions (
          id INT AUTO_INCREMENT PRIMARY KEY,
          step_id INT NOT NULL,
          question_text TEXT NOT NULL,
          keywords JSON NOT NULL,
          synonyms JSON,
          max_score INT DEFAULT 10,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (step_id) REFERENCES case_steps(id) ON DELETE CASCADE,
          INDEX idx_step_id (step_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
      );
      console.log("✅ Migration: Created essay_questions table");
    }

    // Migration: Add essay_answer column to step_attempts
    const [essayAnswerColumn] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'step_attempts' AND COLUMN_NAME = 'essay_answer'`,
      [DB_CONFIG.database]
    );

    if (essayAnswerColumn.length === 0) {
      await pool.query(
        `ALTER TABLE step_attempts 
         ADD COLUMN essay_answer TEXT`
      );
      console.log("✅ Migration: Added essay_answer column to step_attempts table");
    }

    // Migration: Add matched_keywords column to step_attempts
    const [matchedKeywordsColumn] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'step_attempts' AND COLUMN_NAME = 'matched_keywords'`,
      [DB_CONFIG.database]
    );

    if (matchedKeywordsColumn.length === 0) {
      await pool.query(
        `ALTER TABLE step_attempts 
         ADD COLUMN matched_keywords JSON`
      );
      console.log("✅ Migration: Added matched_keywords column to step_attempts table");
    }

    // Migration: Add perfect_answer column to essay_questions
    const [perfectAnswerColumn] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'essay_questions' AND COLUMN_NAME = 'perfect_answer'`,
      [DB_CONFIG.database]
    );

    if (perfectAnswerColumn.length === 0) {
      await pool.query(
        `ALTER TABLE essay_questions 
         ADD COLUMN perfect_answer TEXT`
      );
      console.log("✅ Migration: Added perfect_answer column to essay_questions table");
    }
  } catch (err) {
    console.error("⚠️ Migration failed:", err.message);
  }
}

connectDatabase();

/* ======================
   SQLITE-COMPAT DB API
====================== */


/* ======================
   AUTH MIDDLEWARE (JWT-BASED VALIDATION)
====================== */
function authMiddleware(requiredRole) {
  return async (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ message: "Missing token" });

    try {
      const token = header.split(" ")[1];
      const payload = jwt.verify(token, JWT_SECRET);

      // Role check
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ message: "Forbidden" });
      }

      // NEW: JWT-based device validation (no DB query!)
      const clientIP = getClientIP(req);
      const fingerprint = getDeviceFingerprint(req);
      const deviceType = getDeviceType(req);

      // Check if device locking is enabled in JWT
      if (payload.device_locked) {
        // Match against device1
        const device1Match = matchDevice(
          {
            ip: payload.device1_ip,
            fingerprint: payload.device1_fingerprint,
            last_seen: new Date() // Not used for JWT validation
          },
          clientIP,
          fingerprint,
          deviceType
        );

        // Match against device2
        const device2Match = matchDevice(
          {
            ip: payload.device2_ip,
            fingerprint: payload.device2_fingerprint,
            last_seen: new Date()
          },
          clientIP,
          fingerprint,
          deviceType
        );

        // Block if neither device matches
        if (!device1Match && !device2Match) {
          return res.status(403).json({
            message: "Access denied: Device not recognized. Please log in again from an authorized device."
          });
        }
      }

      // Periodic token version check (throttled to avoid DB overload)
      const cacheKey = `token_v_${payload.id}`;
      const cached = tokenVersionCache.get(cacheKey);
      const now = Date.now();

      if (!cached || (now - cached.timestamp > CACHE_TTL)) {
        // Check token version in DB (every 5 minutes)
        if (pool) {
          try {
            const [rows] = await pool.query(
              `SELECT token_version FROM users WHERE id = ? LIMIT 1`,
              [payload.id]
            );

            if (rows.length > 0) {
              const currentVersion = rows[0].token_version;

              // Cache the result
              tokenVersionCache.set(cacheKey, { version: currentVersion, timestamp: now });

              // Reject if version mismatch (admin reset)
              if (payload.token_version !== currentVersion) {
                return res.status(401).json({
                  message: "Session invalidated. Please log in again."
                });
              }
            }
          } catch (dbErr) {
            console.error('Token version check failed:', dbErr);
            // Continue without version check (fail-open for availability)
          }
        }
      } else {
        // Use cached version
        if (payload.token_version !== cached.version) {
          return res.status(401).json({
            message: "Session invalidated. Please log in again."
          });
        }
      }

      req.user = payload;
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: "Token expired" });
      }
      res.status(401).json({ message: "Invalid token" });
    }
  };
}

/* ======================
   AUTH ROUTES
====================== */
// Rate Limiter for Registration (uses rateLimit defined globally)
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 registration requests per windowMs
  message: { message: "Too many accounts created from this IP, please try again after 15 minutes" },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

app.post("/api/auth/register", registerLimiter, async (req, res) => {
  if (!pool) return res.status(503).json({ message: "DB unavailable" });

  let { name, email, phone, password, profileImage } = req.body;

  // 1. Name Validation
  if (!name) return res.status(400).json({ message: "Name is required" });
  name = name.trim();
  // Allow only English/Arabic letters and spaces. Length 3-25.
  const nameRegex = /^[A-Za-z\u0600-\u06FF\s]{3,25}$/;
  if (!nameRegex.test(name)) {
    return res.status(400).json({
      message: "Name must be 3–25 characters and contain only letters (Arabic or English) and spaces"
    });
  }

  // 2. Email Validation
  if (!email) return res.status(400).json({ message: "Email is required" });
  email = email.trim().toLowerCase();

  const emailRegex = /^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  // Deny-list check
  const domain = email.split('@')[1];
  const denyList = [
    // Gmail typos
    "gamil.com",
    "gmial.com",
    "gmai.com",
    "gmal.com",
    "gmail.co",
    "gmail.con",
    "gmail.cmo",
    "gmail.cm",
    "gmail.om",
    "gmail.comm",
    "gmail.coom",
    "gmail.xom",
    "gail.com",

    // Yahoo typos
    "yaho.com",
    "yhoo.com",
    "yhaoo.com",
    "yahoo.co",
    "yahoo.con",
    "yahoo.cmo",
    "yahho.com",
    "yaoo.com",
    "yaho.co",

    // Outlook / Hotmail typos
    "outlok.com",
    "outllok.com",
    "outloo.com",
    "outlook.co",
    "outlook.con",
    "outlook.cmo",
    "hotnail.com",
    "hotmal.com",
    "hotmial.com",
    "hotmai.com",
    "hotmail.co",
    "hotmail.con",
    "hotmail.cmo",
    "hotmali.com",

    // iCloud / Apple
    "icloud.co",
    "iclod.com",
    "icluod.com",
    "icloud.con",
    "icloud.cmo",

    // Proton / Zoho / Others
    "protnmail.com",
    "protonnmail.com",
    "protonmai.com",
    "zoho.co",
    "zhoo.com",

    // Generic broken domains
    "mail.co",
    "email.com",
    "test.com",
    "example.com",
    "domain.com",
    "yourmail.com",
    "yourdomain.com",
    "none.com",
    "null.com",

    // Common TLD mistakes
    "gmail.c",
    "gmail.o",
    "gmail.m",
    "yahoo.c",
    "outlook.c",
    "hotmail.c",
    "icloud.c",

    // Obvious bot patterns
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "throwawaymail.com",
    "fakeinbox.com",
    "getnada.com",
    "trashmail.com",
  ];

  if (denyList.includes(domain)) {
    // Try to guess the correct one for a helpful message
    let suggestion = "";
    if (domain === "gamil.com" || domain === "gil.com") suggestion = "gmail.com";
    else if (domain === "hotnail.com") suggestion = "hotmail.com";
    else if (domain === "yaho.com") suggestion = "yahoo.com";
    else if (domain === "outlok.com") suggestion = "outlook.com";
    else if (domain === "icloud.co") suggestion = "icloud.com";

    return res.status(400).json({
      message: `Invalid email domain.${suggestion ? ` Did you mean ${suggestion}?` : ""}`
    });
  }

  // 3. Phone Validation & Normalization
  if (!phone) return res.status(400).json({ message: "Phone number is required" });
  phone = phone.trim();

  // Egyptian Phone Regex: Accepts 010, 011, 012, 015 with optional +20 prefix
  const phoneRegex = /^(?:\+20|0)(10|11|12|15)\d{8}$/;

  if (!phoneRegex.test(phone)) {
    return res.status(400).json({
      message: "Please enter a valid Egyptian phone number (010, 011, 012, 015)"
    });
  }

  // Normalize: Convert +2010... to 010...
  if (phone.startsWith("+20")) {
    phone = "0" + phone.substring(3);
  }

  // 4. Password Validation
  if (!password || password.length < 8) {
    return res.status(400).json({
      message: "Password must be at least 8 characters"
    });
  }

  const hash = bcrypt.hashSync(password, 10);

  // NEW: Capture device info
  const clientIP = getClientIP(req);
  const fingerprint = getDeviceFingerprint(req);
  const now = new Date();

  // Validate IP
  if (!isValidIP(clientIP)) {
    console.warn(`Invalid IP detected during registration: ${clientIP}`);
  }

  try {
    // BEGIN TRANSACTION
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Generate verification code
      const verificationCode = crypto.randomInt(100000, 999999).toString();
      const verificationExpires = new Date(now.getTime() + 15 * 60 * 1000); // 15 mins

      // Insert user with device1 info and verification data
      const [result] = await connection.query(
        `INSERT INTO users (
          name, email, phone, passwordHash, profileImage, role,
          device1_ip, device1_fingerprint, device1_last_seen,
          device_locked, token_version,
          email_verified, email_verification_code, email_verification_expires_at
        ) VALUES (?, ?, ?, ?, ?, 'student', ?, ?, ?, TRUE, 1, FALSE, ?, ?)`,
        [name, email, phone, hash, profileImage || null, clientIP, fingerprint, now, verificationCode, verificationExpires]
      );

      const userId = result.insertId;

      // Send verification email
      const emailSent = await sendVerificationEmail(email, verificationCode);
      if (!emailSent) {
        console.error("Failed to send verification email to:", email);
        // We still commit the user, but they will need to resend code
      }

      // COMMIT TRANSACTION
      await connection.commit();
      connection.release();

      res.json({
        message: "Verification code sent to your email",
        userId: userId
      });

    } catch (err) {
      // ROLLBACK on error
      await connection.rollback();
      connection.release();
      throw err;
    }

  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      if (err.message.includes('email')) {
        return res.status(409).json({ message: "Email already exists" });
      } else if (err.message.includes('phone')) {
        return res.status(409).json({ message: "Phone number already exists" });
      }
      return res.status(409).json({ message: "Email or phone already exists" });
    }
    console.error('Registration error:', err);
    return res.status(500).json({ message: "Registration failed", error: err.message });
  }
});

app.post("/api/auth/verify-email", authLimiter, async (req, res) => {
  if (!pool) return res.status(503).json({ message: "DB unavailable" });
  const { userId, code } = req.body;

  if (!userId || !code) {
    return res.status(400).json({ message: "User ID and code are required" });
  }

  try {
    const [rows] = await pool.query(
      `SELECT * FROM users WHERE id = ?`,
      [userId]
    );
    const user = rows[0];

    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.email_verified) return res.json({ message: "Email already verified" });

    if (user.email_verification_code !== code) {
      return res.status(400).json({ message: "Invalid verification code" });
    }

    if (new Date() > new Date(user.email_verification_expires_at)) {
      return res.status(400).json({ message: "Verification code expired" });
    }

    // Mark verified, set default membershipType, and clear code
    await pool.query(
      `UPDATE users SET email_verified = TRUE, membershipType = 'Normal', email_verification_code = NULL, email_verification_expires_at = NULL WHERE id = ?`,
      [userId]
    );

    // Auto-assign Normal subscription
    try {
      const [normalPlan] = await pool.query(`SELECT id FROM subscription_plans WHERE name = 'Normal' LIMIT 1`);
      if (normalPlan.length > 0) {
        const planId = normalPlan[0].id;
        const startDate = new Date().toISOString().split('T')[0];
        // 1 year default for Normal
        const endDate = new Date();
        endDate.setFullYear(endDate.getFullYear() + 1);
        const endDateStr = endDate.toISOString().split('T')[0];

        await pool.query(
          `INSERT INTO subscriptions (userId, planId, startDate, endDate, status) 
           VALUES (?, ?, ?, ?, 'active') 
           ON DUPLICATE KEY UPDATE planId = VALUES(planId), status = 'active', endDate = VALUES(endDate)`,
          [userId, planId, startDate, endDateStr]
        );
      }
    } catch (subErr) {
      console.error("Failed to auto-assign Normal subscription:", subErr);
      // Don't fail the verification if subscription fails
    }

    // Generate JWT (same as login)
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        device1_ip: user.device1_ip,
        device1_fingerprint: user.device1_fingerprint,
        device2_ip: user.device2_ip,
        device2_fingerprint: user.device2_fingerprint,
        device_locked: user.device_locked,
        token_version: user.token_version
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    const { passwordHash, device1_fingerprint, device2_fingerprint, token_version, email_verification_code, ...userResponse } = user;
    res.json({ token, user: { ...userResponse, email_verified: 1 } });

  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).json({ message: "Verification failed" });
  }
});

app.post("/api/auth/resend-code", authLimiter, async (req, res) => {
  if (!pool) return res.status(503).json({ message: "DB unavailable" });
  const { userId } = req.body;

  try {
    const [rows] = await pool.query(`SELECT * FROM users WHERE id = ?`, [userId]);
    const user = rows[0];

    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.email_verified) return res.status(400).json({ message: "Email already verified" });

    // Generate new code
    const newCode = crypto.randomInt(100000, 999999).toString();
    const newExpires = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      `UPDATE users SET email_verification_code = ?, email_verification_expires_at = ? WHERE id = ?`,
      [newCode, newExpires, userId]
    );

    await sendVerificationEmail(user.email, newCode);

    res.json({ message: "New verification code sent" });
  } catch (err) {
    console.error("Resend error:", err);
    res.status(500).json({ message: "Failed to resend code" });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  if (!pool) return res.status(503).json({ message: "DB unavailable" });

  const { identifier, password } = req.body; // identifier can be email or phone

  if (!identifier || !password) {
    return res.status(400).json({ message: "Email/phone and password required" });
  }

  try {
    // Step 1: Find user and verify password (BEFORE transaction)
    const isEmail = identifier.includes('@');
    const query = isEmail
      ? `SELECT * FROM users WHERE email = ?`
      : `SELECT * FROM users WHERE phone = ?`;

    const [rows] = await pool.query(query, [identifier]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.email_verified) {
      return res.status(403).json({ message: "Email not verified" });
    }

    // Step 2: Capture current device info
    const clientIP = getClientIP(req);
    const fingerprint = getDeviceFingerprint(req);
    const deviceType = getDeviceType(req);
    const now = new Date();

    // Step 3: START TRANSACTION for device lock logic
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Lock user row to prevent race conditions
      const [lockedRows] = await connection.query(
        `SELECT id, device1_ip, device1_fingerprint, device1_last_seen,
                device2_ip, device2_fingerprint, device2_last_seen,
                device_locked, token_version
         FROM users
         WHERE id = ?
         FOR UPDATE`, // ROW-LEVEL LOCK
        [user.id]
      );

      const lockedUser = lockedRows[0];

      // Step 4: Device matching logic
      let updateQuery = null;
      let updateParams = [];
      let deviceMatched = false;
      let newTokenVersion = lockedUser.token_version;

      // Check if device locking is enabled
      if (!lockedUser.device_locked) {
        // Device locking disabled - just update last_seen if device exists
        if (lockedUser.device1_ip === clientIP) {
          updateQuery = `UPDATE users SET device1_last_seen = ? WHERE id = ?`;
          updateParams = [now, user.id];
        } else if (lockedUser.device2_ip === clientIP) {
          updateQuery = `UPDATE users SET device2_last_seen = ? WHERE id = ?`;
          updateParams = [now, user.id];
        }
        deviceMatched = true; // Always allow if locking disabled
      } else {
        // Device locking enabled - strict validation

        // Check Device 1
        const device1Match = matchDevice(
          {
            ip: lockedUser.device1_ip,
            fingerprint: lockedUser.device1_fingerprint,
            last_seen: lockedUser.device1_last_seen
          },
          clientIP,
          fingerprint,
          deviceType
        );

        // Check Device 2
        const device2Match = matchDevice(
          {
            ip: lockedUser.device2_ip,
            fingerprint: lockedUser.device2_fingerprint,
            last_seen: lockedUser.device2_last_seen
          },
          clientIP,
          fingerprint,
          deviceType
        );

        if (device1Match) {
          // Update device1 last_seen (and IP in case it changed for mobile)
          updateQuery = `UPDATE users SET device1_ip = ?, device1_last_seen = ? WHERE id = ?`;
          updateParams = [clientIP, now, user.id];
          deviceMatched = true;
        } else if (device2Match) {
          // Update device2 last_seen
          updateQuery = `UPDATE users SET device2_ip = ?, device2_last_seen = ? WHERE id = ?`;
          updateParams = [clientIP, now, user.id];
          deviceMatched = true;
        } else if (!lockedUser.device1_ip) {
          // Device 1 slot is empty - register new device
          updateQuery = `UPDATE users SET device1_ip = ?, device1_fingerprint = ?, device1_last_seen = ?, token_version = token_version + 1 WHERE id = ?`;
          updateParams = [clientIP, fingerprint, now, user.id];
          newTokenVersion = lockedUser.token_version + 1;
          deviceMatched = true;
        } else if (!lockedUser.device2_ip) {
          // Device 2 slot is empty - register new device
          updateQuery = `UPDATE users SET device2_ip = ?, device2_fingerprint = ?, device2_last_seen = ?, token_version = token_version + 1 WHERE id = ?`;
          updateParams = [clientIP, fingerprint, now, user.id];
          newTokenVersion = lockedUser.token_version + 1;
          deviceMatched = true;
        } else {
          // Both slots occupied and no match - BLOCK
          deviceMatched = false;
        }
      }

      // Step 5: Execute update or block
      if (!deviceMatched) {
        await connection.rollback();
        connection.release();
        return res.status(403).json({
          message: "Access denied: This account is restricted to registered devices only. Please contact support to reset your devices."
        });
      }

      // Execute device update
      if (updateQuery) {
        await connection.query(updateQuery, updateParams);
      }

      // Fetch updated user data
      const [updatedRows] = await connection.query(
        `SELECT id, email, role, name, profileImage, membershipType,
                device1_ip, device1_fingerprint, device2_ip, device2_fingerprint,
                device_locked, token_version
         FROM users WHERE id = ?`,
        [user.id]
      );

      const updatedUser = updatedRows[0];

      // COMMIT TRANSACTION
      await connection.commit();
      connection.release();

      // Step 6: Generate JWT with device info
      const token = jwt.sign(
        {
          id: updatedUser.id,
          email: updatedUser.email,
          role: updatedUser.role,
          // Include device info in JWT for middleware validation
          device1_ip: updatedUser.device1_ip,
          device1_fingerprint: updatedUser.device1_fingerprint,
          device2_ip: updatedUser.device2_ip,
          device2_fingerprint: updatedUser.device2_fingerprint,
          device_locked: updatedUser.device_locked,
          token_version: updatedUser.token_version
        },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      // Step 7: Return response
      const { passwordHash, device1_fingerprint, device2_fingerprint, token_version, ...userWithoutSensitive } = updatedUser;
      res.json({ token, user: userWithoutSensitive });

    } catch (err) {
      // ROLLBACK on error
      await connection.rollback();
      connection.release();
      throw err;
    }

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: "Database error" });
  }
});

/* ======================
   🔥 ALL YOUR OTHER ROUTES GO HERE
   (PASTE THEM EXACTLY AS THEY ARE)
====================== */

/* ======================
   DEVELOPMENT ONLY ROUTES - NOT REGISTERED IN PRODUCTION
====================== */
if (process.env.NODE_ENV !== 'production') {
  // Status check endpoint (dev only)
  app.get('/api/dev/status-check', async (req, res) => {
    try {
      if (!pool) return res.status(503).json({ message: "DB unavailable" });
      const [rows] = await pool.query("SELECT status, COUNT(*) as count FROM cases GROUP BY status");
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Failed to check status" });
    }
  });

  // Bulk publish endpoint (dev only)
  app.post('/api/dev/publish-all', async (req, res) => {
    try {
      if (!pool) return res.status(503).json({ message: "DB unavailable" });
      await pool.query("UPDATE cases SET status = 'published'");
      res.json({ message: "All cases published" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Failed to publish cases" });
    }
  });

  // Database seeding endpoint (dev only)
  app.post('/api/dev/seed', async (req, res) => {
    try {
      if (!pool) return res.status(503).json({ message: "DB unavailable" });

      // 1. Create Users
      const usersData = [
        { email: 'student1@test.com', name: 'Alice Student', role: 'student' },
        { email: 'student2@test.com', name: 'Bob User', role: 'student' },
        { email: 'student3@test.com', name: 'Charlie Learner', role: 'student' }
      ];

      const passwordHash = bcrypt.hashSync('password123', 10);
      const userIds = [];

      for (const u of usersData) {
        const [result] = await pool.query(
          `INSERT INTO users (email, passwordHash, role, name) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)`,
          [u.email, passwordHash, u.role, u.name]
        );

        if (result.insertId) {
          userIds.push(result.insertId);
        } else {
          // If insertId is 0 (which can happen with ON DUPLICATE KEY UPDATE if no change), fetch the ID
          const [rows] = await pool.query(`SELECT id FROM users WHERE email = ?`, [u.email]);
          if (rows.length > 0) userIds.push(rows[0].id);
        }
      }

      // 2. Create 4 Complete Cases with Steps
      const casesData = [
        {
          title: 'Knee Pain Assessment',
          difficulty: 'Beginner',
          category: 'Orthopedics',
          steps: [
            {
              type: 'info',
              stepIndex: 0,
              content: JSON.stringify({
                patientName: 'John Smith',
                age: 45,
                gender: 'Male',
                description: 'Patient presents with chronic knee pain',
                chiefComplaint: 'ألم في الركبة منذ 3 أشهر'
              })
            },
            {
              type: 'mcq',
              stepIndex: 1,
              question: 'What is the first step in assessment?',
              maxScore: 10,
              options: [
                { label: 'Order MRI immediately', isCorrect: false, feedback: 'Too aggressive for initial assessment' },
                { label: 'Physical examination', isCorrect: true, feedback: 'Correct! Always start with physical exam' },
                { label: 'Prescribe pain medication', isCorrect: false, feedback: 'Need assessment first' }
              ]
            }
          ]
        },
        {
          title: 'Chest Pain Evaluation',
          difficulty: 'Intermediate',
          category: 'Cardiology',
          steps: [
            {
              type: 'info',
              stepIndex: 0,
              content: JSON.stringify({
                patientName: 'Sarah Johnson',
                age: 62,
                gender: 'Female',
                description: 'Acute chest pain radiating to left arm',
                chiefComplaint: 'ألم في الصدر منذ ساعة'
              })
            },
            {
              type: 'mcq',
              stepIndex: 1,
              question: 'What is the most urgent action?',
              maxScore: 15,
              options: [
                { label: 'ECG and cardiac markers', isCorrect: true, feedback: 'Correct! Rule out MI immediately' },
                { label: 'Schedule stress test', isCorrect: false, feedback: 'Too slow for acute presentation' },
                { label: 'Give antacids', isCorrect: false, feedback: 'Dangerous assumption' }
              ]
            }
          ]
        },
        {
          title: 'Pediatric Fever Management',
          difficulty: 'Intermediate',
          category: 'Pediatrics',
          steps: [
            {
              type: 'info',
              stepIndex: 0,
              content: JSON.stringify({
                patientName: 'Emma Davis',
                age: 3,
                gender: 'Female',
                description: 'High fever 39.5°C for 2 days',
                chiefComplaint: 'حمى عالية منذ يومين'
              })
            },
            {
              type: 'mcq',
              stepIndex: 1,
              question: 'What is the priority assessment?',
              maxScore: 12,
              options: [
                { label: 'Check for meningeal signs', isCorrect: true, feedback: 'Correct! Critical in febrile child' },
                { label: 'Give antibiotics immediately', isCorrect: false, feedback: 'Need diagnosis first' },
                { label: 'Send home with antipyretics', isCorrect: false, feedback: 'Need full assessment' }
              ]
            }
          ]
        },
        {
          title: 'Headache Diagnosis',
          difficulty: 'Advanced',
          category: 'Neurology',
          steps: [
            {
              type: 'info',
              stepIndex: 0,
              content: JSON.stringify({
                patientName: 'Michael Brown',
                age: 38,
                gender: 'Male',
                description: 'Sudden severe headache, worst of life',
                chiefComplaint: 'صداع شديد مفاجئ'
              })
            },
            {
              type: 'mcq',
              stepIndex: 1,
              question: 'What is the most concerning diagnosis?',
              maxScore: 20,
              options: [
                { label: 'Migraine', isCorrect: false, feedback: 'Unlikely with sudden onset' },
                { label: 'Subarachnoid hemorrhage', isCorrect: true, feedback: 'Correct! "Thunderclap" headache is classic' },
                { label: 'Tension headache', isCorrect: false, feedback: 'Not sudden or severe' }
              ]
            }
          ]
        }
      ];

      const caseIds = [];
      for (const caseData of casesData) {
        // Insert case
        const [caseResult] = await pool.query(
          `INSERT INTO cases (title, difficulty, category, duration, isLocked) VALUES (?, ?, ?, 15, 0)`,
          [caseData.title, caseData.difficulty, caseData.category]
        );
        const caseId = caseResult.insertId;

        if (caseId) {
          caseIds.push(caseId);

          // Insert steps for this case
          for (const step of caseData.steps) {
            const [stepResult] = await pool.query(
              `INSERT INTO case_steps (caseId, stepIndex, type, content, question, maxScore) VALUES (?, ?, ?, ?, ?, ?)`,
              [caseId, step.stepIndex, step.type, step.content || null, step.question || null, step.maxScore || 0]
            );
            const stepId = stepResult.insertId;

            // Insert options if this is an MCQ step
            if (step.options && stepId) {
              for (const option of step.options) {
                await pool.query(
                  `INSERT INTO case_step_options (stepId, label, isCorrect, feedback) VALUES (?, ?, ?, ?)`,
                  [stepId, option.label, option.isCorrect ? 1 : 0, option.feedback]
                );
              }
            }
          }
        }
      }

      // 3. Create Progress (Completed) for users
      for (const uid of userIds) {
        for (const cid of caseIds) {
          const score = Math.floor(Math.random() * 50) + 50; // 50-100
          await pool.query(
            `INSERT INTO progress (userId, caseId, score, isCompleted, createdAt) VALUES (?, ?, ?, 1, NOW()) ON DUPLICATE KEY UPDATE score = VALUES(score)`,
            [uid, cid, score]
          );
        }
      }

      res.json({
        message: 'Seeding complete',
        users: userIds.length,
        cases: caseIds.length,
        details: 'Created 3 users and 4 complete cases with steps and options'
      });

    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Seeding failed', error: error.message });
    }
  });

  console.log('🔧 Development routes registered: /api/dev/*');
} else {
  console.log('🔒 Production mode: /api/dev/* routes are disabled');
}



app.get('/api/me', authMiddleware(), async (req, res) => {
  try {
    // Get user basic info
    const [rows] = await pool.query(
      `SELECT id, email, role, name, profileImage FROM users WHERE id = ?`,
      [req.user.id]
    );
    const user = rows[0];

    if (!user) return res.status(404).json({ message: 'User not found' });

    // Get derived membership from active subscription
    const membership = await getUserMembership(pool, req.user.id);

    // Combine user data with derived membership
    res.json({
      ...user,
      membershipType: membership.membershipType,
      membershipExpiresAt: membership.membershipExpiresAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.put('/api/user/profile', authMiddleware(), async (req, res) => {
  const { name, profileImage } = req.body;
  try {
    await pool.query(
      `UPDATE users SET name = ?, profileImage = ? WHERE id = ?`,
      [name, profileImage, req.user.id]
    );
    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/api/profile/stats', authMiddleware(), async (req, res) => {
  try {
    // Get cases completed and total score
    const [statsRows] = await pool.query(
      `SELECT 
         COUNT(DISTINCT caseId) as casesCompleted,
         SUM(score) as totalScore
       FROM progress
       WHERE userId = ? AND isCompleted = 1`,
      [req.user.id]
    );
    const stats = statsRows[0];

    // Get completed cases list
    const [completedCases] = await pool.query(
      `SELECT p.caseId, p.score, p.createdAt as completedAt, c.title
       FROM progress p
       JOIN cases c ON p.caseId = c.id
       WHERE p.userId = ? AND p.isCompleted = 1
       ORDER BY p.createdAt DESC`,
      [req.user.id]
    );

    // Get rank
    const [leaderboard] = await pool.query(
      `SELECT userId, SUM(score) as totalScore
       FROM progress
       WHERE isCompleted = 1
       GROUP BY userId
       ORDER BY totalScore DESC`
    );

    const rank = leaderboard.findIndex(u => u.userId === req.user.id) + 1;

    // Get membership info from active subscription
    const membership = await getUserMembership(pool, req.user.id);

    res.json({
      casesCompleted: stats.casesCompleted || 0,
      totalScore: stats.totalScore || 0,
      rank: rank || '-',
      membershipType: membership.membershipType,
      membershipExpiresAt: membership.membershipExpiresAt,
      planRole: membership.planRole,
      completedCases: completedCases || []
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/api/cases', searchLimiter, async (req, res) => {
  try {
    // Validate query parameters with Zod schema
    const validationResult = searchQuerySchema.safeParse(req.query);
    if (!validationResult.success) {
      console.warn(`[SECURITY] Invalid search params from IP ${req.ip}:`, validationResult.error.flatten());
      return res.status(400).json({
        message: 'Invalid search parameters',
        errors: validationResult.error.flatten().fieldErrors
      });
    }

    const { search, category, difficulty, duration, page, limit } = validationResult.data;
    const offset = (page - 1) * limit;

    // Optional Auth Logic
    let userId = null;
    const header = req.headers.authorization;
    if (header) {
      try {
        const token = header.split(" ")[1];
        const payload = jwt.verify(token, JWT_SECRET);
        userId = payload.id;
      } catch (e) {
        // Invalid token, proceed as guest
      }
    }

    // Build filter conditions
    let filterClauses = ["c.status = 'published'", "EXISTS (SELECT 1 FROM case_steps cs WHERE cs.caseId = c.id)"];
    let filterParams = [];

    if (search) {
      filterClauses.push("(c.title LIKE ? OR c.metadata LIKE ?)");
      filterParams.push(`%${search}%`, `%${search}%`);
    }
    if (category !== 'all') {
      // Try to match by ID or by the category name/string
      filterClauses.push("(c.categoryId = ? OR c.category = ? OR cat.name = ?)");
      filterParams.push(category, category, category);
    }
    if (difficulty !== 'all') {
      filterClauses.push("c.difficulty = ?");
      filterParams.push(difficulty);
    }
    if (duration !== 'all') {
      if (duration === 'short') {
        filterClauses.push("(c.duration <= 10 OR c.duration IS NULL)");
      } else if (duration === 'medium') {
        filterClauses.push("(c.duration > 10 AND c.duration <= 20)");
      } else if (duration === 'long') {
        filterClauses.push("c.duration > 20");
      }
    }

    const whereClause = filterClauses.length > 0 ? "WHERE " + filterClauses.join(" AND ") : "";



    // Count total filtered cases
    const [countRows] = await pool.query(
      `SELECT COUNT(*) as total FROM cases c 
       LEFT JOIN categories cat ON c.categoryId = cat.id
       ${whereClause}`,
      filterParams
    );
    const total = countRows[0].total;
    const totalPages = Math.ceil(total / limit);

    let query;
    let params = [];

    if (userId) {
      query = `SELECT c.*, cat.name as categoryName, cat.icon as categoryIcon,
        sp.name as requiredPlanName, sp.role as requiredPlanRole,
        COALESCE((
          SELECT MAX(isCompleted) FROM progress p
          WHERE p.userId = ? AND p.caseId = c.id
        ), 0) as isCompleted
       FROM cases c
       LEFT JOIN categories cat ON c.categoryId = cat.id
       LEFT JOIN subscription_plans sp ON c.requiredPlanId = sp.id
       ${whereClause}
       ORDER BY c.created_at DESC
       LIMIT ? OFFSET ?`;
      params = [userId, ...filterParams, limit, offset];
    } else {
      // Guest query: no progress, just cases
      query = `SELECT c.*, cat.name as categoryName, cat.icon as categoryIcon,
        sp.name as requiredPlanName, sp.role as requiredPlanRole,
        0 as isCompleted
       FROM cases c
       LEFT JOIN categories cat ON c.categoryId = cat.id
       LEFT JOIN subscription_plans sp ON c.requiredPlanId = sp.id
       ${whereClause}
       ORDER BY c.created_at DESC
       LIMIT ? OFFSET ?`;
      params = [...filterParams, limit, offset];
    }

    const [rows] = await pool.query(query, params);

    // Get user's membership if logged in
    let userMembership = null;
    if (userId) {
      userMembership = await getUserMembership(pool, userId);
    }

    const cases = rows.map((row) => {
      // Determine if case is locked based on required plan
      let isLockedByPlan = false;
      if (row.requiredPlanId) {
        const userRole = (userMembership && userMembership.planRole) ? userMembership.planRole : 'normal';

        // Check plan hierarchy
        const planHierarchy = getPlanHierarchy();
        const userPlanLevel = planHierarchy[userRole] || 1;
        const requiredPlanLevel = planHierarchy[row.requiredPlanRole] || 1;

        // Hierarchical inheritance for Systemic Premium roles
        if (userRole === 'premium' || userRole === 'ultra') {
          isLockedByPlan = userPlanLevel < requiredPlanLevel;
        } else {
          // Strict match or free access for other roles (Custom/Normal)
          isLockedByPlan = userRole !== row.requiredPlanRole;

          // Special case: if it requires 'normal', all roles can see it (hierarchy baseline)
          if (row.requiredPlanRole === 'normal') isLockedByPlan = false;
        }
      }

      return {
        id: row.id,
        title: row.title,
        specialty: row.specialty,
        difficulty: row.difficulty,
        isLocked: !!row.isLocked || isLockedByPlan,
        prerequisiteCaseId: row.prerequisiteCaseId,
        metadata: row.metadata ? JSON.parse(row.metadata) : {},
        isCompleted: !!row.isCompleted,
        thumbnailUrl: row.thumbnailUrl,
        duration: row.duration || 10,
        categoryId: row.categoryId,
        categoryName: row.categoryName || row.category,
        categoryIcon: row.categoryIcon,
        requiredPlanName: row.requiredPlanName,
        isLockedByPlan
      };
    });

    res.json({
      data: cases,
      meta: {
        page,
        limit,
        total,
        totalPages,
        debug: {
          host: DB_CONFIG.host,
          countResult: countRows
        }
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/api/cases/:id', authMiddleware(), async (req, res) => {
  const caseId = req.params.id;
  try {
    const [caseRows] = await pool.query(`SELECT * FROM cases WHERE id = ?`, [caseId]);
    const caseRow = caseRows[0];

    if (!caseRow) return res.status(404).json({ message: 'Case not found' });

    // Check case access based on required plan
    const accessCheck = await checkCaseAccess(pool, req.user.id, caseId);
    if (!accessCheck.hasAccess) {
      return res.status(403).json({
        message: `Access denied: This case requires ${accessCheck.requiredPlan || 'a subscription'} plan.`,
        requiredPlan: accessCheck.requiredPlan,
        reason: accessCheck.reason
      });
    }

    if (caseRow.prerequisiteCaseId) {
      const [progRows] = await pool.query(
        `SELECT MAX(isCompleted) as done
         FROM progress
         WHERE userId = ? AND caseId = ?`,
        [req.user.id, caseRow.prerequisiteCaseId]
      );
      const row = progRows[0];
      if (!row || !row.done) {
        return res.status(403).json({
          message: 'You must complete the prerequisite case first.',
        });
      }
    }

    // Load steps
    const [steps] = await pool.query(
      `SELECT * FROM case_steps WHERE caseId = ? ORDER BY stepIndex ASC`,
      [caseId]
    );

    if (!steps.length) {
      return res.status(500).json({ message: 'Case has no steps configured' });
    }

    const stepIds = steps.map((s) => s.id);

    if (stepIds.length === 0) {
      return res.json({ ...caseRow, steps: [] });
    }

    const placeholders = stepIds.map(() => '?').join(',');

    const [options] = await pool.query(`SELECT * FROM case_step_options WHERE stepId IN (${placeholders})`, stepIds);
    const [inv] = await pool.query(`SELECT * FROM investigations WHERE stepId IN (${placeholders})`, stepIds);
    const [xrays] = await pool.query(`SELECT * FROM xrays WHERE stepId IN (${placeholders})`, stepIds);
    const [essayQuestions] = await pool.query(`SELECT * FROM essay_questions WHERE step_id IN (${placeholders})`, stepIds);

    const stepsDto = steps.map((s) => ({
      id: s.id,
      stepIndex: s.stepIndex,
      type: s.type,
      content: (() => {
        try {
          return s.content ? JSON.parse(s.content) : null;
        } catch (e) {
          console.warn(`Failed to parse content for step ${s.id}:`, e.message);
          return null;
        }
      })(),
      question: s.question,
      explanationOnFail: s.explanationOnFail,
      maxScore: s.maxScore,
      options: options.filter((o) => o.stepId === s.id).map(
        (o) => ({
          id: o.id,
          label: o.label,
        })
      ),
      investigations: inv
        .filter((i) => i.stepId === s.id)
        .map((i) => ({
          id: i.id,
          groupLabel: i.groupLabel,
          testName: i.testName,
          description: i.description,
          result: i.result,
          videoUrl: i.videoUrl,
        })),
      xrays: xrays
        .filter((x) => x.stepId === s.id)
        .map((x) => {
          return {
            id: x.id,
            label: x.label,
            icon: x.icon,
            imageUrl: x.imageUrl,
          };
        }),
      essayQuestions: essayQuestions.filter((eq) => eq.step_id === s.id).map((eq) => {
        const safeParseList = (data) => {
          if (!data) return [];
          try {
            const parsed = JSON.parse(data);
            if (Array.isArray(parsed)) return parsed;
            return [];
          } catch (e) {
            return String(data).split(',').map(s => s.trim()).filter(Boolean);
          }
        };
        return {
          id: eq.id,
          question_text: eq.question_text,
          keywords: safeParseList(eq.keywords),
          synonyms: safeParseList(eq.synonyms),
          max_score: eq.max_score,
          perfect_answer: eq.perfect_answer || ''
        };
      }),
      tag: s.tag,
      expected_time: s.expected_time,
      hint_text: s.hint_text,
      hint_enabled: !!s.hint_enabled
    }));

    // Load attempts if user is logged in
    const [attempts] = await pool.query(
      `SELECT stepId, selectedOptionId, isCorrect, attemptNumber 
       FROM step_attempts 
       WHERE caseId = ? AND userId = ?
       ORDER BY attemptNumber DESC`, // Get latest attempts
      [caseId, req.user.id]
    );

    // Create a map of latest attempts per step
    const latestAttempts = {};
    attempts.forEach(a => {
      // Since we ordered by DESC, the first one we see is the latest
      if (!latestAttempts[a.stepId]) {
        latestAttempts[a.stepId] = {
          selectedOptionId: a.selectedOptionId,
          isCorrect: !!a.isCorrect
        };
      }
    });

    // Check completion status
    const [progressRows] = await pool.query(
      `SELECT isCompleted, score FROM progress WHERE userId = ? AND caseId = ?`,
      [req.user.id, caseId]
    );
    const progress = progressRows[0];

    res.json({
      id: caseRow.id,
      title: caseRow.title,
      specialty: caseRow.specialty,
      difficulty: caseRow.difficulty,
      category: caseRow.category,
      metadata: caseRow.metadata
        ? JSON.parse(caseRow.metadata)
        : {},
      thumbnailUrl: caseRow.thumbnailUrl,
      duration: caseRow.duration || 10,
      isCompleted: !!progress?.isCompleted,
      userScore: progress?.score,
      userProgress: latestAttempts,
      steps: stepsDto,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.post(
  '/api/cases/:caseId/steps/:stepId/answer',
  authMiddleware(),
  async (req, res) => {
    const { selectedOptionId, isFinalStep, timeSpent, hintShown, attemptNumber } = req.body;
    const { caseId, stepId } = req.params;

    try {
      const [optionRows] = await pool.query(
        `SELECT * FROM case_step_options WHERE id = ? AND stepId = ?`,
        [selectedOptionId, stepId]
      );
      const optionRow = optionRows[0];

      if (!optionRow)
        return res.status(400).json({ message: 'Invalid option' });

      const isCorrect = !!optionRow.isCorrect;

      // Record the attempt in step_attempts table for performance tracking
      try {
        await pool.query(
          `INSERT INTO step_attempts (userId, caseId, stepId, selectedOptionId, isCorrect, timeSpent, hintShown, attemptNumber)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            req.user.id,
            caseId,
            stepId,
            selectedOptionId,
            isCorrect ? 1 : 0,
            timeSpent || 0,
            hintShown ? 1 : 0,
            attemptNumber || 1
          ]
        );
      } catch (attemptErr) {
        // Log but don't fail the main request if attempt tracking fails
        console.error('Failed to record step attempt:', attemptErr);
      }

      if (!isCorrect) {
        return res.json({
          correct: false,
          feedback: optionRow.feedback,
        });
      }

      if (isFinalStep) {
        // Calculate total score dynamically (Scoring Fix)
        // Only count correct attempts on MCQ steps
        const [scoreRows] = await pool.query(
          `SELECT SUM(cs.maxScore) as totalScore
           FROM step_attempts sa
           JOIN case_steps cs ON sa.stepId = cs.id
           WHERE sa.caseId = ? AND sa.userId = ? AND cs.type = 'mcq' AND sa.isCorrect = 1
           AND sa.id IN (
               SELECT MAX(id) FROM step_attempts 
               WHERE caseId = ? AND userId = ? 
               GROUP BY stepId
           )`,
          [caseId, req.user.id, caseId, req.user.id]
        );
        const score = scoreRows[0].totalScore || 0;

        // Completion Persistence Fix: Upsert progress
        await pool.query(
          `INSERT INTO progress (userId, caseId, score, isCompleted, createdAt)
           VALUES (?, ?, ?, 1, NOW())
           ON DUPLICATE KEY UPDATE score = VALUES(score), isCompleted = 1, createdAt = VALUES(createdAt)`,
          [req.user.id, caseId, score]
        );

        const [statsRows] = await pool.query(
          `SELECT 
             COUNT(DISTINCT caseId) as casesCompleted,
             SUM(score) as totalScore
           FROM progress
           WHERE userId = ? AND isCompleted = 1`,
          [req.user.id]
        );
        const stats = statsRows[0];

        res.json({
          correct: true,
          final: true,
          score,
          stats: {
            casesCompleted: stats.casesCompleted || 0,
            totalScore: stats.totalScore || 0,
          },
        });
      } else {
        res.json({
          correct: true,
        });
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Database error' });
    }
  }
);

// Essay Answer Submission Endpoint
app.post(
  '/api/cases/:caseId/steps/:stepId/answer-essay',
  authMiddleware(),
  async (req, res) => {
    const { essayAnswer, isFinalStep, timeSpent, hintShown, attemptNumber } = req.body;
    const { caseId, stepId } = req.params;

    try {
      // Fetch essay questions for this step
      const [essayQuestions] = await pool.query(
        `SELECT * FROM essay_questions WHERE step_id = ?`,
        [stepId]
      );

      if (essayQuestions.length === 0) {
        return res.status(400).json({ message: 'No essay questions found for this step' });
      }

      // Scoring algorithm
      let totalScore = 0;
      let allMatchedKeywords = [];
      let totalKeywords = 0;
      let isPerfectMatch = false;

      // Helper function to calculate similarity between two strings
      const calculateSimilarity = (str1, str2) => {
        const normalize = (str) => str
          .toLowerCase()
          .replace(/[.,\/#!$%\^&\*;:{}=\-_`~()]/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();

        const s1 = normalize(str1);
        const s2 = normalize(str2);

        if (s1 === s2) return 100;
        if (s1.length === 0 || s2.length === 0) return 0;

        // Calculate Levenshtein distance
        const matrix = [];
        for (let i = 0; i <= s2.length; i++) {
          matrix[i] = [i];
        }
        for (let j = 0; j <= s1.length; j++) {
          matrix[0][j] = j;
        }
        for (let i = 1; i <= s2.length; i++) {
          for (let j = 1; j <= s1.length; j++) {
            if (s2.charAt(i - 1) === s1.charAt(j - 1)) {
              matrix[i][j] = matrix[i - 1][j - 1];
            } else {
              matrix[i][j] = Math.min(
                matrix[i - 1][j - 1] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j] + 1
              );
            }
          }
        }

        const distance = matrix[s2.length][s1.length];
        const maxLength = Math.max(s1.length, s2.length);
        return ((maxLength - distance) / maxLength) * 100;
      };

      for (const eq of essayQuestions) {
        const safeParseList = (data) => {
          if (!data) return [];
          try {
            const parsed = JSON.parse(data);
            if (Array.isArray(parsed)) return parsed;
            return [];
          } catch (e) {
            return String(data).split(',').map(s => s.trim()).filter(Boolean);
          }
        };

        const keywords = safeParseList(eq.keywords);
        const synonyms = safeParseList(eq.synonyms);
        totalKeywords += keywords.length;

        // Check if answer is very similar to perfect answer (85% or more)
        if (eq.perfect_answer && eq.perfect_answer.trim()) {
          const similarity = calculateSimilarity(essayAnswer, eq.perfect_answer);
          if (similarity >= 85) {
            // Award full marks for this question
            totalScore += (eq.max_score || 10);
            allMatchedKeywords.push(...keywords); // Mark all keywords as matched
            isPerfectMatch = true;
            continue; // Skip keyword checking for this question
          }
        }

        // Normalize answer - remove punctuation and convert to lowercase
        const normalizedAnswer = essayAnswer
          .toLowerCase()
          .replace(/[.,\/#!$%\^&\*;:{}=\-_`~()]/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();

        // Check keyword matches
        const matchedKeywords = [];
        for (const keyword of keywords) {
          const normalizedKeyword = keyword.toLowerCase();

          // Check if keyword or any synonym is in the answer
          const keywordMatch = normalizedAnswer.includes(normalizedKeyword);
          const synonymMatch = synonyms.some(syn =>
            normalizedAnswer.includes(syn.toLowerCase())
          );

          if (keywordMatch || synonymMatch) {
            matchedKeywords.push(keyword);
          }
        }

        allMatchedKeywords.push(...matchedKeywords);

        // Calculate score for this question
        const questionScore = keywords.length > 0
          ? (matchedKeywords.length / keywords.length) * (eq.max_score || 10)
          : 0;

        totalScore += questionScore;
      }

      // Get step info for maxScore
      const [stepRows] = await pool.query(
        `SELECT maxScore FROM case_steps WHERE id = ?`,
        [stepId]
      );
      const stepMaxScore = stepRows[0]?.maxScore || 10;

      // Normalize score to step's maxScore
      const finalScore = Math.min(totalScore, stepMaxScore);
      const isCorrect = finalScore >= (stepMaxScore * 0.6); // 60% threshold

      // Record the attempt
      await pool.query(
        `INSERT INTO step_attempts 
         (userId, caseId, stepId, selectedOptionId, isCorrect, timeSpent, hintShown, attemptNumber, essay_answer, matched_keywords)
         VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)`,
        [
          req.user.id,
          caseId,
          stepId,
          isCorrect ? 1 : 0,
          timeSpent || 0,
          hintShown ? 1 : 0,
          attemptNumber || 1,
          essayAnswer,
          JSON.stringify(allMatchedKeywords)
        ]
      );

      // If final step, update progress
      if (isFinalStep) {
        const [scoreRows] = await pool.query(
          `SELECT SUM(cs.maxScore) as totalScore
           FROM step_attempts sa
           JOIN case_steps cs ON sa.stepId = cs.id
           WHERE sa.caseId = ? AND sa.userId = ? AND sa.isCorrect = 1
           AND sa.id IN (
               SELECT MAX(id) FROM step_attempts 
               WHERE caseId = ? AND userId = ? 
               GROUP BY stepId
           )`,
          [caseId, req.user.id, caseId, req.user.id]
        );
        const totalCaseScore = scoreRows[0].totalScore || 0;

        await pool.query(
          `INSERT INTO progress (userId, caseId, score, isCompleted, createdAt)
           VALUES (?, ?, ?, 1, NOW())
           ON DUPLICATE KEY UPDATE score = VALUES(score), isCompleted = 1, createdAt = VALUES(createdAt)`,
          [req.user.id, caseId, totalCaseScore]
        );

        const [statsRows] = await pool.query(
          `SELECT 
             COUNT(DISTINCT caseId) as casesCompleted,
             SUM(score) as totalScore
           FROM progress
           WHERE userId = ? AND isCompleted = 1`,
          [req.user.id]
        );
        const stats = statsRows[0];

        res.json({
          correct: isCorrect,
          final: true,
          score: Math.round(finalScore),
          maxScore: stepMaxScore,
          matchedKeywords: allMatchedKeywords,
          totalKeywords: totalKeywords,
          feedback: isPerfectMatch
            ? `🎉 Perfect! Your answer matches the model answer. Excellent work!`
            : isCorrect
              ? `Great job! You matched ${allMatchedKeywords.length} out of ${totalKeywords} key concepts.`
              : `You matched ${allMatchedKeywords.length} out of ${totalKeywords} key concepts. Review the material and try to include more relevant terms.`,
          stats: {
            casesCompleted: stats.casesCompleted || 0,
            totalScore: stats.totalScore || 0,
          }
        });
      } else {
        res.json({
          correct: isCorrect,
          score: Math.round(finalScore),
          maxScore: stepMaxScore,
          matchedKeywords: allMatchedKeywords,
          totalKeywords: totalKeywords,
          feedback: isPerfectMatch
            ? `🎉 Perfect! Your answer matches the model answer. Excellent work!`
            : isCorrect
              ? `Great job! You matched ${allMatchedKeywords.length} out of ${totalKeywords} key concepts.`
              : `You matched ${allMatchedKeywords.length} out of ${totalKeywords} key concepts. Review the material and try to include more relevant terms.`
        });
      }

    } catch (err) {
      console.error('Essay answer error:', err);
      res.status(500).json({ message: 'Database error' });
    }
  }
);


app.get('/api/stats/me', authMiddleware(), async (req, res) => {
  try {
    const [statsRows] = await pool.query(
      `SELECT 
         COUNT(DISTINCT caseId) as casesCompleted,
         SUM(score) as totalScore
       FROM progress
       WHERE userId = ? AND isCompleted = 1`,
      [req.user.id]
    );
    const stats = statsRows[0];
    res.json({
      casesCompleted: stats.casesCompleted || 0,
      totalScore: stats.totalScore || 0,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/api/admin/cases', authMiddleware('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT c.*, 
             cat.name as categoryName, 
             sp.name as requiredPlanName, 
             sp.role as requiredPlanRole,
             (SELECT COUNT(*) FROM case_steps WHERE caseId = c.id) as stepCount
      FROM cases c 
      LEFT JOIN categories cat ON c.categoryId = cat.id 
      LEFT JOIN subscription_plans sp ON c.requiredPlanId = sp.id 
      ORDER BY c.id DESC
    `);
    const cases = rows.map((row) => ({
      id: row.id,
      title: row.title,
      specialty: row.specialty,
      category: row.category,
      categoryId: row.categoryId,
      categoryName: row.categoryName,
      difficulty: row.difficulty,
      isLocked: !!row.isLocked,
      prerequisiteCaseId: row.prerequisiteCaseId,
      metadata: row.metadata ? JSON.parse(row.metadata) : {},
      thumbnailUrl: row.thumbnailUrl,
      duration: row.duration || 10,
      requiredPlanId: row.requiredPlanId,
      requiredPlanName: row.requiredPlanName,
      requiredPlanRole: row.requiredPlanRole,
      status: row.status || 'draft',
      stepCount: Number(row.stepCount || 0),
      tag: row.tag,
      expected_time: row.expected_time,
      hint_text: row.hint_text,
      hint_enabled: !!row.hint_enabled
    }));
    res.json(cases);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/api/admin/cases/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(`SELECT c.*, cat.name as categoryName, sp.name as requiredPlanName, sp.role as requiredPlanRole FROM cases c LEFT JOIN categories cat ON c.categoryId = cat.id LEFT JOIN subscription_plans sp ON c.requiredPlanId = sp.id WHERE c.id = ?`, [id]);
    const row = rows[0];

    if (!row) return res.status(404).json({ message: 'Case not found' });

    const caseData = {
      id: row.id,
      title: row.title,
      specialty: row.specialty,
      category: row.category,
      categoryId: row.categoryId,
      categoryName: row.categoryName,
      difficulty: row.difficulty,
      isLocked: !!row.isLocked,
      prerequisiteCaseId: row.prerequisiteCaseId,
      metadata: row.metadata ? JSON.parse(row.metadata) : {},
      thumbnailUrl: row.thumbnailUrl,
      duration: row.duration || 10,
      requiredPlanId: row.requiredPlanId,
      requiredPlanName: row.requiredPlanName,
      requiredPlanRole: row.requiredPlanRole,
    };
    res.json(caseData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.post('/api/admin/cases', authMiddleware('admin'), async (req, res) => {
  const { title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration } =
    req.body;
  if (!title) return res.status(400).json({ message: 'Title is required' });

  try {
    const [result] = await pool.query(
      `INSERT INTO cases (title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration, requiredPlanId, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')`,
      [
        title,
        specialty || null,
        category || null,
        categoryId || null,
        difficulty || null,
        isLocked ? 1 : 0,
        prerequisiteCaseId || null,
        metadata ? JSON.stringify(metadata) : null,
        thumbnailUrl || null,
        duration || 10,
        req.body.requiredPlanId || null
      ]
    );

    res.json({
      id: result.insertId,
      title,
      specialty,
      category,
      categoryId,
      difficulty,
      isLocked: !!isLocked,
      prerequisiteCaseId,
      metadata: metadata || {},
      thumbnailUrl,
      duration: duration || 10,
      status: 'draft',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.put('/api/admin/cases/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration, status } =
    req.body;

  console.log(`[DEBUG] Updating case ${id}`, req.body); // DEBUG
  try {
    // Step Count Validation for Publication
    if (status === 'published') {
      const [stepRows] = await pool.query(
        `SELECT * FROM case_steps WHERE caseId = ? ORDER BY stepIndex ASC`,
        [id]
      );
      const sc = stepRows.length;
      if (sc < 3) {
        return res.status(400).json({
          message: 'Cannot publish case with less than 3 steps. The case remains drafted.'
        });
      }

      // MCQ Rule: Case must end with MCQ
      const lastStep = stepRows[stepRows.length - 1];
      if (lastStep.type !== 'mcq') {
        return res.status(400).json({
          message: 'A case must end with an MCQ step to assess the student.'
        });
      }
    }
    // Validate requiredPlanId if provided
    if (req.body.requiredPlanId) {
      const [planRows] = await pool.query(
        `SELECT isActive FROM subscription_plans WHERE id = ?`,
        [req.body.requiredPlanId]
      );

      if (planRows.length === 0) {
        return res.status(400).json({ message: 'Invalid plan ID' });
      }

      if (!planRows[0].isActive) {
        return res.status(400).json({
          message: 'Cannot assign case to deactivated plan. Please activate the plan first or choose an active plan.'
        });
      }

      // Max Free Cases limit check if status is becoming 'published'
      if (status === 'published' || (!status && req.body.status === 'published')) {
        const [planInfo] = await pool.query(
          `SELECT maxFreeCases, name FROM subscription_plans WHERE id = ?`,
          [req.body.requiredPlanId]
        );

        if (planInfo[0] && planInfo[0].maxFreeCases !== null) {
          const limit = planInfo[0].maxFreeCases;
          const [usageRows] = await pool.query(
            `SELECT COUNT(*) as currentUsage FROM cases WHERE requiredPlanId = ? AND status = 'published' AND id != ?`,
            [req.body.requiredPlanId, id]
          );

          if (usageRows[0].currentUsage >= limit) {
            return res.status(400).json({
              message: `Limit reached: The plan "${planInfo[0].name}" only allows a maximum of ${limit} activated cases.`
            });
          }
        }
      }
    } else if (status === 'published') {
      // If status is published but requiredPlanId is NOT provided in body, 
      // check the existing plan assigned to this case
      const [caseRows] = await pool.query(`SELECT requiredPlanId FROM cases WHERE id = ?`, [id]);
      const currentPlanId = caseRows[0]?.requiredPlanId;

      if (currentPlanId) {
        const [planInfo] = await pool.query(
          `SELECT maxFreeCases, name FROM subscription_plans WHERE id = ?`,
          [currentPlanId]
        );

        if (planInfo[0] && planInfo[0].maxFreeCases !== null) {
          const limit = planInfo[0].maxFreeCases;
          const [usageRows] = await pool.query(
            `SELECT COUNT(*) as currentUsage FROM cases WHERE requiredPlanId = ? AND status = 'published' AND id != ?`,
            [currentPlanId, id]
          );

          if (usageRows[0].currentUsage >= limit) {
            return res.status(400).json({
              message: `Limit reached: The plan "${planInfo[0].name}" only allows a maximum of ${limit} activated cases.`
            });
          }
        }
      }
    }

    const params = [
      title,
      specialty || null,
      category || null,
      categoryId || null,
      difficulty || null,
      isLocked ? 1 : 0,
      prerequisiteCaseId || null,
      metadata ? JSON.stringify(metadata) : null,
      thumbnailUrl || null,
      duration || 10,
      req.body.requiredPlanId === undefined ? null : req.body.requiredPlanId,
      status || 'draft',
      id,
    ];

    await pool.query(
      `UPDATE cases
       SET title = ?, specialty = ?, category = ?, categoryId = ?, difficulty = ?, isLocked = ?, prerequisiteCaseId = ?, metadata = ?, thumbnailUrl = ?, duration = ?, requiredPlanId = ?, status = ?
       WHERE id = ?`,
      params
    );
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.delete('/api/admin/cases/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(`DELETE FROM cases WHERE id = ?`, [id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

// --- Step Management Endpoints ---

// GET steps for a case
app.get('/api/admin/cases/:id/steps', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const [steps] = await pool.query(`SELECT * FROM case_steps WHERE caseId = ? ORDER BY stepIndex ASC`, [id]);
    console.log(`[DEBUG] Fetched ${steps.length} steps for case ${id}`);

    const stepIds = steps.map((s) => s.id);
    if (stepIds.length === 0) return res.json([]);

    const placeholders = stepIds.map(() => '?').join(',');

    const [options] = await pool.query(`SELECT * FROM case_step_options WHERE stepId IN (${placeholders})`, stepIds);
    const [invs] = await pool.query(`SELECT * FROM investigations WHERE stepId IN (${placeholders})`, stepIds);
    const [xrays] = await pool.query(`SELECT * FROM xrays WHERE stepId IN (${placeholders})`, stepIds);

    let essayQuestions = [];
    try {
      console.log(`[DEBUG] Fetching essay questions for steps: ${stepIds.join(',')}`);
      const [rows] = await pool.query(`SELECT * FROM essay_questions WHERE step_id IN (${placeholders})`, stepIds);
      essayQuestions = rows;
      console.log(`[DEBUG] Fetched ${essayQuestions.length} essay questions`);
    } catch (err) {
      console.error(`[DEBUG] Error fetching essay questions:`, err.message);
      essayQuestions = [];
    }

    const detailedSteps = steps.map((s) => ({
      ...s,
      content: (() => {
        try {
          return s.content ? JSON.parse(s.content) : {};
        } catch (e) {
          console.warn(`Failed to parse content for step ${s.id}:`, e.message);
          return {};
        }
      })(),
      options: options.filter(o => o.stepId === s.id).map(o => ({ ...o, isCorrect: !!o.isCorrect })),
      investigations: invs.filter(i => i.stepId === s.id),
      xrays: xrays.filter(x => x.stepId === s.id),
      essayQuestions: essayQuestions.filter(eq => eq.step_id === s.id).map(eq => {
        const safeParseList = (data) => {
          if (!data) return [];
          try {
            const parsed = JSON.parse(data);
            // Verify it is an array
            if (Array.isArray(parsed)) return parsed;
            return [];
          } catch (e) {
            // If parse fails, assume it is a comma-separated string
            return String(data).split(',').map(s => s.trim()).filter(Boolean);
          }
        };

        return {
          ...eq,
          keywords: safeParseList(eq.keywords),
          synonyms: safeParseList(eq.synonyms),
          perfect_answer: eq.perfect_answer || ''
        };
      }),
      tag: s.tag,
      expected_time: s.expected_time,
      hint_text: s.hint_text,
      hint_enabled: !!s.hint_enabled
    }));
    res.json(detailedSteps);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

// POST new step
app.post('/api/admin/cases/:id/steps', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { stepIndex, type, content, question, explanationOnFail, maxScore, options, investigations, xrays, essayQuestions, hint_text, tag, expected_time, hint_enabled } = req.body;

  try {
    const [result] = await pool.query(
      `INSERT INTO case_steps (caseId, stepIndex, type, content, question, explanationOnFail, maxScore, hint_text, tag, expected_time, hint_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, stepIndex, type, JSON.stringify(content), question, explanationOnFail, maxScore, hint_text || null, tag || null, expected_time || null, hint_enabled !== undefined ? (hint_enabled ? 1 : 0) : 1]
    );
    const stepId = result.insertId;

    // Insert Options
    if (options && options.length > 0) {
      for (const o of options) {
        await pool.query(
          `INSERT INTO case_step_options (stepId, label, isCorrect, feedback) VALUES (?, ?, ?, ?)`,
          [stepId, o.label, o.isCorrect ? 1 : 0, o.feedback]
        );
      }
    }

    // Insert Investigations
    if (investigations && investigations.length > 0) {
      for (const i of investigations) {
        await pool.query(
          `INSERT INTO investigations (stepId, groupLabel, testName, description, result, videoUrl) VALUES (?, ?, ?, ?, ?, ?)`,
          [stepId, i.groupLabel, i.testName, i.description, i.result, i.videoUrl]
        );
      }
    }

    // Insert X-Rays
    if (xrays && xrays.length > 0) {
      for (const x of xrays) {
        await pool.query(
          `INSERT INTO xrays (stepId, label, icon, imageUrl) VALUES (?, ?, ?, ?)`,
          [stepId, x.label, x.icon, x.imageUrl]
        );
      }
    }

    // Insert Essay Questions
    if (essayQuestions && essayQuestions.length > 0) {
      for (const eq of essayQuestions) {
        await pool.query(
          `INSERT INTO essay_questions (step_id, question_text, keywords, synonyms, max_score, perfect_answer) VALUES (?, ?, ?, ?, ?, ?)`,
          [stepId, eq.question_text, JSON.stringify(eq.keywords || []), JSON.stringify(eq.synonyms || []), eq.max_score || maxScore, eq.perfect_answer || null]
        );
      }
    }

    res.json({ id: stepId, message: 'Step created' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

// PUT update step
app.put('/api/admin/steps/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { stepIndex, type, content, question, explanationOnFail, maxScore, options, investigations, xrays, essayQuestions, hint_text, tag, expected_time, hint_enabled } = req.body;

  try {
    await pool.query(
      `UPDATE case_steps SET stepIndex=?, type=?, content=?, question=?, explanationOnFail=?, maxScore=?, hint_text=?, tag=?, expected_time=?, hint_enabled=? WHERE id=?`,
      [stepIndex, type, JSON.stringify(content), question, explanationOnFail, maxScore, hint_text || null, tag || null, expected_time || null, hint_enabled !== undefined ? (hint_enabled ? 1 : 0) : 1, id]
    );

    // Clean up related data to overwrite
    await pool.query(`DELETE FROM case_step_options WHERE stepId = ?`, [id]);
    await pool.query(`DELETE FROM investigations WHERE stepId = ?`, [id]);
    await pool.query(`DELETE FROM xrays WHERE stepId = ?`, [id]);
    await pool.query(`DELETE FROM essay_questions WHERE step_id = ?`, [id]);

    // Re-Insert Options
    if (options && options.length > 0) {
      for (const o of options) {
        await pool.query(
          `INSERT INTO case_step_options (stepId, label, isCorrect, feedback) VALUES (?, ?, ?, ?)`,
          [id, o.label, o.isCorrect ? 1 : 0, o.feedback]
        );
      }
    }

    // Re-Insert Investigations
    if (investigations && investigations.length > 0) {
      for (const i of investigations) {
        await pool.query(
          `INSERT INTO investigations (stepId, groupLabel, testName, description, result, videoUrl) VALUES (?, ?, ?, ?, ?, ?)`,
          [id, i.groupLabel, i.testName, i.description, i.result, i.videoUrl]
        );
      }
    }

    // Re-Insert X-Rays
    if (xrays && xrays.length > 0) {
      for (const x of xrays) {
        await pool.query(
          `INSERT INTO xrays (stepId, label, icon, imageUrl) VALUES (?, ?, ?, ?)`,
          [id, x.label, x.icon, x.imageUrl]
        );
      }
    }

    // Re-Insert Essay Questions
    if (essayQuestions && essayQuestions.length > 0) {
      for (const eq of essayQuestions) {
        await pool.query(
          `INSERT INTO essay_questions (step_id, question_text, keywords, synonyms, max_score, perfect_answer) VALUES (?, ?, ?, ?, ?, ?)`,
          [id, eq.question_text, JSON.stringify(eq.keywords || []), JSON.stringify(eq.synonyms || []), eq.max_score || maxScore, eq.perfect_answer || null]
        );
      }
    }

    res.json({ message: 'Step updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

// DELETE Step
app.delete('/api/admin/steps/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(`DELETE FROM case_steps WHERE id = ?`, [id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

// Admin Dashboard Overview
app.get('/api/admin/overview', authMiddleware('admin'), async (req, res) => {
  try {
    const [usersRows] = await pool.query(`SELECT COUNT(*) as totalUsers FROM users WHERE role = 'student'`);
    const [casesRows] = await pool.query(`SELECT COUNT(*) as totalCases FROM cases`);
    const [progressRows] = await pool.query(`SELECT COUNT(*) as totalProgress FROM progress WHERE isCompleted = 1`);
    const [premiumRows] = await pool.query(`SELECT COUNT(*) as premiumUsers FROM users WHERE membershipType = 'premium'`);

    // Get recent activity
    const [activity] = await pool.query(`
      (SELECT 'user_joined' as type, email as title, createdAt as date FROM users WHERE role = 'student' ORDER BY createdAt DESC LIMIT 5)
      UNION ALL
      (SELECT 'case_created' as type, title, createdAt as date FROM cases ORDER BY createdAt DESC LIMIT 5)
      ORDER BY date DESC
      LIMIT 10
    `);

    res.json({
      totalUsers: usersRows[0] ? usersRows[0].totalUsers : 0,
      totalCases: casesRows[0] ? casesRows[0].totalCases : 0,
      totalCompletions: progressRows[0] ? progressRows[0].totalProgress : 0,
      premiumUsers: premiumRows[0] ? premiumRows[0].premiumUsers : 0,
      recentActivity: activity || []
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

// User Management
app.get('/api/admin/users', authMiddleware('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, email, role, name,
              device1_ip, device1_last_seen, device2_ip, device2_last_seen,
              device_locked, token_version, createdAt
       FROM users
       ORDER BY createdAt DESC`
    );

    console.log(`[Users API] Fetching users with derived membership via getUserMembership...`);

    const users = await Promise.all(rows.map(async (row) => {
      // Get derived membership from active subscription
      const membership = await getUserMembership(pool, row.id);

      const [stats] = await pool.query(
        `SELECT COUNT(DISTINCT caseId) as casesCompleted, SUM(score) as totalScore
         FROM progress WHERE userId = ? AND isCompleted = 1`,
        [row.id]
      );

      return {
        id: row.id,
        email: row.email,
        name: row.name,
        role: row.role,
        membershipType: membership.membershipType,
        membershipExpiresAt: membership.membershipExpiresAt,
        planRole: membership.planRole,
        deviceInfo: {
          device1: row.device1_ip ? {
            ip: row.device1_ip,
            lastSeen: row.device1_last_seen,
            active: row.device1_last_seen && (new Date() - new Date(row.device1_last_seen)) < 7 * 24 * 60 * 60 * 1000
          } : null,
          device2: row.device2_ip ? {
            ip: row.device2_ip,
            lastSeen: row.device2_last_seen,
            active: row.device2_last_seen && (new Date() - new Date(row.device2_last_seen)) < 7 * 24 * 60 * 60 * 1000
          } : null,
          deviceCount: (row.device1_ip ? 1 : 0) + (row.device2_ip ? 1 : 0),
          locked: !!row.device_locked,
          tokenVersion: row.token_version
        },
        createdAt: row.createdAt,
        stats: {
          casesCompleted: stats[0]?.casesCompleted || 0,
          totalScore: stats[0]?.totalScore || 0,
        },
      };
    }));
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ message: 'Database error' });
  }
});

// DEPRECATED: Membership is now derived from active subscriptions
// Use the Subscriptions tab to manage user access levels
/*
app.put('/api/admin/users/:id/membership', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { membershipType, membershipExpiresAt } = req.body;
  try {
    await pool.query(`UPDATE users SET membershipType = ?, membershipExpiresAt = ? WHERE id = ?`, [membershipType, membershipExpiresAt || null, id]);
    res.json({ message: 'Membership updated' });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});
*/

// --- Device Management Endpoints ---

// Get detailed device info for specific user
app.get('/api/admin/users/:id/devices', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(
      `SELECT email, name,
              device1_ip, device1_fingerprint, device1_last_seen,
              device2_ip, device2_fingerprint, device2_last_seen,
              device_locked, token_version, createdAt
       FROM users WHERE id = ?`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = rows[0];
    res.json({
      userId: id,
      email: user.email,
      name: user.name,
      devices: {
        device1: user.device1_ip ? {
          ip: user.device1_ip,
          fingerprint: user.device1_fingerprint?.substring(0, 16) + '...', // Truncate for display
          lastSeen: user.device1_last_seen
        } : null,
        device2: user.device2_ip ? {
          ip: user.device2_ip,
          fingerprint: user.device2_fingerprint?.substring(0, 16) + '...', // Truncate for display
          lastSeen: user.device2_last_seen
        } : null,
      },
      locked: !!user.device_locked,
      tokenVersion: user.token_version,
      registeredAt: user.createdAt
    });
  } catch (err) {
    console.error('Error fetching device info:', err);
    res.status(500).json({ message: 'Database error' });
  }
});

// Reset device locks (with transaction and token invalidation)
app.post('/api/admin/users/:id/reset-devices', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Lock row
      const [userRows] = await connection.query(
        `SELECT id, email FROM users WHERE id = ? FOR UPDATE`,
        [id]
      );

      if (userRows.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({ message: 'User not found' });
      }

      // Reset devices and increment token version
      await connection.query(
        `UPDATE users
         SET device1_ip = NULL,
             device1_fingerprint = NULL,
             device1_last_seen = NULL,
             device2_ip = NULL,
             device2_fingerprint = NULL,
             device2_last_seen = NULL,
             token_version = token_version + 1,
             device_locked = FALSE
         WHERE id = ?`,
        [id]
      );

      await connection.commit();
      connection.release();

      // Clear token version cache
      tokenVersionCache.delete(`token_v_${id}`);

      // Log admin action
      console.log(`[ADMIN ACTION] User ${req.user.id} reset devices for user ${id} (${userRows[0].email})`);

      res.json({
        message: 'Device locks reset successfully. User tokens invalidated.',
        userId: id
      });
    } catch (err) {
      await connection.rollback();
      connection.release();
      throw err;
    }
  } catch (err) {
    console.error('Error resetting devices:', err);
    res.status(500).json({ message: 'Database error' });
  }
});

// --- Categories Management ---

app.get('/api/categories', async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM categories ORDER BY name ASC`);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.post('/api/admin/categories', authMiddleware('admin'), async (req, res) => {
  const { name, icon, description } = req.body;
  if (!name) return res.status(400).json({ message: 'Name is required' });
  try {
    const [result] = await pool.query(
      `INSERT INTO categories (name, icon, description) VALUES (?, ?, ?)`,
      [name, icon, description]
    );
    res.json({ id: result.insertId, name, icon, description });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Category already exists' });
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.put('/api/admin/categories/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { name, icon, description } = req.body;
  try {
    await pool.query(
      `UPDATE categories SET name = ?, icon = ?, description = ? WHERE id = ?`,
      [name, icon, description, id]
    );
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.delete('/api/admin/categories/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    // Check if used
    const [rows] = await pool.query(`SELECT COUNT(*) as count FROM cases WHERE categoryId = ?`, [id]);
    if (rows[0].count > 0) return res.status(400).json({ message: 'Cannot delete category used by cases' });

    await pool.query(`DELETE FROM categories WHERE id = ?`, [id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});


// --- Leaderboard ---

app.get('/api/leaderboard', authMiddleware(), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        u.id as userId, 
        u.email, 
        COUNT(p.id) as casesCompleted, 
        SUM(p.score) as totalScore 
      FROM users u 
      JOIN progress p ON u.id = p.userId 
      WHERE p.isCompleted = 1 
      GROUP BY u.id, u.email 
      ORDER BY totalScore DESC 
      LIMIT 100
    `);

    // Add rank
    const leaderboard = rows.map((row, index) => ({
      rank: index + 1,
      userId: row.userId,
      email: row.email,
      name: row.name || row.email.split('@')[0],
      casesCompleted: row.casesCompleted,
      totalScore: Number(row.totalScore || 0)
    }));

    res.json(leaderboard);
  } catch (err) {
    console.error("Leaderboard Error:", err);
    res.status(500).json({ message: 'Database error: ' + err.message });
  }
});



//    ADMIN SUBSCRIPTION ROUTES
// ====================== */

// Get all subscription plans
app.get('/api/admin/subscription-plans', authMiddleware('admin'), async (req, res) => {
  try {
    const { activeOnly } = req.query;

    let query = `SELECT * FROM subscription_plans`;
    if (activeOnly === 'true') {
      query += ` WHERE isActive = 1`;
    }
    query += ` ORDER BY price ASC`;

    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Create subscription plan
app.post('/api/admin/subscription-plans', authMiddleware('admin'), async (req, res) => {
  try {
    const { name, price, duration_value, duration_unit, durationDays, maxFreeCases, description, features, isActive } = req.body;

    // Support both new flexible duration and legacy durationDays
    let finalDurationValue = duration_value;
    let finalDurationUnit = duration_unit || 'day';
    let calculatedDurationDays = durationDays;

    if (duration_value && duration_unit) {
      // New flexible duration provided
      calculatedDurationDays = convertToDays(duration_value, duration_unit);
    } else if (durationDays) {
      // Legacy durationDays provided
      finalDurationValue = durationDays;
      finalDurationUnit = 'day';
      calculatedDurationDays = durationDays;
    } else {
      return res.status(400).json({ message: 'Either duration_value+duration_unit or durationDays is required' });
    }

    // Basic Validation
    if (!name || price === undefined) {
      return res.status(400).json({ message: 'Name and price are required' });
    }

    // Determine role: use provided role, or infer from name (legacy support)
    let role = req.body.role || 'custom';
    if (!req.body.role) {
      if (name.toLowerCase() === 'normal') role = 'normal';
      if (name.toLowerCase() === 'premium') role = 'premium';
      if (name.toLowerCase() === 'ultra') role = 'ultra';
    }

    await pool.query(
      `INSERT INTO subscription_plans (name, role, price, durationDays, duration_value, duration_unit, maxFreeCases, description, features, isActive) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, role, price, calculatedDurationDays, finalDurationValue, finalDurationUnit, maxFreeCases, description, JSON.stringify(features || []), isActive ? 1 : 0]
    );

    res.status(201).json({ message: 'Plan created' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'A plan with this name already exists' });
    }
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Update subscription plan
app.put('/api/admin/subscription-plans/:id', authMiddleware('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, price, duration_value, duration_unit, durationDays, maxFreeCases, description, features, isActive } = req.body;

    const [current] = await pool.query(`SELECT * FROM subscription_plans WHERE id = ?`, [id]);
    if (!current.length) return res.status(404).json({ message: 'Plan not found' });

    // Allow updating name and role freely (Admin request)
    const newName = name || current[0].name;
    const newRole = req.body.role || current[0].role;

    // Handle flexible duration update
    let finalDurationValue = current[0].duration_value;
    let finalDurationUnit = current[0].duration_unit || 'day';
    let calculatedDurationDays = current[0].durationDays;

    if (duration_value !== undefined && duration_unit) {
      // New flexible duration provided
      finalDurationValue = duration_value;
      finalDurationUnit = duration_unit;
      calculatedDurationDays = convertToDays(duration_value, duration_unit);
    } else if (durationDays !== undefined) {
      // Legacy durationDays provided
      finalDurationValue = durationDays;
      finalDurationUnit = 'day';
      calculatedDurationDays = durationDays;
    }

    await pool.query(
      `UPDATE subscription_plans 
       SET name = ?, role = ?, price = ?, durationDays = ?, duration_value = ?, duration_unit = ?, maxFreeCases = ?, description = ?, features = ?, isActive = ? 
       WHERE id = ?`,
      [
        newName,
        newRole,
        price !== undefined ? price : current[0].price,
        calculatedDurationDays,
        finalDurationValue,
        finalDurationUnit,
        maxFreeCases, // Can be null
        description !== undefined ? description : current[0].description,
        features ? JSON.stringify(features) : (typeof current[0].features === 'string' ? current[0].features : JSON.stringify(current[0].features)),
        isActive !== undefined ? (isActive ? 1 : 0) : current[0].isActive,
        id
      ]
    );

    // If durationDays changed, update existing active subscriptions for this plan
    if (calculatedDurationDays !== current[0].durationDays) {
      console.log(`[Admin] Plan ${id} duration changed from ${current[0].durationDays} to ${calculatedDurationDays}. Updating existing subscriptions...`);

      // Update end dates for all active/pending subscriptions of this plan
      // Formula: endDate = startDate + newDurationDays
      await pool.query(
        `UPDATE subscriptions 
         SET endDate = DATE_ADD(startDate, INTERVAL (? * 24) HOUR)
         WHERE planId = ? AND status = 'active'`,
        [calculatedDurationDays, id]
      );

      console.log(`[Admin] Successfully updated end dates for subscribers of plan ${id}`);
    }

    res.json({ message: 'Plan updated and active subscriptions recalculated' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'A plan with this name already exists' });
    }
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Delete subscription plan
app.delete('/api/admin/subscription-plans/:id', authMiddleware('admin'), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if plan has subscriptions
    const [subs] = await pool.query(`SELECT COUNT(*) as count FROM subscriptions WHERE planId = ?`, [id]);
    if (subs[0].count > 0) {
      return res.status(400).json({ message: 'Cannot delete plan with existing subscriptions' });
    }

    // Check if core plan
    const [plan] = await pool.query(`SELECT role FROM subscription_plans WHERE id = ?`, [id]);
    if (plan.length && (plan[0].role === 'normal' || plan[0].role === 'premium')) {
      return res.status(400).json({ message: 'Cannot delete core plans (Normal/Premium)' });
    }

    await pool.query(`DELETE FROM subscription_plans WHERE id = ?`, [id]);
    res.json({ message: 'Plan deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Get all subscriptions
app.get('/api/admin/subscriptions', authMiddleware('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        s.id,
        u.id as userId,
        u.name as userName,
        u.email,
        s.planId,
        COALESCE(sp.name, 'Normal') as planName,
        COALESCE(s.status, 'active') as status,
        COALESCE(s.startDate, u.createdAt) as startDate,
        COALESCE(s.endDate, DATE_ADD(u.createdAt, INTERVAL 365 DAY)) as endDate,
        COALESCE(DATEDIFF(s.endDate, CURDATE()), 365) as daysRemaining,
        CASE 
          WHEN s.endDate IS NULL THEN 'active'
          WHEN s.endDate < CURDATE() THEN 'expired'
          WHEN DATEDIFF(s.endDate, CURDATE()) <= 7 THEN 'expiring_soon'
          ELSE 'active'
        END AS health
      FROM users u
      LEFT JOIN subscriptions s ON u.id = s.userId AND s.status = 'active'
      LEFT JOIN subscription_plans sp ON s.planId = sp.id
      WHERE u.role = 'student'
      ORDER BY s.createdAt DESC, u.createdAt DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Create subscription
app.post('/api/admin/subscriptions', authMiddleware('admin'), async (req, res) => {
  try {
    const { userId, planId, startDate, endDate } = req.body;

    if (!userId || !planId || !startDate || !endDate) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user already has a subscription
    const [existingSub] = await pool.query(
      `SELECT id FROM subscriptions WHERE userId = ? AND status = 'active' LIMIT 1`,
      [userId]
    );

    const [plan] = await pool.query(`SELECT name FROM subscription_plans WHERE id = ?`, [planId]);

    if (existingSub.length > 0) {
      // Update existing subscription instead of creating new one
      await pool.query(
        `UPDATE subscriptions SET planId = ?, startDate = ?, endDate = ?, status = 'active' WHERE id = ?`,
        [planId, startDate, endDate, existingSub[0].id]
      );

      await pool.query(
        `INSERT INTO subscription_history (subscriptionId, userId, action, newPlanId, newEndDate, performedBy, notes) 
         VALUES (?, ?, 'upgraded', ?, ?, ?, 'Updated by admin')`,
        [existingSub[0].id, userId, planId, endDate, req.user.id]
      );

      res.status(200).json({
        message: 'Subscription updated',
        planName: plan[0]?.name || 'Unknown'
      });
    } else {
      // Create new subscription only if none exists
      const [result] = await pool.query(
        `INSERT INTO subscriptions (userId, planId, startDate, endDate, status) VALUES (?, ?, ?, ?, 'active')`,
        [userId, planId, startDate, endDate]
      );

      await pool.query(
        `INSERT INTO subscription_history (subscriptionId, userId, action, newPlanId, newEndDate, performedBy, notes) 
         VALUES (?, ?, 'created', ?, ?, ?, 'Created by admin')`,
        [result.insertId, userId, planId, endDate, req.user.id]
      );

      res.status(201).json({
        message: 'Subscription created',
        planName: plan[0]?.name || 'Unknown'
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Extend subscription
app.put('/api/admin/subscriptions/:id/extend', authMiddleware('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { daysToAdd } = req.body;

    if (!daysToAdd || isNaN(daysToAdd)) {
      return res.status(400).json({ message: 'Valid days to add is required' });
    }

    const [sub] = await pool.query(`SELECT * FROM subscriptions WHERE id = ?`, [id]);
    if (!sub.length) return res.status(404).json({ message: 'Subscription not found' });

    const currentEndDate = new Date(sub[0].endDate);
    const newEndDate = new Date(currentEndDate);
    newEndDate.setDate(newEndDate.getDate() + parseInt(daysToAdd));

    // Update the same row - extend the end date
    await pool.query(
      `UPDATE subscriptions SET endDate = ?, status = 'active' WHERE id = ?`,
      [newEndDate, id]
    );

    await pool.query(
      `INSERT INTO subscription_history (subscriptionId, userId, action, oldEndDate, newEndDate, performedBy, notes) 
       VALUES (?, ?, 'extended', ?, ?, ?, ?)`,
      [id, sub[0].userId, sub[0].endDate, newEndDate, req.user.id, `Extended by ${daysToAdd} days`]
    );

    res.json({ message: 'Subscription extended successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Changed plan
app.put('/api/admin/subscriptions/:id/change-plan', authMiddleware('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { newPlanId } = req.body;

    const [sub] = await pool.query(`SELECT * FROM subscriptions WHERE id = ?`, [id]);
    if (!sub.length) return res.status(404).json({ message: 'Subscription not found' });

    // Fetch the new plan details to get duration
    const [newPlan] = await pool.query(`SELECT * FROM subscription_plans WHERE id = ?`, [newPlanId]);
    if (!newPlan.length) return res.status(404).json({ message: 'New plan not found' });

    // Calculate new end date based on plan duration
    const today = new Date();
    const endDate = new Date(today);
    endDate.setDate(endDate.getDate() + (newPlan[0].durationDays || 0));

    // Format dates for MySQL
    const startDateStr = today.toISOString().split('T')[0];
    const endDateStr = endDate.toISOString().split('T')[0];

    // Update the subscription with new plan, start date, and end date
    await pool.query(
      `UPDATE subscriptions SET planId = ?, startDate = ?, endDate = ?, status = 'active' WHERE id = ?`,
      [newPlanId, startDateStr, endDateStr, id]
    );

    await pool.query(
      `INSERT INTO subscription_history (subscriptionId, userId, action, oldPlanId, newPlanId, performedBy, notes) 
       VALUES (?, ?, 'upgraded', ?, ?, ?, 'Plan changed by admin')`,
      [id, sub[0].userId, sub[0].planId, newPlanId, req.user.id]
    );

    res.json({ message: 'Plan changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Cancel subscription
app.put('/api/admin/subscriptions/:id/cancel', authMiddleware('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    const [sub] = await pool.query(`SELECT * FROM subscriptions WHERE id = ?`, [id]);
    if (!sub.length) return res.status(404).json({ message: 'Subscription not found' });

    const [normalPlan] = await pool.query(`SELECT id FROM subscription_plans WHERE name = 'Normal' LIMIT 1`);

    if (!normalPlan.length) {
      return res.status(400).json({ message: 'Normal plan not found. Cannot cancel subscription.' });
    }

    // Update existing subscription to Normal plan instead of creating new row
    await pool.query(
      `UPDATE subscriptions 
       SET planId = ?, status = 'active', endDate = DATE_ADD(CURDATE(), INTERVAL 365 DAY)
       WHERE id = ?`,
      [normalPlan[0].id, id]
    );

    await pool.query(
      `INSERT INTO subscription_history (subscriptionId, userId, action, performedBy, notes) 
       VALUES (?, ?, 'cancelled', ?, ?)`,
      [id, sub[0].userId, req.user.id, reason || 'Cancelled by admin - downgraded to Normal plan']
    );

    res.json({ message: 'Subscription cancelled and downgraded to Normal plan' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Add users listing if missing
app.get('/api/admin/users', authMiddleware('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT id, name, email, role, phone, createdAt FROM users ORDER BY createdAt DESC`);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

/* ======================
   ADMIN CASE ACCESS CONTROL
====================== */

// Update case required plan
app.put('/api/admin/cases/:id/access', authMiddleware('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { requiredPlanId } = req.body;

    // Validate case exists
    const [caseRows] = await pool.query(`SELECT id FROM cases WHERE id = ?`, [id]);
    if (!caseRows.length) {
      return res.status(404).json({ message: 'Case not found' });
    }

    // Validate plan exists if provided
    if (requiredPlanId !== null && requiredPlanId !== undefined) {
      const [planRows] = await pool.query(`SELECT id FROM subscription_plans WHERE id = ?`, [requiredPlanId]);
      if (!planRows.length) {
        return res.status(400).json({ message: 'Invalid plan ID' });
      }
    }

    // Update case required plan
    await pool.query(
      `UPDATE cases SET requiredPlanId = ? WHERE id = ?`,
      [requiredPlanId || null, id]
    );

    res.json({ message: 'Case access updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Get all cases with access info (for admin)
app.get('/api/admin/cases/access', authMiddleware('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT c.id, c.title, c.requiredPlanId, sp.name as requiredPlanName
      FROM cases c
      LEFT JOIN subscription_plans sp ON c.requiredPlanId = sp.id
      ORDER BY c.id ASC
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

/* ======================
   PERFORMANCE ANALYTICS ENDPOINTS
====================== */

// Default expected times by step type (in seconds)
const STEP_TYPE_EXPECTED_TIMES = {
  'mcq': 45,
  'history': 90,
  'diagnosis': 120,
  'treatment': 90,
  'info': 30,
  'investigation': 60
};

// Get performance analysis for current user
app.get('/api/performance/analysis', authMiddleware(), async (req, res) => {
  try {
    const userId = req.user.id;

    // Get overall stats
    const [overallRows] = await pool.query(
      `SELECT 
         COUNT(*) as totalAttempts,
         SUM(isCorrect) as correctAttempts,
         AVG(timeSpent) as avgTimePerQuestion
       FROM step_attempts
       WHERE userId = ?`,
      [userId]
    );
    const overall = overallRows[0];
    const accuracyRate = overall.totalAttempts > 0
      ? Math.round((overall.correctAttempts / overall.totalAttempts) * 100)
      : 0;

    // Get stats grouped by tag
    const [tagRows] = await pool.query(
      `SELECT 
         cs.tag,
         -- cs.type as stepType, -- Removed from group by
         AVG(cs.expected_time) as expected_time,
         COUNT(*) as totalAttempts,
         SUM(sa.isCorrect) as correctAttempts,
         AVG(sa.timeSpent) as avgTimeSpent
       FROM step_attempts sa
       JOIN case_steps cs ON sa.stepId = cs.id
       WHERE sa.userId = ? AND cs.tag IS NOT NULL
       GROUP BY cs.tag`,
      [userId]
    );

    const byTag = tagRows.map(row => {
      const errorRate = row.totalAttempts > 0
        ? Math.round(((row.totalAttempts - row.correctAttempts) / row.totalAttempts) * 100 * 10) / 10
        : 0;

      // Use aggregated expected_time (avg) or default to 60 if null
      // Since we group by tag, steps might have different types, but usually tags align with types or topics.
      // Simplification: use 60s as baseline or average.
      const expectedTime = Math.round(row.expected_time || 60);
      const avgTimeSpent = Math.round(row.avgTimeSpent || 0);

      // Determine confidence tier
      let confidence, label;
      if (errorRate < 25 && avgTimeSpent <= expectedTime) {
        confidence = 'strong';
        label = `Strong in ${row.tag}`;
      } else if (errorRate >= 25 && errorRate <= 50) {
        confidence = 'neutral';
        label = 'Needs improvement';
      } else {
        confidence = 'weak';
        label = 'Critical weakness';
      }

      return {
        tag: row.tag,
        totalAttempts: row.totalAttempts,
        correctAttempts: row.correctAttempts || 0,
        errorRate,
        avgTimeSpent,
        expectedTime,
        confidence,
        label
      };
    });

    // Get accuracy over time (last 30 days)
    const [timeRows] = await pool.query(
      `SELECT 
         DATE(createdAt) as date,
         COUNT(*) as total,
         SUM(isCorrect) as correct
       FROM step_attempts
       WHERE userId = ? AND createdAt >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
       GROUP BY DATE(createdAt)
       ORDER BY date ASC`,
      [userId]
    );

    const accuracyOverTime = timeRows.map(row => ({
      date: row.date,
      accuracy: row.total > 0 ? Math.round((row.correct / row.total) * 100) : 0
    }));

    res.json({
      overallStats: {
        totalAttempts: overall.totalAttempts || 0,
        correctAttempts: overall.correctAttempts || 0,
        accuracyRate,
        avgTimePerQuestion: Math.round(overall.avgTimePerQuestion || 0)
      },
      byTag,
      accuracyOverTime
    });

  } catch (err) {
    console.error('Performance analysis error:', err);
    res.status(500).json({ message: 'Database error' });
  }
});

// Get hint for a specific step
app.get('/api/steps/:stepId/hint', authMiddleware(), async (req, res) => {
  try {
    const { stepId } = req.params;

    const [rows] = await pool.query(
      `SELECT hint_text FROM case_steps WHERE id = ?`,
      [stepId]
    );

    if (!rows.length) {
      return res.status(404).json({ message: 'Step not found' });
    }

    const hintText = rows[0].hint_text;

    if (!hintText) {
      return res.json({ hint: null, message: 'No hint available for this step' });
    }

    res.json({ hint: hintText });

  } catch (err) {
    console.error('Hint retrieval error:', err);
    res.status(500).json({ message: 'Database error' });
  }
});

/* ======================
   GLOBAL ERROR HANDLER (SECURITY)
====================== */
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);

  // Don't leak stack traces or internal errors in production
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message || 'Internal server error';

  res.status(err.status || 500).json({ message });
});

/* ======================
   SERVER START
====================== */
console.log("DEBUG: About to listen on port " + PORT);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
