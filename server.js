require("dotenv").config();
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
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key";

/* ======================
   MIDDLEWARE
====================== */
app.use(cors());
app.use(express.json());

/* ======================
   HEALTH CHECK (REQUIRED)
====================== */
app.get("/", (req, res) => {
  res.json({ status: "OK" });
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
  } catch (err) {
    console.error("❌ Database connection failed:", err.message);
    console.log("⚠️ Server will keep running without DB");
  }
}

connectDatabase();

/* ======================
   SQLITE-COMPAT DB API
====================== */


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
      res.status(401).json({ message: "Invalid token" });
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

  const hash = bcrypt.hashSync(password, 10);

  try {
    const [result] = await pool.query(
      `INSERT INTO users (email, passwordHash, role) VALUES (?, ?, 'student')`,
      [email, hash]
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
    return res.status(500).json({ message: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  if (!pool) return res.status(503).json({ message: "DB unavailable" });

  const { email, password } = req.body;

  try {
    const [rows] = await pool.query(`SELECT * FROM users WHERE email = ?`, [email]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

/* ======================
   🔥 ALL YOUR OTHER ROUTES GO HERE
   (PASTE THEM EXACTLY AS THEY ARE)
====================== */

// SEED OPTION - REMOVE IN PRODUCTION
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



app.get('/api/me', authMiddleware(), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, email, role, name, profileImage, membershipType, membershipExpiresAt FROM users WHERE id = ?`,
      [req.user.id]
    );
    const user = rows[0];

    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
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

    // Get membership info
    const [userRows] = await pool.query(
      `SELECT membershipType, membershipExpiresAt FROM users WHERE id = ?`,
      [req.user.id]
    );
    const user = userRows[0];

    res.json({
      casesCompleted: stats.casesCompleted || 0,
      totalScore: stats.totalScore || 0,
      rank: rank || '-',
      membershipType: user.membershipType,
      membershipExpiresAt: user.membershipExpiresAt,
      completedCases: completedCases || []
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/api/cases', async (req, res) => {
  try {
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

    let query;
    let params = [];

    if (userId) {
      query = `SELECT c.*, cat.name as categoryName, cat.icon as categoryIcon,
        COALESCE((
          SELECT MAX(isCompleted) FROM progress p
          WHERE p.userId = ? AND p.caseId = c.id
        ), 0) as isCompleted
       FROM cases c
       LEFT JOIN categories cat ON c.categoryId = cat.id
       ORDER BY c.id ASC`;
      params = [userId];
    } else {
      // Guest query: no progress, just cases
      query = `SELECT c.*, cat.name as categoryName, cat.icon as categoryIcon,
        0 as isCompleted
       FROM cases c
       LEFT JOIN categories cat ON c.categoryId = cat.id
       ORDER BY c.id ASC`;
    }

    const [rows] = await pool.query(query, params);

    const cases = rows.map((row) => ({
      id: row.id,
      title: row.title,
      specialty: row.specialty,
      difficulty: row.difficulty,
      isLocked: !!row.isLocked,
      prerequisiteCaseId: row.prerequisiteCaseId,
      metadata: row.metadata ? JSON.parse(row.metadata) : {},
      isCompleted: !!row.isCompleted,
      thumbnailUrl: row.thumbnailUrl,
      duration: row.duration || 10,
      categoryId: row.categoryId,
      categoryName: row.categoryName || row.category,
      categoryIcon: row.categoryIcon
    }));
    res.json(cases);
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

    const stepsDto = steps.map((s) => ({
      id: s.id,
      stepIndex: s.stepIndex,
      type: s.type,
      content: s.content ? JSON.parse(s.content) : null,
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
    }));

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
    const { selectedOptionId, isFinalStep } = req.body;
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
      if (!isCorrect) {
        return res.json({
          correct: false,
          feedback: optionRow.feedback,
        });
      }

      if (isFinalStep) {
        const [scoreRows] = await pool.query(
          `SELECT SUM(maxScore) as totalScore
           FROM case_steps WHERE caseId = ?`,
          [caseId]
        );
        const score = scoreRows[0].totalScore || 0;

        await pool.query(
          `INSERT INTO progress (userId, caseId, score, isCompleted)
           VALUES (?, ?, ?, 1)`,
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
    const [rows] = await pool.query(`SELECT c.*, cat.name as categoryName FROM cases c LEFT JOIN categories cat ON c.categoryId = cat.id ORDER BY c.id DESC`);
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
    const [rows] = await pool.query(`SELECT c.*, cat.name as categoryName FROM cases c LEFT JOIN categories cat ON c.categoryId = cat.id WHERE c.id = ?`, [id]);
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
      `INSERT INTO cases (title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.put('/api/admin/cases/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration } =
    req.body;

  try {
    await pool.query(
      `UPDATE cases
       SET title = ?, specialty = ?, category = ?, categoryId = ?, difficulty = ?, isLocked = ?, prerequisiteCaseId = ?, metadata = ?, thumbnailUrl = ?, duration = ?
       WHERE id = ?`,
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
        id,
      ]
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

    const stepIds = steps.map((s) => s.id);
    if (stepIds.length === 0) return res.json([]);

    const placeholders = stepIds.map(() => '?').join(',');

    const [options] = await pool.query(`SELECT * FROM case_step_options WHERE stepId IN (${placeholders})`, stepIds);
    const [invs] = await pool.query(`SELECT * FROM investigations WHERE stepId IN (${placeholders})`, stepIds);
    const [xrays] = await pool.query(`SELECT * FROM xrays WHERE stepId IN (${placeholders})`, stepIds);

    const detailedSteps = steps.map((s) => ({
      ...s,
      content: s.content ? JSON.parse(s.content) : {},
      options: options.filter(o => o.stepId === s.id).map(o => ({ ...o, isCorrect: !!o.isCorrect })),
      investigations: invs.filter(i => i.stepId === s.id),
      xrays: xrays.filter(x => x.stepId === s.id)
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
  const { stepIndex, type, content, question, explanationOnFail, maxScore, options, investigations, xrays } = req.body;

  try {
    const [result] = await pool.query(
      `INSERT INTO case_steps (caseId, stepIndex, type, content, question, explanationOnFail, maxScore) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, stepIndex, type, JSON.stringify(content), question, explanationOnFail, maxScore]
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

    res.json({ id: stepId, message: 'Step created' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

// PUT update step
app.put('/api/admin/steps/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { stepIndex, type, content, question, explanationOnFail, maxScore, options, investigations, xrays } = req.body;

  try {
    await pool.query(
      `UPDATE case_steps SET stepIndex=?, type=?, content=?, question=?, explanationOnFail=?, maxScore=? WHERE id=?`,
      [stepIndex, type, JSON.stringify(content), question, explanationOnFail, maxScore, id]
    );

    // Clean up related data to overwrite
    await pool.query(`DELETE FROM case_step_options WHERE stepId = ?`, [id]);
    await pool.query(`DELETE FROM investigations WHERE stepId = ?`, [id]);
    await pool.query(`DELETE FROM xrays WHERE stepId = ?`, [id]);

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
    const [rows] = await pool.query(`SELECT id, email, role, membershipType, membershipExpiresAt, createdAt FROM users ORDER BY createdAt DESC`);

    const users = await Promise.all(rows.map(async (row) => {
      const [stats] = await pool.query(`SELECT COUNT(DISTINCT caseId) as casesCompleted, SUM(score) as totalScore FROM progress WHERE userId = ? AND isCompleted = 1`, [row.id]);
      return {
        id: row.id,
        email: row.email,
        role: row.role,
        membershipType: row.membershipType || 'free',
        membershipExpiresAt: row.membershipExpiresAt,
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

app.put('/api/admin/users/:id/membership', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  const { membershipType, membershipExpiresAt } = req.body;
  try {
    await pool.query(`UPDATE users SET membershipType = ?, membershipExpiresAt = ? WHERE id = ?`, [membershipType, membershipExpiresAt || null, id]);
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error(err);
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



/* ======================
   SERVER START
====================== */
console.log("DEBUG: About to listen on port " + PORT);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
