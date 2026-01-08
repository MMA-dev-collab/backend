const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';

app.use(cors());
app.use(express.json());

// MySQL configuration
const dbConfig = {
  host: '127.0.0.1',
  user: 'root',
  password: 'Mazen198165967#',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  multipleStatements: true
};

// Initial connection to create DB if not exists
const initDbPromise = new Promise((resolve, reject) => {
  const conn = mysql.createConnection({
    host: dbConfig.host,
    user: dbConfig.user,
    password: dbConfig.password
  });

  conn.query(`CREATE DATABASE IF NOT EXISTS PhysioCaseLab`, (err) => {
    if (err) {
      console.error('Failed to create database:', err);
      reject(err);
      return;
    }
    console.log('Database PhysioCaseLab ensured.');
    conn.end();
    resolve();
  });
});

let pool;

async function init() {
  try {
    await initDbPromise;
    pool = mysql.createPool({ ...dbConfig, database: 'PhysioCaseLab' });
    // Use async migrations
    await runMigrationsAsync();
    console.log('Database initialization complete.');
  } catch (err) {
    console.error('Initialization failed:', err);
    process.exit(1);
  }
}

init();

// DB Compatibility Wrapper (for existing code that uses db.run/get/all)
const db = {
  run: function (sql, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = [];
    }
    pool.query(sql, params, function (err, results) {
      if (callback) {
        const context = {
          lastID: results ? results.insertId : 0,
          changes: results ? results.affectedRows : 0
        };
        callback.call(context, err);
      }
    });
  },
  get: function (sql, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = [];
    }
    pool.query(sql, params, function (err, results) {
      if (err) return callback(err);
      callback(null, results && results.length > 0 ? results[0] : undefined);
    });
  },
  all: function (sql, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = [];
    }
    pool.query(sql, params, function (err, results) {
      callback(err, results);
    });
  },
  serialize: function (callback) {
    if (callback) callback();
  },
  prepare: function (sql) {
    return {
      run: function (...args) {
        const callback = args.length > 0 && typeof args[args.length - 1] === 'function' ? args.pop() : null;
        pool.query(sql, args, function (err, results) {
          if (callback) callback(err);
        });
      },
      finalize: function () { }
    };
  }
};

// Promisified helper for migrations
const queryAsync = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    pool.query(sql, params, (err, res) => {
      if (err) reject(err);
      else resolve(res);
    });
  });
};

async function runMigrationsAsync() {
  try {
    // 1. Create Tables
    await queryAsync(`
      CREATE TABLE IF NOT EXISTS categories (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(100) UNIQUE NOT NULL,
        icon VARCHAR(50),
        description TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        passwordHash TEXT NOT NULL,
        name VARCHAR(255),
        profileImage LONGTEXT,
        role VARCHAR(50) NOT NULL CHECK(role IN ('student', 'admin')),
        membershipType VARCHAR(50) DEFAULT 'free',
        membershipExpiresAt TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS cases (
        id INT PRIMARY KEY AUTO_INCREMENT,
        title TEXT NOT NULL,
        specialty TEXT,
        category TEXT,
        categoryId INT,
        difficulty TEXT,
        isLocked BOOLEAN NOT NULL DEFAULT 0,
        prerequisiteCaseId INT,
        metadata TEXT,
        thumbnailUrl LONGTEXT,
        duration INT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(categoryId) REFERENCES categories(id) ON DELETE SET NULL
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS case_steps (
        id INT PRIMARY KEY AUTO_INCREMENT,
        caseId INT NOT NULL,
        stepIndex INT NOT NULL,
        type VARCHAR(50) NOT NULL,
        content LONGTEXT NOT NULL,
        question TEXT,
        explanationOnFail TEXT,
        maxScore INT DEFAULT 0,
        FOREIGN KEY(caseId) REFERENCES cases(id) ON DELETE CASCADE
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS case_step_options (
        id INT PRIMARY KEY AUTO_INCREMENT,
        stepId INT NOT NULL,
        label TEXT NOT NULL,
        isCorrect BOOLEAN NOT NULL DEFAULT 0,
        feedback TEXT,
        FOREIGN KEY(stepId) REFERENCES case_steps(id) ON DELETE CASCADE
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS investigations (
        id INT PRIMARY KEY AUTO_INCREMENT,
        stepId INT NOT NULL,
        groupLabel TEXT NOT NULL,
        testName TEXT NOT NULL,
        description TEXT,
        result TEXT,
        videoUrl TEXT,
        FOREIGN KEY(stepId) REFERENCES case_steps(id) ON DELETE CASCADE
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS xrays (
        id INT PRIMARY KEY AUTO_INCREMENT,
        stepId INT NOT NULL,
        label TEXT NOT NULL,
        icon TEXT,
        imageUrl LONGTEXT,
        FOREIGN KEY(stepId) REFERENCES case_steps(id) ON DELETE CASCADE
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS progress (
        id INT PRIMARY KEY AUTO_INCREMENT,
        userId INT NOT NULL,
        caseId INT NOT NULL,
        score INT NOT NULL,
        isCompleted BOOLEAN NOT NULL DEFAULT 0,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(caseId) REFERENCES cases(id) ON DELETE CASCADE
      )
    `);

    await queryAsync(`
      CREATE TABLE IF NOT EXISTS website_content (
        id INT PRIMARY KEY AUTO_INCREMENT,
        page VARCHAR(100) NOT NULL,
        section VARCHAR(100) NOT NULL,
        content TEXT NOT NULL,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE(page, section)
      )
    `);

    // 2. Initial Seeding (Admin & Case & Categories)
    // Check Admin
    const adminRows = await queryAsync(`SELECT COUNT(*) as count FROM users WHERE role='admin'`);
    if (adminRows[0].count === 0) {
      const passwordHash = bcrypt.hashSync('admin123', 10);
      await queryAsync(
        `INSERT INTO users (email, passwordHash, role) VALUES (?, ?, 'admin')`,
        ['admin@example.com', passwordHash]
      );
      console.log('Seeded default admin: admin@example.com / admin123');
    }

    // Seed Categories
    const catRows = await queryAsync(`SELECT COUNT(*) as count FROM categories`);
    if (catRows[0].count === 0) {
      const defaultCats = [
        { name: 'Knee', icon: '🦵' },
        { name: 'Back', icon: '🦴' },
        { name: 'Shoulder', icon: '💪' },
        { name: 'Hip', icon: '🦴' },
        { name: 'Ankle', icon: '🦶' },
        { name: 'Other', icon: '📋' }
      ];
      for (const cat of defaultCats) {
        await queryAsync(`INSERT INTO categories (name, icon) VALUES (?, ?)`, [cat.name, cat.icon]);
      }
      console.log('Seeded default categories');
    }

    // Check Case
    const caseRows = await queryAsync(`SELECT COUNT(*) as count FROM cases`);
    if (caseRows[0].count === 0) {
      seedInitialCase();
    }

    // 3. Alter Migrations (Check and Add Column)
    // Helper
    const ensureColumn = async (table, column, def) => {
      const rows = await queryAsync(`SHOW COLUMNS FROM ${table} LIKE '${column}'`);
      if (rows.length === 0) {
        await queryAsync(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`);
        console.log(`Added column ${column} to ${table}`);
      }
    };

    await ensureColumn('xrays', 'imageUrl', 'LONGTEXT');
    await ensureColumn('cases', 'thumbnailUrl', 'LONGTEXT');
    await ensureColumn('cases', 'duration', 'INT DEFAULT 10');
    await ensureColumn('cases', 'category', 'TEXT');
    await ensureColumn('cases', 'categoryId', 'INT');
    await ensureColumn('users', 'name', 'VARCHAR(255)');
    await ensureColumn('users', 'profileImage', 'LONGTEXT');
    await ensureColumn('users', 'membershipType', "VARCHAR(50) DEFAULT 'free'");
    await ensureColumn('users', 'membershipExpiresAt', 'TEXT');
    await ensureColumn('users', 'createdAt', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP');

    // Migrate existing string categories to categoryId
    try {
      await queryAsync(`
        UPDATE cases c 
        JOIN categories cat ON c.category = cat.name 
        SET c.categoryId = cat.id 
        WHERE c.categoryId IS NULL AND c.category IS NOT NULL
      `);
      // console.log('Migrated existing categories to categoryId');
    } catch (e) {
      // Ignore if fails (e.g. table doesn't exist yet in weird state)
    }

    // 4. Upgrade Columns to LONGTEXT (Explicit migration for existing tables)
    try {
      await queryAsync(`ALTER TABLE cases MODIFY COLUMN thumbnailUrl LONGTEXT`);
      await queryAsync(`ALTER TABLE case_steps MODIFY COLUMN content LONGTEXT`);
      await queryAsync(`ALTER TABLE xrays MODIFY COLUMN imageUrl LONGTEXT`);
      console.log('Upgraded columns to LONGTEXT');
    } catch (e) {
      console.log('Column upgrade error (might already be upgraded):', e.message);
    }

  } catch (err) {
    console.error('Migration Error:', err);
  }
}

function seedInitialCase() {
  db.serialize(() => {
    db.get(`SELECT id FROM categories WHERE name = 'Knee'`, [], (err, catRow) => {
      const categoryId = catRow ? catRow.id : null;
      db.run(
        `INSERT INTO cases (title, specialty, difficulty, isLocked, metadata, category, categoryId)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          '54-year-old female with knee pain',
          'Physical Therapy',
          'Intermediate',
          0,
          JSON.stringify({
            brief:
              '54-year-old female with chronic knee pain, worse on stairs and during prayer on the floor.',
          }),
          'Knee',
          categoryId
        ],
        function (err) {
          if (err) return console.error(err);
          const caseId = this.lastID;

          db.run(
            `INSERT INTO case_steps
             (caseId, stepIndex, type, content, question, explanationOnFail, maxScore)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
              caseId,
              0,
              'info',
              JSON.stringify({
                patientName: 'Ms. A',
                age: 54,
                gender: 'Female',
                imageUrl: null,
                description:
                  'I have had knee pain for a few months. The pain is worse when I go up and down stairs. At first it felt better after moving, but now it is there all the time and makes it difficult to pray on the floor.',
                chiefComplaint:
                  'طلوع ونزل السلم بيتعبوني ودلوقتي بقيت اصلي على كرسي علشان مبقتش اعرف اسجد',
              }),
              null,
              null,
              0,
            ]
          );

          db.run(
            `INSERT INTO case_steps
             (caseId, stepIndex, type, content, question, explanationOnFail, maxScore)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
              caseId,
              1,
              'mcq',
              JSON.stringify({
                prompt:
                  'What is the MOST appropriate next action after hearing this chief complaint?',
              }),
              'Choose the best next step in managing this patient.',
              'Incorrect. Remember that the first priority is to take a focused history before jumping to investigations or treatment.',
              10,
            ],
            function (err2) {
              if (err2) return console.error(err2);
              const stepId = this.lastID;
              const options = [
                {
                  label: 'Order MRI of the knee immediately',
                  isCorrect: 0,
                  feedback:
                    'Jumping to advanced imaging without a proper history and examination is not appropriate as a first step.',
                },
                {
                  label: 'Start the patient on strong analgesics and send her home',
                  isCorrect: 0,
                  feedback:
                    'Symptomatic treatment alone without understanding the cause and functional limitations is not adequate.',
                },
                {
                  label: 'Begin quadriceps strengthening exercises right away',
                  isCorrect: 0,
                  feedback:
                    'Exercise may be part of management but should follow a complete assessment, not precede it.',
                },
                {
                  label: 'Take a detailed history of the knee pain and functional limitations',
                  isCorrect: 1,
                  feedback:
                    'Correct. A structured, detailed history is the essential next step.',
                },
              ];
              const stmt = db.prepare(
                `INSERT INTO case_step_options (stepId, label, isCorrect, feedback)
                 VALUES (?, ?, ?, ?)`
              );
              options.forEach((opt) => {
                stmt.run(stepId, opt.label, opt.isCorrect, opt.feedback);
              });
              stmt.finalize();
            }
          );
        }
      );
    });
  });
}

function authMiddleware(requiredRole) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'Missing token' });
    const token = authHeader.split(' ')[1];
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ message: 'Forbidden' });
      }
      req.user = payload;
      next();
    } catch (e) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  };
}

app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  const role = 'student';
  db.run(
    `INSERT INTO users (email, passwordHash, role) VALUES (?, ?, ?)`,
    [email, passwordHash, role],
    function (err) {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: 'Email already exists' });
        }
        console.error(err);
        return res.status(500).json({ message: 'Error creating user' });
      }
      const token = jwt.sign(
        { id: this.lastID, email, role },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      res.json({ token, user: { id: this.lastID, email, role, name: null, profileImage: null } });
    }
  );
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    (err, user) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      const match = bcrypt.compareSync(password, user.passwordHash);
      if (!match) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          name: user.name,
          profileImage: user.profileImage
        },
      });
    }
  );
});

app.get('/api/me', authMiddleware(), (req, res) => {
  db.get(
    `SELECT id, email, role, name, profileImage, membershipType, membershipExpiresAt FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json(user);
    }
  );
});

app.put('/api/user/profile', authMiddleware(), (req, res) => {
  const { name, profileImage } = req.body;
  db.run(
    `UPDATE users SET name = ?, profileImage = ? WHERE id = ?`,
    [name, profileImage, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({ message: 'Profile updated successfully' });
    }
  );
});

app.get('/api/profile/stats', authMiddleware(), (req, res) => {
  // Get cases completed and total score
  db.get(
    `SELECT 
       COUNT(DISTINCT caseId) as casesCompleted,
       SUM(score) as totalScore
     FROM progress
     WHERE userId = ? AND isCompleted = 1`,
    [req.user.id],
    (err, stats) => {
      if (err) return res.status(500).json({ message: 'Database error' });

      // Get completed cases list
      db.all(
        `SELECT p.caseId, p.score, p.createdAt as completedAt, c.title
         FROM progress p
         JOIN cases c ON p.caseId = c.id
         WHERE p.userId = ? AND p.isCompleted = 1
         ORDER BY p.createdAt DESC`,
        [req.user.id],
        (errCases, completedCases) => {
          if (errCases) return res.status(500).json({ message: 'Database error' });

          // Get rank
          db.all(
            `SELECT userId, SUM(score) as totalScore
             FROM progress
             WHERE isCompleted = 1
             GROUP BY userId
             ORDER BY totalScore DESC`,
            [],
            (err2, leaderboard) => {
              if (err2) return res.status(500).json({ message: 'Database error' });

              const rank = leaderboard.findIndex(u => u.userId === req.user.id) + 1;

              // Get membership info
              db.get(
                `SELECT membershipType, membershipExpiresAt FROM users WHERE id = ?`,
                [req.user.id],
                (err3, user) => {
                  if (err3) return res.status(500).json({ message: 'Database error' });

                  res.json({
                    casesCompleted: stats.casesCompleted || 0,
                    totalScore: stats.totalScore || 0,
                    rank: rank || '-',
                    membershipType: user.membershipType,
                    membershipExpiresAt: user.membershipExpiresAt,
                    completedCases: completedCases || []
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

app.get('/api/cases', authMiddleware(), (req, res) => {
  db.all(
    `SELECT c.*, cat.name as categoryName, cat.icon as categoryIcon,
      COALESCE((
        SELECT MAX(isCompleted) FROM progress p
        WHERE p.userId = ? AND p.caseId = c.id
      ), 0) as isCompleted
     FROM cases c
     LEFT JOIN categories cat ON c.categoryId = cat.id
     ORDER BY c.id ASC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Database error' });
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
    }
  );
});

app.get('/api/cases/:id', authMiddleware(), (req, res) => {
  const caseId = req.params.id;
  db.get(`SELECT * FROM cases WHERE id = ?`, [caseId], (err, caseRow) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!caseRow) return res.status(404).json({ message: 'Case not found' });

    if (caseRow.prerequisiteCaseId) {
      db.get(
        `SELECT MAX(isCompleted) as done
         FROM progress
         WHERE userId = ? AND caseId = ?`,
        [req.user.id, caseRow.prerequisiteCaseId],
        (err2, row) => {
          if (err2) return res.status(500).json({ message: 'Database error' });
          if (!row || !row.done) {
            return res.status(403).json({
              message: 'You must complete the prerequisite case first.',
            });
          }
          loadCaseSteps();
        }
      );
    } else {
      loadCaseSteps();
    }

    function loadCaseSteps() {
      db.all(
        `SELECT * FROM case_steps WHERE caseId = ? ORDER BY stepIndex ASC`,
        [caseId],
        (err3, steps) => {
          if (err3) return res.status(500).json({ message: 'Database error' });
          if (!steps.length)
            return res
              .status(500)
              .json({ message: 'Case has no steps configured' });

          const stepIds = steps.map((s) => s.id);
          const placeholders = stepIds.map(() => '?').join(',');

          if (stepIds.length === 0) {
            return res.json({ ...caseRow, steps: [] });
          }

          db.all(
            `SELECT * FROM case_step_options WHERE stepId IN (${placeholders})`,
            stepIds,
            (err4, options) => {
              if (err4)
                return res.status(500).json({ message: 'Database error' });
              db.all(
                `SELECT * FROM investigations WHERE stepId IN (${placeholders})`,
                stepIds,
                (err5, inv) => {
                  if (err5)
                    return res
                      .status(500)
                      .json({ message: 'Database error' });
                  db.all(
                    `SELECT * FROM xrays WHERE stepId IN (${placeholders})`,
                    stepIds,
                    (err6, xrays) => {
                      if (err6)
                        return res
                          .status(500)
                          .json({ message: 'Database error' });

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
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  });
});

app.post(
  '/api/cases/:caseId/steps/:stepId/answer',
  authMiddleware(),
  (req, res) => {
    const { selectedOptionId, isFinalStep } = req.body;
    const { caseId, stepId } = req.params;

    db.get(
      `SELECT * FROM case_step_options WHERE id = ? AND stepId = ?`,
      [selectedOptionId, stepId],
      (err, optionRow) => {
        if (err) return res.status(500).json({ message: 'Database error' });
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
          db.get(
            `SELECT SUM(maxScore) as totalScore
             FROM case_steps WHERE caseId = ?`,
            [caseId],
            (err2, row) => {
              if (err2)
                return res.status(500).json({ message: 'Database error' });
              const score = row.totalScore || 0;
              db.run(
                `INSERT INTO progress (userId, caseId, score, isCompleted)
                 VALUES (?, ?, ?, 1)`,
                [req.user.id, caseId, score],
                function (err3) {
                  if (err3)
                    return res
                      .status(500)
                      .json({ message: 'Database error' });

                  db.get(
                    `SELECT 
                       COUNT(DISTINCT caseId) as casesCompleted,
                       SUM(score) as totalScore
                     FROM progress
                     WHERE userId = ? AND isCompleted = 1`,
                    [req.user.id],
                    (err4, stats) => {
                      if (err4)
                        return res
                          .status(500)
                          .json({ message: 'Database error' });

                      res.json({
                        correct: true,
                        final: true,
                        score,
                        stats: {
                          casesCompleted: stats.casesCompleted || 0,
                          totalScore: stats.totalScore || 0,
                        },
                      });
                    }
                  );
                }
              );
            }
          );
        } else {
          res.json({
            correct: true,
          });
        }
      }
    );
  }
);

app.get('/api/stats/me', authMiddleware(), (req, res) => {
  db.get(
    `SELECT 
       COUNT(DISTINCT caseId) as casesCompleted,
       SUM(score) as totalScore
     FROM progress
     WHERE userId = ? AND isCompleted = 1`,
    [req.user.id],
    (err, stats) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({
        casesCompleted: stats.casesCompleted || 0,
        totalScore: stats.totalScore || 0,
      });
    }
  );
});

app.get('/api/admin/cases', authMiddleware('admin'), (req, res) => {
  db.all(`SELECT c.*, cat.name as categoryName FROM cases c LEFT JOIN categories cat ON c.categoryId = cat.id ORDER BY c.id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error' });
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
  });
});

app.post('/api/admin/cases', authMiddleware('admin'), (req, res) => {
  const { title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration } =
    req.body;
  if (!title) return res.status(400).json({ message: 'Title is required' });
  db.run(
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
    ],
    function (err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({
        id: this.lastID,
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
    }
  );
});

app.put('/api/admin/cases/:id', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  const { title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration } =
    req.body;
  db.run(
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
    ],
    function (err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({ message: 'Updated' });
    }
  );
});

app.delete('/api/admin/cases/:id', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  db.run(`DELETE FROM cases WHERE id = ?`, [id], function (err) {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Deleted' });
  });
});

// --- Step Management Endpoints ---

// GET steps for a case
app.get('/api/admin/cases/:id/steps', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM case_steps WHERE caseId = ? ORDER BY stepIndex ASC`, [id], (err, steps) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    const stepIds = steps.map((s) => s.id);
    if (stepIds.length === 0) return res.json([]);

    const placeholders = stepIds.map(() => '?').join(',');

    db.all(`SELECT * FROM case_step_options WHERE stepId IN (${placeholders})`, stepIds, (err2, options) => {
      if (err2) return res.status(500).json({ message: 'Database error' });
      db.all(`SELECT * FROM investigations WHERE stepId IN (${placeholders})`, stepIds, (err3, invs) => {
        if (err3) return res.status(500).json({ message: 'Database error' });
        db.all(`SELECT * FROM xrays WHERE stepId IN (${placeholders})`, stepIds, (err4, xrays) => {
          if (err4) return res.status(500).json({ message: 'Database error' });

          const detailedSteps = steps.map((s) => ({
            ...s,
            content: s.content ? JSON.parse(s.content) : {},
            options: options.filter(o => o.stepId === s.id).map(o => ({ ...o, isCorrect: !!o.isCorrect })),
            investigations: invs.filter(i => i.stepId === s.id),
            xrays: xrays.filter(x => x.stepId === s.id)
          }));
          res.json(detailedSteps);
        });
      });
    });
  });
});

// POST new step
app.post('/api/admin/cases/:id/steps', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  const { stepIndex, type, content, question, explanationOnFail, maxScore, options, investigations, xrays } = req.body;

  db.run(
    `INSERT INTO case_steps (caseId, stepIndex, type, content, question, explanationOnFail, maxScore) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, stepIndex, type, JSON.stringify(content), question, explanationOnFail, maxScore],
    function (err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      const stepId = this.lastID;

      // Insert Options
      if (options && options.length > 0) {
        const stmt = db.prepare(`INSERT INTO case_step_options (stepId, label, isCorrect, feedback) VALUES (?, ?, ?, ?)`);
        options.forEach(o => stmt.run(stepId, o.label, o.isCorrect ? 1 : 0, o.feedback));
        stmt.finalize();
      }

      // Insert Investigations
      if (investigations && investigations.length > 0) {
        const stmt = db.prepare(`INSERT INTO investigations (stepId, groupLabel, testName, description, result, videoUrl) VALUES (?, ?, ?, ?, ?, ?)`);
        investigations.forEach(i => stmt.run(stepId, i.groupLabel, i.testName, i.description, i.result, i.videoUrl));
        stmt.finalize();
      }

      // Insert X-Rays
      if (xrays && xrays.length > 0) {
        const stmt = db.prepare(`INSERT INTO xrays (stepId, label, icon, imageUrl) VALUES (?, ?, ?, ?)`);
        xrays.forEach(x => stmt.run(stepId, x.label, x.icon, x.imageUrl));
        stmt.finalize();
      }

      res.json({ id: stepId, message: 'Step created' });
    }
  );
});

// PUT update step
app.put('/api/admin/steps/:id', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  const { stepIndex, type, content, question, explanationOnFail, maxScore, options, investigations, xrays } = req.body;

  db.run(
    `UPDATE case_steps SET stepIndex=?, type=?, content=?, question=?, explanationOnFail=?, maxScore=? WHERE id=?`,
    [stepIndex, type, JSON.stringify(content), question, explanationOnFail, maxScore, id],
    function (err) {
      if (err) return res.status(500).json({ message: 'Database error' });

      // Clean up related data to overwrite
      db.run(`DELETE FROM case_step_options WHERE stepId = ?`, [id]);
      db.run(`DELETE FROM investigations WHERE stepId = ?`, [id]);
      db.run(`DELETE FROM xrays WHERE stepId = ?`, [id]);

      // Re-Insert Options
      if (options && options.length > 0) {
        const stmt = db.prepare(`INSERT INTO case_step_options (stepId, label, isCorrect, feedback) VALUES (?, ?, ?, ?)`);
        options.forEach(o => stmt.run(id, o.label, o.isCorrect ? 1 : 0, o.feedback));
        stmt.finalize();
      }

      // Re-Insert Investigations
      if (investigations && investigations.length > 0) {
        const stmt = db.prepare(`INSERT INTO investigations (stepId, groupLabel, testName, description, result, videoUrl) VALUES (?, ?, ?, ?, ?, ?)`);
        investigations.forEach(i => stmt.run(id, i.groupLabel, i.testName, i.description, i.result, i.videoUrl));
        stmt.finalize();
      }

      // Re-Insert X-Rays
      if (xrays && xrays.length > 0) {
        const stmt = db.prepare(`INSERT INTO xrays (stepId, label, icon, imageUrl) VALUES (?, ?, ?, ?)`);
        xrays.forEach(x => stmt.run(id, x.label, x.icon, x.imageUrl));
        stmt.finalize();
      }

      res.json({ message: 'Step updated' });
    }
  );
});

// DELETE Step
app.delete('/api/admin/steps/:id', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  db.run(`DELETE FROM case_steps WHERE id = ?`, [id], function (err) {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Deleted' });
  });
});

// Admin Dashboard Overview
app.get('/api/admin/overview', authMiddleware('admin'), (req, res) => {
  db.get(`SELECT COUNT(*) as totalUsers FROM users WHERE role = 'student'`, (err1, users) => {
    if (err1) return res.status(500).json({ message: 'Database error' });
    db.get(`SELECT COUNT(*) as totalCases FROM cases`, (err2, cases) => {
      if (err2) return res.status(500).json({ message: 'Database error' });
      db.get(`SELECT COUNT(*) as totalProgress FROM progress WHERE isCompleted = 1`, (err3, progress) => {
        if (err3) return res.status(500).json({ message: 'Database error' });
        db.get(`SELECT COUNT(*) as premiumUsers FROM users WHERE membershipType = 'premium'`, (err4, premium) => {
          if (err4) return res.status(500).json({ message: 'Database error' });
          res.json({
            totalUsers: users.totalUsers,
            totalCases: cases.totalCases,
            totalCompletions: progress.totalProgress,
            premiumUsers: premium.premiumUsers,
          });
        });
      });
    });
  });
});

// User Management
app.get('/api/admin/users', authMiddleware('admin'), (req, res) => {
  db.all(`SELECT id, email, role, membershipType, membershipExpiresAt, createdAt FROM users ORDER BY createdAt DESC`, [], (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    const users = rows.map(async (row) => {
      return new Promise((resolve) => {
        db.get(`SELECT COUNT(DISTINCT caseId) as casesCompleted, SUM(score) as totalScore FROM progress WHERE userId = ? AND isCompleted = 1`, [row.id], (err2, stats) => {
          resolve({
            id: row.id,
            email: row.email,
            role: row.role,
            membershipType: row.membershipType || 'free',
            membershipExpiresAt: row.membershipExpiresAt,
            createdAt: row.createdAt,
            stats: {
              casesCompleted: stats?.casesCompleted || 0,
              totalScore: stats?.totalScore || 0,
            },
          });
        });
      });
    });
    Promise.all(users).then((usersWithStats) => res.json(usersWithStats));
  });
});

app.put('/api/admin/users/:id/membership', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  const { membershipType, membershipExpiresAt } = req.body;
  db.run(`UPDATE users SET membershipType = ?, membershipExpiresAt = ? WHERE id = ?`, [membershipType, membershipExpiresAt || null, id], function (err) {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Updated' });
  });
});

// --- Categories Management ---

app.get('/api/categories', (req, res) => {
  db.all(`SELECT * FROM categories ORDER BY name ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/admin/categories', authMiddleware('admin'), (req, res) => {
  const { name, icon, description } = req.body;
  if (!name) return res.status(400).json({ message: 'Name is required' });
  db.run(
    `INSERT INTO categories (name, icon, description) VALUES (?, ?, ?)`,
    [name, icon, description],
    function (err) {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Category already exists' });
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ id: this.lastID, name, icon, description });
    }
  );
});

app.put('/api/admin/categories/:id', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  const { name, icon, description } = req.body;
  db.run(
    `UPDATE categories SET name = ?, icon = ?, description = ? WHERE id = ?`,
    [name, icon, description, id],
    function (err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({ message: 'Updated' });
    }
  );
});

app.delete('/api/admin/categories/:id', authMiddleware('admin'), (req, res) => {
  const { id } = req.params;
  // Check if used
  db.get(`SELECT COUNT(*) as count FROM cases WHERE categoryId = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (row.count > 0) return res.status(400).json({ message: 'Cannot delete category used by cases' });

    db.run(`DELETE FROM categories WHERE id = ?`, [id], function (err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({ message: 'Deleted' });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Backend API running on http://localhost:${PORT}`);
});
