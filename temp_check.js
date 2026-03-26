const mysql = require("mysql2/promise");
require("dotenv").config();

const DB_CONFIG = {
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 26324),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
};

async function check() {
  let connection;
  try {
    connection = await mysql.createConnection(DB_CONFIG);
    console.log("Connected to DB");

    const [cases] = await connection.query("SELECT id, title, status FROM cases");
    console.log("Cases in DB:", cases.length);
    console.log(JSON.stringify(cases, null, 2));

    const [steps] = await connection.query("SELECT caseId, COUNT(*) as stepCount FROM case_steps GROUP BY caseId");
    console.log("Steps per Case:", JSON.stringify(steps, null, 2));

    const [pubWithSteps] = await connection.query(`
      SELECT COUNT(*) as count
      FROM cases c
      WHERE c.status = 'published'
      AND EXISTS (SELECT 1 FROM case_steps cs WHERE cs.caseId = c.id)
    `);
    console.log("Cases passing filter (published + steps):", pubWithSteps[0].count);

  } catch (err) {
    console.error("Error:", err);
  } finally {
    if (connection) await connection.end();
  }
}

check();
