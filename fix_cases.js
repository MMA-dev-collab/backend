require("dotenv").config();
const mysql = require("mysql2/promise");
const fs = require('fs');

const DB_CONFIG = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 26324),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false,
    },
};

function log(msg) {
    try {
        fs.appendFileSync('fix_log.txt', msg + '\n');
        console.log(msg);
    } catch (e) {
        console.error("Log error:", e);
    }
}

async function fixCases() {
    try {
        log("Starting fix_cases.js...");
        log("DB Config Host: " + DB_CONFIG.host);

        log("Connecting to database...");
        const connection = await mysql.createConnection(DB_CONFIG);
        log("Connected.");

        log("Updating all cases to 'published'...");
        const [result] = await connection.query("UPDATE cases SET status = 'published'");
        log(`Updated ${result.changedRows} cases.`);

        const [rows] = await connection.query("SELECT status, COUNT(*) as count FROM cases GROUP BY status");
        log("Current status counts: " + JSON.stringify(rows));

        await connection.end();
        log("Done.");
        process.exit(0);
    } catch (err) {
        log("Error: " + err.message);
        process.exit(1);
    }
}

fixCases();
