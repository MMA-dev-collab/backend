require('dotenv').config();
const mysql = require('mysql2/promise');

const DB_CONFIG = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 26324),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false },
};

async function debug() {
    try {
        const connection = await mysql.createConnection(DB_CONFIG);
        console.log('Connected to DB');

        console.log('\n--- CHECKING DUPLICATE ACTIVE SUBSCRIPTIONS ---');
        const [rows] = await connection.query(`
      SELECT userId, COUNT(*) as count 
      FROM subscriptions 
      WHERE status = 'active'
      GROUP BY userId 
      HAVING count > 1
    `);

        if (rows.length > 0) {
            console.log('WARNING: Users with multiple active subscriptions found:', rows);
            for (const row of rows) {
                const [subs] = await connection.query('SELECT * FROM subscriptions WHERE userId = ? AND status = "active"', [row.userId]);
                console.table(subs);
            }
        } else {
            console.log('No users with duplicate active subscriptions found.');
        }

        await connection.end();
    } catch (err) {
        console.error(err);
    }
}

debug();
