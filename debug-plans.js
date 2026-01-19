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

        console.log('\n--- PLANS ---');
        const [plans] = await connection.query('SELECT id, name, role FROM subscription_plans');
        console.table(plans);

        await connection.end();
    } catch (err) {
        console.error(err);
    }
}

debug();
