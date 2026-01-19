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

        console.log('\n--- PLANS (Full Dump) ---');
        const [plans] = await connection.query('SELECT * FROM subscription_plans');
        console.table(plans);

        console.log('\n--- USER 11 (Student1) Raw Data ---');
        const [users] = await connection.query('SELECT id, email, membershipType FROM users WHERE id = 11');
        console.table(users);

        await connection.end();
    } catch (err) {
        console.error(err);
    }
}

debug();
