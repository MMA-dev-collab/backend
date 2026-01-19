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

        const [plans] = await connection.query('SELECT id, name, role FROM subscription_plans');
        console.log('PLANS:', JSON.stringify(plans, null, 2));

        const [users] = await connection.query('SELECT id, email, membershipType FROM users WHERE id = 11');
        console.log('USER 11:', JSON.stringify(users, null, 2));

        await connection.end();
    } catch (err) {
        console.error(err);
    }
}

debug();
