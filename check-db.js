const mysql = require('mysql2/promise');
require('dotenv').config();

const DB_CONFIG = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false,
    },
};

async function checkDb() {
    try {
        const connection = await mysql.createConnection(DB_CONFIG);
        const [rows] = await connection.query('SELECT * FROM subscription_plans');
        console.log('Plans found:', rows.length);
        if (rows.length > 0) {
            console.log('Sample plan:', rows[0].name);
        } else {
            console.log('No plans found in database.');
        }
        await connection.end();
    } catch (err) {
        console.error('Database check failed:', err.message);
    }
}

checkDb();
