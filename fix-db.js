const mysql = require('mysql2/promise');
require('dotenv').config();

const DB_CONFIG = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 26324),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    }
};

async function fixDb() {
    console.log('Connecting to DB...');
    let pool;
    try {
        pool = mysql.createPool(DB_CONFIG);
        await pool.query("SELECT 1");
        console.log('Connected.');

        console.log('Adding requiredPlanId column...');
        try {
            await pool.query("ALTER TABLE cases ADD COLUMN requiredPlanId INT NULL");
            console.log('✅ Column added successfully.');
        } catch (e) {
            if (e.code === 'ER_DUP_FIELDNAME') {
                console.log('ℹ️ Column already exists.');
            } else {
                console.error('❌ Error adding column:', e.message);
            }
        }
    } catch (error) {
        console.error('❌ Connection failed:', error);
    } finally {
        if (pool) await pool.end();
    }
}

fixDb();
