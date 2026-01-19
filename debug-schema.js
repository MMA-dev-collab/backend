const mysql = require('mysql2/promise');
require('dotenv').config();

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'physiosim',
};

async function checkSchema() {
    try {
        const pool = mysql.createPool(dbConfig);
        const [rows] = await pool.query('DESCRIBE cases');
        console.log('Columns in cases table:');
        rows.forEach(row => console.log(`- ${row.Field} (${row.Type})`));
        await pool.end();
    } catch (error) {
        console.error('Error:', error);
    }
}

checkSchema();
