
const mysql = require('mysql2/promise');
require('dotenv').config();

const DB_CONFIG = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'physio_sim_db',
};

async function checkSchema() {
    try {
        const connection = await mysql.createConnection(DB_CONFIG);
        console.log('Connected to database.');

        console.log('--- Checking essay_questions table ---');
        const [columns] = await connection.query(`DESCRIBE essay_questions`);
        console.table(columns);

        console.log('--- Checking sample data from essay_questions ---');
        const [rows] = await connection.query(`SELECT * FROM essay_questions LIMIT 5`);
        console.log(rows);

        await connection.end();
    } catch (error) {
        console.error('Error checking schema:', error);
    }
}

checkSchema();
