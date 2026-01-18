const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const fs = require('fs');
const mysql = require('mysql2/promise');

const DB_CONFIG = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false,
    },
    multipleStatements: true
};

async function runMigrations() {
    let connection;
    try {
        console.log('Connecting to database...');
        connection = await mysql.createConnection(DB_CONFIG);
        console.log('Connected to database.');

        const migrationsDir = path.join(__dirname, 'migrations');
        const files = fs.readdirSync(migrationsDir)
            .filter(file => file.endsWith('.sql'))
            .sort(); // Run in order

        console.log(`Found ${files.length} migration files.`);

        for (const file of files) {
            console.log(`Running migration: ${file}`);
            const filePath = path.join(migrationsDir, file);
            const sql = fs.readFileSync(filePath, 'utf8');

            try {
                await connection.query(sql);
                console.log(`✅ Successfully ran ${file}`);
            } catch (err) {
                console.error(`❌ Error running ${file}:`, err.message);
                // Continue with other migrations? For now, yes, as some might fail if tables exist
            }
        }

        console.log('All migrations processed.');
    } catch (err) {
        console.error('Migration script failed:', err);
    } finally {
        if (connection) await connection.end();
    }
}

runMigrations();
