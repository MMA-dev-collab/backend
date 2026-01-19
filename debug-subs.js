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

        console.log('\n--- USERS ---');
        const [users] = await connection.query('SELECT id, email, name FROM users');
        console.table(users);

        console.log('\n--- PLANS ---');
        const [plans] = await connection.query('SELECT id, name, role, durationDays, duration_value, duration_unit FROM subscription_plans');
        console.table(plans);

        console.log('\n--- SUBSCRIPTIONS ---');
        const [subs] = await connection.query('SELECT id, userId, planId, startDate, endDate, status FROM subscriptions');
        console.table(subs);

        console.log('\n--- TEST getUserMembership Logic ---');
        for (const user of users) {
            const query = `
            SELECT 
                u.email,
                COALESCE(sp.name, 'Free') AS membershipType,
                s.endDate,
                s.status,
                DATEDIFF(s.endDate, CURDATE()) as daysRemaining
            FROM users u
            LEFT JOIN subscriptions s ON u.id = s.userId 
                AND s.status = 'active' 
                AND s.endDate >= CURDATE()
            LEFT JOIN subscription_plans sp ON s.planId = sp.id
            WHERE u.id = ?
            ORDER BY sp.price DESC, s.endDate DESC
            LIMIT 1
        `;
            const [rows] = await connection.query(query, [user.id]);
            console.log(`User ${user.email}:`, rows[0]);
        }

        await connection.end();
    } catch (err) {
        console.error(err);
    }
}

debug();
