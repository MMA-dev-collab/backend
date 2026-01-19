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

        const userId = 11; // student1

        console.log(`\n--- EXECUTING getUserMembership QUERY for User ${userId} ---`);
        const query = `
      SELECT 
        u.email,
        u.id,
        s.id as subId,
        s.status as subStatus,
        s.endDate,
        s.planId,
        sp.name as planName,
        sp.role as planRole,
        COALESCE(sp.name, 'FreeResult') AS derivedMembership
      FROM users u
      LEFT JOIN subscriptions s ON u.id = s.userId 
      LEFT JOIN subscription_plans sp ON s.planId = sp.id
      WHERE u.id = ?
    `;

        // Dump ALL subscriptions for this user first
        const [allSubs] = await connection.query(query, [userId]);
        console.table(allSubs);

        console.log('\n--- EXECUTING EXACT LOGIC ---');
        const exactQuery = `
      SELECT 
        COALESCE(sp.name, 'Free') AS membershipType,
        s.endDate AS membershipExpiresAt,
        sp.id AS activePlanId,
        sp.role AS planRole
      FROM users u
      LEFT JOIN subscriptions s ON u.id = s.userId 
        AND s.status = 'active' 
        AND (s.endDate >= CURDATE() OR s.endDate >= DATE_SUB(NOW(), INTERVAL 24 HOUR))
      LEFT JOIN subscription_plans sp ON s.planId = sp.id
      WHERE u.id = ?
      ORDER BY sp.price DESC, s.endDate DESC
      LIMIT 1
    `;
        const [rows] = await connection.query(exactQuery, [userId]);
        console.log('Result:', rows[0]);

        await connection.end();
    } catch (err) {
        console.error(err);
    }
}

debug();
