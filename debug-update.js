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

async function testUpdate() {
    console.log('Connecting...');
    const pool = mysql.createPool(DB_CONFIG);
    try {
        // Get a case ID
        const [rows] = await pool.query('SELECT id, title, requiredPlanId FROM cases LIMIT 1');
        if (rows.length === 0) {
            console.log('No cases found to test.');
            return;
        }
        const caseId = rows[0].id;
        console.log(`Testing update on Case ID ${caseId} (${rows[0].title}). Current Plan: ${rows[0].requiredPlanId}`);

        // Update to something new (toggle between 1 and 2)
        const newPlanId = rows[0].requiredPlanId === 1 ? 2 : 1;
        console.log(`Updating to Plan ID ${newPlanId}...`);

        await pool.query('UPDATE cases SET requiredPlanId = ? WHERE id = ?', [newPlanId, caseId]);
        console.log('Update query executed.');

        // Verify
        const [verifyRows] = await pool.query('SELECT id, requiredPlanId FROM cases WHERE id = ?', [caseId]);
        console.log(`New Plan verified: ${verifyRows[0].requiredPlanId}`);

        if (verifyRows[0].requiredPlanId === newPlanId) {
            console.log('✅ Update SUCCESSFUL.');
        } else {
            console.log('❌ Update FAILED.');
        }

    } catch (e) {
        console.error('Error:', e);
    } finally {
        await pool.end();
    }
}

testUpdate();
