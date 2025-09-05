// Script: set_difficulty_easy.js
// Usage: node scripts/set_difficulty_easy.js
// This script is safe to run multiple times; it ensures the 'difficulty' column exists
// and sets existing NULL/empty values to 'easy'. It reads DB config from the project's env.

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const db = require('../db');

(async function run() {
    try {
        console.log('Connecting to DB and applying migration to set existing questions difficulty to "easy"...');
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT`);
        const result = await db.query(`UPDATE questions SET difficulty = 'easy' WHERE difficulty IS NULL OR difficulty = ''`);
        console.log('Migration applied. Rows affected:', result.rowCount);
        process.exit(0);
    } catch (err) {
        console.error('Migration failed:', err && err.message ? err.message : err);
        process.exit(2);
    }
})();
