// Script: check_questions_difficulty.js
// Prints counts by difficulty and a sample row
if (process.env.NODE_ENV !== 'production') require('dotenv').config();
const db = require('../db');

(async function(){
    try {
        const r = await db.query('SELECT difficulty, COUNT(*) as cnt FROM questions GROUP BY difficulty');
        console.log('Counts by difficulty:');
        console.table(r.rows);
        const sample = await db.query('SELECT id, theme_id, question, difficulty FROM questions LIMIT 5');
        console.log('Sample rows:');
        console.table(sample.rows);
        process.exit(0);
    } catch (e) {
        console.error('Check failed:', e && e.message ? e.message : e);
        process.exit(2);
    }
})();
