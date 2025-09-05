// Script: find_questions_no_answer.js
// Usage: node scripts/find_questions_no_answer.js
if (process.env.NODE_ENV !== 'production') require('dotenv').config();
const db = require('../db');

(async function(){
    try {
        console.log('Checking for questions with missing answer...');
        const countRes = await db.query("SELECT COUNT(*) as cnt FROM questions WHERE answer IS NULL OR TRIM(answer) = ''");
        const cnt = parseInt(countRes.rows[0].cnt, 10);
        console.log('Total questions with missing/empty answer:', cnt);
        if (cnt > 0) {
            const sample = await db.query("SELECT id, theme_id, question, options, answer FROM questions WHERE answer IS NULL OR TRIM(answer) = '' LIMIT 20");
            console.log('Sample rows (up to 20):');
            console.table(sample.rows);
        }
        process.exit(0);
    } catch (e) {
        console.error('Check failed:', e && e.message ? e.message : e);
        process.exit(2);
    }
})();
