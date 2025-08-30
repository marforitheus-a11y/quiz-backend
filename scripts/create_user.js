// Temporary script to create a regular user for local testing
require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('../db');

async function main() {
  const username = 'local_user';
  const password = 'UserPass123!';
  try {
    await db.query('DELETE FROM users WHERE username = $1', [username]);
    const hashed = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, hashed, 'user']
    );
    console.log('Created user:', result.rows[0]);
    console.log('User credentials -> username:', username, 'password:', password);
    process.exit(0);
  } catch (err) {
    console.error('Error creating user:', err);
    process.exit(1);
  }
}

main();
