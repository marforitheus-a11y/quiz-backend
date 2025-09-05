// Temporary script to create an admin user for local testing
require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('../db');

async function main() {
  const username = 'local_admin';
  const password = 'AdminPass123!';
  try {
    await db.query('DELETE FROM users WHERE username = $1', [username]);
    const hashed = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, hashed, 'admin']
    );
    console.log('Created admin user:', result.rows[0]);
    console.log('Admin credentials -> username:', username, 'password:', password);
    process.exit(0);
  } catch (err) {
    console.error('Error creating admin user:', err);
    process.exit(1);
  }
}

main();
