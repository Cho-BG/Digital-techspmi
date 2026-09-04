import 'dotenv/config';
import { closeDB, getDB, initDB } from '../database.js';
import { hashPassword, isValidPassword } from '../security.js';

const password = process.env.ADMIN_INITIAL_PASSWORD;
if (!password || !isValidPassword(password)) {
  throw new Error('ADMIN_INITIAL_PASSWORD must contain 8-10 Latin letters or numbers');
}

await initDB();
const db = getDB();
await db.run(`INSERT INTO admin_accounts (login, password, full_name, account_enabled)
  VALUES ('admin/dpk', ?, 'Администратор ДПК', 1)
  ON CONFLICT (login) DO UPDATE SET password = EXCLUDED.password, account_enabled = 1`, [hashPassword(password)]);
await closeDB();
console.log('Admin account admin/dpk created or reset.');
