/**
 * Create or upgrade a local admin user (run against your Postgres).
 *
 * Usage (from backend/):
 *   copy .env.example .env
 *   set ADMIN_EMAIL=admin@local.test
 *   set ADMIN_PASSWORD=your-long-password
 *   npm run seed:admin
 *
 * Or: dotenv already loads .env — put ADMIN_EMAIL / ADMIN_PASSWORD there.
 */
import 'dotenv/config';
import bcrypt from 'bcrypt';
import pg from 'pg';

const BCRYPT_ROUNDS = 12;
const email = String(process.env.ADMIN_EMAIL || '')
  .trim()
  .toLowerCase();
const password = String(process.env.ADMIN_PASSWORD || '');
const name = String(process.env.ADMIN_NAME || 'Admin').trim() || 'Admin';

if (!email || !password || password.length < 8) {
  console.error(
    'Set ADMIN_EMAIL and ADMIN_PASSWORD (min 8 characters) in backend/.env or the environment.'
  );
  process.exit(1);
}

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('DATABASE_URL is required.');
  process.exit(1);
}

const pool = new pg.Pool({ connectionString });

try {
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const { rows } = await pool.query(
    `INSERT INTO users (email, password_hash, name, role)
     VALUES ($1, $2, $3, 'admin')
     ON CONFLICT (email) DO UPDATE SET
       password_hash = EXCLUDED.password_hash,
       role = 'admin',
       name = COALESCE(NULLIF(EXCLUDED.name, ''), users.name),
       updated_at = NOW()
     RETURNING id, email, role`,
    [email, hash, name]
  );
  console.log('Admin user ready:', { id: rows[0].id, email: rows[0].email, role: rows[0].role });
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
} finally {
  await pool.end();
}
