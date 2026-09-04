import pg from 'pg';
import { fileURLToPath } from 'node:url';

const { Pool, types } = pg;

// Keep date-only and bigint values compatible with the application's existing JSON API.
types.setTypeParser(1082, value => value);
types.setTypeParser(20, value => Number(value));

let pool;

function connectionString() {
  const value = process.env.DATABASE_URL;
  if (!value) throw new Error('DATABASE_URL is required (use the Supabase pooled connection string)');
  if (process.env.DATABASE_SSL === 'false') return value;

  // URL SSL settings override Pool.ssl, so keep the trusted CA in the URL too.
  const url = new URL(value);
  url.searchParams.set('sslmode', 'verify-full');
  url.searchParams.set('sslrootcert', fileURLToPath(new URL('./certs/supabase-root.crt', import.meta.url)));
  return url.toString();
}

function postgresSql(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

function createDatabase(executor) {
  return {
    async all(sql, params = []) {
      return (await executor.query(postgresSql(sql), params)).rows;
    },
    async one(sql, params = []) {
      return (await executor.query(postgresSql(sql), params)).rows[0] || null;
    },
    async exists(sql, params = []) {
      return (await executor.query(postgresSql(sql), params)).rowCount > 0;
    },
    async run(sql, params = []) {
      return executor.query(postgresSql(sql), params);
    }
  };
}

export function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: connectionString(),
      max: Number(process.env.DATABASE_POOL_SIZE || 1),
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 10_000,
      ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: true }
    });
    pool.on('error', error => console.error('Unexpected PostgreSQL pool error:', error));
  }
  return pool;
}

export function getDB() {
  return createDatabase(getPool());
}

export async function initDB() {
  await getPool().query('SELECT 1');
  return getDB();
}

export async function transaction(callback) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const result = await callback(createDatabase(client));
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function closeDB() {
  if (pool) await pool.end();
  pool = undefined;
}
