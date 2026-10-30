// PostgreSQL connection pool (configured through DATABASE_URL in .env)
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.on('error', (err) => console.error('Unexpected PostgreSQL error:', err.message));

module.exports = pool;
