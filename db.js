'use strict';

// Postgres access. Render hands the connection string over in DATABASE_URL.

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === '0' ? false : { rejectUnauthorized: false },
  max: 5,
});

async function query(text, params) {
  return pool.query(text, params);
}

async function one(text, params) {
  const res = await pool.query(text, params);
  return res.rows[0] || null;
}

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          BIGSERIAL PRIMARY KEY,
      username    TEXT UNIQUE NOT NULL,
      pass_hash   TEXT NOT NULL,
      role        TEXT NOT NULL DEFAULT 'owner',
      disabled    BOOLEAN NOT NULL DEFAULT FALSE,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS keys (
      id          BIGSERIAL PRIMARY KEY,
      code        TEXT UNIQUE NOT NULL,
      days        INTEGER NOT NULL DEFAULT 30,
      note        TEXT,
      active      BOOLEAN NOT NULL DEFAULT TRUE,
      banned      BOOLEAN NOT NULL DEFAULT FALSE,
      ban_reason  TEXT,
      banned_at   TIMESTAMPTZ,
      hwid        TEXT,
      hw_info     JSONB,
      first_ip    TEXT,
      last_ip     TEXT,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      first_seen  TIMESTAMPTZ,
      last_seen   TIMESTAMPTZ
    );

    -- one row per machine that ever used a key; the dashboard reads these
    CREATE TABLE IF NOT EXISTS devices (
      id          BIGSERIAL PRIMARY KEY,
      key_id      BIGINT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
      hwid        TEXT NOT NULL,
      hw_info     JSONB,
      ip          TEXT,
      first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE (key_id, hwid)
    );

    CREATE INDEX IF NOT EXISTS devices_key_idx ON devices(key_id);
    CREATE INDEX IF NOT EXISTS devices_seen_idx ON devices(last_seen DESC);

    -- pushed offset tables: the client compares its version against the newest
    CREATE TABLE IF NOT EXISTS updates (
      id          BIGSERIAL PRIMARY KEY,
      version     INTEGER NOT NULL,
      payload     TEXT NOT NULL,
      sha         TEXT NOT NULL,
      note        TEXT,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

module.exports = { pool, query, one, migrate };
