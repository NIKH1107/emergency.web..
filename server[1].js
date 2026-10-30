'use strict';
/**
 * Emergency Response Portal - backend
 * Express REST API + serves ../frontend/index.html
 * Security: helmet, rate limiting, JWT, bcrypt, parameterized SQL only.
 */
require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error('Set JWT_SECRET (16+ characters) in backend/.env');
  process.exit(1);
}
const PORT = process.env.PORT || 3000;

const TYPES = ['medical', 'fire', 'police', 'flood', 'accident', 'other'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const STATUSES = ['reported', 'acknowledged', 'dispatched', 'in_progress', 'resolved', 'cancelled'];
const CLOSED = ['resolved', 'cancelled'];
const ROLES = ['citizen', 'responder', 'dispatcher', 'admin'];
const DEPARTMENTS = ['police', 'fire', 'ambulance', 'disaster', 'other'];
const LEVELS = ['info', 'warning', 'danger'];

// ---------------------------------------------------------------- helpers
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const httpError = (status, message) => Object.assign(new Error(message), { status, expose: true });
// strip control characters, trim, cap length
const clean = (v, max) =>
  String(v ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max);
const toId = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : null; };
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 255;
const validPhone = (p) => /^[0-9+\-\s()]{5,20}$/.test(p);
const validPassword = (p) =>
  typeof p === 'string' && p.length >= 8 && p.length <= 72 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p);
const PASSWORD_RULE = 'Password must be 8-72 characters with an uppercase letter, a lowercase letter and a number';
const signToken = (u) => jwt.sign({ id: u.id, role: u.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h' });
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

async function tx(fn) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await fn(c);
    await c.query('COMMIT');
    return r;
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

const audit = (req, action, entityType, entityId, details, db = pool) =>
  db.query(
    'INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address) VALUES ($1,$2,$3,$4,$5,$6)',
    [req.user ? req.user.id : null, action, entityType, entityId, details ? JSON.stringify(details) : null, req.ip]
  );

// Authentication: verifies the JWT and re-checks the user in the DB so that
// deactivated users / role changes take effect immediately.
const auth = (required = true) =>
  ah(async (req, res, next) => {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (token) {
      try {
        const p = jwt.verify(token, JWT_SECRET);
        const { rows } = await pool.query('SELECT id, name, role, is_active FROM users WHERE id = $1', [p.id]);
        if (rows[0] && rows[0].is_active) req.user = rows[0];
      } catch { /* invalid or expired token -> treated as not logged in */ }
    }
    if (required && !req.user) throw httpError(401, 'Please log in');
    next();
  });

const allow = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : next(httpError(403, 'You do not have permission'));

// ------------------------------------------------------------------- app
const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // inline <script>/<style> are used by the single-file frontend; Leaflet comes from unpkg
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
        imgSrc: ["'self'", 'data:', 'https://tile.openstreetmap.org', 'https://unpkg.com'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: null, // allow plain http://localhost during development
      },
    },
  })
);
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map((s) => s.trim()) : false }));
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const limiter = (windowMin, max, message) =>
  rateLimit({ windowMs: windowMin * 60 * 1000, max, standardHeaders: true, legacyHeaders: false, message: { error: message } });
app.use('/api', limiter(15, 600, 'Too many requests, please slow down'));
const authLimiter = limiter(15, 30, 'Too many login attempts, try again later');
const reportLimiter = limiter(15, 15, 'Too many reports from this device, please call the emergency number');

// ------------------------------------------------------------------ auth
app.post('/api/auth/register', authLimiter, ah(async (req, res) => {
  const name = clean(req.body.name, 100);
  const email = clean(req.body.email, 255).toLowerCase();
  const phone = clean(req.body.phone, 20) || null;
  if (name.length < 2) throw httpError(400, 'Name is required');
  if (!validEmail(email)) throw httpError(400, 'A valid email is required');
  if (phone && !validPhone(phone)) throw httpError(400, 'Invalid phone number');
  if (!validPassword(req.body.password)) throw httpError(400, PASSWORD_RULE);
  const hash = await bcrypt.hash(req.body.password, 10);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash, role) VALUES ($1,$2,$3,$4,'citizen')
       RETURNING id, name, email, role`, [name, email, phone, hash]);
    res.status(201).json({ token: signToken(rows[0]), user: publicUser(rows[0]) });
  } catch (e) {
    if (e.code === '23505') throw httpError(409, 'Email already registered');
    throw e;
  }
}));

app.post('/api/auth/login', authLimiter, ah(async (req, res) => {
  const email = clean(req.body.email, 255).toLowerCase();
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const u = rows[0];
  const ok = u && u.is_active && (await bcrypt.compare(String(req.body.password || ''), u.password_hash));
  if (!ok) throw httpError(401, 'Incorrect email or password');
  res.json({ token: signToken(u), user: publicUser(u) });
}));

app.get('/api/auth/me', auth(), ah(async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, email, phone, role, created_at FROM users WHERE id = $1', [req.user.id]);
  res.json(rows[0]);
}));

// ------------------------------------------------------------- incidents
// Create (anonymous allowed; if logged in the report is linked to the user)
app.post('/api/incidents', reportLimiter, auth(false), ah(async (req, res) => {
  const { type, severity = 'medium' } = req.body;
  const description = clean(req.body.description, 2000);
  const address = clean(req.body.address, 255) || null;
  const phone = clean(req.body.phone, 20) || null;
  if (!TYPES.includes(type)) throw httpError(400, 'Invalid emergency type');
  if (!SEVERITIES.includes(severity)) throw httpError(400, 'Invalid severity');
  if (description.length < 5) throw httpError(400, 'Please describe the emergency (at least 5 characters)');
  if (phone && !validPhone(phone)) throw httpError(400, 'Invalid phone number');

  let { latitude, longitude } = req.body;
  const hasCoords = latitude !== undefined && latitude !== null && latitude !== '' &&
                    longitude !== undefined && longitude !== null && longitude !== '';
  if (hasCoords) {
    latitude = Number(latitude); longitude = Number(longitude);
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude) ||
        Math.abs(latitude) > 90 || Math.abs(longitude) > 180) throw httpError(400, 'Invalid coordinates');
  } else { latitude = null; longitude = null; }
  if (!hasCoords && !address) throw httpError(400, 'Share your location or type an address');

  const row = await tx(async (c) => {
    const r = await c.query(
      `INSERT INTO incidents (reporter_id, reporter_phone, type, description, severity, latitude, longitude, address)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, tracking_code, status, created_at`,
      [req.user ? req.user.id : null, phone, type, description, severity, latitude, longitude, address]);
    await c.query(`INSERT INTO incident_updates (incident_id, updated_by, status, note) VALUES ($1,$2,'reported','Incident reported')`,
      [r.rows[0].id, req.user ? req.user.id : null]);
    return r.rows[0];
  });
  res.status(201).json({ tracking_code: row.tracking_code, status: row.status, created_at: row.created_at });
}));

// Logged-in user's own reports
app.get('/api/incidents/mine', auth(), ah(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, tracking_code, type, severity, status, address, created_at FROM incidents
     WHERE reporter_id = $1 ORDER BY created_at DESC LIMIT 50`, [req.user.id]);
  res.json(rows);
}));

// Public tracking by tracking code (limited fields, no personal data)
app.get('/api/incidents/track/:code', ah(async (req, res) => {
  const code = clean(req.params.code, 12).toUpperCase();
  const inc = await pool.query(
    'SELECT id, tracking_code, type, severity, status, address, created_at, updated_at FROM incidents WHERE tracking_code = $1', [code]);
  if (!inc.rowCount) throw httpError(404, 'No incident found with that tracking code');
  const timeline = await pool.query(
    'SELECT status, created_at FROM incident_updates WHERE incident_id = $1 ORDER BY created_at, id', [inc.rows[0].id]);
  const { id, ...incident } = inc.rows[0];
  res.json({ ...incident, timeline: timeline.rows });
}));

// Staff list with filters
app.get('/api/incidents', auth(), allow('dispatcher', 'admin'), ah(async (req, res) => {
  const where = []; const params = [];
  for (const [key, list] of [['status', STATUSES], ['type', TYPES], ['severity', SEVERITIES]]) {
    const v = req.query[key];
    if (v) {
      if (!list.includes(v)) throw httpError(400, `Invalid ${key} filter`);
      params.push(v); where.push(`i.${key} = $${params.length}`);
    }
  }
  const { rows } = await pool.query(
    `SELECT i.*,
            COALESCE(json_agg(json_build_object('responder_id', r.id, 'name', u.name, 'department', r.department))
                     FILTER (WHERE r.id IS NOT NULL), '[]') AS responders
       FROM incidents i
       LEFT JOIN assignments a ON a.incident_id = i.id
       LEFT JOIN responders r ON r.id = a.responder_id
       LEFT JOIN users u ON u.id = r.user_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      GROUP BY i.id ORDER BY i.created_at DESC LIMIT 200`, params);
  res.json(rows);
}));

// Single incident (staff, or the responder it is assigned to)
app.get('/api/incidents/:id', auth(), allow('dispatcher', 'admin', 'responder'), ah(async (req, res) => {
  const id = toId(req.params.id);
  if (!id) throw httpError(400, 'Invalid incident id');
  const inc = await pool.query('SELECT * FROM incidents WHERE id = $1', [id]);
  if (!inc.rowCount) throw httpError(404, 'Incident not found');
  if (req.user.role === 'responder') {
    const own = await pool.query(
      'SELECT 1 FROM assignments a JOIN responders r ON r.id = a.responder_id WHERE a.incident_id = $1 AND r.user_id = $2', [id, req.user.id]);
    if (!own.rowCount) throw httpError(403, 'This incident is not assigned to you');
  }
  const [updates, assignments] = await Promise.all([
    pool.query(`SELECT iu.status, iu.note, iu.created_at, u.name AS updated_by_name FROM incident_updates iu
                LEFT JOIN users u ON u.id = iu.updated_by WHERE iu.incident_id = $1 ORDER BY iu.created_at, iu.id`, [id]),
    pool.query(`SELECT a.id, a.assigned_at, a.arrived_at, a.completed_at, r.id AS responder_id, r.department, u.name
                FROM assignments a JOIN responders r ON r.id = a.responder_id JOIN users u ON u.id = r.user_id
                WHERE a.incident_id = $1 ORDER BY a.assigned_at`, [id]),
  ]);
  res.json({ ...inc.rows[0], updates: updates.rows, assignments: assignments.rows });
}));

// Update status (dispatcher/admin: any; responder: only own assignment, in_progress/resolved)
app.patch('/api/incidents/:id/status', auth(), allow('dispatcher', 'admin', 'responder'), ah(async (req, res) => {
  const id = toId(req.params.id);
  const { status } = req.body;
  const note = clean(req.body.note, 500) || null;
  if (!id) throw httpError(400, 'Invalid incident id');
  if (!STATUSES.includes(status)) throw httpError(400, 'Invalid status');
  const isResp = req.user.role === 'responder';
  if (isResp && !['in_progress', 'resolved'].includes(status)) throw httpError(403, 'Responders can only set in progress or resolved');

  const result = await tx(async (c) => {
    const cur = (await c.query('SELECT status FROM incidents WHERE id = $1 FOR UPDATE', [id])).rows[0];
    if (!cur) throw httpError(404, 'Incident not found');
    if (isResp) {
      const own = await c.query(
        'SELECT 1 FROM assignments a JOIN responders r ON r.id = a.responder_id WHERE a.incident_id = $1 AND r.user_id = $2', [id, req.user.id]);
      if (!own.rowCount) throw httpError(403, 'This incident is not assigned to you');
    }
    if (CLOSED.includes(cur.status) && cur.status !== status) throw httpError(409, 'This incident is already closed');

    const upd = await c.query('UPDATE incidents SET status = $1 WHERE id = $2 RETURNING id, status, updated_at', [status, id]);
    await c.query('INSERT INTO incident_updates (incident_id, updated_by, status, note) VALUES ($1,$2,$3,$4)', [id, req.user.id, status, note]);

    if (status === 'in_progress' && isResp) {
      await c.query(
        `UPDATE assignments a SET arrived_at = COALESCE(a.arrived_at, NOW()) FROM responders r
          WHERE r.id = a.responder_id AND a.incident_id = $1 AND r.user_id = $2`, [id, req.user.id]);
    }
    if (CLOSED.includes(status)) {
      await c.query('UPDATE assignments SET completed_at = COALESCE(completed_at, NOW()) WHERE incident_id = $1', [id]);
      // free responders that have no other open assignment
      await c.query(
        `UPDATE responders r SET is_available = TRUE
          WHERE r.id IN (SELECT responder_id FROM assignments WHERE incident_id = $1)
            AND NOT EXISTS (SELECT 1 FROM assignments a2 WHERE a2.responder_id = r.id AND a2.completed_at IS NULL)`, [id]);
    }
    if (!isResp) await audit(req, 'incident.status', 'incident', id, { from: cur.status, to: status }, c);
    return upd.rows[0];
  });
  res.json(result);
}));

// Assign a responder (dispatcher/admin)
app.post('/api/incidents/:id/assign', auth(), allow('dispatcher', 'admin'), ah(async (req, res) => {
  const id = toId(req.params.id);
  const responderId = toId(req.body.responder_id);
  if (!id || !responderId) throw httpError(400, 'incident id and responder_id are required');

  const result = await tx(async (c) => {
    const inc = (await c.query('SELECT status FROM incidents WHERE id = $1 FOR UPDATE', [id])).rows[0];
    if (!inc) throw httpError(404, 'Incident not found');
    if (CLOSED.includes(inc.status)) throw httpError(409, 'This incident is already closed');
    const resp = (await c.query(
      `SELECT r.id, r.is_available, u.name FROM responders r JOIN users u ON u.id = r.user_id
        WHERE r.id = $1 AND u.is_active FOR UPDATE OF r`, [responderId])).rows[0];
    if (!resp) throw httpError(404, 'Responder not found');
    if (!resp.is_available) throw httpError(409, `${resp.name} is not available`);

    const ins = await c.query(
      'INSERT INTO assignments (incident_id, responder_id, assigned_by) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id',
      [id, responderId, req.user.id]);
    if (!ins.rowCount) throw httpError(409, 'Responder is already assigned to this incident');
    await c.query('UPDATE responders SET is_available = FALSE WHERE id = $1', [responderId]);
    if (['reported', 'acknowledged'].includes(inc.status)) {
      await c.query(`UPDATE incidents SET status = 'dispatched' WHERE id = $1`, [id]);
    }
    await c.query(`INSERT INTO incident_updates (incident_id, updated_by, status, note)
                   VALUES ($1,$2,(SELECT status FROM incidents WHERE id = $1),$3)`, [id, req.user.id, `Assigned to ${resp.name}`]);
    await audit(req, 'incident.assign', 'incident', id, { responder_id: responderId }, c);
    return { assignment_id: ins.rows[0].id, incident_id: id, responder_id: responderId };
  });
  res.status(201).json(result);
}));

// ------------------------------------------------------------ responders
app.get('/api/responders', auth(), allow('dispatcher', 'admin'), ah(async (req, res) => {
  const where = ['u.is_active']; const params = [];
  if (req.query.available === 'true') where.push('r.is_available');
  if (req.query.department) {
    if (!DEPARTMENTS.includes(req.query.department)) throw httpError(400, 'Invalid department');
    params.push(req.query.department); where.push(`r.department = $${params.length}`);
  }
  const { rows } = await pool.query(
    `SELECT r.id, u.name, u.phone, r.department, r.vehicle_info, r.is_available, r.current_lat, r.current_lng
       FROM responders r JOIN users u ON u.id = r.user_id WHERE ${where.join(' AND ')} ORDER BY r.department, u.name`, params);
  res.json(rows);
}));

app.get('/api/responders/me', auth(), allow('responder'), ah(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, department, vehicle_info, is_available FROM responders WHERE user_id = $1', [req.user.id]);
  if (!rows[0]) throw httpError(404, 'No responder profile for this account');
  res.json(rows[0]);
}));

app.get('/api/responders/me/assignments', auth(), allow('responder'), ah(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT a.id AS assignment_id, a.assigned_at, a.arrived_at, a.completed_at,
            i.id, i.tracking_code, i.type, i.description, i.severity, i.status,
            i.latitude, i.longitude, i.address, i.reporter_phone, i.created_at
       FROM assignments a JOIN responders r ON r.id = a.responder_id JOIN incidents i ON i.id = a.incident_id
      WHERE r.user_id = $1 ORDER BY (a.completed_at IS NOT NULL), a.assigned_at DESC LIMIT 100`, [req.user.id]);
  res.json(rows);
}));

app.patch('/api/responders/:id/availability', auth(), allow('responder', 'dispatcher', 'admin'), ah(async (req, res) => {
  const id = toId(req.params.id);
  if (!id) throw httpError(400, 'Invalid responder id');
  if (typeof req.body.is_available !== 'boolean') throw httpError(400, 'is_available must be true or false');
  const params = [req.body.is_available, id];
  let sql = 'UPDATE responders SET is_available = $1 WHERE id = $2';
  if (req.user.role === 'responder') { params.push(req.user.id); sql += ' AND user_id = $3'; } // only your own record
  const r = await pool.query(sql + ' RETURNING id, is_available', params);
  if (!r.rowCount) throw httpError(404, 'Responder not found');
  res.json(r.rows[0]);
}));

// ---------------------------------------------------------------- alerts
app.get('/api/alerts', ah(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, title, message, level, created_at, expires_at FROM alerts WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY created_at DESC LIMIT 10');
  res.json(rows);
}));

app.post('/api/alerts', auth(), allow('admin'), ah(async (req, res) => {
  const title = clean(req.body.title, 150);
  const message = clean(req.body.message, 1000);
  const level = req.body.level || 'info';
  const hours = req.body.expires_in_hours === undefined || req.body.expires_in_hours === '' ? null : Number(req.body.expires_in_hours);
  if (!title || !message) throw httpError(400, 'Title and message are required');
  if (!LEVELS.includes(level)) throw httpError(400, 'Invalid level');
  if (hours !== null && (!Number.isInteger(hours) || hours < 1 || hours > 24 * 30)) throw httpError(400, 'Expiry must be 1-720 hours');
  const { rows } = await pool.query(
    `INSERT INTO alerts (title, message, level, created_by, expires_at)
     VALUES ($1,$2,$3,$4, CASE WHEN $5::int IS NULL THEN NULL ELSE NOW() + make_interval(hours => $5::int) END)
     RETURNING id, title, message, level, created_at, expires_at`, [title, message, level, req.user.id, hours]);
  await audit(req, 'alert.create', 'alert', rows[0].id, { title });
  res.status(201).json(rows[0]);
}));

app.delete('/api/alerts/:id', auth(), allow('admin'), ah(async (req, res) => {
  const id = toId(req.params.id);
  if (!id) throw httpError(400, 'Invalid alert id');
  const r = await pool.query('DELETE FROM alerts WHERE id = $1', [id]);
  if (!r.rowCount) throw httpError(404, 'Alert not found');
  await audit(req, 'alert.delete', 'alert', id);
  res.status(204).end();
}));

// -------------------------------------------------------------- contacts
app.get('/api/contacts', ah(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, name, service_type, phone, city FROM emergency_contacts WHERE is_active ORDER BY id');
  res.json(rows);
}));

app.get('/api/contacts/all', auth(), allow('admin'), ah(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM emergency_contacts ORDER BY id');
  res.json(rows);
}));

app.post('/api/contacts', auth(), allow('admin'), ah(async (req, res) => {
  const name = clean(req.body.name, 100), service_type = clean(req.body.service_type, 30);
  const phone = clean(req.body.phone, 20), city = clean(req.body.city, 100) || null;
  if (!name || !service_type) throw httpError(400, 'Name and service type are required');
  if (!validPhone(phone)) throw httpError(400, 'A valid phone number is required');
  const { rows } = await pool.query(
    'INSERT INTO emergency_contacts (name, service_type, phone, city) VALUES ($1,$2,$3,$4) RETURNING *', [name, service_type, phone, city]);
  await audit(req, 'contact.create', 'contact', rows[0].id, { name });
  res.status(201).json(rows[0]);
}));

app.put('/api/contacts/:id', auth(), allow('admin'), ah(async (req, res) => {
  const id = toId(req.params.id);
  if (!id) throw httpError(400, 'Invalid contact id');
  const b = req.body;
  const phone = b.phone === undefined ? null : clean(b.phone, 20);
  if (phone !== null && !validPhone(phone)) throw httpError(400, 'Invalid phone number');
  const { rows } = await pool.query(
    `UPDATE emergency_contacts SET name = COALESCE($1, name), service_type = COALESCE($2, service_type),
            phone = COALESCE($3, phone), city = COALESCE($4, city), is_active = COALESCE($5, is_active)
      WHERE id = $6 RETURNING *`,
    [b.name === undefined ? null : clean(b.name, 100), b.service_type === undefined ? null : clean(b.service_type, 30),
     phone, b.city === undefined ? null : clean(b.city, 100), typeof b.is_active === 'boolean' ? b.is_active : null, id]);
  if (!rows[0]) throw httpError(404, 'Contact not found');
  await audit(req, 'contact.update', 'contact', id, b);
  res.json(rows[0]);
}));

app.delete('/api/contacts/:id', auth(), allow('admin'), ah(async (req, res) => {
  const id = toId(req.params.id);
  if (!id) throw httpError(400, 'Invalid contact id');
  const r = await pool.query('DELETE FROM emergency_contacts WHERE id = $1', [id]);
  if (!r.rowCount) throw httpError(404, 'Contact not found');
  await audit(req, 'contact.delete', 'contact', id);
  res.status(204).end();
}));

// ----------------------------------------------------------------- admin
app.get('/api/admin/stats', auth(), allow('dispatcher', 'admin'), ah(async (req, res) => {
  const [st, ty, sev, resp] = await Promise.all([
    pool.query('SELECT status, COUNT(*)::int AS n FROM incidents GROUP BY status'),
    pool.query('SELECT type, COUNT(*)::int AS n FROM incidents GROUP BY type'),
    pool.query(`SELECT severity, COUNT(*)::int AS n FROM incidents WHERE status NOT IN ('resolved','cancelled') GROUP BY severity`),
    pool.query(`SELECT ROUND(AVG(EXTRACT(EPOCH FROM (a.first_assigned - i.created_at)) / 60)::numeric, 1) AS avg_min
                  FROM incidents i JOIN (SELECT incident_id, MIN(assigned_at) AS first_assigned FROM assignments GROUP BY incident_id) a
                    ON a.incident_id = i.id`),
  ]);
  const by_status = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  const by_type = Object.fromEntries(TYPES.map((t) => [t, 0]));
  const open_by_severity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  st.rows.forEach((r) => (by_status[r.status] = r.n));
  ty.rows.forEach((r) => (by_type[r.type] = r.n));
  sev.rows.forEach((r) => (open_by_severity[r.severity] = r.n));
  res.json({
    total: Object.values(by_status).reduce((a, b) => a + b, 0),
    open: Object.entries(by_status).filter(([s]) => !CLOSED.includes(s)).reduce((a, [, n]) => a + n, 0),
    by_status, by_type, open_by_severity,
    avg_response_minutes: resp.rows[0].avg_min === null ? null : Number(resp.rows[0].avg_min),
  });
}));

app.get('/api/admin/users', auth(), allow('admin'), ah(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.name, u.email, u.phone, u.role, u.is_active, u.created_at, r.department
       FROM users u LEFT JOIN responders r ON r.user_id = u.id ORDER BY u.id`);
  res.json(rows);
}));

app.post('/api/admin/users', auth(), allow('admin'), ah(async (req, res) => {
  const name = clean(req.body.name, 100);
  const email = clean(req.body.email, 255).toLowerCase();
  const phone = clean(req.body.phone, 20) || null;
  const role = req.body.role;
  const department = req.body.department;
  const vehicle = clean(req.body.vehicle_info, 100) || null;
  if (name.length < 2) throw httpError(400, 'Name is required');
  if (!validEmail(email)) throw httpError(400, 'A valid email is required');
  if (phone && !validPhone(phone)) throw httpError(400, 'Invalid phone number');
  if (!ROLES.includes(role)) throw httpError(400, 'Invalid role');
  if (role === 'responder' && !DEPARTMENTS.includes(department)) throw httpError(400, 'Responders need a valid department');
  if (!validPassword(req.body.password)) throw httpError(400, PASSWORD_RULE);
  const hash = await bcrypt.hash(req.body.password, 10);
  try {
    const user = await tx(async (c) => {
      const u = (await c.query(
        'INSERT INTO users (name, email, phone, password_hash, role) VALUES ($1,$2,$3,$4,$5) RETURNING id, name, email, role',
        [name, email, phone, hash, role])).rows[0];
      if (role === 'responder') {
        await c.query('INSERT INTO responders (user_id, department, vehicle_info) VALUES ($1,$2,$3)', [u.id, department, vehicle]);
      }
      await audit(req, 'user.create', 'user', u.id, { role }, c);
      return u;
    });
    res.status(201).json(user);
  } catch (e) {
    if (e.code === '23505') throw httpError(409, 'Email already registered');
    throw e;
  }
}));

app.patch('/api/admin/users/:id', auth(), allow('admin'), ah(async (req, res) => {
  const id = toId(req.params.id);
  if (!id) throw httpError(400, 'Invalid user id');
  if (typeof req.body.is_active !== 'boolean') throw httpError(400, 'is_active must be true or false');
  if (id === req.user.id && !req.body.is_active) throw httpError(400, 'You cannot deactivate your own account');
  const r = await pool.query('UPDATE users SET is_active = $1 WHERE id = $2 RETURNING id, is_active', [req.body.is_active, id]);
  if (!r.rowCount) throw httpError(404, 'User not found');
  await audit(req, req.body.is_active ? 'user.activate' : 'user.deactivate', 'user', id);
  res.json(r.rows[0]);
}));

// ------------------------------------------------------ fallbacks / errors
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON body' });
  if (err.status && err.expose) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

app.listen(PORT, () => console.log(`Emergency portal running at http://localhost:${PORT}`));
