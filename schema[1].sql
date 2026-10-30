-- =====================================================================
-- Emergency Response Portal - PostgreSQL schema
-- Run:  psql -U postgres -d emergency_portal -f database/schema.sql
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid(), crypt() for seed data

-- Clean re-run (development only)
DROP TABLE IF EXISTS audit_logs        CASCADE;
DROP TABLE IF EXISTS alerts            CASCADE;
DROP TABLE IF EXISTS emergency_contacts CASCADE;
DROP TABLE IF EXISTS assignments       CASCADE;
DROP TABLE IF EXISTS incident_updates  CASCADE;
DROP TABLE IF EXISTS incidents         CASCADE;
DROP TABLE IF EXISTS responders        CASCADE;
DROP TABLE IF EXISTS users             CASCADE;

-- ---------------------------------------------------------------------
-- Shared trigger: keep updated_at fresh
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------
CREATE TABLE users (
  id             SERIAL PRIMARY KEY,
  name           VARCHAR(100) NOT NULL,
  email          VARCHAR(255) NOT NULL UNIQUE,
  phone          VARCHAR(20),
  password_hash  VARCHAR(255) NOT NULL,
  role           VARCHAR(20)  NOT NULL DEFAULT 'citizen'
                 CHECK (role IN ('citizen', 'responder', 'dispatcher', 'admin')),
  is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_role ON users(role);

-- ---------------------------------------------------------------------
-- responders (1:1 extension of users with role = 'responder')
-- ---------------------------------------------------------------------
CREATE TABLE responders (
  id             SERIAL PRIMARY KEY,
  user_id        INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  department     VARCHAR(20) NOT NULL
                 CHECK (department IN ('police', 'fire', 'ambulance', 'disaster', 'other')),
  vehicle_info   VARCHAR(100),
  is_available   BOOLEAN NOT NULL DEFAULT TRUE,
  current_lat    NUMERIC(9,6) CHECK (current_lat BETWEEN -90  AND 90),
  current_lng    NUMERIC(9,6) CHECK (current_lng BETWEEN -180 AND 180)
);
CREATE INDEX idx_responders_available ON responders(is_available, department);

-- ---------------------------------------------------------------------
-- incidents
-- tracking_code is a hard-to-guess public code so anonymous reporters
-- can track an incident without exposing sequential IDs.
-- ---------------------------------------------------------------------
CREATE TABLE incidents (
  id             SERIAL PRIMARY KEY,
  tracking_code  VARCHAR(12) NOT NULL UNIQUE
                 DEFAULT upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10)),
  reporter_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,   -- NULL = anonymous
  reporter_phone VARCHAR(20),
  type           VARCHAR(20) NOT NULL
                 CHECK (type IN ('medical', 'fire', 'police', 'flood', 'accident', 'other')),
  description    TEXT NOT NULL CHECK (char_length(description) BETWEEN 5 AND 2000),
  severity       VARCHAR(10) NOT NULL DEFAULT 'medium'
                 CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  status         VARCHAR(20) NOT NULL DEFAULT 'reported'
                 CHECK (status IN ('reported', 'acknowledged', 'dispatched',
                                   'in_progress', 'resolved', 'cancelled')),
  latitude       NUMERIC(9,6) CHECK (latitude  BETWEEN -90  AND 90),
  longitude      NUMERIC(9,6) CHECK (longitude BETWEEN -180 AND 180),
  address        VARCHAR(255),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- need either coordinates or an address so help can actually be sent
  CONSTRAINT chk_location CHECK (
    (latitude IS NOT NULL AND longitude IS NOT NULL) OR address IS NOT NULL
  )
);
CREATE INDEX idx_incidents_status     ON incidents(status);
CREATE INDEX idx_incidents_type       ON incidents(type);
CREATE INDEX idx_incidents_severity   ON incidents(severity);
CREATE INDEX idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX idx_incidents_reporter   ON incidents(reporter_id);

CREATE TRIGGER trg_incidents_updated_at
  BEFORE UPDATE ON incidents
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- incident_updates (status timeline)
-- ---------------------------------------------------------------------
CREATE TABLE incident_updates (
  id           SERIAL PRIMARY KEY,
  incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  updated_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  status       VARCHAR(20) NOT NULL
               CHECK (status IN ('reported', 'acknowledged', 'dispatched',
                                 'in_progress', 'resolved', 'cancelled')),
  note         TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_incident_updates_incident ON incident_updates(incident_id, created_at);

-- ---------------------------------------------------------------------
-- assignments
-- ---------------------------------------------------------------------
CREATE TABLE assignments (
  id            SERIAL PRIMARY KEY,
  incident_id   INTEGER NOT NULL REFERENCES incidents(id)  ON DELETE CASCADE,
  responder_id  INTEGER NOT NULL REFERENCES responders(id) ON DELETE RESTRICT,
  assigned_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  assigned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  arrived_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  UNIQUE (incident_id, responder_id),
  CHECK (arrived_at   IS NULL OR arrived_at   >= assigned_at),
  CHECK (completed_at IS NULL OR completed_at >= assigned_at)
);
CREATE INDEX idx_assignments_responder ON assignments(responder_id);
CREATE INDEX idx_assignments_incident  ON assignments(incident_id);

-- ---------------------------------------------------------------------
-- emergency_contacts
-- ---------------------------------------------------------------------
CREATE TABLE emergency_contacts (
  id            SERIAL PRIMARY KEY,
  name          VARCHAR(100) NOT NULL,
  service_type  VARCHAR(30)  NOT NULL,
  phone         VARCHAR(20)  NOT NULL,
  city          VARCHAR(100),                -- NULL = nationwide
  is_active     BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX idx_contacts_active ON emergency_contacts(is_active, service_type);

-- ---------------------------------------------------------------------
-- alerts (public announcements)
-- ---------------------------------------------------------------------
CREATE TABLE alerts (
  id          SERIAL PRIMARY KEY,
  title       VARCHAR(150) NOT NULL,
  message     TEXT NOT NULL,
  level       VARCHAR(10) NOT NULL DEFAULT 'info'
              CHECK (level IN ('info', 'warning', 'danger')),
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ,
  CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX idx_alerts_expiry ON alerts(expires_at);

-- ---------------------------------------------------------------------
-- audit_logs (admin / dispatcher actions)
-- ---------------------------------------------------------------------
CREATE TABLE audit_logs (
  id           BIGSERIAL PRIMARY KEY,
  user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action       VARCHAR(50)  NOT NULL,        -- e.g. 'incident.assign', 'user.deactivate'
  entity_type  VARCHAR(50),
  entity_id    INTEGER,
  details      JSONB,
  ip_address   INET,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_user    ON audit_logs(user_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);
