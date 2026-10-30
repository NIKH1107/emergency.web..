-- =====================================================================
-- Seed data (DEVELOPMENT ONLY - change all passwords before real use)
-- Run after schema.sql:  psql -U postgres -d emergency_portal -f database/seed.sql
-- All test accounts use the password:  Password@123
-- (bcrypt hashes generated with pgcrypto; compatible with Node bcrypt/bcryptjs)
-- =====================================================================

INSERT INTO users (name, email, phone, password_hash, role) VALUES
  ('Site Admin',      'admin@portal.test',      '9000000001', crypt('Password@123', gen_salt('bf', 10)), 'admin'),
  ('Dispatcher One',  'dispatcher@portal.test', '9000000002', crypt('Password@123', gen_salt('bf', 10)), 'dispatcher'),
  ('Ravi Ambulance',  'ambulance@portal.test',  '9000000003', crypt('Password@123', gen_salt('bf', 10)), 'responder'),
  ('Sana Fire Team',  'fire@portal.test',       '9000000004', crypt('Password@123', gen_salt('bf', 10)), 'responder'),
  ('Imran Police',    'police@portal.test',     '9000000005', crypt('Password@123', gen_salt('bf', 10)), 'responder'),
  ('Asha Citizen',    'citizen@portal.test',    '9000000006', crypt('Password@123', gen_salt('bf', 10)), 'citizen');

INSERT INTO responders (user_id, department, vehicle_info, is_available, current_lat, current_lng)
SELECT id, 'ambulance', 'Ambulance UP32-AM-1001', TRUE, 26.850000, 80.949000 FROM users WHERE email = 'ambulance@portal.test';
INSERT INTO responders (user_id, department, vehicle_info, is_available, current_lat, current_lng)
SELECT id, 'fire', 'Fire Tender UP32-FT-2002', TRUE, 26.840000, 80.940000 FROM users WHERE email = 'fire@portal.test';
INSERT INTO responders (user_id, department, vehicle_info, is_available, current_lat, current_lng)
SELECT id, 'police', 'Patrol Car UP32-PC-3003', TRUE, 26.860000, 80.955000 FROM users WHERE email = 'police@portal.test';

-- Nationwide emergency numbers (India). Edit for your region.
INSERT INTO emergency_contacts (name, service_type, phone, city) VALUES
  ('National Emergency Number', 'general',   '112',  NULL),
  ('Police',                    'police',    '100',  NULL),
  ('Fire Brigade',              'fire',      '101',  NULL),
  ('Ambulance',                 'ambulance', '102',  NULL),
  ('Emergency Medical Service', 'medical',   '108',  NULL),
  ('Disaster Management',       'disaster',  '108',  NULL),
  ('Women Helpline',            'women',     '1091', NULL),
  ('Child Helpline',            'child',     '1098', NULL);

-- Sample incidents (Lucknow area)
INSERT INTO incidents (reporter_id, reporter_phone, type, description, severity, status, latitude, longitude, address, created_at)
VALUES
  ((SELECT id FROM users WHERE email='citizen@portal.test'), '9000000006', 'medical',
   'Elderly person collapsed near the bus stop, not responding.', 'critical', 'dispatched',
   26.846700, 80.946200, 'Hazratganj, Lucknow', NOW() - INTERVAL '25 minutes'),
  (NULL, NULL, 'fire',
   'Smoke coming from a shop on the ground floor of a market building.', 'high', 'reported',
   26.866000, 80.921000, 'Aminabad Market, Lucknow', NOW() - INTERVAL '8 minutes'),
  (NULL, '9111111111', 'accident',
   'Two-wheeler collision, rider has minor injuries.', 'medium', 'resolved',
   26.831000, 80.918000, 'Charbagh Road, Lucknow', NOW() - INTERVAL '3 hours');

INSERT INTO incident_updates (incident_id, updated_by, status, note, created_at)
VALUES
  (1, NULL, 'reported',   'Incident reported by citizen.',           NOW() - INTERVAL '25 minutes'),
  (1, (SELECT id FROM users WHERE email='dispatcher@portal.test'), 'dispatched',
      'Ambulance assigned.',                                          NOW() - INTERVAL '22 minutes'),
  (2, NULL, 'reported',   'Anonymous report received.',               NOW() - INTERVAL '8 minutes'),
  (3, NULL, 'reported',   'Incident reported.',                       NOW() - INTERVAL '3 hours'),
  (3, (SELECT id FROM users WHERE email='police@portal.test'), 'resolved',
      'Rider treated at scene, traffic cleared.',                     NOW() - INTERVAL '2 hours');

INSERT INTO assignments (incident_id, responder_id, assigned_by, assigned_at, arrived_at, completed_at)
VALUES
  (1, (SELECT r.id FROM responders r JOIN users u ON u.id = r.user_id WHERE u.email='ambulance@portal.test'),
      (SELECT id FROM users WHERE email='dispatcher@portal.test'),
      NOW() - INTERVAL '22 minutes', NULL, NULL),
  (3, (SELECT r.id FROM responders r JOIN users u ON u.id = r.user_id WHERE u.email='police@portal.test'),
      (SELECT id FROM users WHERE email='dispatcher@portal.test'),
      NOW() - INTERVAL '170 minutes', NOW() - INTERVAL '150 minutes', NOW() - INTERVAL '120 minutes');

UPDATE responders SET is_available = FALSE
WHERE user_id = (SELECT id FROM users WHERE email='ambulance@portal.test');

INSERT INTO alerts (title, message, level, created_by, expires_at)
VALUES ('Heavy rain expected',
        'Heavy rainfall expected tonight. Avoid low-lying areas and underpasses.',
        'warning',
        (SELECT id FROM users WHERE email='admin@portal.test'),
        NOW() + INTERVAL '2 days');

-- Fixed tracking codes for the sample incidents so you can try the "Track" page
UPDATE incidents SET tracking_code = 'DEMO000001' WHERE id = 1;
UPDATE incidents SET tracking_code = 'DEMO000002' WHERE id = 2;
UPDATE incidents SET tracking_code = 'DEMO000003' WHERE id = 3;
