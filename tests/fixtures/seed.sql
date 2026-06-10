-- Minimal fixture so the G2 cross-join exploit is observable in the smoke rig.
-- Column names mirror prod (booking_booking: created/expert_earnings/testing/currency).
-- Two distinct experts + a third "victim" user_user row: pre-G2-fix a scoped
-- expert's `SELECT u.* FROM user_user u CROSS JOIN booking_booking b` would leak
-- ALL three user_user rows; post-fix scope_sql rejects it.

CREATE TABLE IF NOT EXISTS user_user (
    id        serial PRIMARY KEY,
    username  text,
    email     text
);

CREATE TABLE IF NOT EXISTS booking_booking (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    expert_id       integer,
    created         timestamptz DEFAULT now(),
    expert_earnings numeric,
    testing         boolean DEFAULT false,
    currency        jsonb
);

CREATE TABLE IF NOT EXISTS services_service (
    id       serial PRIMARY KEY,
    user_id  integer
);

INSERT INTO user_user (id, username, email) VALUES
    (42, 'expert_bob', 'bob@x.com'),
    (7,  'expert_amy', 'amy@x.com'),
    (99, 'victim',     'victim@x.com')
ON CONFLICT (id) DO NOTHING;

INSERT INTO booking_booking (expert_id, expert_earnings, testing, currency) VALUES
    (42, 100.00, false, '{"code":"INR"}'),
    (42, 250.00, false, '{"code":"USD"}'),
    (7,  500.00, false, '{"code":"INR"}');

INSERT INTO services_service (user_id) VALUES (42), (7);
