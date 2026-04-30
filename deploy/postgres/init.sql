-- Demo schema for local development

CREATE TABLE IF NOT EXISTS products (
    id          SERIAL PRIMARY KEY,
    name        TEXT           NOT NULL,
    category    TEXT           NOT NULL,
    price       NUMERIC(10,2)  NOT NULL,
    stock       INT            NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    id          SERIAL PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    user_id     TEXT        NOT NULL,
    product     TEXT        NOT NULL,
    amount      NUMERIC(10,2) NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    email       TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Row Level Security (defense in depth)
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE users  ENABLE ROW LEVEL SECURITY;

-- The agentgate role can only see its own tenant rows
-- (currently bypassed for local dev, enable in prod)
-- CREATE POLICY tenant_isolation ON orders USING (tenant_id = current_setting('app.tenant_id'));

-- Seed data
INSERT INTO products (name, category, price, stock) VALUES
    ('Widget Pro',  'hardware', 99.99,  42),
    ('Widget Lite', 'hardware', 29.99, 120),
    ('Widget Max',  'software', 149.99,  0),
    ('Support Plan','services',  49.99, 999);

INSERT INTO orders (tenant_id, user_id, product, amount, status) VALUES
    ('tenant_1', 'user_1', 'Widget Pro',  99.99,  'completed'),
    ('tenant_1', 'user_2', 'Widget Lite', 29.99,  'pending'),
    ('tenant_2', 'user_3', 'Widget Pro',  99.99,  'completed');

INSERT INTO users (tenant_id, email, name) VALUES
    ('tenant_1', 'alice@example.com', 'Alice'),
    ('tenant_1', 'bob@example.com',   'Bob'),
    ('tenant_2', 'carol@example.com', 'Carol');
