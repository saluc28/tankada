-- Fintech demo schema (Tankada)
-- Two tenants: tenant_1 (Demobank NA), tenant_2 (Demobank EU)

-- ── Global tables (no tenant_id) ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS merchants (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    country     TEXT NOT NULL,
    mcc_code    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Tenant-scoped tables ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS customers (
    id            SERIAL PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL,
    phone         TEXT NOT NULL,
    date_of_birth DATE NOT NULL,
    ssn           TEXT NOT NULL,
    kyc_status    TEXT NOT NULL DEFAULT 'pending',
    risk_score    INT  NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
    id             SERIAL PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    customer_id    INT  NOT NULL REFERENCES customers(id),
    account_number TEXT NOT NULL,
    iban           TEXT NOT NULL,
    account_type   TEXT NOT NULL,
    balance        NUMERIC(15,2) NOT NULL DEFAULT 0,
    currency       TEXT NOT NULL DEFAULT 'EUR',
    status         TEXT NOT NULL DEFAULT 'active',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    id            SERIAL PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    account_id    INT  NOT NULL REFERENCES accounts(id),
    amount        NUMERIC(15,2) NOT NULL,
    currency      TEXT NOT NULL DEFAULT 'EUR',
    tx_type       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'completed',
    merchant_name TEXT,
    description   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cards (
    id           SERIAL PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    customer_id  INT  NOT NULL REFERENCES customers(id),
    account_id   INT  NOT NULL REFERENCES accounts(id),
    card_number  TEXT NOT NULL,
    card_type    TEXT NOT NULL,
    expiry_date  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    credit_limit NUMERIC(15,2),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS loans (
    id              SERIAL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    customer_id     INT  NOT NULL REFERENCES customers(id),
    amount          NUMERIC(15,2) NOT NULL,
    interest_rate   NUMERIC(5,2)  NOT NULL,
    term_months     INT  NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    monthly_payment NUMERIC(15,2) NOT NULL,
    disbursed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Access control ────────────────────────────────────────────────────────────

CREATE ROLE tankada_app NOLOGIN;
GRANT SELECT ON merchants, customers, accounts, transactions, cards, loans TO tankada_app;

-- ── Row Level Security ────────────────────────────────────────────────────────

ALTER TABLE customers    ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers    FORCE ROW LEVEL SECURITY;
ALTER TABLE accounts     ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts     FORCE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE cards        ENABLE ROW LEVEL SECURITY;
ALTER TABLE cards        FORCE ROW LEVEL SECURITY;
ALTER TABLE loans        ENABLE ROW LEVEL SECURITY;
ALTER TABLE loans        FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON customers
    FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation ON accounts
    FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation ON transactions
    FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation ON cards
    FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation ON loans
    FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));

-- ── Seed: merchants (global) ──────────────────────────────────────────────────

INSERT INTO merchants (name, category, country, mcc_code) VALUES
    ('Amazon',          'retail',        'US', '5411'),
    ('Starbucks',       'food_beverage', 'US', '5812'),
    ('Shell',           'fuel',          'NL', '5541'),
    ('Netflix',         'entertainment', 'US', '4899'),
    ('Uber',            'transport',     'US', '4121'),
    ('Apple Store',     'electronics',   'US', '5732'),
    ('McDonald''s',     'food_beverage', 'US', '5814'),
    ('Airbnb',          'travel',        'US', '7011'),
    ('Spotify',         'entertainment', 'SE', '4899'),
    ('Walmart',         'retail',        'US', '5411'),
    ('H&M',             'retail',        'SE', '5621'),
    ('Booking.com',     'travel',        'NL', '4722'),
    ('Google Play',     'digital',       'US', '5816'),
    ('Carrefour',       'retail',        'FR', '5411'),
    ('Zara',            'retail',        'ES', '5621'),
    ('PayPal Transfer', 'transfer',      'US', '6012'),
    ('Western Union',   'transfer',      'US', '6099'),
    ('ING Direct',      'banking',       'NL', '6010'),
    ('Revolut',         'banking',       'GB', '6010'),
    ('Stripe',          'payments',      'US', '7372');

-- ── Seed: customers tenant_1 (Demobank NA) ────────────────────────────────────

INSERT INTO customers (tenant_id, name, email, phone, date_of_birth, ssn, kyc_status, risk_score) VALUES
    ('tenant_1', 'Marco Rossi',      'marco.rossi@nexusbank.it',   '+39 333 1234567',   '1985-03-15', '123-45-6789', 'approved', 12),
    ('tenant_1', 'Sofia Bianchi',    'sofia.bianchi@email.it',     '+39 333 9876543',   '1990-07-22', '234-56-7890', 'approved',  8),
    ('tenant_1', 'Luca Ferrari',     'luca.ferrari@nexusbank.it',  '+39 347 5551234',   '1978-11-08', '345-67-8901', 'approved',  5),
    ('tenant_1', 'Anna Conti',       'anna.conti@gmail.com',       '+39 320 4445678',   '1995-02-14', '456-78-9012', 'pending',  25),
    ('tenant_1', 'Giovanni Marino',  'g.marino@business.it',       '+39 335 7778901',   '1982-09-30', '567-89-0123', 'approved',  3),
    ('tenant_1', 'Chiara Greco',     'chiara.greco@email.it',      '+39 349 2223456',   '1988-06-05', '678-90-1234', 'approved', 15),
    ('tenant_1', 'Fabio Romano',     'fabio.romano@firm.it',       '+39 333 8889012',   '1975-12-20', '789-01-2345', 'approved',  7),
    ('tenant_1', 'Elena Ricci',      'elena.ricci@startup.io',     '+39 342 1112345',   '1993-04-18', '890-12-3456', 'approved', 18),
    ('tenant_1', 'Matteo Esposito',  'm.esposito@email.it',        '+39 338 6667890',   '1987-08-25', '901-23-4567', 'rejected', 72),
    ('tenant_1', 'Laura Colombo',    'laura.colombo@nexusbank.it', '+39 346 3334567',   '1991-01-10', '012-34-5678', 'approved',  9),
    ('tenant_1', 'Roberto Mancini',  'r.mancini@corp.it',          '+39 333 4445678',   '1970-05-28', '111-22-3333', 'approved',  4),
    ('tenant_1', 'Valentina Costa',  'v.costa@email.it',           '+39 347 5556789',   '1996-10-12', '222-33-4444', 'pending',  31),
    ('tenant_1', 'Alessandro Bruno', 'a.bruno@tech.it',            '+39 335 6667890',   '1983-07-03', '333-44-5555', 'approved', 11),
    ('tenant_1', 'Federica Gallo',   'f.gallo@media.it',           '+39 320 7778901',   '1989-03-27', '444-55-6666', 'approved',  6),
    ('tenant_1', 'Simone Martini',   's.martini@finance.it',       '+39 349 8889012',   '1986-11-15', '555-66-7777', 'approved', 20);

-- ── Seed: customers tenant_2 (Demobank EU) ─────────────────────────────────

INSERT INTO customers (tenant_id, name, email, phone, date_of_birth, ssn, kyc_status, risk_score) VALUES
    ('tenant_2', 'Carlos Garcia',    'c.garcia@orionfinance.es',   '+34 612 3456789',   '1984-05-20', '666-77-8888', 'approved', 14),
    ('tenant_2', 'Marie Dupont',     'marie.dupont@email.fr',      '+33 612 345678',    '1991-08-14', '777-88-9999', 'approved',  6),
    ('tenant_2', 'Hans Mueller',     'h.mueller@orionfinance.de',  '+49 151 12345678',  '1979-02-28', '888-99-0000', 'approved',  3),
    ('tenant_2', 'Emma Wilson',      'emma.wilson@email.co.uk',    '+44 7911 123456',   '1994-11-05', '999-00-1111', 'pending',  28),
    ('tenant_2', 'Pierre Martin',    'p.martin@business.fr',       '+33 698 765432',    '1981-06-17', '000-11-2222', 'approved',  9),
    ('tenant_2', 'Ingrid Johansson', 'i.johansson@email.se',       '+46 701 234567',    '1987-09-03', '101-21-3131', 'approved', 17),
    ('tenant_2', 'Diego Lopez',      'diego.lopez@corp.es',        '+34 666 9876543',   '1976-01-25', '202-32-4242', 'approved',  5),
    ('tenant_2', 'Nathalie Bernard', 'n.bernard@startup.fr',       '+33 655 443322',    '1992-07-11', '303-43-5353', 'approved', 22),
    ('tenant_2', 'Thomas Schmidt',   't.schmidt@email.de',         '+49 160 98765432',  '1988-03-30', '404-54-6464', 'rejected', 68),
    ('tenant_2', 'Clara Petit',      'c.petit@orionfinance.fr',    '+33 611 223344',    '1990-12-08', '505-65-7575', 'approved',  7),
    ('tenant_2', 'Jan van der Berg', 'j.vanderberg@email.nl',      '+31 612 345678',    '1973-04-16', '606-76-8686', 'approved',  2),
    ('tenant_2', 'Sophie Lefevre',   's.lefevre@corp.fr',          '+33 677 889900',    '1995-09-22', '707-87-9797', 'pending',  35),
    ('tenant_2', 'Rafael Fernandez', 'r.fernandez@tech.es',        '+34 677 1234567',   '1982-12-01', '808-98-0808', 'approved', 13),
    ('tenant_2', 'Anna Kowalski',    'a.kowalski@email.pl',        '+48 512 345678',    '1989-06-19', '909-09-1919', 'approved',  8),
    ('tenant_2', 'Liam O''Brien',    'l.obrien@finance.ie',        '+353 871 234567',   '1985-10-07', '010-10-2020', 'approved', 19);

-- ── Seed: accounts tenant_1 ───────────────────────────────────────────────────

INSERT INTO accounts (tenant_id, customer_id, account_number, iban, account_type, balance, currency, status) VALUES
    ('tenant_1',  1, 'NX-001-0001', 'IT60X0542811101000000001001', 'checking',    12450.00, 'EUR', 'active'),
    ('tenant_1',  1, 'NX-001-0002', 'IT60X0542811101000000001002', 'savings',     85000.00, 'EUR', 'active'),
    ('tenant_1',  2, 'NX-001-0003', 'IT60X0542811101000000001003', 'checking',     3210.50, 'EUR', 'active'),
    ('tenant_1',  3, 'NX-001-0004', 'IT60X0542811101000000001004', 'business',   145000.00, 'EUR', 'active'),
    ('tenant_1',  4, 'NX-001-0005', 'IT60X0542811101000000001005', 'checking',      450.20, 'EUR', 'active'),
    ('tenant_1',  5, 'NX-001-0006', 'IT60X0542811101000000001006', 'checking',    22100.00, 'EUR', 'active'),
    ('tenant_1',  5, 'NX-001-0007', 'IT60X0542811101000000001007', 'investment',  310000.00, 'EUR', 'active'),
    ('tenant_1',  6, 'NX-001-0008', 'IT60X0542811101000000001008', 'checking',     7820.75, 'EUR', 'active'),
    ('tenant_1',  7, 'NX-001-0009', 'IT60X0542811101000000001009', 'business',    95000.00, 'EUR', 'active'),
    ('tenant_1',  8, 'NX-001-0010', 'IT60X0542811101000000001010', 'checking',     1250.30, 'EUR', 'active'),
    ('tenant_1',  9, 'NX-001-0011', 'IT60X0542811101000000001011', 'checking',       12.00, 'EUR', 'frozen'),
    ('tenant_1', 10, 'NX-001-0012', 'IT60X0542811101000000001012', 'checking',    18900.00, 'EUR', 'active'),
    ('tenant_1', 10, 'NX-001-0013', 'IT60X0542811101000000001013', 'savings',     52000.00, 'EUR', 'active'),
    ('tenant_1', 11, 'NX-001-0014', 'IT60X0542811101000000001014', 'business',   220000.00, 'EUR', 'active'),
    ('tenant_1', 12, 'NX-001-0015', 'IT60X0542811101000000001015', 'checking',      980.00, 'EUR', 'active'),
    ('tenant_1', 13, 'NX-001-0016', 'IT60X0542811101000000001016', 'checking',    34500.00, 'EUR', 'active'),
    ('tenant_1', 14, 'NX-001-0017', 'IT60X0542811101000000001017', 'savings',     28000.00, 'EUR', 'active'),
    ('tenant_1', 15, 'NX-001-0018', 'IT60X0542811101000000001018', 'checking',     9600.00, 'EUR', 'active'),
    ('tenant_1', 15, 'NX-001-0019', 'IT60X0542811101000000001019', 'investment',  125000.00, 'EUR', 'active'),
    ('tenant_1',  2, 'NX-001-0020', 'IT60X0542811101000000001020', 'savings',     15000.00, 'EUR', 'active');

-- ── Seed: accounts tenant_2 ───────────────────────────────────────────────────

INSERT INTO accounts (tenant_id, customer_id, account_number, iban, account_type, balance, currency, status) VALUES
    ('tenant_2', 16, 'OR-002-0001', 'ES9121000418450200051332',      'checking',    18700.00, 'EUR', 'active'),
    ('tenant_2', 16, 'OR-002-0002', 'ES9121000418450200051333',      'savings',     42000.00, 'EUR', 'active'),
    ('tenant_2', 17, 'OR-002-0003', 'FR7614508710005262944668',      'checking',     5430.00, 'EUR', 'active'),
    ('tenant_2', 18, 'OR-002-0004', 'DE89370400440532013000',        'business',   189000.00, 'EUR', 'active'),
    ('tenant_2', 19, 'OR-002-0005', 'GB29NWBK60161331926819',        'checking',     2100.50, 'GBP', 'active'),
    ('tenant_2', 20, 'OR-002-0006', 'FR7614508710005262944669',      'checking',    31200.00, 'EUR', 'active'),
    ('tenant_2', 20, 'OR-002-0007', 'FR7614508710005262944670',      'investment',  275000.00, 'EUR', 'active'),
    ('tenant_2', 21, 'OR-002-0008', 'SE4550000000058398257466',      'checking',     9100.00, 'SEK', 'active'),
    ('tenant_2', 22, 'OR-002-0009', 'ES9121000418450200051334',      'business',    76000.00, 'EUR', 'active'),
    ('tenant_2', 23, 'OR-002-0010', 'FR7614508710005262944671',      'checking',      340.00, 'EUR', 'active'),
    ('tenant_2', 24, 'OR-002-0011', 'FR7614508710005262944672',      'checking',    22500.00, 'EUR', 'frozen'),
    ('tenant_2', 25, 'OR-002-0012', 'NL91ABNA0417164300',            'checking',    14300.00, 'EUR', 'active'),
    ('tenant_2', 25, 'OR-002-0013', 'NL91ABNA0417164301',            'savings',     38000.00, 'EUR', 'active'),
    ('tenant_2', 26, 'OR-002-0014', 'FR7614508710005262944673',      'business',   165000.00, 'EUR', 'active'),
    ('tenant_2', 27, 'OR-002-0015', 'FR7614508710005262944674',      'checking',     3750.00, 'EUR', 'active'),
    ('tenant_2', 28, 'OR-002-0016', 'ES9121000418450200051335',      'checking',    27800.00, 'EUR', 'active'),
    ('tenant_2', 29, 'OR-002-0017', 'PL61109010140000071219812874',  'checking',    12100.00, 'PLN', 'active'),
    ('tenant_2', 30, 'OR-002-0018', 'IE29AIBK93115212345678',        'checking',     8400.00, 'EUR', 'active'),
    ('tenant_2', 30, 'OR-002-0019', 'IE29AIBK93115212345679',        'investment',   95000.00, 'EUR', 'active'),
    ('tenant_2', 17, 'OR-002-0020', 'FR7614508710005262944675',      'savings',     20000.00, 'EUR', 'active');

-- ── Seed: transactions tenant_1 ──────────────────────────────────────────────

INSERT INTO transactions (tenant_id, account_id, amount, currency, tx_type, status, merchant_name, description) VALUES
    ('tenant_1',  1,   -42.50, 'EUR', 'purchase',   'completed', 'Amazon',         'Online order #A1234'),
    ('tenant_1',  1,    -8.90, 'EUR', 'purchase',   'completed', 'Starbucks',      'Coffee and pastry'),
    ('tenant_1',  1,   -65.00, 'EUR', 'purchase',   'completed', 'Shell',          'Fuel'),
    ('tenant_1',  1,   -14.99, 'EUR', 'purchase',   'completed', 'Netflix',        'Monthly subscription'),
    ('tenant_1',  1,   -23.40, 'EUR', 'purchase',   'completed', 'Uber',           'Ride to airport'),
    ('tenant_1',  1,  2500.00, 'EUR', 'transfer',   'completed', NULL,             'Salary deposit'),
    ('tenant_1',  1,  -200.00, 'EUR', 'transfer',   'completed', NULL,             'Transfer to savings'),
    ('tenant_1',  2,   200.00, 'EUR', 'transfer',   'completed', NULL,             'Transfer from checking'),
    ('tenant_1',  2,  -500.00, 'EUR', 'withdrawal', 'completed', NULL,             'ATM withdrawal'),
    ('tenant_1',  3,   -55.20, 'EUR', 'purchase',   'completed', 'H&M',            'Clothing'),
    ('tenant_1',  3,   -12.99, 'EUR', 'purchase',   'completed', 'Spotify',        'Premium subscription'),
    ('tenant_1',  3,   -89.00, 'EUR', 'purchase',   'completed', 'Zara',           'Jacket'),
    ('tenant_1',  3,  1800.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_1',  4, -2400.00, 'EUR', 'purchase',   'completed', 'Apple Store',    'MacBook Pro'),
    ('tenant_1',  4, 15000.00, 'EUR', 'transfer',   'completed', NULL,             'Client invoice payment'),
    ('tenant_1',  4,  -450.00, 'EUR', 'purchase',   'completed', 'Airbnb',         'Weekend stay Milan'),
    ('tenant_1',  5,    -9.50, 'EUR', 'purchase',   'completed', 'McDonald''s',    'Lunch'),
    ('tenant_1',  5,   -35.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Books'),
    ('tenant_1',  5,   500.00, 'EUR', 'transfer',   'pending',   NULL,             'Incoming transfer'),
    ('tenant_1',  6,  -128.00, 'EUR', 'purchase',   'completed', 'Walmart',        'Groceries'),
    ('tenant_1',  6,  -320.00, 'EUR', 'purchase',   'completed', 'Shell',          'Monthly fuel'),
    ('tenant_1',  6,  3200.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_1',  7, -5000.00, 'EUR', 'transfer',   'completed', NULL,             'Investment rebalance'),
    ('tenant_1',  7,  8000.00, 'EUR', 'transfer',   'completed', NULL,             'Dividend payment'),
    ('tenant_1',  8,   -45.00, 'EUR', 'purchase',   'completed', 'Booking.com',    'Hotel Florence'),
    ('tenant_1',  8,   -22.00, 'EUR', 'purchase',   'completed', 'Uber',           'City ride'),
    ('tenant_1',  8,  2800.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_1',  9,  -750.00, 'EUR', 'purchase',   'completed', 'Apple Store',    'iPhone 16'),
    ('tenant_1',  9, 25000.00, 'EUR', 'transfer',   'completed', NULL,             'Contract payment received'),
    ('tenant_1', 10,   -18.90, 'EUR', 'purchase',   'completed', 'Starbucks',      'Team coffee'),
    ('tenant_1', 10,   -99.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Office supplies'),
    ('tenant_1', 11,  -500.00, 'EUR', 'transfer',   'failed',    NULL,             'Transfer blocked - frozen account'),
    ('tenant_1', 11, -1200.00, 'EUR', 'withdrawal', 'failed',    NULL,             'ATM blocked - frozen account'),
    ('tenant_1', 12,   -67.50, 'EUR', 'purchase',   'completed', 'Carrefour',      'Weekly groceries'),
    ('tenant_1', 12,   -14.99, 'EUR', 'purchase',   'completed', 'Netflix',        'Monthly subscription'),
    ('tenant_1', 12,  2600.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_1', 13, -1000.00, 'EUR', 'transfer',   'completed', NULL,             'Deposit to savings'),
    ('tenant_1', 14,-12000.00, 'EUR', 'purchase',   'completed', 'Apple Store',    'Server hardware'),
    ('tenant_1', 14, 45000.00, 'EUR', 'transfer',   'completed', NULL,             'Enterprise contract'),
    ('tenant_1', 15,   -33.00, 'EUR', 'purchase',   'completed', 'Zara',           'Accessories'),
    ('tenant_1', 15,  1200.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_1', 16,  -210.00, 'EUR', 'purchase',   'completed', 'H&M',            'Seasonal wardrobe'),
    ('tenant_1', 16,  2900.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_1', 17,   -88.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Books and media'),
    ('tenant_1', 17,   -15.99, 'EUR', 'purchase',   'completed', 'Spotify',        'Family plan'),
    ('tenant_1', 18,  -145.00, 'EUR', 'purchase',   'completed', 'Airbnb',         'Weekend trip Rome'),
    ('tenant_1', 18,    -9.99, 'EUR', 'purchase',   'completed', 'Google Play',    'App purchase'),
    ('tenant_1', 18,  3100.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_1', 19,-10000.00, 'EUR', 'transfer',   'completed', NULL,             'Investment fund'),
    ('tenant_1', 19, 12500.00, 'EUR', 'transfer',   'completed', NULL,             'Investment return'),
    ('tenant_1', 20,  -250.00, 'EUR', 'transfer',   'completed', NULL,             'Monthly savings'),
    ('tenant_1', 20,   350.00, 'EUR', 'transfer',   'completed', NULL,             'Interest payment'),
    ('tenant_1',  1,  -180.00, 'EUR', 'purchase',   'completed', 'Western Union',  'International transfer'),
    ('tenant_1',  4, -3200.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Equipment purchase'),
    ('tenant_1',  6,  -450.00, 'EUR', 'purchase',   'completed', 'Booking.com',    'Business trip hotel'),
    ('tenant_1',  9, -8500.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Large B2B order'),
    ('tenant_1', 12,   -95.00, 'EUR', 'purchase',   'completed', 'Shell',          'Monthly fuel'),
    ('tenant_1',  3,  -220.00, 'EUR', 'purchase',   'completed', 'Airbnb',         'Short rental'),
    ('tenant_1',  7,  5000.00, 'EUR', 'transfer',   'completed', NULL,             'Portfolio distribution'),
    ('tenant_1', 14, -7500.00, 'EUR', 'purchase',   'completed', 'Apple Store',    'Team devices'),
    ('tenant_1', 18,   -75.00, 'EUR', 'purchase',   'completed', 'Carrefour',      'Groceries'),
    ('tenant_1',  2,  -800.00, 'EUR', 'withdrawal', 'completed', NULL,             'Cash withdrawal'),
    ('tenant_1',  5,   -15.00, 'EUR', 'purchase',   'completed', 'Starbucks',      'Coffee meeting'),
    ('tenant_1',  8,  -450.00, 'EUR', 'purchase',   'completed', 'Zara',           'Clothing'),
    ('tenant_1', 10,  -230.00, 'EUR', 'purchase',   'completed', 'H&M',            'Office wardrobe'),
    ('tenant_1', 16,  -190.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Home items'),
    ('tenant_1', 19,-15000.00, 'EUR', 'transfer',   'completed', NULL,             'Quarterly rebalance'),
    ('tenant_1', 13, -2000.00, 'EUR', 'withdrawal', 'completed', NULL,             'Major cash withdrawal'),
    ('tenant_1',  6,  -560.00, 'EUR', 'purchase',   'completed', 'Apple Store',    'iPad for work'),
    ('tenant_1',  1,   -34.99, 'EUR', 'purchase',   'completed', 'Amazon',         'Subscription box'),
    ('tenant_1',  3,   900.00, 'EUR', 'transfer',   'completed', NULL,             'Bonus payment'),
    ('tenant_1',  9, -4200.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Inventory order'),
    ('tenant_1', 12,  2600.00, 'EUR', 'transfer',   'completed', NULL,             'Salary Q2'),
    ('tenant_1', 15,   -48.00, 'EUR', 'purchase',   'completed', 'H&M',            'Sale items');

-- ── Seed: transactions tenant_2 ──────────────────────────────────────────────

INSERT INTO transactions (tenant_id, account_id, amount, currency, tx_type, status, merchant_name, description) VALUES
    ('tenant_2', 21,    -55.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Electronics'),
    ('tenant_2', 21,   2200.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 21,    -12.99, 'EUR', 'purchase',   'completed', 'Netflix',        'Subscription'),
    ('tenant_2', 22,    -38.50, 'EUR', 'purchase',   'completed', 'Starbucks',      'Team coffee'),
    ('tenant_2', 22,   1950.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 23,  -89000.00,'EUR', 'purchase',   'completed', NULL,             'Equipment procurement'),
    ('tenant_2', 23, 200000.00, 'EUR', 'transfer',   'completed', NULL,             'Business revenue Q1'),
    ('tenant_2', 24,   -320.00, 'GBP', 'purchase',  'completed', 'H&M',            'Clothing'),
    ('tenant_2', 24,   2400.00, 'GBP', 'transfer',  'completed', NULL,             'Salary GBP'),
    ('tenant_2', 25,    -75.00, 'EUR', 'purchase',   'completed', 'Zara',           'Wardrobe update'),
    ('tenant_2', 25,   3400.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 26,   -190.00, 'EUR', 'purchase',   'completed', 'Booking.com',    'Stockholm trip'),
    ('tenant_2', 26,    800.00, 'SEK', 'transfer',   'completed', NULL,             'SEK deposit'),
    ('tenant_2', 27,  -4500.00, 'EUR', 'purchase',   'completed', NULL,             'Supplier payment'),
    ('tenant_2', 27,  35000.00, 'EUR', 'transfer',   'completed', NULL,             'Invoice received'),
    ('tenant_2', 28,    -22.00, 'EUR', 'purchase',   'completed', 'Uber',           'Business ride'),
    ('tenant_2', 28,   -500.00, 'EUR', 'transfer',   'failed',    NULL,             'Transfer blocked'),
    ('tenant_2', 29,   -900.00, 'EUR', 'transfer',   'failed',    NULL,             'Flagged suspicious'),
    ('tenant_2', 30,    -85.00, 'EUR', 'purchase',   'completed', 'Carrefour',      'Groceries'),
    ('tenant_2', 30,   2750.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 31,    -45.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Office supplies'),
    ('tenant_2', 31,   2200.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 32,  -1200.00, 'EUR', 'transfer',   'completed', NULL,             'Savings transfer'),
    ('tenant_2', 32,   -250.00, 'EUR', 'withdrawal', 'completed', NULL,             'ATM'),
    ('tenant_2', 33,  -55000.00,'EUR', 'purchase',   'completed', NULL,             'Real estate deposit'),
    ('tenant_2', 33,  80000.00, 'EUR', 'transfer',   'completed', NULL,             'Property sale proceeds'),
    ('tenant_2', 34,    -33.00, 'EUR', 'purchase',   'completed', 'Starbucks',      'Coffee'),
    ('tenant_2', 34,   -750.00, 'EUR', 'purchase',   'completed', 'Apple Store',    'iPhone upgrade'),
    ('tenant_2', 35,    -99.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Home office'),
    ('tenant_2', 35,   2100.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 36,   -180.00, 'PLN', 'purchase',  'completed', 'Walmart',        'Weekly shop'),
    ('tenant_2', 36,   3200.00, 'PLN', 'transfer',  'completed', NULL,             'Salary PLN'),
    ('tenant_2', 37,    -65.00, 'EUR', 'purchase',   'completed', 'Uber',           'Airport transfer'),
    ('tenant_2', 37,   2800.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 38,  -12000.00,'EUR', 'transfer',   'completed', NULL,             'Investment allocation'),
    ('tenant_2', 38,  15000.00, 'EUR', 'transfer',   'completed', NULL,             'Return on investment'),
    ('tenant_2', 39,    -48.00, 'EUR', 'purchase',   'completed', 'H&M',            'Clothing'),
    ('tenant_2', 39,   2500.00, 'EUR', 'transfer',   'completed', NULL,             'Salary'),
    ('tenant_2', 21,   -890.00, 'EUR', 'purchase',   'completed', 'Airbnb',         'Vacation rental'),
    ('tenant_2', 22,    -14.99, 'EUR', 'purchase',   'completed', 'Spotify',        'Subscription'),
    ('tenant_2', 25,   -340.00, 'EUR', 'purchase',   'completed', 'Booking.com',    'Paris hotel'),
    ('tenant_2', 27,  -12000.00,'EUR', 'purchase',   'completed', 'Apple Store',    'Company devices'),
    ('tenant_2', 30,    -78.00, 'EUR', 'purchase',   'completed', 'Carrefour',      'Weekly groceries'),
    ('tenant_2', 32,   8000.00, 'EUR', 'transfer',   'completed', NULL,             'Savings interest'),
    ('tenant_2', 34,  -2200.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Home renovation'),
    ('tenant_2', 21,    -29.99, 'EUR', 'purchase',   'completed', 'Google Play',    'Apps'),
    ('tenant_2', 23,  -5600.00, 'EUR', 'purchase',   'completed', NULL,             'Supplier B payment'),
    ('tenant_2', 25,   -240.00, 'EUR', 'purchase',   'completed', 'Zara',           'Seasonal collection'),
    ('tenant_2', 28,  -1800.00, 'EUR', 'transfer',   'failed',    NULL,             'Third flagged transfer'),
    ('tenant_2', 35,   -420.00, 'EUR', 'purchase',   'completed', 'H&M',            'Wardrobe refresh'),
    ('tenant_2', 37,   -380.00, 'EUR', 'purchase',   'completed', 'Booking.com',    'Business trip'),
    ('tenant_2', 38,  -8000.00, 'EUR', 'transfer',   'completed', NULL,             'Portfolio rebalance'),
    ('tenant_2', 39,   -155.00, 'EUR', 'purchase',   'completed', 'Airbnb',         'Team offsite'),
    ('tenant_2', 22,   2100.00, 'EUR', 'transfer',   'completed', NULL,             'Bonus Q1'),
    ('tenant_2', 30,     -9.99, 'EUR', 'purchase',   'completed', 'Spotify',        'Monthly plan'),
    ('tenant_2', 31,    -67.00, 'EUR', 'purchase',   'completed', 'Shell',          'Fuel'),
    ('tenant_2', 33,  -15000.00,'EUR', 'transfer',   'completed', NULL,             'Tax payment'),
    ('tenant_2', 36,   1500.00, 'PLN', 'transfer',  'completed', NULL,             'Freelance income'),
    ('tenant_2', 24,   -220.00, 'GBP', 'purchase',  'completed', 'Amazon',         'UK order'),
    ('tenant_2', 26,   -450.00, 'SEK', 'purchase',  'completed', 'H&M',            'Stockholm shopping'),
    ('tenant_2', 27,  -3300.00, 'EUR', 'purchase',   'completed', NULL,             'Logistics supplier'),
    ('tenant_2', 32,  -3000.00, 'EUR', 'withdrawal', 'completed', NULL,             'Large cash withdrawal'),
    ('tenant_2', 35,   -190.00, 'EUR', 'purchase',   'completed', 'Carrefour',      'Bulk groceries'),
    ('tenant_2', 37,   2800.00, 'EUR', 'transfer',   'completed', NULL,             'Salary Q2'),
    ('tenant_2', 38,   -500.00, 'EUR', 'purchase',   'completed', 'Airbnb',         'Conference accommodation'),
    ('tenant_2', 39,    -75.00, 'EUR', 'purchase',   'completed', 'Amazon',         'Stationery'),
    ('tenant_2', 21,    -15.99, 'EUR', 'purchase',   'completed', 'Netflix',        'Monthly plan'),
    ('tenant_2', 22,     -5.99, 'EUR', 'purchase',   'completed', 'Google Play',    'App subscription'),
    ('tenant_2', 30,   -360.00, 'EUR', 'purchase',   'completed', 'Booking.com',    'Summer trip'),
    ('tenant_2', 34,    -44.00, 'EUR', 'purchase',   'completed', 'Starbucks',      'Client meeting coffee'),
    ('tenant_2', 32,  -2800.00, 'EUR', 'transfer',   'completed', NULL,             'Mortgage payment');

-- ── Seed: cards tenant_1 ─────────────────────────────────────────────────────

INSERT INTO cards (tenant_id, customer_id, account_id, card_number, card_type, expiry_date, status, credit_limit) VALUES
    ('tenant_1',  1,  1, '4532 0151 1234 5678', 'visa_debit',        '2027-09', 'active', NULL),
    ('tenant_1',  1,  1, '4485 3765 4321 8765', 'visa_credit',       '2026-12', 'active', 5000.00),
    ('tenant_1',  2,  3, '5425 2334 3010 9903', 'mastercard_debit',  '2028-03', 'active', NULL),
    ('tenant_1',  3,  4, '5105 1051 0510 5100', 'mastercard_credit', '2027-06', 'active', 10000.00),
    ('tenant_1',  4,  5, '4916 6741 9836 0259', 'visa_debit',        '2026-08', 'active', NULL),
    ('tenant_1',  5,  6, '4929 3813 3813 3813', 'visa_credit',       '2027-11', 'active', 15000.00),
    ('tenant_1',  6,  8, '5399 9999 9999 9999', 'mastercard_debit',  '2028-01', 'active', NULL),
    ('tenant_1',  7,  9, '4111 1111 1111 1111', 'visa_credit',       '2026-05', 'active', 20000.00),
    ('tenant_1',  8, 10, '5500 0055 5555 5559', 'mastercard_credit', '2027-09', 'active', 8000.00),
    ('tenant_1',  9, 11, '4012 8888 8888 1881', 'visa_debit',        '2025-12', 'frozen', NULL),
    ('tenant_1', 10, 12, '4222 2222 2222 2222', 'visa_credit',       '2028-04', 'active', 12000.00),
    ('tenant_1', 11, 14, '5105 1051 0510 5101', 'mastercard_credit', '2027-07', 'active', 25000.00),
    ('tenant_1', 12, 15, '4532 0151 1234 5679', 'visa_debit',        '2027-10', 'active', NULL),
    ('tenant_1', 13, 16, '3782 8224 6310 0053', 'amex_credit',       '2026-03', 'active', 30000.00),
    ('tenant_1', 14, 17, '4916 6741 9836 0260', 'visa_credit',       '2028-06', 'active', 18000.00);

-- ── Seed: cards tenant_2 ─────────────────────────────────────────────────────

INSERT INTO cards (tenant_id, customer_id, account_id, card_number, card_type, expiry_date, status, credit_limit) VALUES
    ('tenant_2', 16, 21, '4532 1111 2222 3333', 'visa_debit',        '2027-08', 'active', NULL),
    ('tenant_2', 17, 22, '5425 2334 3010 9904', 'mastercard_debit',  '2028-02', 'active', NULL),
    ('tenant_2', 18, 23, '5105 1051 0510 5102', 'mastercard_credit', '2027-05', 'active', 15000.00),
    ('tenant_2', 19, 24, '4916 6741 9836 0261', 'visa_credit',       '2026-11', 'active', 7500.00),
    ('tenant_2', 20, 25, '4929 3813 3813 3814', 'visa_credit',       '2027-10', 'active', 20000.00),
    ('tenant_2', 21, 26, '5399 9999 9999 9998', 'mastercard_debit',  '2028-01', 'active', NULL),
    ('tenant_2', 22, 27, '4111 1111 1111 1112', 'visa_credit',       '2026-04', 'active', 25000.00),
    ('tenant_2', 23, 28, '5500 0055 5555 5558', 'mastercard_credit', '2027-08', 'active', 10000.00),
    ('tenant_2', 24, 29, '4012 8888 8888 1882', 'visa_debit',        '2025-11', 'frozen', NULL),
    ('tenant_2', 25, 30, '4222 2222 2222 2223', 'visa_credit',       '2028-03', 'active', 14000.00),
    ('tenant_2', 26, 31, '3782 8224 6310 0063', 'amex_credit',       '2026-02', 'active', 40000.00),
    ('tenant_2', 27, 32, '5105 1051 0510 5103', 'mastercard_debit',  '2027-09', 'active', NULL),
    ('tenant_2', 28, 34, '4532 0151 1234 5680', 'visa_debit',        '2027-12', 'active', NULL),
    ('tenant_2', 29, 36, '4916 6741 9836 0262', 'visa_credit',       '2028-05', 'active', 11000.00),
    ('tenant_2', 30, 37, '5425 2334 3010 9905', 'mastercard_credit', '2027-07', 'active', 16000.00);

-- ── Seed: loans ──────────────────────────────────────────────────────────────

INSERT INTO loans (tenant_id, customer_id, amount, interest_rate, term_months, status, monthly_payment, disbursed_at) VALUES
    ('tenant_1',  1,  15000.00, 6.50,  36, 'active',    455.00, '2024-01-15'),
    ('tenant_1',  3,  80000.00, 3.20, 240, 'active',    456.00, '2022-06-01'),
    ('tenant_1',  5,  25000.00, 7.10,  60, 'active',    495.00, '2023-09-20'),
    ('tenant_1',  7,  50000.00, 4.50, 120, 'active',    518.00, '2021-03-10'),
    ('tenant_1',  9,   8000.00,12.00,  24, 'defaulted', 376.00, '2023-01-05'),
    ('tenant_1', 10,  30000.00, 5.80,  84, 'active',    440.00, '2023-11-01'),
    ('tenant_1', 11, 120000.00, 2.90, 300, 'active',    558.00, '2020-07-15'),
    ('tenant_1', 13,  10000.00, 8.20,  36, 'active',    314.00, '2024-02-28'),
    ('tenant_1', 14, 200000.00, 3.10, 240, 'active',   1110.00, '2022-11-30'),
    ('tenant_1', 15,  18000.00, 6.90,  48, 'active',    430.00, '2024-03-01'),
    ('tenant_2', 16,  22000.00, 6.20,  48, 'active',    518.00, '2024-01-20'),
    ('tenant_2', 18,  95000.00, 3.40, 240, 'active',    543.00, '2022-04-01'),
    ('tenant_2', 20,  35000.00, 7.00,  60, 'active',    693.00, '2023-08-15'),
    ('tenant_2', 22,  45000.00, 4.80, 120, 'active',    468.00, '2021-05-20'),
    ('tenant_2', 24,   6000.00,11.50,  24, 'defaulted', 280.00, '2023-02-10'),
    ('tenant_2', 25,  28000.00, 5.50,  84, 'active',    404.00, '2023-10-15'),
    ('tenant_2', 26, 150000.00, 2.80, 300, 'active',    692.00, '2020-09-01'),
    ('tenant_2', 28,  12000.00, 7.90,  36, 'active',    374.00, '2024-02-01'),
    ('tenant_2', 29, 180000.00, 3.20, 240, 'active',   1020.00, '2022-08-20'),
    ('tenant_2', 30,  20000.00, 6.50,  48, 'active',    474.00, '2024-04-01');
