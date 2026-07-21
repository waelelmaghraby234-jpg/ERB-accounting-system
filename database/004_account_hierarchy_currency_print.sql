BEGIN;

/* =========================================================
   Account hierarchy metadata
   ========================================================= */
ALTER TABLE erp.group_accounts
    ADD COLUMN IF NOT EXISTS account_level INTEGER,
    ADD COLUMN IF NOT EXISTS notes TEXT;

/* Existing hierarchy levels are calculated by the application; this
   stored column is kept optional for future reporting/performance. */

/* =========================================================
   Currency master and exchange rates
   Rate meaning: 1 unit of from_currency = rate units of to_currency.
   For Cairo Group, to_currency is normally EGP.
   ========================================================= */
CREATE TABLE IF NOT EXISTS erp.currencies (
    group_id UUID NOT NULL,
    currency_code CHAR(3) NOT NULL,
    currency_name_ar VARCHAR(100) NOT NULL,
    currency_name_en VARCHAR(100),
    symbol VARCHAR(10),
    decimal_places SMALLINT NOT NULL DEFAULT 2 CHECK (decimal_places BETWEEN 0 AND 6),
    is_base BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, currency_code),
    FOREIGN KEY (group_id)
      REFERENCES erp.corporate_groups(group_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_currencies_one_base_per_group
    ON erp.currencies(group_id)
    WHERE is_base = TRUE;

CREATE TABLE IF NOT EXISTS erp.exchange_rates (
    exchange_rate_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID,
    rate_date DATE NOT NULL,
    from_currency CHAR(3) NOT NULL,
    to_currency CHAR(3) NOT NULL DEFAULT 'EGP',
    rate_type VARCHAR(12) NOT NULL DEFAULT 'SPOT'
      CHECK (rate_type IN ('SPOT','AVERAGE','CLOSING')),
    rate NUMERIC(20,10) NOT NULL CHECK (rate > 0),
    source VARCHAR(100),
    notes TEXT,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE NULLS NOT DISTINCT
      (group_id, company_id, rate_date, from_currency, to_currency, rate_type),
    FOREIGN KEY (group_id, from_currency)
      REFERENCES erp.currencies(group_id, currency_code) ON DELETE RESTRICT,
    FOREIGN KEY (group_id, to_currency)
      REFERENCES erp.currencies(group_id, currency_code) ON DELETE RESTRICT,
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_exchange_rates_lookup
    ON erp.exchange_rates(group_id, company_id, from_currency, to_currency, rate_type, rate_date DESC);

INSERT INTO erp.currencies
    (group_id, currency_code, currency_name_ar, currency_name_en, symbol, is_base)
SELECT group_id, 'EGP', 'الجنيه المصري', 'Egyptian Pound', 'ج.م', TRUE
FROM erp.corporate_groups
ON CONFLICT (group_id, currency_code) DO UPDATE
SET currency_name_ar=EXCLUDED.currency_name_ar,
    currency_name_en=EXCLUDED.currency_name_en,
    symbol=EXCLUDED.symbol,
    is_base=TRUE,
    is_active=TRUE;

INSERT INTO erp.currencies
    (group_id, currency_code, currency_name_ar, currency_name_en, symbol, is_base)
SELECT g.group_id, v.code, v.name_ar, v.name_en, v.symbol, FALSE
FROM erp.corporate_groups g
CROSS JOIN (VALUES
    ('USD'::CHAR(3), 'الدولار الأمريكي', 'US Dollar', '$'),
    ('EUR'::CHAR(3), 'اليورو', 'Euro', '€'),
    ('GBP'::CHAR(3), 'الجنيه الإسترليني', 'British Pound', '£'),
    ('SAR'::CHAR(3), 'الريال السعودي', 'Saudi Riyal', 'ر.س'),
    ('AED'::CHAR(3), 'الدرهم الإماراتي', 'UAE Dirham', 'د.إ')
) AS v(code, name_ar, name_en, symbol)
ON CONFLICT (group_id, currency_code) DO NOTHING;

/* =========================================================
   Foreign-currency invoice values and base-currency values
   ========================================================= */
ALTER TABLE erp.invoices
    ADD COLUMN IF NOT EXISTS base_subtotal NUMERIC(20,4),
    ADD COLUMN IF NOT EXISTS base_tax_amount NUMERIC(20,4),
    ADD COLUMN IF NOT EXISTS base_total_amount NUMERIC(20,4),
    ADD COLUMN IF NOT EXISTS exchange_rate_source VARCHAR(30);

UPDATE erp.invoices
SET base_subtotal = COALESCE(base_subtotal, ROUND(subtotal * exchange_rate, 4)),
    base_tax_amount = COALESCE(base_tax_amount, ROUND(tax_amount * exchange_rate, 4)),
    base_total_amount = COALESCE(base_total_amount, ROUND(total_amount * exchange_rate, 4)),
    exchange_rate_source = COALESCE(exchange_rate_source, 'MIGRATED')
WHERE base_total_amount IS NULL OR base_subtotal IS NULL OR base_tax_amount IS NULL;

ALTER TABLE erp.invoices
    ALTER COLUMN base_subtotal SET DEFAULT 0,
    ALTER COLUMN base_tax_amount SET DEFAULT 0,
    ALTER COLUMN base_total_amount SET DEFAULT 0;

ALTER TABLE erp.invoice_lines
    ADD COLUMN IF NOT EXISTS base_net_amount NUMERIC(20,4),
    ADD COLUMN IF NOT EXISTS base_tax_amount NUMERIC(20,4),
    ADD COLUMN IF NOT EXISTS base_total_amount NUMERIC(20,4);

UPDATE erp.invoice_lines il
SET base_net_amount = COALESCE(il.base_net_amount, ROUND(il.net_amount * i.exchange_rate, 4)),
    base_tax_amount = COALESCE(il.base_tax_amount, ROUND(il.tax_amount * i.exchange_rate, 4)),
    base_total_amount = COALESCE(il.base_total_amount, ROUND(il.total_amount * i.exchange_rate, 4))
FROM erp.invoices i
WHERE i.invoice_id = il.invoice_id
  AND (il.base_total_amount IS NULL OR il.base_net_amount IS NULL OR il.base_tax_amount IS NULL);

ALTER TABLE erp.invoice_lines
    ALTER COLUMN base_net_amount SET DEFAULT 0,
    ALTER COLUMN base_tax_amount SET DEFAULT 0,
    ALTER COLUMN base_total_amount SET DEFAULT 0;

/* =========================================================
   Foreign currency bank accounts and cash movements
   ========================================================= */
ALTER TABLE erp.bank_accounts
    ADD COLUMN IF NOT EXISTS opening_exchange_rate NUMERIC(20,10) NOT NULL DEFAULT 1 CHECK (opening_exchange_rate > 0),
    ADD COLUMN IF NOT EXISTS opening_balance_base NUMERIC(20,4);

UPDATE erp.bank_accounts
SET opening_balance_base = COALESCE(opening_balance_base, ROUND(opening_balance * opening_exchange_rate, 4))
WHERE opening_balance_base IS NULL;

ALTER TABLE erp.bank_accounts
    ALTER COLUMN opening_balance_base SET DEFAULT 0;

ALTER TABLE erp.cash_transactions
    ADD COLUMN IF NOT EXISTS currency CHAR(3),
    ADD COLUMN IF NOT EXISTS exchange_rate NUMERIC(20,10) NOT NULL DEFAULT 1 CHECK (exchange_rate > 0),
    ADD COLUMN IF NOT EXISTS base_amount NUMERIC(20,4);

UPDATE erp.cash_transactions ct
SET currency = COALESCE(ct.currency, b.currency),
    base_amount = COALESCE(ct.base_amount, ROUND(ct.amount * ct.exchange_rate, 4))
FROM erp.bank_accounts b
WHERE b.bank_account_id = ct.bank_account_id
  AND (ct.currency IS NULL OR ct.base_amount IS NULL);

ALTER TABLE erp.cash_transactions
    ALTER COLUMN currency SET DEFAULT 'EGP',
    ALTER COLUMN base_amount SET DEFAULT 0;

/* =========================================================
   Bank revaluation audit trail
   ========================================================= */
CREATE TABLE IF NOT EXISTS erp.bank_revaluations (
    bank_revaluation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    bank_account_id UUID NOT NULL,
    revaluation_date DATE NOT NULL,
    currency CHAR(3) NOT NULL,
    closing_rate NUMERIC(20,10) NOT NULL CHECK (closing_rate > 0),
    foreign_balance NUMERIC(20,4) NOT NULL,
    book_base_balance NUMERIC(20,4) NOT NULL,
    revalued_base_balance NUMERIC(20,4) NOT NULL,
    difference_amount NUMERIC(20,4) NOT NULL,
    voucher_id UUID,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, bank_account_id, revaluation_date),
    FOREIGN KEY (bank_account_id, company_id, group_id)
      REFERENCES erp.bank_accounts(bank_account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (voucher_id, company_id, group_id)
      REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id) ON DELETE RESTRICT
);

COMMIT;
