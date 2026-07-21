BEGIN;

ALTER TABLE erp.corporate_groups
    ADD COLUMN IF NOT EXISTS country_code CHAR(2) NOT NULL DEFAULT 'EG',
    ADD COLUMN IF NOT EXISTS fiscal_year_start_month SMALLINT NOT NULL DEFAULT 1
        CHECK (fiscal_year_start_month BETWEEN 1 AND 12);

ALTER TABLE erp.companies
    ADD COLUMN IF NOT EXISTS legal_name VARCHAR(250),
    ADD COLUMN IF NOT EXISTS tax_registration_no VARCHAR(100),
    ADD COLUMN IF NOT EXISTS commercial_registration_no VARCHAR(100),
    ADD COLUMN IF NOT EXISTS address TEXT,
    ADD COLUMN IF NOT EXISTS phone VARCHAR(50),
    ADD COLUMN IF NOT EXISTS email VARCHAR(320);

ALTER TABLE erp.app_users
    ADD COLUMN IF NOT EXISTS full_name VARCHAR(250),
    ADD COLUMN IF NOT EXISTS role_code VARCHAR(30) NOT NULL DEFAULT 'GROUP_ADMIN',
    ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

ALTER TABLE erp.journal_vouchers
    ADD COLUMN IF NOT EXISTS source_module VARCHAR(30) NOT NULL DEFAULT 'GL',
    ADD COLUMN IF NOT EXISTS external_reference VARCHAR(150),
    ADD COLUMN IF NOT EXISTS reviewed_by UUID,
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approved_by UUID,
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS erp.branches (
    branch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    branch_code VARCHAR(30) NOT NULL,
    branch_name VARCHAR(250) NOT NULL,
    address TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (branch_id, company_id, group_id),
    UNIQUE (company_id, branch_code),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.cost_centers (
    cost_center_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    center_code VARCHAR(30) NOT NULL,
    center_name VARCHAR(250) NOT NULL,
    parent_cost_center_id UUID,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cost_center_id, company_id, group_id),
    UNIQUE (company_id, center_code),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_cost_center_id, company_id, group_id)
      REFERENCES erp.cost_centers(cost_center_id, company_id, group_id) ON DELETE RESTRICT
);

ALTER TABLE erp.journal_entries
    ADD COLUMN IF NOT EXISTS branch_id UUID,
    ADD COLUMN IF NOT EXISTS cost_center_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_entries_branch'
    ) THEN
        ALTER TABLE erp.journal_entries
          ADD CONSTRAINT fk_entries_branch
          FOREIGN KEY (branch_id, company_id, group_id)
          REFERENCES erp.branches(branch_id, company_id, group_id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_entries_cost_center'
    ) THEN
        ALTER TABLE erp.journal_entries
          ADD CONSTRAINT fk_entries_cost_center
          FOREIGN KEY (cost_center_id, company_id, group_id)
          REFERENCES erp.cost_centers(cost_center_id, company_id, group_id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS erp.fiscal_years (
    fiscal_year_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    year_name VARCHAR(50) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    status VARCHAR(12) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (fiscal_year_id, company_id, group_id),
    UNIQUE (company_id, year_name),
    CHECK (end_date >= start_date),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.fiscal_periods (
    period_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    fiscal_year_id UUID NOT NULL,
    period_no SMALLINT NOT NULL CHECK (period_no BETWEEN 1 AND 13),
    period_name VARCHAR(50) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    status VARCHAR(12) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED','LOCKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, fiscal_year_id, period_no),
    FOREIGN KEY (fiscal_year_id, company_id, group_id)
      REFERENCES erp.fiscal_years(fiscal_year_id, company_id, group_id) ON DELETE CASCADE,
    CHECK (end_date >= start_date)
);

CREATE TABLE IF NOT EXISTS erp.parties (
    party_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    party_code VARCHAR(30) NOT NULL,
    party_name VARCHAR(250) NOT NULL,
    party_type VARCHAR(12) NOT NULL CHECK (party_type IN ('CUSTOMER','VENDOR','BOTH')),
    tax_registration_no VARCHAR(100),
    email VARCHAR(320),
    phone VARCHAR(50),
    address TEXT,
    receivable_account_id UUID,
    payable_account_id UUID,
    credit_limit NUMERIC(20,4) NOT NULL DEFAULT 0,
    payment_terms_days INTEGER NOT NULL DEFAULT 0 CHECK (payment_terms_days >= 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (party_id, company_id, group_id),
    UNIQUE (company_id, party_code),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (receivable_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (payable_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.bank_accounts (
    bank_account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    bank_code VARCHAR(30) NOT NULL,
    bank_name VARCHAR(250) NOT NULL,
    account_name VARCHAR(250) NOT NULL,
    account_number VARCHAR(100),
    iban VARCHAR(100),
    currency CHAR(3) NOT NULL DEFAULT 'EGP',
    gl_account_id UUID NOT NULL,
    opening_balance NUMERIC(20,4) NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (bank_account_id, company_id, group_id),
    UNIQUE (company_id, bank_code),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (gl_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.invoices (
    invoice_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    invoice_type VARCHAR(10) NOT NULL CHECK (invoice_type IN ('SALES','PURCHASE')),
    invoice_no VARCHAR(50) NOT NULL,
    party_id UUID NOT NULL,
    invoice_date DATE NOT NULL,
    due_date DATE NOT NULL,
    currency CHAR(3) NOT NULL DEFAULT 'EGP',
    exchange_rate NUMERIC(18,8) NOT NULL DEFAULT 1 CHECK (exchange_rate > 0),
    description TEXT,
    subtotal NUMERIC(20,4) NOT NULL DEFAULT 0,
    tax_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    total_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    control_account_id UUID NOT NULL,
    tax_account_id UUID,
    status VARCHAR(12) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','POSTED','PAID','CANCELLED')),
    voucher_id UUID,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (invoice_id, company_id, group_id),
    UNIQUE (company_id, invoice_type, invoice_no),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (party_id, company_id, group_id)
      REFERENCES erp.parties(party_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (control_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (tax_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (voucher_id, company_id, group_id)
      REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.invoice_lines (
    invoice_line_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    invoice_id UUID NOT NULL,
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    line_no INTEGER NOT NULL,
    description VARCHAR(500) NOT NULL,
    account_id UUID NOT NULL,
    quantity NUMERIC(20,4) NOT NULL DEFAULT 1 CHECK (quantity > 0),
    unit_price NUMERIC(20,4) NOT NULL DEFAULT 0 CHECK (unit_price >= 0),
    tax_rate NUMERIC(8,4) NOT NULL DEFAULT 0 CHECK (tax_rate >= 0),
    net_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    tax_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    total_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    cost_center_id UUID,
    UNIQUE (invoice_id, line_no),
    FOREIGN KEY (invoice_id, company_id, group_id)
      REFERENCES erp.invoices(invoice_id, company_id, group_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (cost_center_id, company_id, group_id)
      REFERENCES erp.cost_centers(cost_center_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.cash_transactions (
    cash_transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    transaction_type VARCHAR(10) NOT NULL CHECK (transaction_type IN ('RECEIPT','PAYMENT')),
    transaction_no VARCHAR(50) NOT NULL,
    transaction_date DATE NOT NULL,
    bank_account_id UUID NOT NULL,
    party_id UUID,
    offset_account_id UUID NOT NULL,
    amount NUMERIC(20,4) NOT NULL CHECK (amount > 0),
    description TEXT,
    reference_no VARCHAR(150),
    status VARCHAR(12) NOT NULL DEFAULT 'POSTED' CHECK (status IN ('DRAFT','POSTED','CANCELLED')),
    voucher_id UUID,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, transaction_type, transaction_no),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (bank_account_id, company_id, group_id)
      REFERENCES erp.bank_accounts(bank_account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (party_id, company_id, group_id)
      REFERENCES erp.parties(party_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (offset_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (voucher_id, company_id, group_id)
      REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.asset_categories (
    asset_category_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    category_code VARCHAR(30) NOT NULL,
    category_name VARCHAR(250) NOT NULL,
    asset_account_id UUID NOT NULL,
    accumulated_depreciation_account_id UUID NOT NULL,
    depreciation_expense_account_id UUID NOT NULL,
    useful_life_months INTEGER NOT NULL CHECK (useful_life_months > 0),
    depreciation_method VARCHAR(20) NOT NULL DEFAULT 'STRAIGHT_LINE'
      CHECK (depreciation_method IN ('STRAIGHT_LINE')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_category_id, company_id, group_id),
    UNIQUE (company_id, category_code),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (asset_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (accumulated_depreciation_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (depreciation_expense_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.fixed_assets (
    asset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    asset_code VARCHAR(30) NOT NULL,
    asset_name VARCHAR(250) NOT NULL,
    asset_category_id UUID NOT NULL,
    acquisition_date DATE NOT NULL,
    placed_in_service_date DATE NOT NULL,
    acquisition_cost NUMERIC(20,4) NOT NULL CHECK (acquisition_cost >= 0),
    residual_value NUMERIC(20,4) NOT NULL DEFAULT 0 CHECK (residual_value >= 0),
    useful_life_months INTEGER NOT NULL CHECK (useful_life_months > 0),
    accumulated_depreciation NUMERIC(20,4) NOT NULL DEFAULT 0,
    last_depreciation_date DATE,
    status VARCHAR(15) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','DISPOSED')),
    location VARCHAR(250),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, company_id, group_id),
    UNIQUE (company_id, asset_code),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (asset_category_id, company_id, group_id)
      REFERENCES erp.asset_categories(asset_category_id, company_id, group_id) ON DELETE RESTRICT,
    CHECK (residual_value <= acquisition_cost)
);

CREATE TABLE IF NOT EXISTS erp.asset_depreciation_entries (
    depreciation_entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    asset_id UUID NOT NULL,
    depreciation_date DATE NOT NULL,
    amount NUMERIC(20,4) NOT NULL CHECK (amount > 0),
    voucher_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, depreciation_date),
    FOREIGN KEY (asset_id, company_id, group_id)
      REFERENCES erp.fixed_assets(asset_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (voucher_id, company_id, group_id)
      REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.audit_log (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id UUID NOT NULL,
    company_id UUID,
    user_id UUID,
    action VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(100),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_parties_company_type ON erp.parties(company_id, party_type);
CREATE INDEX IF NOT EXISTS idx_invoices_company_date ON erp.invoices(company_id, invoice_type, invoice_date);
CREATE INDEX IF NOT EXISTS idx_cash_transactions_company_date ON erp.cash_transactions(company_id, transaction_date);
CREATE INDEX IF NOT EXISTS idx_assets_company ON erp.fixed_assets(company_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_group_date ON erp.audit_log(group_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fiscal_periods_company_dates ON erp.fiscal_periods(company_id, start_date, end_date);

CREATE OR REPLACE FUNCTION erp.ensure_open_period(
    p_company_id UUID,
    p_posting_date DATE
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
      FROM erp.fiscal_periods
     WHERE company_id = p_company_id
       AND p_posting_date BETWEEN start_date AND end_date
       AND status = 'OPEN';

    IF v_count = 0 THEN
        RAISE EXCEPTION 'No open fiscal period for posting date %', p_posting_date;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION erp.create_monthly_periods(
    p_fiscal_year_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_year RECORD;
    v_i INTEGER;
    v_start DATE;
    v_end DATE;
BEGIN
    SELECT * INTO v_year FROM erp.fiscal_years WHERE fiscal_year_id = p_fiscal_year_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Fiscal year not found'; END IF;

    FOR v_i IN 1..12 LOOP
        v_start := (v_year.start_date + ((v_i - 1) || ' month')::interval)::date;
        v_end := LEAST((v_start + interval '1 month - 1 day')::date, v_year.end_date);
        INSERT INTO erp.fiscal_periods
            (group_id, company_id, fiscal_year_id, period_no, period_name, start_date, end_date)
        VALUES
            (v_year.group_id, v_year.company_id, v_year.fiscal_year_id,
             v_i, TO_CHAR(v_start, 'YYYY-MM'), v_start, v_end)
        ON CONFLICT (company_id, fiscal_year_id, period_no) DO NOTHING;
    END LOOP;
END;
$$;

COMMIT;
