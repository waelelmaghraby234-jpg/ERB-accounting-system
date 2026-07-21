BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS erp;

CREATE TABLE IF NOT EXISTS erp.corporate_groups (
    group_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_code VARCHAR(30) NOT NULL UNIQUE,
    group_name VARCHAR(250) NOT NULL,
    presentation_currency CHAR(3) NOT NULL DEFAULT 'EGP',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS erp.companies (
    company_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES erp.corporate_groups(group_id) ON DELETE RESTRICT,
    company_code VARCHAR(30) NOT NULL,
    company_name VARCHAR(250) NOT NULL,
    company_kind VARCHAR(20) NOT NULL CHECK (company_kind IN ('HOLDING','SUBSIDIARY','ELIMINATION')),
    parent_company_id UUID NULL,
    ownership_percent NUMERIC(7,4) NOT NULL DEFAULT 100 CHECK (ownership_percent > 0 AND ownership_percent <= 100),
    functional_currency CHAR(3) NOT NULL DEFAULT 'EGP',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, group_id),
    UNIQUE (group_id, company_code),
    FOREIGN KEY (parent_company_id, group_id)
        REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    CHECK (
        (company_kind = 'HOLDING' AND parent_company_id IS NULL)
        OR (company_kind <> 'HOLDING')
    )
);

CREATE TABLE IF NOT EXISTS erp.group_accounts (
    group_account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES erp.corporate_groups(group_id) ON DELETE RESTRICT,
    account_code VARCHAR(50) NOT NULL,
    account_name VARCHAR(250) NOT NULL,
    account_class VARCHAR(20) NOT NULL CHECK (account_class IN ('ASSET','LIABILITY','EQUITY','REVENUE','EXPENSE')),
    normal_balance VARCHAR(6) NOT NULL CHECK (normal_balance IN ('DEBIT','CREDIT')),
    parent_group_account_id UUID NULL,
    is_postable BOOLEAN NOT NULL DEFAULT TRUE,
    is_intercompany BOOLEAN NOT NULL DEFAULT FALSE,
    intercompany_role VARCHAR(30) NOT NULL DEFAULT 'NONE',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_account_id, group_id),
    UNIQUE (group_id, account_code),
    FOREIGN KEY (parent_group_account_id, group_id)
        REFERENCES erp.group_accounts(group_account_id, group_id) ON DELETE RESTRICT,
    CHECK (
        (is_intercompany = FALSE AND intercompany_role = 'NONE')
        OR (is_intercompany = TRUE AND intercompany_role <> 'NONE')
    )
);

CREATE TABLE IF NOT EXISTS erp.accounts (
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    group_account_id UUID NOT NULL,
    local_account_code VARCHAR(50) NOT NULL,
    local_account_name VARCHAR(250) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, company_id, group_id),
    UNIQUE (company_id, local_account_code),
    FOREIGN KEY (company_id, group_id)
        REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (group_account_id, group_id)
        REFERENCES erp.group_accounts(group_account_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.journal_vouchers (
    voucher_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    voucher_no VARCHAR(50) NOT NULL,
    voucher_type VARCHAR(20) NOT NULL DEFAULT 'GENERAL',
    status VARCHAR(12) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','POSTED','CANCELLED')),
    document_date DATE NOT NULL,
    posting_date DATE NOT NULL,
    description TEXT NULL,
    created_by UUID NULL,
    posted_by UUID NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posted_at TIMESTAMPTZ NULL,
    UNIQUE (voucher_id, company_id, group_id),
    UNIQUE (company_id, voucher_no),
    FOREIGN KEY (company_id, group_id)
        REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS erp.journal_entries (
    entry_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    voucher_id UUID NOT NULL,
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    account_id UUID NOT NULL,
    line_no INTEGER NOT NULL,
    entry_description TEXT NULL,
    debit_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    credit_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    counterparty_company_id UUID NULL,
    intercompany_reference VARCHAR(150) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (voucher_id, line_no),
    FOREIGN KEY (voucher_id, company_id, group_id)
        REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, company_id, group_id)
        REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (counterparty_company_id, group_id)
        REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    CHECK (
        (debit_amount > 0 AND credit_amount = 0)
        OR (credit_amount > 0 AND debit_amount = 0)
    ),
    CHECK (counterparty_company_id IS NULL OR counterparty_company_id <> company_id)
);

CREATE TABLE IF NOT EXISTS erp.app_users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES erp.corporate_groups(group_id) ON DELETE RESTRICT,
    company_id UUID NULL,
    email VARCHAR(320) NOT NULL,
    password_hash TEXT NOT NULL,
    is_group_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, email),
    FOREIGN KEY (company_id, group_id)
        REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    CHECK (is_group_admin = TRUE OR company_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_vouchers_company_date
    ON erp.journal_vouchers(company_id, posting_date)
    WHERE status = 'POSTED';

CREATE INDEX IF NOT EXISTS idx_entries_account
    ON erp.journal_entries(account_id);

CREATE INDEX IF NOT EXISTS idx_entries_intercompany
    ON erp.journal_entries(company_id, counterparty_company_id, intercompany_reference)
    WHERE counterparty_company_id IS NOT NULL;

CREATE OR REPLACE FUNCTION erp.prevent_posted_voucher_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'POSTED' THEN
        RAISE EXCEPTION 'Posted voucher cannot be changed or deleted';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_posted_voucher_change ON erp.journal_vouchers;
CREATE TRIGGER trg_prevent_posted_voucher_change
BEFORE UPDATE OR DELETE ON erp.journal_vouchers
FOR EACH ROW EXECUTE FUNCTION erp.prevent_posted_voucher_change();

CREATE OR REPLACE FUNCTION erp.prevent_posted_entry_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_status VARCHAR(12);
    v_voucher UUID;
BEGIN
    v_voucher := CASE WHEN TG_OP = 'DELETE' THEN OLD.voucher_id ELSE NEW.voucher_id END;
    SELECT status INTO v_status FROM erp.journal_vouchers WHERE voucher_id = v_voucher;
    IF v_status = 'POSTED' THEN
        RAISE EXCEPTION 'Entries of a posted voucher cannot be changed';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_posted_entry_change ON erp.journal_entries;
CREATE TRIGGER trg_prevent_posted_entry_change
BEFORE INSERT OR UPDATE OR DELETE ON erp.journal_entries
FOR EACH ROW EXECUTE FUNCTION erp.prevent_posted_entry_change();


CREATE OR REPLACE FUNCTION erp.validate_intercompany_entry()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_is_intercompany BOOLEAN;
BEGIN
    SELECT ga.is_intercompany
      INTO v_is_intercompany
      FROM erp.accounts a
      JOIN erp.group_accounts ga
        ON ga.group_account_id = a.group_account_id
       AND ga.group_id = a.group_id
     WHERE a.account_id = NEW.account_id
       AND a.company_id = NEW.company_id
       AND a.group_id = NEW.group_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account does not belong to voucher company';
    END IF;

    IF v_is_intercompany AND NEW.counterparty_company_id IS NULL THEN
        RAISE EXCEPTION 'Counterparty is required for intercompany account';
    END IF;

    IF v_is_intercompany AND NULLIF(BTRIM(NEW.intercompany_reference), '') IS NULL THEN
        RAISE EXCEPTION 'Intercompany reference is required';
    END IF;

    IF NOT v_is_intercompany AND NEW.counterparty_company_id IS NOT NULL THEN
        RAISE EXCEPTION 'Counterparty cannot be used with a non-intercompany account';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_intercompany_entry ON erp.journal_entries;
CREATE TRIGGER trg_validate_intercompany_entry
BEFORE INSERT OR UPDATE ON erp.journal_entries
FOR EACH ROW EXECUTE FUNCTION erp.validate_intercompany_entry();

CREATE OR REPLACE FUNCTION erp.post_voucher(
    p_voucher_id UUID,
    p_user_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_status VARCHAR(12);
    v_line_count BIGINT;
    v_debit NUMERIC(20,4);
    v_credit NUMERIC(20,4);
BEGIN
    SELECT status
      INTO v_status
      FROM erp.journal_vouchers
     WHERE voucher_id = p_voucher_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Voucher not found';
    END IF;

    IF v_status <> 'DRAFT' THEN
        RAISE EXCEPTION 'Only draft vouchers can be posted';
    END IF;

    SELECT COUNT(*), COALESCE(SUM(debit_amount), 0), COALESCE(SUM(credit_amount), 0)
      INTO v_line_count, v_debit, v_credit
      FROM erp.journal_entries
     WHERE voucher_id = p_voucher_id;

    IF v_line_count < 2 THEN
        RAISE EXCEPTION 'Voucher must contain at least two lines';
    END IF;

    IF v_debit <= 0 OR v_debit <> v_credit THEN
        RAISE EXCEPTION 'Voucher is not balanced. Debit %, credit %', v_debit, v_credit;
    END IF;

    UPDATE erp.journal_vouchers
       SET status = 'POSTED',
           posted_by = p_user_id,
           posted_at = NOW()
     WHERE voucher_id = p_voucher_id;
END;
$$;

COMMIT;
