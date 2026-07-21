BEGIN;

/* =========================================================
   Draft workflow metadata and stronger immutability
   ========================================================= */
ALTER TABLE erp.journal_vouchers
    ADD COLUMN IF NOT EXISTS updated_by UUID,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS draft_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS cancellation_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_vouchers_company_status_date
    ON erp.journal_vouchers(company_id, status, posting_date DESC, created_at DESC);

CREATE OR REPLACE FUNCTION erp.prevent_non_draft_voucher_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status <> 'DRAFT' THEN
        RAISE EXCEPTION 'Only draft vouchers can be changed or deleted';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        NEW.updated_at := NOW();
        NEW.draft_version := OLD.draft_version + 1;
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_posted_voucher_change ON erp.journal_vouchers;
DROP TRIGGER IF EXISTS trg_prevent_non_draft_voucher_change ON erp.journal_vouchers;
CREATE TRIGGER trg_prevent_non_draft_voucher_change
BEFORE UPDATE OR DELETE ON erp.journal_vouchers
FOR EACH ROW EXECUTE FUNCTION erp.prevent_non_draft_voucher_change();

CREATE OR REPLACE FUNCTION erp.prevent_non_draft_entry_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_status VARCHAR(12);
    v_voucher UUID;
BEGIN
    v_voucher := CASE WHEN TG_OP = 'DELETE' THEN OLD.voucher_id ELSE NEW.voucher_id END;
    SELECT status INTO v_status FROM erp.journal_vouchers WHERE voucher_id = v_voucher;
    IF v_status IS DISTINCT FROM 'DRAFT' THEN
        RAISE EXCEPTION 'Only entries of a draft voucher can be changed';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_posted_entry_change ON erp.journal_entries;
DROP TRIGGER IF EXISTS trg_prevent_non_draft_entry_change ON erp.journal_entries;
CREATE TRIGGER trg_prevent_non_draft_entry_change
BEFORE INSERT OR UPDATE OR DELETE ON erp.journal_entries
FOR EACH ROW EXECUTE FUNCTION erp.prevent_non_draft_entry_change();

/* =========================================================
   Optional transaction-currency fields for GL/opening balances
   Base debit/credit remain the statutory EGP ledger values.
   ========================================================= */
ALTER TABLE erp.journal_entries
    ADD COLUMN IF NOT EXISTS currency CHAR(3),
    ADD COLUMN IF NOT EXISTS exchange_rate NUMERIC(20,10) NOT NULL DEFAULT 1 CHECK (exchange_rate > 0),
    ADD COLUMN IF NOT EXISTS foreign_debit NUMERIC(20,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS foreign_credit NUMERIC(20,4) NOT NULL DEFAULT 0;

UPDATE erp.journal_entries
SET currency = COALESCE(currency, 'EGP'),
    foreign_debit = CASE WHEN foreign_debit = 0 THEN debit_amount ELSE foreign_debit END,
    foreign_credit = CASE WHEN foreign_credit = 0 THEN credit_amount ELSE foreign_credit END
WHERE currency IS NULL OR (foreign_debit = 0 AND debit_amount <> 0) OR (foreign_credit = 0 AND credit_amount <> 0);

ALTER TABLE erp.journal_entries
    ALTER COLUMN currency SET DEFAULT 'EGP';

/* =========================================================
   Opening balance batches. Financial lines live in the linked
   OPENING journal voucher to preserve one source of truth.
   ========================================================= */
CREATE TABLE IF NOT EXISTS erp.opening_balance_batches (
    opening_batch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    batch_no VARCHAR(50) NOT NULL,
    opening_date DATE NOT NULL,
    description TEXT,
    voucher_id UUID NOT NULL,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, batch_no),
    UNIQUE (voucher_id),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (voucher_id, company_id, group_id)
      REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_opening_batches_company_date
    ON erp.opening_balance_batches(company_id, opening_date DESC);

/* Populate explicit role permissions for existing users when their
   custom list is empty. The API still applies secure role defaults. */
UPDATE erp.app_users
SET permissions = CASE role_code
    WHEN 'FINANCE_MANAGER' THEN '["ACCOUNT_MANAGE","CURRENCY_MANAGE","VOUCHER_CREATE","VOUCHER_EDIT","VOUCHER_DELETE","VOUCHER_POST","OPENING_BALANCE_CREATE","REPORT_VIEW","PARTY_MANAGE","BANK_MANAGE","ASSET_MANAGE"]'::jsonb
    WHEN 'ACCOUNTANT' THEN '["VOUCHER_CREATE","VOUCHER_EDIT","VOUCHER_DELETE","OPENING_BALANCE_CREATE","REPORT_VIEW","PARTY_MANAGE","BANK_MANAGE","ASSET_MANAGE"]'::jsonb
    WHEN 'REVIEWER' THEN '["VOUCHER_POST","REPORT_VIEW"]'::jsonb
    WHEN 'VIEWER' THEN '["REPORT_VIEW"]'::jsonb
    ELSE permissions
END
WHERE permissions = '[]'::jsonb;

COMMIT;
