BEGIN;

/* Management metadata used by the editable company/user/chart screens. */
ALTER TABLE erp.corporate_groups
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE erp.companies
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE erp.group_accounts
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE erp.app_users
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

/* Journal-register filters: company, date, status and account. */
CREATE INDEX IF NOT EXISTS idx_vouchers_register
    ON erp.journal_vouchers(group_id, company_id, posting_date, status, voucher_no);
CREATE INDEX IF NOT EXISTS idx_entries_register
    ON erp.journal_entries(group_id, company_id, account_id, voucher_id, line_no);

COMMIT;
