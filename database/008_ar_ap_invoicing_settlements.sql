BEGIN;

/* =========================================================
   AR/AP invoices, payment methods and invoice settlements
   Version 0.8.0
   ========================================================= */

ALTER TABLE erp.invoices
    ADD COLUMN IF NOT EXISTS payment_method VARCHAR(10) NOT NULL DEFAULT 'CREDIT',
    ADD COLUMN IF NOT EXISTS settlement_account_id UUID,
    ADD COLUMN IF NOT EXISTS bank_account_id UUID,
    ADD COLUMN IF NOT EXISTS paid_amount NUMERIC(20,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS base_paid_amount NUMERIC(20,4) NOT NULL DEFAULT 0;

UPDATE erp.invoices
SET paid_amount = CASE WHEN status = 'PAID' THEN total_amount ELSE COALESCE(paid_amount, 0) END,
    base_paid_amount = CASE WHEN status = 'PAID' THEN base_total_amount ELSE COALESCE(base_paid_amount, 0) END,
    payment_method = COALESCE(payment_method, 'CREDIT');

ALTER TABLE erp.invoices DROP CONSTRAINT IF EXISTS invoices_status_check;
ALTER TABLE erp.invoices DROP CONSTRAINT IF EXISTS invoices_payment_method_check;
ALTER TABLE erp.invoices
    ADD CONSTRAINT invoices_status_check
        CHECK (status IN ('DRAFT','POSTED','PARTIALLY_PAID','PAID','CANCELLED')),
    ADD CONSTRAINT invoices_payment_method_check
        CHECK (payment_method IN ('CREDIT','CASH','BANK'));

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_invoices_settlement_account'
          AND conrelid = 'erp.invoices'::regclass
    ) THEN
        ALTER TABLE erp.invoices
            ADD CONSTRAINT fk_invoices_settlement_account
            FOREIGN KEY (settlement_account_id, company_id, group_id)
            REFERENCES erp.accounts(account_id, company_id, group_id)
            ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_invoices_bank_account'
          AND conrelid = 'erp.invoices'::regclass
    ) THEN
        ALTER TABLE erp.invoices
            ADD CONSTRAINT fk_invoices_bank_account
            FOREIGN KEY (bank_account_id, company_id, group_id)
            REFERENCES erp.bank_accounts(bank_account_id, company_id, group_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS erp.invoice_payments (
    invoice_payment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    invoice_id UUID NOT NULL,
    payment_no VARCHAR(50) NOT NULL,
    payment_date DATE NOT NULL,
    payment_method VARCHAR(10) NOT NULL CHECK (payment_method IN ('CASH','BANK')),
    settlement_account_id UUID NOT NULL,
    bank_account_id UUID,
    amount NUMERIC(20,4) NOT NULL CHECK (amount > 0),
    currency CHAR(3) NOT NULL,
    exchange_rate NUMERIC(18,8) NOT NULL CHECK (exchange_rate > 0),
    base_amount NUMERIC(20,4) NOT NULL CHECK (base_amount > 0),
    reference_no VARCHAR(150),
    description TEXT,
    status VARCHAR(12) NOT NULL DEFAULT 'POSTED' CHECK (status IN ('POSTED','CANCELLED')),
    voucher_id UUID NOT NULL,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (invoice_id, payment_no),
    UNIQUE (invoice_payment_id, company_id, group_id),
    FOREIGN KEY (invoice_id, company_id, group_id)
      REFERENCES erp.invoices(invoice_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (settlement_account_id, company_id, group_id)
      REFERENCES erp.accounts(account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (bank_account_id, company_id, group_id)
      REFERENCES erp.bank_accounts(bank_account_id, company_id, group_id) ON DELETE RESTRICT,
    FOREIGN KEY (voucher_id, company_id, group_id)
      REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_invoice_payments_invoice
    ON erp.invoice_payments (invoice_id, payment_date);
CREATE INDEX IF NOT EXISTS idx_invoice_payments_company_date
    ON erp.invoice_payments (company_id, payment_date);

COMMIT;
