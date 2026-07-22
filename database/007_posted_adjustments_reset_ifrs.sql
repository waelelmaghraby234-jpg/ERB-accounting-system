BEGIN;

/* =========================================================
   Safe correction of posted vouchers
   Posted vouchers remain immutable. Corrections are represented by
   a posted reversing voucher and, optionally, a new editable draft.
   ========================================================= */
ALTER TABLE erp.journal_vouchers
    ADD COLUMN IF NOT EXISTS reversal_of_voucher_id UUID,
    ADD COLUMN IF NOT EXISTS correction_of_voucher_id UUID,
    ADD COLUMN IF NOT EXISTS action_reason TEXT,
    ADD COLUMN IF NOT EXISTS test_unposted_by UUID,
    ADD COLUMN IF NOT EXISTS test_unposted_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_voucher_reversal_of') THEN
        ALTER TABLE erp.journal_vouchers
          ADD CONSTRAINT fk_voucher_reversal_of
          FOREIGN KEY (reversal_of_voucher_id, company_id, group_id)
          REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id)
          ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_voucher_correction_of') THEN
        ALTER TABLE erp.journal_vouchers
          ADD CONSTRAINT fk_voucher_correction_of
          FOREIGN KEY (correction_of_voucher_id, company_id, group_id)
          REFERENCES erp.journal_vouchers(voucher_id, company_id, group_id)
          ON DELETE RESTRICT;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_one_reversal_per_voucher
    ON erp.journal_vouchers(reversal_of_voucher_id)
    WHERE reversal_of_voucher_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_voucher_correction_links
    ON erp.journal_vouchers(company_id, reversal_of_voucher_id, correction_of_voucher_id);

/* Controlled test-only unposting and company reset. */
CREATE OR REPLACE FUNCTION erp.prevent_non_draft_voucher_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_reset BOOLEAN := COALESCE(current_setting('erp.company_reset', TRUE), '') = 'on';
    v_unpost BOOLEAN := COALESCE(current_setting('erp.allow_test_unpost', TRUE), '') = 'on';
BEGIN
    IF v_reset THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;

    IF OLD.status <> 'DRAFT' THEN
        IF TG_OP = 'UPDATE'
           AND v_unpost
           AND OLD.status = 'POSTED'
           AND NEW.status = 'DRAFT'
           AND NEW.voucher_id = OLD.voucher_id
           AND NEW.company_id = OLD.company_id
           AND NEW.group_id = OLD.group_id
        THEN
            NEW.updated_at := NOW();
            NEW.draft_version := OLD.draft_version + 1;
            RETURN NEW;
        END IF;
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

CREATE OR REPLACE FUNCTION erp.prevent_non_draft_entry_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_status VARCHAR(12);
    v_voucher UUID;
    v_reset BOOLEAN := COALESCE(current_setting('erp.company_reset', TRUE), '') = 'on';
BEGIN
    IF v_reset THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    v_voucher := CASE WHEN TG_OP = 'DELETE' THEN OLD.voucher_id ELSE NEW.voucher_id END;
    SELECT status INTO v_status FROM erp.journal_vouchers WHERE voucher_id = v_voucher;
    IF v_status IS DISTINCT FROM 'DRAFT' THEN
        RAISE EXCEPTION 'Only entries of a draft voucher can be changed';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_non_draft_voucher_change ON erp.journal_vouchers;
CREATE TRIGGER trg_prevent_non_draft_voucher_change
BEFORE UPDATE OR DELETE ON erp.journal_vouchers
FOR EACH ROW EXECUTE FUNCTION erp.prevent_non_draft_voucher_change();

DROP TRIGGER IF EXISTS trg_prevent_non_draft_entry_change ON erp.journal_entries;
CREATE TRIGGER trg_prevent_non_draft_entry_change
BEFORE INSERT OR UPDATE OR DELETE ON erp.journal_entries
FOR EACH ROW EXECUTE FUNCTION erp.prevent_non_draft_entry_change();

CREATE OR REPLACE FUNCTION erp.test_unpost_voucher(
    p_voucher_id UUID,
    p_user_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_status VARCHAR(12);
    v_source VARCHAR(30);
    v_has_links BOOLEAN;
BEGIN
    SELECT status, source_module
      INTO v_status, v_source
      FROM erp.journal_vouchers
     WHERE voucher_id = p_voucher_id
     FOR UPDATE;

    IF NOT FOUND THEN RAISE EXCEPTION 'Voucher not found'; END IF;
    IF v_status <> 'POSTED' THEN RAISE EXCEPTION 'Only posted vouchers can be returned to draft'; END IF;
    IF v_source <> 'GL' THEN RAISE EXCEPTION 'System-generated vouchers must be corrected by reversal'; END IF;

    SELECT EXISTS(
        SELECT 1 FROM erp.journal_vouchers WHERE reversal_of_voucher_id = p_voucher_id
        UNION ALL SELECT 1 FROM erp.invoices WHERE voucher_id = p_voucher_id
        UNION ALL SELECT 1 FROM erp.cash_transactions WHERE voucher_id = p_voucher_id
        UNION ALL SELECT 1 FROM erp.asset_depreciation_entries WHERE voucher_id = p_voucher_id
        UNION ALL SELECT 1 FROM erp.bank_revaluations WHERE voucher_id = p_voucher_id
        UNION ALL SELECT 1 FROM erp.opening_balance_batches WHERE voucher_id = p_voucher_id
    ) INTO v_has_links;

    IF v_has_links THEN
        RAISE EXCEPTION 'Voucher has linked documents or a reversal and cannot be unposted';
    END IF;

    PERFORM set_config('erp.allow_test_unpost', 'on', TRUE);
    UPDATE erp.journal_vouchers
       SET status = 'DRAFT',
           posted_by = NULL,
           posted_at = NULL,
           test_unposted_by = p_user_id,
           test_unposted_at = NOW()
     WHERE voucher_id = p_voucher_id;
END;
$$;

/* =========================================================
   Company reset audit trail
   ========================================================= */
CREATE TABLE IF NOT EXISTS erp.company_data_resets (
    reset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,
    company_id UUID NOT NULL,
    reset_mode VARCHAR(30) NOT NULL CHECK (reset_mode IN ('FINANCIAL_ONLY','FULL_PRESERVE_CHART')),
    counts_before JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_by UUID,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (company_id, group_id)
      REFERENCES erp.companies(company_id, group_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_company_resets_company_date
    ON erp.company_data_resets(company_id, created_at DESC);

/* =========================================================
   IFRS-oriented presentation metadata
   IAS 1 is the default for periods beginning before 1 Jan 2027.
   IFRS 18 can be selected for early adoption / periods from 2027.
   ========================================================= */
ALTER TABLE erp.corporate_groups
    ADD COLUMN IF NOT EXISTS financial_statement_standard VARCHAR(20) NOT NULL DEFAULT 'IAS1_2026'
      CHECK (financial_statement_standard IN ('IAS1_2026','IFRS18_2027'));

ALTER TABLE erp.group_accounts
    ADD COLUMN IF NOT EXISTS ifrs_category VARCHAR(30),
    ADD COLUMN IF NOT EXISTS ifrs_line_code VARCHAR(30),
    ADD COLUMN IF NOT EXISTS ifrs_line_name_ar VARCHAR(250),
    ADD COLUMN IF NOT EXISTS ifrs_sort_order INTEGER;

/* Assets */
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_ASSET', ifrs_line_code='CASH_EQUIVALENTS',
    ifrs_line_name_ar='النقدية وما في حكمها', ifrs_sort_order=110
WHERE account_code LIKE '1101%';
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_ASSET', ifrs_line_code='TRADE_RECEIVABLES',
    ifrs_line_name_ar='العملاء وأوراق القبض', ifrs_sort_order=120
WHERE account_code LIKE '1102%';
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_ASSET', ifrs_line_code='INVENTORIES',
    ifrs_line_name_ar='المخزون', ifrs_sort_order=130
WHERE account_code LIKE '1103%';
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_ASSET', ifrs_line_code='OTHER_CURRENT_ASSETS',
    ifrs_line_name_ar='أصول متداولة أخرى', ifrs_sort_order=140
WHERE account_code LIKE '1104%';
UPDATE erp.group_accounts SET
    ifrs_category='NONCURRENT_ASSET', ifrs_line_code='PROPERTY_PLANT_EQUIPMENT',
    ifrs_line_name_ar='العقارات والآلات والمعدات', ifrs_sort_order=210
WHERE account_code LIKE '1201%';
UPDATE erp.group_accounts SET
    ifrs_category='NONCURRENT_ASSET', ifrs_line_code='CONSTRUCTION_IN_PROGRESS',
    ifrs_line_name_ar='مشروعات تحت التنفيذ', ifrs_sort_order=220
WHERE account_code LIKE '1202%';
UPDATE erp.group_accounts SET
    ifrs_category='NONCURRENT_ASSET', ifrs_line_code='INTANGIBLE_ASSETS',
    ifrs_line_name_ar='الأصول غير الملموسة', ifrs_sort_order=230
WHERE account_code LIKE '1203%';

/* Liabilities and equity */
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_LIABILITY', ifrs_line_code='TRADE_PAYABLES',
    ifrs_line_name_ar='الموردون وأوراق الدفع', ifrs_sort_order=310
WHERE account_code LIKE '2101%';
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_LIABILITY', ifrs_line_code='ACCRUALS',
    ifrs_line_name_ar='مصروفات والتزامات مستحقة', ifrs_sort_order=320
WHERE account_code LIKE '2102%';
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_LIABILITY', ifrs_line_code='TAX_PAYABLES',
    ifrs_line_name_ar='ضرائب وتأمينات مستحقة', ifrs_sort_order=330
WHERE account_code LIKE '2103%';
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_LIABILITY', ifrs_line_code='CURRENT_BORROWINGS',
    ifrs_line_name_ar='قروض وتسهيلات قصيرة الأجل', ifrs_sort_order=340
WHERE account_code LIKE '2104%';
UPDATE erp.group_accounts SET
    ifrs_category='NONCURRENT_LIABILITY', ifrs_line_code='NONCURRENT_BORROWINGS',
    ifrs_line_name_ar='قروض والتزامات تمويل طويلة الأجل', ifrs_sort_order=410
WHERE account_code LIKE '2201%';
UPDATE erp.group_accounts SET
    ifrs_category='NONCURRENT_LIABILITY', ifrs_line_code='NONCURRENT_PROVISIONS',
    ifrs_line_name_ar='مخصصات طويلة الأجل', ifrs_sort_order=420
WHERE account_code LIKE '2202%';
UPDATE erp.group_accounts SET
    ifrs_category='EQUITY', ifrs_line_code='SHARE_CAPITAL_RESERVES',
    ifrs_line_name_ar='رأس المال والاحتياطيات', ifrs_sort_order=510
WHERE account_code LIKE '310%';
UPDATE erp.group_accounts SET
    ifrs_category='EQUITY', ifrs_line_code='RETAINED_EARNINGS',
    ifrs_line_name_ar='الأرباح والخسائر المرحلة', ifrs_sort_order=520
WHERE account_code LIKE '320%';

/* Profit or loss categories used for current-period result. */
UPDATE erp.group_accounts SET ifrs_category='OPERATING_REVENUE', ifrs_line_code='OPERATING_REVENUE', ifrs_line_name_ar='إيرادات النشاط', ifrs_sort_order=610 WHERE account_code LIKE '41%';
UPDATE erp.group_accounts SET ifrs_category='OTHER_INCOME', ifrs_line_code='OTHER_INCOME', ifrs_line_name_ar='إيرادات أخرى', ifrs_sort_order=620 WHERE account_code LIKE '42%';
UPDATE erp.group_accounts SET ifrs_category='COST_OF_SALES', ifrs_line_code='COST_OF_SALES', ifrs_line_name_ar='تكلفة الإيرادات', ifrs_sort_order=710 WHERE account_code LIKE '51%';
UPDATE erp.group_accounts SET ifrs_category='OPERATING_EXPENSE', ifrs_line_code='OPERATING_EXPENSE', ifrs_line_name_ar='مصروفات التشغيل', ifrs_sort_order=720 WHERE account_code LIKE '53%';
UPDATE erp.group_accounts SET ifrs_category='ADMIN_EXPENSE', ifrs_line_code='ADMIN_EXPENSE', ifrs_line_name_ar='مصروفات عمومية وإدارية', ifrs_sort_order=730 WHERE account_code LIKE '54%';
UPDATE erp.group_accounts SET ifrs_category='FINANCE_COST', ifrs_line_code='FINANCE_COST', ifrs_line_name_ar='تكاليف التمويل', ifrs_sort_order=740 WHERE account_code LIKE '55%';
UPDATE erp.group_accounts SET ifrs_category='DEPRECIATION_AMORTISATION', ifrs_line_code='DEPRECIATION_AMORTISATION', ifrs_line_name_ar='الإهلاك والإطفاء', ifrs_sort_order=750 WHERE account_code LIKE '56%';

/* Conservative fallbacks for custom accounts. */
UPDATE erp.group_accounts SET ifrs_category='CURRENT_ASSET', ifrs_line_code=COALESCE(ifrs_line_code,'OTHER_CURRENT_ASSETS'), ifrs_line_name_ar=COALESCE(ifrs_line_name_ar,account_name), ifrs_sort_order=COALESCE(ifrs_sort_order,199)
WHERE account_class='ASSET' AND ifrs_category IS NULL AND account_code LIKE '11%';
UPDATE erp.group_accounts SET ifrs_category='NONCURRENT_ASSET', ifrs_line_code=COALESCE(ifrs_line_code,'OTHER_NONCURRENT_ASSETS'), ifrs_line_name_ar=COALESCE(ifrs_line_name_ar,account_name), ifrs_sort_order=COALESCE(ifrs_sort_order,299)
WHERE account_class='ASSET' AND ifrs_category IS NULL;
UPDATE erp.group_accounts SET ifrs_category='CURRENT_LIABILITY', ifrs_line_code=COALESCE(ifrs_line_code,'OTHER_CURRENT_LIABILITIES'), ifrs_line_name_ar=COALESCE(ifrs_line_name_ar,account_name), ifrs_sort_order=COALESCE(ifrs_sort_order,399)
WHERE account_class='LIABILITY' AND ifrs_category IS NULL AND account_code LIKE '21%';
UPDATE erp.group_accounts SET ifrs_category='NONCURRENT_LIABILITY', ifrs_line_code=COALESCE(ifrs_line_code,'OTHER_NONCURRENT_LIABILITIES'), ifrs_line_name_ar=COALESCE(ifrs_line_name_ar,account_name), ifrs_sort_order=COALESCE(ifrs_sort_order,499)
WHERE account_class='LIABILITY' AND ifrs_category IS NULL;
UPDATE erp.group_accounts SET ifrs_category='EQUITY', ifrs_line_code=COALESCE(ifrs_line_code,'OTHER_EQUITY'), ifrs_line_name_ar=COALESCE(ifrs_line_name_ar,account_name), ifrs_sort_order=COALESCE(ifrs_sort_order,599)
WHERE account_class='EQUITY' AND ifrs_category IS NULL;

CREATE INDEX IF NOT EXISTS idx_group_accounts_ifrs
    ON erp.group_accounts(group_id, ifrs_category, ifrs_sort_order, ifrs_line_code);

CREATE OR REPLACE FUNCTION erp.refresh_ifrs_account_mapping(p_group_id UUID)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE erp.group_accounts
       SET ifrs_category = CASE
            WHEN account_class='ASSET' AND account_code LIKE '11%' THEN 'CURRENT_ASSET'
            WHEN account_class='ASSET' THEN 'NONCURRENT_ASSET'
            WHEN account_class='LIABILITY' AND account_code LIKE '21%' THEN 'CURRENT_LIABILITY'
            WHEN account_class='LIABILITY' THEN 'NONCURRENT_LIABILITY'
            WHEN account_class='EQUITY' THEN 'EQUITY'
            WHEN account_class='REVENUE' AND account_code LIKE '42%' THEN 'OTHER_INCOME'
            WHEN account_class='REVENUE' THEN 'OPERATING_REVENUE'
            WHEN account_class='EXPENSE' AND account_code LIKE '51%' THEN 'COST_OF_SALES'
            WHEN account_class='EXPENSE' AND account_code LIKE '55%' THEN 'FINANCE_COST'
            WHEN account_class='EXPENSE' THEN 'OPERATING_EXPENSE'
            ELSE ifrs_category END,
           ifrs_line_code = COALESCE(ifrs_line_code, account_code),
           ifrs_line_name_ar = COALESCE(ifrs_line_name_ar, account_name),
           ifrs_sort_order = COALESCE(ifrs_sort_order,
                CASE account_class WHEN 'ASSET' THEN 299 WHEN 'LIABILITY' THEN 499
                                   WHEN 'EQUITY' THEN 599 WHEN 'REVENUE' THEN 699 ELSE 799 END)
     WHERE group_id=p_group_id AND ifrs_category IS NULL;
END;
$$;

SELECT erp.refresh_ifrs_account_mapping(group_id) FROM erp.corporate_groups;

COMMIT;
