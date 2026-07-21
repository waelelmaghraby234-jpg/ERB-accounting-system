BEGIN;

-- Idempotent repair for installations upgraded from the starter schema.
ALTER TABLE erp.corporate_groups
    ADD COLUMN IF NOT EXISTS country_code CHAR(2) NOT NULL DEFAULT 'EG',
    ADD COLUMN IF NOT EXISTS fiscal_year_start_month SMALLINT NOT NULL DEFAULT 1;

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

UPDATE erp.corporate_groups
   SET country_code = COALESCE(country_code, 'EG'),
       fiscal_year_start_month = COALESCE(fiscal_year_start_month, 1);

UPDATE erp.app_users
   SET role_code = COALESCE(NULLIF(role_code, ''), 'GROUP_ADMIN'),
       permissions = COALESCE(permissions, '[]'::jsonb);

COMMIT;
