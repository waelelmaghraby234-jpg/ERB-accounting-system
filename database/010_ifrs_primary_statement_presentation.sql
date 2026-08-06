BEGIN;

/* Presentation metadata for the detailed IFRS-style primary statements. */
ALTER TABLE erp.group_accounts
    ADD COLUMN IF NOT EXISTS ifrs_note_no VARCHAR(20);

/* Normalise legacy line codes used by previous releases. */
UPDATE erp.group_accounts SET ifrs_line_code='CASH_AND_CASH_EQUIVALENTS'
WHERE ifrs_line_code IN ('CASH_EQUIVALENTS','CASH_AND_CASH_EQUIVALENTS') OR account_code LIKE '1101%';
UPDATE erp.group_accounts SET ifrs_line_code='CAPITAL_WORK_IN_PROGRESS'
WHERE ifrs_line_code IN ('CONSTRUCTION_IN_PROGRESS','CAPITAL_WORK_IN_PROGRESS') OR account_code LIKE '1202%';
UPDATE erp.group_accounts SET ifrs_line_code='TAXES_PAYABLE'
WHERE ifrs_line_code IN ('TAX_PAYABLES','TAXES_PAYABLE') OR account_code LIKE '2103%';
UPDATE erp.group_accounts SET ifrs_line_code='SHORT_TERM_BORROWINGS'
WHERE ifrs_line_code IN ('CURRENT_BORROWINGS','SHORT_TERM_BORROWINGS') OR account_code LIKE '2104%';
UPDATE erp.group_accounts SET ifrs_line_code='LONG_TERM_BORROWINGS'
WHERE ifrs_line_code IN ('NONCURRENT_BORROWINGS','LONG_TERM_BORROWINGS') OR account_code LIKE '2201%';
UPDATE erp.group_accounts SET ifrs_line_code='LONG_TERM_PROVISIONS'
WHERE ifrs_line_code IN ('NONCURRENT_PROVISIONS','LONG_TERM_PROVISIONS') OR account_code LIKE '2202%';
UPDATE erp.group_accounts SET ifrs_line_code='CAPITAL_RESERVES'
WHERE ifrs_line_code IN ('SHARE_CAPITAL_RESERVES','CAPITAL_RESERVES') OR account_code LIKE '310%';

/* Compatibility mapping for the original compact group chart. */
UPDATE erp.group_accounts SET ifrs_category='CURRENT_ASSET',ifrs_line_code='CASH_AND_CASH_EQUIVALENTS',ifrs_line_name_ar='نقدية بالبنوك والصندوق',ifrs_line_name_en='Cash and cash equivalents',ifrs_sort_order=110,ifrs_note_no='7' WHERE account_code IN ('111000','112000');
UPDATE erp.group_accounts SET ifrs_category='CURRENT_ASSET',ifrs_line_code='TRADE_RECEIVABLES',ifrs_line_name_ar='عملاء ومدينون وأرصدة مدينة أخرى',ifrs_line_name_en='Trade and other receivables',ifrs_sort_order=120,ifrs_note_no='5' WHERE account_code='113000';
UPDATE erp.group_accounts SET ifrs_category='CURRENT_ASSET',ifrs_line_code='OTHER_CURRENT_ASSETS',ifrs_line_name_ar='أصول متداولة أخرى',ifrs_line_name_en='Other current assets',ifrs_sort_order=140,ifrs_note_no='5' WHERE account_code='114000';
UPDATE erp.group_accounts SET ifrs_category='NONCURRENT_ASSET',ifrs_line_code='PROPERTY_PLANT_EQUIPMENT',ifrs_line_name_ar='الأصول الثابتة (بالصافي)',ifrs_line_name_en='Property, plant and equipment, net',ifrs_sort_order=210,ifrs_note_no='2' WHERE account_code IN ('121000','122000','123000','124000');
UPDATE erp.group_accounts SET ifrs_category='NONCURRENT_ASSET',ifrs_line_code='INVESTMENTS',ifrs_line_name_ar='استثمارات طويلة الأجل',ifrs_line_name_en='Long-term investments',ifrs_sort_order=240,ifrs_note_no='3' WHERE account_code='125000';
UPDATE erp.group_accounts SET ifrs_category='CURRENT_LIABILITY',ifrs_line_code='TRADE_PAYABLES',ifrs_line_name_ar='موردون وأوراق دفع',ifrs_line_name_en='Trade payables and notes payable',ifrs_sort_order=310,ifrs_note_no='9' WHERE account_code='211000';
UPDATE erp.group_accounts SET ifrs_category='CURRENT_LIABILITY',ifrs_line_code='ACCRUALS',ifrs_line_name_ar='دائنون وأرصدة دائنة أخرى',ifrs_line_name_en='Accrued and other current liabilities',ifrs_sort_order=320,ifrs_note_no='11' WHERE account_code='212000';
UPDATE erp.group_accounts SET ifrs_category='CURRENT_LIABILITY',ifrs_line_code='TAXES_PAYABLE',ifrs_line_name_ar='ضرائب مستحقة',ifrs_line_name_en='Taxes payable',ifrs_sort_order=330,ifrs_note_no='11' WHERE account_code='213000';
UPDATE erp.group_accounts SET ifrs_category='EQUITY',ifrs_line_code='CAPITAL_RESERVES',ifrs_line_name_ar='رأس المال المصدر والمدفوع',ifrs_line_name_en='Issued and paid-up capital',ifrs_sort_order=510,ifrs_note_no='8' WHERE account_code='311000';
UPDATE erp.group_accounts SET ifrs_category='EQUITY',ifrs_line_code='RETAINED_EARNINGS',ifrs_line_name_ar='أرباح / (خسائر) مرحلة',ifrs_line_name_en='Retained earnings / (accumulated losses)',ifrs_sort_order=540,ifrs_note_no='8' WHERE account_code IN ('312000','313000');

/* Compatibility mapping for compact profit-or-loss accounts. */
UPDATE erp.group_accounts SET ifrs_category='OTHER_INCOME',ifrs_line_code='OTHER_INCOME',ifrs_line_name_ar='إيرادات أخرى',ifrs_line_name_en='Other income',ifrs_sort_order=740,ifrs_note_no='15' WHERE account_code='414000';
UPDATE erp.group_accounts SET ifrs_category='COST_OF_SALES',ifrs_line_code='COST_OF_SALES',ifrs_line_name_ar='تكلفة النشاط / الإيرادات',ifrs_line_name_en='Cost of activity / revenue',ifrs_sort_order=710,ifrs_note_no='13' WHERE account_code='511000';
UPDATE erp.group_accounts SET ifrs_category='OPERATING_EXPENSE',ifrs_line_code='OPERATING_EXPENSE',ifrs_line_name_ar='مصروفات تشغيلية',ifrs_line_name_en='Operating expenses',ifrs_sort_order=720,ifrs_note_no='13' WHERE account_code IN ('512000','513000','514000','515000','519000');
UPDATE erp.group_accounts SET ifrs_category='DEPRECIATION_AMORTISATION',ifrs_line_code='DEPRECIATION_AMORTISATION',ifrs_line_name_ar='إهلاك وإطفاء الأصول',ifrs_line_name_en='Depreciation and amortisation',ifrs_sort_order=730,ifrs_note_no='14' WHERE account_code='516000';
UPDATE erp.group_accounts SET ifrs_category='FINANCE_COST',ifrs_line_code='FINANCE_COST',ifrs_line_name_ar='تكاليف التمويل',ifrs_line_name_en='Finance costs',ifrs_sort_order=750,ifrs_note_no='15' WHERE account_code IN ('517000','520000');
UPDATE erp.group_accounts SET ifrs_category='ADMIN_EXPENSE',ifrs_line_code='ADMIN_EXPENSE',ifrs_line_name_ar='مصروفات إدارية وعمومية',ifrs_line_name_en='General and administrative expenses',ifrs_sort_order=725,ifrs_note_no='13' WHERE account_code='518000';

/* Detailed line mapping modelled on a comparative statutory financial statement. */
UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_ASSET', ifrs_line_code='RELATED_PARTY_RECEIVABLES',
    ifrs_line_name_ar='مستحق من أطراف ذات علاقة', ifrs_line_name_en='Due from related parties',
    ifrs_sort_order=135, ifrs_note_no='6'
WHERE account_code='115000' OR intercompany_role='DUE_FROM';

UPDATE erp.group_accounts SET
    ifrs_category='CURRENT_LIABILITY', ifrs_line_code='RELATED_PARTY_PAYABLES',
    ifrs_line_name_ar='مستحق إلى أطراف ذات علاقة', ifrs_line_name_en='Due to related parties',
    ifrs_sort_order=325, ifrs_note_no='10'
WHERE account_code='214000' OR intercompany_role='DUE_TO';

UPDATE erp.group_accounts SET ifrs_note_no='2' WHERE ifrs_line_code='PROPERTY_PLANT_EQUIPMENT';
UPDATE erp.group_accounts SET ifrs_note_no='3' WHERE ifrs_line_code='CAPITAL_WORK_IN_PROGRESS';
UPDATE erp.group_accounts SET ifrs_note_no='4' WHERE ifrs_line_code='INVENTORIES';
UPDATE erp.group_accounts SET ifrs_note_no='5' WHERE ifrs_line_code='TRADE_RECEIVABLES';
UPDATE erp.group_accounts SET ifrs_note_no='7' WHERE ifrs_line_code='CASH_AND_CASH_EQUIVALENTS';
UPDATE erp.group_accounts SET ifrs_note_no='8' WHERE ifrs_line_code IN ('CAPITAL_RESERVES','RETAINED_EARNINGS');
UPDATE erp.group_accounts SET ifrs_note_no='9' WHERE ifrs_line_code='TRADE_PAYABLES';
UPDATE erp.group_accounts SET ifrs_note_no='11' WHERE ifrs_line_code IN ('ACCRUALS','TAXES_PAYABLE','OTHER_CURRENT_LIABILITIES','SHORT_TERM_BORROWINGS');
UPDATE erp.group_accounts SET ifrs_note_no='12' WHERE ifrs_category='OPERATING_REVENUE';
UPDATE erp.group_accounts SET ifrs_note_no='13' WHERE ifrs_category IN ('COST_OF_SALES','OPERATING_EXPENSE','ADMIN_EXPENSE');
UPDATE erp.group_accounts SET ifrs_note_no='14' WHERE ifrs_category='DEPRECIATION_AMORTISATION';
UPDATE erp.group_accounts SET ifrs_note_no='15' WHERE ifrs_category IN ('OTHER_INCOME','FINANCE_COST','FINANCE_INCOME');
UPDATE erp.group_accounts SET ifrs_note_no='16' WHERE ifrs_category='INCOME_TAX';

/* Interest income is shown separately from other income. */
UPDATE erp.group_accounts SET
    ifrs_category='FINANCE_INCOME', ifrs_line_code='FINANCE_INCOME',
    ifrs_line_name_ar='إيرادات تمويلية', ifrs_line_name_en='Finance income',
    ifrs_sort_order=735, ifrs_note_no='15'
WHERE account_code='420100';

UPDATE erp.group_accounts SET
    ifrs_category='OTHER_INCOME', ifrs_line_code='OTHER_INCOME',
    ifrs_line_name_ar='إيرادات أخرى', ifrs_line_name_en='Other income',
    ifrs_sort_order=740, ifrs_note_no='15'
WHERE account_code LIKE '42%' AND account_code<>'420100';

CREATE INDEX IF NOT EXISTS idx_group_accounts_ifrs_note
    ON erp.group_accounts(group_id, ifrs_note_no, ifrs_line_code);

COMMIT;
