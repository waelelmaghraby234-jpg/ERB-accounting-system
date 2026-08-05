BEGIN;

ALTER TABLE erp.corporate_groups
    ADD COLUMN IF NOT EXISTS group_name_en VARCHAR(250);

ALTER TABLE erp.companies
    ADD COLUMN IF NOT EXISTS company_name_en VARCHAR(250),
    ADD COLUMN IF NOT EXISTS legal_name_en VARCHAR(250);

ALTER TABLE erp.group_accounts
    ADD COLUMN IF NOT EXISTS account_name_en VARCHAR(250),
    ADD COLUMN IF NOT EXISTS ifrs_line_name_en VARCHAR(250);

ALTER TABLE erp.accounts
    ADD COLUMN IF NOT EXISTS local_account_name_en VARCHAR(250);

ALTER TABLE erp.branches
    ADD COLUMN IF NOT EXISTS branch_name_en VARCHAR(250);

ALTER TABLE erp.cost_centers
    ADD COLUMN IF NOT EXISTS center_name_en VARCHAR(250);

ALTER TABLE erp.parties
    ADD COLUMN IF NOT EXISTS party_name_en VARCHAR(250);

ALTER TABLE erp.asset_categories
    ADD COLUMN IF NOT EXISTS category_name_en VARCHAR(250);

ALTER TABLE erp.fixed_assets
    ADD COLUMN IF NOT EXISTS asset_name_en VARCHAR(250);

WITH english_names(account_code, account_name_en) AS (
    VALUES
    ('100000','Assets'),
('110000','Current assets'),
('111000','Cash on hand'),
('112000','Banks'),
('113000','Trade receivables'),
('114000','Input VAT'),
('115000','Due from group companies'),
('120000','Non-current assets'),
('121000','Land and buildings'),
('122000','Furniture and fixtures'),
('123000','Vehicles'),
('124000','Accumulated depreciation'),
('125000','Investments in subsidiaries'),
('200000','Liabilities'),
('210000','Current liabilities'),
('211000','Trade payables'),
('212000','Accrued expenses'),
('213000','Output VAT'),
('214000','Due to group companies'),
('300000','Equity'),
('311000','Share capital'),
('312000','Retained earnings'),
('313000','Current year profit or loss'),
('400000','Revenue'),
('411000','Hotel revenue'),
('412000','Development revenue'),
('413000','Management and service revenue'),
('414000','Foreign exchange gains'),
('419000','Intercompany revenue'),
('500000','Expenses'),
('511000','Operating costs'),
('512000','Salaries and wages'),
('513000','Rent expense'),
('514000','Utilities and energy'),
('515000','Marketing expenses'),
('516000','Depreciation expense'),
('517000','Bank charges'),
('518000','General and administrative expenses'),
('519000','Intercompany expenses'),
('520000','Foreign exchange losses'),
('110100','Cash and cash equivalents'),
('110110','Cash funds and imprests'),
('110111','Main cash fund'),
('110112','Branch cash funds'),
('110113','Cash imprests'),
('110120','Bank accounts'),
('110121','Local-currency bank accounts'),
('110122','Foreign-currency bank accounts'),
('110200','Trade receivables and notes receivable'),
('110210','Local customers'),
('110220','Foreign customers'),
('110230','Notes receivable'),
('110240','Expected credit loss allowance'),
('110300','Inventories'),
('110310','Raw materials and supplies'),
('110320','Work in progress'),
('110330','Finished goods'),
('110340','Spare parts and consumables'),
('110400','Other current assets'),
('110410','Prepaid expenses'),
('110420','Deposits with third parties'),
('110430','Employee advances'),
('110440','Tax receivables'),
('120100','Property, plant and equipment'),
('120110','Land'),
('120120','Buildings and structures'),
('120130','Machinery and equipment'),
('120140','Vehicles and transport equipment'),
('120150','Furniture and fixtures'),
('120160','Computers and communication equipment'),
('120170','Accumulated depreciation of property, plant and equipment'),
('120171','Accumulated depreciation — buildings'),
('120172','Accumulated depreciation — machinery and equipment'),
('120173','Accumulated depreciation — vehicles'),
('120174','Accumulated depreciation — furniture and fixtures'),
('120200','Capital work in progress'),
('120210','Construction work in progress'),
('120220','Equipment under installation'),
('120230','Capital design and consultancy fees'),
('120240','Advances to contractors'),
('120300','Intangible assets'),
('120310','Software and systems'),
('120320','Licences and rights of use'),
('120330','Accumulated amortisation of intangible assets'),
('210100','Trade payables and notes payable'),
('210110','Local vendors'),
('210120','Foreign vendors'),
('210130','Notes payable'),
('210200','Accrued expenses and liabilities'),
('210210','Accrued salaries and wages'),
('210220','Accrued interest'),
('210230','Accrued operating expenses'),
('210300','Taxes and social insurance payable'),
('210310','VAT payable'),
('210320','Payroll tax payable'),
('210330','Social insurance payable'),
('210400','Short-term loans and facilities'),
('210410','Short-term bank loans'),
('210420','Bank overdrafts'),
('210430','Current portion of long-term borrowings'),
('220000','Non-current liabilities'),
('220100','Long-term borrowings'),
('220110','Long-term bank loans'),
('220120','Asset finance loans'),
('220130','Lease liabilities'),
('220200','Long-term provisions'),
('220210','End-of-service benefits provision'),
('220220','Claims and obligations provision'),
('310000','Capital and reserves'),
('310100','Paid-up capital'),
('310200','Legal reserve'),
('310300','Other reserves'),
('320000','Retained earnings and accumulated losses'),
('320100','Retained earnings'),
('320200','Current-period result'),
('410000','Operating revenue'),
('410100','Rooms and accommodation revenue'),
('410200','Food and beverage revenue'),
('410300','Development and contracting revenue'),
('410400','Management and service revenue'),
('420000','Other income'),
('420100','Interest income'),
('420200','Gain on disposal of assets'),
('420300','Foreign exchange gains'),
('510000','Cost of revenue'),
('510100','Hotel operating costs'),
('510200','Development and contracting costs'),
('510300','Direct labour costs'),
('530000','Operating expenses'),
('530100','Salaries and wages'),
('530110','Basic salaries'),
('530120','Bonuses and allowances'),
('530130','Social insurance and employee benefits'),
('530200','Utilities and energy'),
('530210','Electricity'),
('530220','Water'),
('530230','Gas and fuel'),
('530300','Repairs and maintenance'),
('530310','Building maintenance'),
('530320','Equipment maintenance'),
('530330','Spare parts'),
('540000','General and administrative expenses'),
('540100','Rent expense'),
('540200','Telecommunications and internet'),
('540300','Professional and consultancy fees'),
('540400','Marketing and advertising'),
('540500','Travel and transportation'),
('540600','Office supplies and printing'),
('550000','Finance costs'),
('550100','Loan interest'),
('550200','Bank charges and commissions'),
('550300','Foreign exchange losses'),
('560000','Depreciation and amortisation'),
('560100','Depreciation expense — property, plant and equipment'),
('560200','Amortisation expense — intangible assets')
)
UPDATE erp.group_accounts ga
SET account_name_en = e.account_name_en
FROM english_names e
WHERE ga.account_code=e.account_code
  AND (ga.account_name_en IS NULL OR BTRIM(ga.account_name_en)='');

UPDATE erp.accounts a
SET local_account_name_en=ga.account_name_en
FROM erp.group_accounts ga
WHERE ga.group_account_id=a.group_account_id
  AND ga.group_id=a.group_id
  AND (a.local_account_name_en IS NULL OR BTRIM(a.local_account_name_en)='');

UPDATE erp.companies SET company_name_en='Cairo Group Holding', legal_name_en=COALESCE(legal_name_en,'Cairo Group Holding')
WHERE company_code='HOLD' AND (company_name_en IS NULL OR BTRIM(company_name_en)='');
UPDATE erp.companies SET company_name_en='Hotels Company', legal_name_en=COALESCE(legal_name_en,'Hotels Company')
WHERE company_code='HOTE' AND (company_name_en IS NULL OR BTRIM(company_name_en)='');
UPDATE erp.companies SET company_name_en='Development Company', legal_name_en=COALESCE(legal_name_en,'Development Company')
WHERE company_code='DEV' AND (company_name_en IS NULL OR BTRIM(company_name_en)='');
UPDATE erp.companies SET company_name_en='Management Company', legal_name_en=COALESCE(legal_name_en,'Management Company')
WHERE company_code='MGT' AND (company_name_en IS NULL OR BTRIM(company_name_en)='');
UPDATE erp.companies SET company_name_en='Group Eliminations', legal_name_en=COALESCE(legal_name_en,'Group Eliminations')
WHERE company_code='ELIM' AND (company_name_en IS NULL OR BTRIM(company_name_en)='');

UPDATE erp.branches SET branch_name_en='Head Office'
WHERE branch_code='MAIN' AND (branch_name_en IS NULL OR BTRIM(branch_name_en)='');

UPDATE erp.cost_centers SET center_name_en='General Cost Centre'
WHERE center_code='GENERAL' AND (center_name_en IS NULL OR BTRIM(center_name_en)='');

WITH ifrs_names(ifrs_line_code, line_name_en) AS (
    VALUES
    ('CASH_AND_CASH_EQUIVALENTS','Cash and cash equivalents'),
('TRADE_RECEIVABLES','Trade receivables and notes receivable'),
('INVENTORIES','Inventories'),
('OTHER_CURRENT_ASSETS','Other current assets'),
('PROPERTY_PLANT_EQUIPMENT','Property, plant and equipment'),
('CAPITAL_WORK_IN_PROGRESS','Capital work in progress'),
('INTANGIBLE_ASSETS','Intangible assets'),
('TRADE_PAYABLES','Trade payables and notes payable'),
('ACCRUALS','Accrued expenses and liabilities'),
('TAXES_PAYABLE','Taxes and social insurance payable'),
('SHORT_TERM_BORROWINGS','Short-term borrowings and facilities'),
('LONG_TERM_BORROWINGS','Long-term borrowings and finance liabilities'),
('LONG_TERM_PROVISIONS','Long-term provisions'),
('CAPITAL_RESERVES','Capital and reserves'),
('RETAINED_EARNINGS','Retained earnings and accumulated losses'),
('OPERATING_REVENUE','Operating revenue'),
('OTHER_INCOME','Other income'),
('COST_OF_SALES','Cost of revenue'),
('OPERATING_EXPENSE','Operating expenses'),
('ADMIN_EXPENSE','General and administrative expenses'),
('FINANCE_COST','Finance costs'),
('DEPRECIATION_AMORTISATION','Depreciation and amortisation'),
('INCOME_TAX','Income tax expense')
)
UPDATE erp.group_accounts ga
SET ifrs_line_name_en=n.line_name_en
FROM ifrs_names n
WHERE ga.ifrs_line_code=n.ifrs_line_code
  AND (ga.ifrs_line_name_en IS NULL OR BTRIM(ga.ifrs_line_name_en)='');

UPDATE erp.group_accounts
SET ifrs_line_name_en=COALESCE(ifrs_line_name_en, account_name_en, account_name)
WHERE ifrs_line_name_en IS NULL OR BTRIM(ifrs_line_name_en)='';

COMMIT;
