from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
AUTO_MIGRATE = os.environ.get("AUTO_MIGRATE", "true").lower() == "true"
SYNC_ADMIN_CREDENTIALS = os.environ.get("SYNC_ADMIN_CREDENTIALS", "true").lower() == "true"
ALLOW_COMPANY_RESET = os.environ.get("ALLOW_COMPANY_RESET", "false").lower() == "true"
ALLOW_TEST_UNPOST = os.environ.get("ALLOW_TEST_UNPOST", "false").lower() == "true"
ALGORITHM = "HS256"
MONEY = Decimal("0.0001")

ALL_PERMISSIONS = {
    "ACCOUNT_MANAGE", "CURRENCY_MANAGE", "VOUCHER_CREATE", "VOUCHER_EDIT",
    "VOUCHER_DELETE", "VOUCHER_POST", "OPENING_BALANCE_CREATE", "REPORT_VIEW",
    "PARTY_MANAGE", "BANK_MANAGE", "ASSET_MANAGE", "USER_MANAGE",
    "VOUCHER_REVERSE", "VOUCHER_UNPOST_TEST", "COMPANY_RESET",
}
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "GROUP_ADMIN": set(ALL_PERMISSIONS),
    "FINANCE_MANAGER": set(ALL_PERMISSIONS) - {"USER_MANAGE"},
    "ACCOUNTANT": {
        "VOUCHER_CREATE", "VOUCHER_EDIT", "VOUCHER_DELETE",
        "OPENING_BALANCE_CREATE", "REPORT_VIEW", "PARTY_MANAGE",
        "BANK_MANAGE", "ASSET_MANAGE",
    },
    "REVIEWER": {"VOUCHER_POST", "REPORT_VIEW", "VOUCHER_REVERSE"},
    "VIEWER": {"REPORT_VIEW"},
}

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 characters")

pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=1,
    max_size=int(os.environ.get("DB_POOL_MAX", "10")),
    kwargs={"row_factory": dict_row},
    open=False,
)


def money(value: Decimal | float | int | str) -> Decimal:
    return Decimal(str(value)).quantize(MONEY, rounding=ROUND_HALF_UP)


def get_base_currency(conn: Connection, group_id: UUID) -> str:
    row = conn.execute(
        "SELECT presentation_currency FROM erp.corporate_groups WHERE group_id=%s",
        (group_id,),
    ).fetchone()
    return str(row["presentation_currency"] if row else "EGP").upper()


def resolve_exchange_rate_db(
    conn: Connection,
    *,
    group_id: UUID,
    company_id: UUID | None,
    currency_code: str,
    rate_date: date,
    rate_type: str = "SPOT",
) -> tuple[Decimal, str]:
    currency = currency_code.upper()
    base = get_base_currency(conn, group_id)
    if currency == base:
        return Decimal("1"), "BASE"
    row = conn.execute(
        """
        SELECT rate, rate_date, rate_type, source
        FROM erp.exchange_rates
        WHERE group_id=%s
          AND from_currency=%s
          AND to_currency=%s
          AND rate_type=%s
          AND rate_date<=%s
          AND (company_id=%s OR company_id IS NULL)
        ORDER BY (company_id IS NOT NULL) DESC, rate_date DESC
        LIMIT 1
        """,
        (group_id, currency, base, rate_type, rate_date, company_id),
    ).fetchone()
    if not row and rate_type != "SPOT":
        row = conn.execute(
            """
            SELECT rate, rate_date, rate_type, source
            FROM erp.exchange_rates
            WHERE group_id=%s
              AND from_currency=%s
              AND to_currency=%s
              AND rate_type='SPOT'
              AND rate_date<=%s
              AND (company_id=%s OR company_id IS NULL)
            ORDER BY (company_id IS NOT NULL) DESC, rate_date DESC
            LIMIT 1
            """,
            (group_id, currency, base, rate_date, company_id),
        ).fetchone()
    if not row:
        raise HTTPException(
            status_code=422,
            detail=f"لا يوجد سعر صرف للعملة {currency} حتى تاريخ {rate_date}. أضف السعر من شاشة العملات.",
        )
    source = f"{row['rate_type']} {row['rate_date']}" + (f" / {row['source']}" if row.get('source') else "")
    return Decimal(str(row["rate"])), source


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def create_token(user: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["user_id"]),
        "group_id": str(user["group_id"]),
        "company_id": str(user["company_id"]) if user.get("company_id") else None,
        "is_group_admin": bool(user.get("is_group_admin")),
        "role_code": user.get("role_code", "GROUP_ADMIN"),
        "permissions": sorted(set(user.get("permissions") or [])),
        "email": user["email"],
        "iat": now,
        "exp": now + timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def audit(
    conn: Connection,
    user: dict[str, Any],
    action: str,
    entity_type: str,
    entity_id: Any = None,
    company_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO erp.audit_log
            (group_id, company_id, user_id, action, entity_type, entity_id, details)
        VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)
        """,
        (
            user["group_id"], company_id, user["user_id"], action,
            entity_type, str(entity_id) if entity_id else None,
            json.dumps(details or {}, ensure_ascii=False, default=str),
        ),
    )


def ensure_account(conn: Connection, group_id: UUID, company_id: UUID, account_id: UUID) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT a.account_id, a.local_account_code, a.local_account_name,
               ga.account_class, ga.is_intercompany, ga.intercompany_role
        FROM erp.accounts a
        JOIN erp.group_accounts ga
          ON ga.group_account_id=a.group_account_id AND ga.group_id=a.group_id
        WHERE a.group_id=%s AND a.company_id=%s AND a.account_id=%s AND a.is_active=TRUE
        """,
        (group_id, company_id, account_id),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=422, detail="الحساب لا يتبع الشركة المختارة")
    return row


def ensure_open_period(conn: Connection, company_id: UUID, posting_date: date) -> None:
    conn.execute("SELECT erp.ensure_open_period(%s,%s)", (company_id, posting_date))


def _insert_voucher_entries(
    conn: Connection,
    *,
    user: dict[str, Any],
    company_id: UUID,
    voucher_id: UUID,
    entries: list[dict[str, Any]],
) -> None:
    if not entries:
        raise HTTPException(status_code=422, detail="أضف سطراً واحداً على الأقل للقيد")
    for line_no, entry in enumerate(entries, 1):
        debit_amount = money(entry.get("debit_amount", 0))
        credit_amount = money(entry.get("credit_amount", 0))
        if (debit_amount > 0) == (credit_amount > 0):
            raise HTTPException(status_code=422, detail="كل سطر يجب أن يكون مديناً أو دائناً فقط")
        account = ensure_account(conn, user["group_id"], company_id, UUID(str(entry["account_id"])))
        counterparty = entry.get("counterparty_company_id")
        ic_ref = entry.get("intercompany_reference")
        if account["is_intercompany"] and not counterparty:
            raise HTTPException(status_code=422, detail="الشركة المقابلة مطلوبة لحساب Intercompany")
        if account["is_intercompany"] and not ic_ref:
            raise HTTPException(status_code=422, detail="مرجع المعاملة المتبادلة مطلوب")
        currency = str(entry.get("currency") or "EGP").upper()
        exchange_rate = Decimal(str(entry.get("exchange_rate") or 1))
        foreign_debit = money(entry.get("foreign_debit") if entry.get("foreign_debit") is not None else debit_amount)
        foreign_credit = money(entry.get("foreign_credit") if entry.get("foreign_credit") is not None else credit_amount)
        conn.execute(
            """
            INSERT INTO erp.journal_entries
                (voucher_id, group_id, company_id, account_id, line_no,
                 entry_description, debit_amount, credit_amount,
                 counterparty_company_id, intercompany_reference,
                 branch_id, cost_center_id, currency, exchange_rate,
                 foreign_debit, foreign_credit)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                voucher_id, user["group_id"], company_id, entry["account_id"], line_no,
                entry.get("description"), debit_amount, credit_amount, counterparty, ic_ref,
                entry.get("branch_id"), entry.get("cost_center_id"), currency, exchange_rate,
                foreign_debit, foreign_credit,
            ),
        )


def create_voucher_db(
    conn: Connection,
    *,
    user: dict[str, Any],
    company_id: UUID,
    voucher_no: str,
    document_date: date,
    posting_date: date,
    description: str | None,
    entries: list[dict[str, Any]],
    source_module: str = "GL",
    external_reference: str | None = None,
    post_immediately: bool = True,
    voucher_type: str = "GENERAL",
    reversal_of_voucher_id: UUID | None = None,
    correction_of_voucher_id: UUID | None = None,
    action_reason: str | None = None,
) -> dict[str, Any]:
    debit = money(sum(money(e.get("debit_amount", 0)) for e in entries))
    credit = money(sum(money(e.get("credit_amount", 0)) for e in entries))
    if post_immediately:
        ensure_open_period(conn, company_id, posting_date)
        if len(entries) < 2 or debit <= 0 or debit != credit:
            raise HTTPException(status_code=422, detail=f"لا يمكن ترحيل قيد غير متوازن: مدين {debit} / دائن {credit}")

    voucher = conn.execute(
        """
        INSERT INTO erp.journal_vouchers
            (group_id, company_id, voucher_no, voucher_type, status,
             document_date, posting_date, description, source_module,
             external_reference, created_by, updated_by, reversal_of_voucher_id,
             correction_of_voucher_id, action_reason)
        VALUES (%s,%s,%s,%s,'DRAFT',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING voucher_id, voucher_no, voucher_type, status, posting_date
        """,
        (
            user["group_id"], company_id, voucher_no, voucher_type, document_date, posting_date,
            description, source_module, external_reference, user["user_id"], user["user_id"],
            reversal_of_voucher_id, correction_of_voucher_id, action_reason,
        ),
    ).fetchone()
    _insert_voucher_entries(
        conn, user=user, company_id=company_id, voucher_id=voucher["voucher_id"], entries=entries
    )
    if post_immediately:
        conn.execute("SELECT erp.post_voucher(%s,%s)", (voucher["voucher_id"], user["user_id"]))
        voucher["status"] = "POSTED"
    return voucher


def seed_default_chart(conn: Connection, group_id: UUID) -> None:
    chart = [
        ("100000", "الأصول", "ASSET", "DEBIT", None, False, False, "NONE"),
        ("110000", "الأصول المتداولة", "ASSET", "DEBIT", "100000", False, False, "NONE"),
        ("111000", "الصندوق", "ASSET", "DEBIT", "110000", True, False, "NONE"),
        ("112000", "البنوك", "ASSET", "DEBIT", "110000", True, False, "NONE"),
        ("113000", "العملاء", "ASSET", "DEBIT", "110000", True, False, "NONE"),
        ("114000", "ضريبة قيمة مضافة مدخلات", "ASSET", "DEBIT", "110000", True, False, "NONE"),
        ("115000", "مستحق من شركات المجموعة", "ASSET", "DEBIT", "110000", True, True, "DUE_FROM"),
        ("120000", "الأصول غير المتداولة", "ASSET", "DEBIT", "100000", False, False, "NONE"),
        ("121000", "الأراضي والمباني", "ASSET", "DEBIT", "120000", True, False, "NONE"),
        ("122000", "الأثاث والتجهيزات", "ASSET", "DEBIT", "120000", True, False, "NONE"),
        ("123000", "السيارات", "ASSET", "DEBIT", "120000", True, False, "NONE"),
        ("124000", "مجمع إهلاك الأصول", "ASSET", "CREDIT", "120000", True, False, "NONE"),
        ("125000", "استثمارات في شركات تابعة", "ASSET", "DEBIT", "120000", True, True, "IC_INVESTMENT"),
        ("200000", "الالتزامات", "LIABILITY", "CREDIT", None, False, False, "NONE"),
        ("210000", "الالتزامات المتداولة", "LIABILITY", "CREDIT", "200000", False, False, "NONE"),
        ("211000", "الموردون", "LIABILITY", "CREDIT", "210000", True, False, "NONE"),
        ("212000", "مصروفات مستحقة", "LIABILITY", "CREDIT", "210000", True, False, "NONE"),
        ("213000", "ضريبة قيمة مضافة مخرجات", "LIABILITY", "CREDIT", "210000", True, False, "NONE"),
        ("214000", "مستحق لشركات المجموعة", "LIABILITY", "CREDIT", "210000", True, True, "DUE_TO"),
        ("300000", "حقوق الملكية", "EQUITY", "CREDIT", None, False, False, "NONE"),
        ("311000", "رأس المال", "EQUITY", "CREDIT", "300000", True, False, "NONE"),
        ("312000", "الأرباح المحتجزة", "EQUITY", "CREDIT", "300000", True, False, "NONE"),
        ("313000", "أرباح وخسائر العام", "EQUITY", "CREDIT", "300000", True, False, "NONE"),
        ("400000", "الإيرادات", "REVENUE", "CREDIT", None, False, False, "NONE"),
        ("411000", "إيرادات الفنادق", "REVENUE", "CREDIT", "400000", True, False, "NONE"),
        ("412000", "إيرادات التطوير", "REVENUE", "CREDIT", "400000", True, False, "NONE"),
        ("413000", "إيرادات الإدارة والخدمات", "REVENUE", "CREDIT", "400000", True, False, "NONE"),
        ("414000", "أرباح فروق العملة", "REVENUE", "CREDIT", "400000", True, False, "NONE"),
        ("419000", "إيرادات بين شركات المجموعة", "REVENUE", "CREDIT", "400000", True, True, "IC_REVENUE"),
        ("500000", "المصروفات", "EXPENSE", "DEBIT", None, False, False, "NONE"),
        ("511000", "تكلفة التشغيل", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("512000", "الرواتب والأجور", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("513000", "الإيجارات", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("514000", "المرافق والطاقة", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("515000", "مصروفات التسويق", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("516000", "مصروف الإهلاك", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("517000", "مصروفات بنكية", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("518000", "مصروفات عمومية وإدارية", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
        ("519000", "مصروفات بين شركات المجموعة", "EXPENSE", "DEBIT", "500000", True, True, "IC_EXPENSE"),
        ("520000", "خسائر فروق العملة", "EXPENSE", "DEBIT", "500000", True, False, "NONE"),
    ]
    ids: dict[str, UUID] = {}
    for code, name, cls, normal, _parent, postable, inter, role in chart:
        row = conn.execute(
            """
            INSERT INTO erp.group_accounts
                (group_id, account_code, account_name, account_class, normal_balance,
                 is_postable, is_intercompany, intercompany_role)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (group_id, account_code) DO UPDATE
              SET account_name=EXCLUDED.account_name,
                  account_class=EXCLUDED.account_class,
                  normal_balance=EXCLUDED.normal_balance,
                  is_postable=EXCLUDED.is_postable,
                  is_intercompany=EXCLUDED.is_intercompany,
                  intercompany_role=EXCLUDED.intercompany_role,
                  is_active=TRUE
            RETURNING group_account_id
            """,
            (group_id, code, name, cls, normal, postable, inter, role),
        ).fetchone()
        ids[code] = row["group_account_id"]
    for code, _name, _cls, _normal, parent, _postable, _inter, _role in chart:
        if parent:
            conn.execute(
                """UPDATE erp.group_accounts SET parent_group_account_id=%s
                   WHERE group_id=%s AND account_code=%s""",
                (ids[parent], group_id, code),
            )


def seed_professional_chart(conn: Connection, group_id: UUID) -> int:
    """Add a detailed, multi-level chart without changing legacy accounts.

    The codes intentionally use unused ranges so existing postings and mappings
    remain untouched. The function is idempotent and can be safely re-run.
    """
    chart = [
        # Current assets
        ("110100", "النقدية وما في حكمها", "ASSET", "DEBIT", "110000", False),
        ("110110", "الصناديق والعهد", "ASSET", "DEBIT", "110100", False),
        ("110111", "الصندوق الرئيسي", "ASSET", "DEBIT", "110110", True),
        ("110112", "الصناديق الفرعية", "ASSET", "DEBIT", "110110", True),
        ("110113", "العهد النقدية", "ASSET", "DEBIT", "110110", True),
        ("110120", "الحسابات البنكية", "ASSET", "DEBIT", "110100", False),
        ("110121", "بنوك بالعملة المحلية", "ASSET", "DEBIT", "110120", True),
        ("110122", "بنوك بالعملات الأجنبية", "ASSET", "DEBIT", "110120", True),
        ("110200", "العملاء وأوراق القبض", "ASSET", "DEBIT", "110000", False),
        ("110210", "العملاء المحليون", "ASSET", "DEBIT", "110200", True),
        ("110220", "العملاء الأجانب", "ASSET", "DEBIT", "110200", True),
        ("110230", "أوراق القبض", "ASSET", "DEBIT", "110200", True),
        ("110240", "مخصص الخسائر الائتمانية المتوقعة", "ASSET", "CREDIT", "110200", True),
        ("110300", "المخزون", "ASSET", "DEBIT", "110000", False),
        ("110310", "مواد خام ومهمات", "ASSET", "DEBIT", "110300", True),
        ("110320", "أعمال تحت التنفيذ", "ASSET", "DEBIT", "110300", True),
        ("110330", "إنتاج تام", "ASSET", "DEBIT", "110300", True),
        ("110340", "قطع غيار ومستلزمات", "ASSET", "DEBIT", "110300", True),
        ("110400", "أصول متداولة أخرى", "ASSET", "DEBIT", "110000", False),
        ("110410", "مصروفات مدفوعة مقدماً", "ASSET", "DEBIT", "110400", True),
        ("110420", "تأمينات لدى الغير", "ASSET", "DEBIT", "110400", True),
        ("110430", "سلف العاملين", "ASSET", "DEBIT", "110400", True),
        ("110440", "ضرائب مدينة", "ASSET", "DEBIT", "110400", True),
        # Non-current assets and projects under construction
        ("120100", "الأصول الثابتة الملموسة", "ASSET", "DEBIT", "120000", False),
        ("120110", "الأراضي", "ASSET", "DEBIT", "120100", True),
        ("120120", "المباني والإنشاءات", "ASSET", "DEBIT", "120100", True),
        ("120130", "الآلات والمعدات", "ASSET", "DEBIT", "120100", True),
        ("120140", "السيارات ووسائل النقل", "ASSET", "DEBIT", "120100", True),
        ("120150", "الأثاث والتجهيزات", "ASSET", "DEBIT", "120100", True),
        ("120160", "أجهزة الحاسب والاتصالات", "ASSET", "DEBIT", "120100", True),
        ("120170", "مجمع إهلاك الأصول الثابتة", "ASSET", "CREDIT", "120100", False),
        ("120171", "مجمع إهلاك المباني", "ASSET", "CREDIT", "120170", True),
        ("120172", "مجمع إهلاك الآلات والمعدات", "ASSET", "CREDIT", "120170", True),
        ("120173", "مجمع إهلاك السيارات", "ASSET", "CREDIT", "120170", True),
        ("120174", "مجمع إهلاك الأثاث والتجهيزات", "ASSET", "CREDIT", "120170", True),
        ("120200", "مشروعات تحت التنفيذ", "ASSET", "DEBIT", "120000", False),
        ("120210", "أعمال إنشائية تحت التنفيذ", "ASSET", "DEBIT", "120200", True),
        ("120220", "معدات تحت التركيب", "ASSET", "DEBIT", "120200", True),
        ("120230", "أتعاب تصميم واستشارات رأسمالية", "ASSET", "DEBIT", "120200", True),
        ("120240", "دفعات مقدمة للمقاولين", "ASSET", "DEBIT", "120200", True),
        ("120300", "الأصول غير الملموسة", "ASSET", "DEBIT", "120000", False),
        ("120310", "برامج وأنظمة", "ASSET", "DEBIT", "120300", True),
        ("120320", "تراخيص وحقوق استخدام", "ASSET", "DEBIT", "120300", True),
        ("120330", "مجمع إطفاء الأصول غير الملموسة", "ASSET", "CREDIT", "120300", True),
        # Current liabilities
        ("210100", "الموردون وأوراق الدفع", "LIABILITY", "CREDIT", "210000", False),
        ("210110", "الموردون المحليون", "LIABILITY", "CREDIT", "210100", True),
        ("210120", "الموردون الأجانب", "LIABILITY", "CREDIT", "210100", True),
        ("210130", "أوراق الدفع", "LIABILITY", "CREDIT", "210100", True),
        ("210200", "مصروفات والتزامات مستحقة", "LIABILITY", "CREDIT", "210000", False),
        ("210210", "رواتب وأجور مستحقة", "LIABILITY", "CREDIT", "210200", True),
        ("210220", "فوائد مستحقة", "LIABILITY", "CREDIT", "210200", True),
        ("210230", "مصروفات تشغيل مستحقة", "LIABILITY", "CREDIT", "210200", True),
        ("210300", "ضرائب وتأمينات مستحقة", "LIABILITY", "CREDIT", "210000", False),
        ("210310", "ضريبة قيمة مضافة مستحقة", "LIABILITY", "CREDIT", "210300", True),
        ("210320", "ضرائب كسب عمل مستحقة", "LIABILITY", "CREDIT", "210300", True),
        ("210330", "تأمينات اجتماعية مستحقة", "LIABILITY", "CREDIT", "210300", True),
        ("210400", "قروض وتسهيلات قصيرة الأجل", "LIABILITY", "CREDIT", "210000", False),
        ("210410", "قروض بنكية قصيرة الأجل", "LIABILITY", "CREDIT", "210400", True),
        ("210420", "سحب على المكشوف", "LIABILITY", "CREDIT", "210400", True),
        ("210430", "الجزء المتداول من القروض طويلة الأجل", "LIABILITY", "CREDIT", "210400", True),
        # Non-current liabilities
        ("220000", "الالتزامات غير المتداولة", "LIABILITY", "CREDIT", "200000", False),
        ("220100", "القروض طويلة الأجل", "LIABILITY", "CREDIT", "220000", False),
        ("220110", "قروض بنكية طويلة الأجل", "LIABILITY", "CREDIT", "220100", True),
        ("220120", "قروض تمويل أصول", "LIABILITY", "CREDIT", "220100", True),
        ("220130", "التزامات عقود الإيجار", "LIABILITY", "CREDIT", "220100", True),
        ("220200", "مخصصات طويلة الأجل", "LIABILITY", "CREDIT", "220000", False),
        ("220210", "مخصص مكافأة نهاية الخدمة", "LIABILITY", "CREDIT", "220200", True),
        ("220220", "مخصص مطالبات والتزامات", "LIABILITY", "CREDIT", "220200", True),
        # Equity
        ("310000", "رأس المال والاحتياطيات", "EQUITY", "CREDIT", "300000", False),
        ("310100", "رأس المال المدفوع", "EQUITY", "CREDIT", "310000", True),
        ("310200", "الاحتياطي القانوني", "EQUITY", "CREDIT", "310000", True),
        ("310300", "احتياطيات أخرى", "EQUITY", "CREDIT", "310000", True),
        ("320000", "الأرباح والخسائر المرحلة", "EQUITY", "CREDIT", "300000", False),
        ("320100", "أرباح محتجزة", "EQUITY", "CREDIT", "320000", True),
        ("320200", "نتيجة الفترة الحالية", "EQUITY", "CREDIT", "320000", True),
        # Revenues
        ("410000", "إيرادات النشاط", "REVENUE", "CREDIT", "400000", False),
        ("410100", "إيرادات الغرف والإقامة", "REVENUE", "CREDIT", "410000", True),
        ("410200", "إيرادات الأغذية والمشروبات", "REVENUE", "CREDIT", "410000", True),
        ("410300", "إيرادات التطوير والمقاولات", "REVENUE", "CREDIT", "410000", True),
        ("410400", "إيرادات الإدارة والخدمات", "REVENUE", "CREDIT", "410000", True),
        ("420000", "إيرادات أخرى", "REVENUE", "CREDIT", "400000", False),
        ("420100", "إيرادات فوائد", "REVENUE", "CREDIT", "420000", True),
        ("420200", "أرباح بيع أصول", "REVENUE", "CREDIT", "420000", True),
        ("420300", "أرباح فروق عملة", "REVENUE", "CREDIT", "420000", True),
        # Expenses
        ("510000", "تكلفة الإيرادات", "EXPENSE", "DEBIT", "500000", False),
        ("510100", "تكلفة تشغيل الفنادق", "EXPENSE", "DEBIT", "510000", True),
        ("510200", "تكلفة التطوير والمقاولات", "EXPENSE", "DEBIT", "510000", True),
        ("510300", "تكلفة العمالة المباشرة", "EXPENSE", "DEBIT", "510000", True),
        ("530000", "مصروفات التشغيل", "EXPENSE", "DEBIT", "500000", False),
        ("530100", "الرواتب والأجور", "EXPENSE", "DEBIT", "530000", False),
        ("530110", "رواتب أساسية", "EXPENSE", "DEBIT", "530100", True),
        ("530120", "حوافز وبدلات", "EXPENSE", "DEBIT", "530100", True),
        ("530130", "تأمينات ومزايا العاملين", "EXPENSE", "DEBIT", "530100", True),
        ("530200", "المرافق والطاقة", "EXPENSE", "DEBIT", "530000", False),
        ("530210", "كهرباء", "EXPENSE", "DEBIT", "530200", True),
        ("530220", "مياه", "EXPENSE", "DEBIT", "530200", True),
        ("530230", "غاز ووقود", "EXPENSE", "DEBIT", "530200", True),
        ("530300", "الصيانة والإصلاح", "EXPENSE", "DEBIT", "530000", False),
        ("530310", "صيانة مبانٍ", "EXPENSE", "DEBIT", "530300", True),
        ("530320", "صيانة معدات", "EXPENSE", "DEBIT", "530300", True),
        ("530330", "قطع غيار", "EXPENSE", "DEBIT", "530300", True),
        ("540000", "المصروفات العمومية والإدارية", "EXPENSE", "DEBIT", "500000", False),
        ("540100", "إيجارات", "EXPENSE", "DEBIT", "540000", True),
        ("540200", "اتصالات وإنترنت", "EXPENSE", "DEBIT", "540000", True),
        ("540300", "أتعاب مهنية واستشارية", "EXPENSE", "DEBIT", "540000", True),
        ("540400", "تسويق وإعلان", "EXPENSE", "DEBIT", "540000", True),
        ("540500", "انتقالات وسفر", "EXPENSE", "DEBIT", "540000", True),
        ("540600", "أدوات مكتبية ومطبوعات", "EXPENSE", "DEBIT", "540000", True),
        ("550000", "تكاليف التمويل", "EXPENSE", "DEBIT", "500000", False),
        ("550100", "فوائد قروض", "EXPENSE", "DEBIT", "550000", True),
        ("550200", "عمولات ومصروفات بنكية", "EXPENSE", "DEBIT", "550000", True),
        ("550300", "خسائر فروق عملة", "EXPENSE", "DEBIT", "550000", True),
        ("560000", "الإهلاك والإطفاء", "EXPENSE", "DEBIT", "500000", False),
        ("560100", "مصروف إهلاك الأصول الثابتة", "EXPENSE", "DEBIT", "560000", True),
        ("560200", "مصروف إطفاء الأصول غير الملموسة", "EXPENSE", "DEBIT", "560000", True),
    ]
    existing = {r["account_code"]: r["group_account_id"] for r in conn.execute(
        "SELECT group_account_id, account_code FROM erp.group_accounts WHERE group_id=%s", (group_id,)
    ).fetchall()}
    inserted = 0
    # Multiple passes allow parents defined in the same list.
    for code, name, cls, normal, parent_code, postable in chart:
        was_new = code not in existing
        parent_id = existing.get(parent_code) if parent_code else None
        row = conn.execute(
            """
            INSERT INTO erp.group_accounts
                (group_id, account_code, account_name, account_class, normal_balance,
                 parent_group_account_id, is_postable, is_intercompany, intercompany_role, is_active)
            VALUES (%s,%s,%s,%s,%s,%s,%s,FALSE,'NONE',TRUE)
            ON CONFLICT (group_id, account_code) DO UPDATE
              SET account_name=EXCLUDED.account_name,
                  parent_group_account_id=COALESCE(erp.group_accounts.parent_group_account_id, EXCLUDED.parent_group_account_id),
                  is_active=TRUE
            RETURNING group_account_id
            """,
            (group_id, code, name, cls, normal, parent_id, postable),
        ).fetchone()
        existing[code] = row["group_account_id"]
        if was_new:
            inserted += 1
    return inserted


def sync_company_accounts_for_group(conn: Connection, group_id: UUID) -> int:
    result = conn.execute(
        """
        INSERT INTO erp.accounts
            (group_id, company_id, group_account_id, local_account_code, local_account_name)
        SELECT ga.group_id, c.company_id, ga.group_account_id, ga.account_code, ga.account_name
        FROM erp.group_accounts ga
        CROSS JOIN erp.companies c
        WHERE ga.group_id=%s AND c.group_id=ga.group_id
          AND ga.is_active=TRUE AND ga.is_postable=TRUE AND c.is_active=TRUE
        ON CONFLICT (company_id, local_account_code) DO NOTHING
        """,
        (group_id,),
    )
    return result.rowcount or 0


def seed_cairo_group(conn: Connection, group_id: UUID) -> None:
    holding = conn.execute(
        """
        INSERT INTO erp.companies
            (group_id, company_code, company_name, legal_name, company_kind,
             ownership_percent, functional_currency)
        VALUES (%s,'HOLD','Cairo Group Holding','Cairo Group Holding','HOLDING',100,'EGP')
        ON CONFLICT (group_id, company_code) DO UPDATE
          SET is_active=TRUE
        RETURNING company_id
        """,
        (group_id,),
    ).fetchone()
    company_specs = [
        ("HOTE", "شركة الفنادق", "SUBSIDIARY"),
        ("DEV", "شركة التطوير", "SUBSIDIARY"),
        ("MGT", "شركة الإدارة", "SUBSIDIARY"),
        ("ELIM", "استبعادات المجموعة", "ELIMINATION"),
    ]
    for code, name, kind in company_specs:
        conn.execute(
            """
            INSERT INTO erp.companies
                (group_id, company_code, company_name, legal_name, company_kind,
                 parent_company_id, ownership_percent, functional_currency)
            VALUES (%s,%s,%s,%s,%s,%s,100,'EGP')
            ON CONFLICT (group_id, company_code) DO UPDATE
              SET parent_company_id=EXCLUDED.parent_company_id, is_active=TRUE
            """,
            (group_id, code, name, name, kind, holding["company_id"]),
        )

    companies = conn.execute(
        "SELECT company_id, company_code FROM erp.companies WHERE group_id=%s AND is_active=TRUE",
        (group_id,),
    ).fetchall()
    postable = conn.execute(
        """
        SELECT group_account_id, account_code, account_name
        FROM erp.group_accounts WHERE group_id=%s AND is_postable=TRUE AND is_active=TRUE
        """,
        (group_id,),
    ).fetchall()
    current_year = date.today().year
    for company in companies:
        for account in postable:
            conn.execute(
                """
                INSERT INTO erp.accounts
                    (group_id, company_id, group_account_id, local_account_code, local_account_name)
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (company_id, local_account_code) DO UPDATE
                  SET group_account_id=EXCLUDED.group_account_id,
                      local_account_name=EXCLUDED.local_account_name,
                      is_active=TRUE
                """,
                (group_id, company["company_id"], account["group_account_id"], account["account_code"], account["account_name"]),
            )
        conn.execute(
            """
            INSERT INTO erp.branches (group_id, company_id, branch_code, branch_name)
            VALUES (%s,%s,'MAIN','المركز الرئيسي')
            ON CONFLICT (company_id, branch_code) DO NOTHING
            """,
            (group_id, company["company_id"]),
        )
        conn.execute(
            """
            INSERT INTO erp.cost_centers (group_id, company_id, center_code, center_name)
            VALUES (%s,%s,'GENERAL','مركز تكلفة عام')
            ON CONFLICT (company_id, center_code) DO NOTHING
            """,
            (group_id, company["company_id"]),
        )
        fy = conn.execute(
            """
            INSERT INTO erp.fiscal_years
                (group_id, company_id, year_name, start_date, end_date)
            VALUES (%s,%s,%s,%s,%s)
            ON CONFLICT (company_id, year_name) DO UPDATE SET year_name=EXCLUDED.year_name
            RETURNING fiscal_year_id
            """,
            (group_id, company["company_id"], str(current_year), date(current_year, 1, 1), date(current_year, 12, 31)),
        ).fetchone()
        conn.execute("SELECT erp.create_monthly_periods(%s)", (fy["fiscal_year_id"],))


def migrate_and_seed() -> None:
    database_dir = Path(__file__).resolve().parent.parent / "database"
    with pool.connection() as conn:
        if AUTO_MIGRATE:
            for schema_path in sorted(database_dir.glob("*.sql")):
                conn.execute(schema_path.read_text(encoding="utf-8"))
                conn.commit()

        admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com").lower().strip()
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if len(admin_password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters")
        group_code = os.environ.get("ADMIN_GROUP_CODE", "GROUP001").strip()
        group_name = os.environ.get("ADMIN_GROUP_NAME", "Cairo Group Holding").strip()

        group = conn.execute(
            """
            INSERT INTO erp.corporate_groups
                (group_code, group_name, presentation_currency, country_code, fiscal_year_start_month)
            VALUES (%s,%s,'EGP','EG',1)
            ON CONFLICT (group_code) DO UPDATE
              SET presentation_currency='EGP', country_code='EG', fiscal_year_start_month=1
            RETURNING group_id
            """,
            (group_code, group_name),
        ).fetchone()
        seed_default_chart(conn, group["group_id"])
        seed_professional_chart(conn, group["group_id"])
        if AUTO_MIGRATE:
            conn.execute("SELECT erp.refresh_ifrs_account_mapping(%s)", (group["group_id"],))
        seed_cairo_group(conn, group["group_id"])

        existing = conn.execute(
            "SELECT user_id FROM erp.app_users WHERE group_id=%s AND LOWER(email)=LOWER(%s)",
            (group["group_id"], admin_email),
        ).fetchone()
        if existing:
            if SYNC_ADMIN_CREDENTIALS:
                conn.execute(
                    """
                    UPDATE erp.app_users
                       SET password_hash=%s,
                           is_group_admin=TRUE,
                           is_active=TRUE,
                           full_name=COALESCE(NULLIF(full_name,''),'مدير المجموعة'),
                           role_code='GROUP_ADMIN'
                     WHERE user_id=%s
                    """,
                    (hash_password(admin_password), existing["user_id"]),
                )
        else:
            conn.execute(
                """
                INSERT INTO erp.app_users
                    (group_id, email, password_hash, is_group_admin, full_name, role_code)
                VALUES (%s,%s,%s,TRUE,'مدير المجموعة','GROUP_ADMIN')
                """,
                (group["group_id"], admin_email, hash_password(admin_password)),
            )
        conn.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    pool.open(wait=True)
    migrate_and_seed()
    yield
    pool.close()


app = FastAPI(
    title="Cairo Group Holding ERP",
    version="0.8.0",
    description="Multi-company accounting with safe posted-voucher corrections, test reset controls and IFRS-oriented reports",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Keep the browser response JSON so the Arabic UI can display a useful message.
    print(f"Unhandled error on {request.method} {request.url.path}: {type(exc).__name__}: {exc}", flush=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "حدث خطأ داخلي في الخادم. افتح Render > Logs وراجع آخر سطر أحمر.",
            "error_type": type(exc).__name__,
        },
    )


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CompanyCreate(BaseModel):
    company_code: str = Field(min_length=1, max_length=30)
    company_name: str = Field(min_length=1, max_length=250)
    company_kind: Literal["HOLDING", "SUBSIDIARY", "ELIMINATION"]
    parent_company_id: UUID | None = None
    ownership_percent: Decimal = Field(default=Decimal("100"), gt=0, le=100)
    functional_currency: str = Field(default="EGP", min_length=3, max_length=3)


class CompanyUpdate(BaseModel):
    company_code: str | None = Field(default=None, min_length=1, max_length=30)
    company_name: str | None = Field(default=None, min_length=1, max_length=250)
    legal_name: str | None = Field(default=None, min_length=1, max_length=250)
    parent_company_id: UUID | None = None
    ownership_percent: Decimal | None = Field(default=None, gt=0, le=100)
    functional_currency: str | None = Field(default=None, min_length=3, max_length=3)
    is_active: bool | None = None


class GroupProfileUpdate(BaseModel):
    group_name: str = Field(min_length=2, max_length=250)


class GroupAccountCreate(BaseModel):
    account_code: str = Field(min_length=1, max_length=50)
    account_name: str = Field(min_length=1, max_length=250)
    account_class: Literal["ASSET", "LIABILITY", "EQUITY", "REVENUE", "EXPENSE"]
    normal_balance: Literal["DEBIT", "CREDIT"]
    parent_group_account_id: UUID | None = None
    is_postable: bool = True
    is_intercompany: bool = False
    intercompany_role: str = "NONE"


class GroupAccountUpdate(BaseModel):
    account_code: str | None = Field(default=None, min_length=1, max_length=50)
    account_name: str | None = Field(default=None, min_length=1, max_length=250)
    account_class: Literal["ASSET", "LIABILITY", "EQUITY", "REVENUE", "EXPENSE"] | None = None
    normal_balance: Literal["DEBIT", "CREDIT"] | None = None
    parent_group_account_id: UUID | None = None
    is_postable: bool | None = None
    is_active: bool | None = None


class CompanyAccountCreate(BaseModel):
    company_id: UUID
    group_account_id: UUID
    local_account_code: str = Field(min_length=1, max_length=50)
    local_account_name: str = Field(min_length=1, max_length=250)


class VoucherEntryCreate(BaseModel):
    account_id: UUID
    description: str | None = None
    debit_amount: Decimal = Field(default=0, ge=0)
    credit_amount: Decimal = Field(default=0, ge=0)
    currency: str = Field(default="EGP", min_length=3, max_length=3)
    exchange_rate: Decimal = Field(default=1, gt=0)
    foreign_debit: Decimal | None = Field(default=None, ge=0)
    foreign_credit: Decimal | None = Field(default=None, ge=0)
    counterparty_company_id: UUID | None = None
    intercompany_reference: str | None = None
    branch_id: UUID | None = None
    cost_center_id: UUID | None = None


class VoucherCreate(BaseModel):
    company_id: UUID
    voucher_no: str = Field(min_length=1, max_length=50)
    document_date: date
    posting_date: date
    description: str | None = None
    entries: list[VoucherEntryCreate] = Field(min_length=1)
    post_immediately: bool = True


class VoucherUpdate(BaseModel):
    voucher_no: str = Field(min_length=1, max_length=50)
    document_date: date
    posting_date: date
    description: str | None = None
    entries: list[VoucherEntryCreate] = Field(min_length=1)


class VoucherActionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
    action_date: date = Field(default_factory=date.today)


class CompanyResetRequest(BaseModel):
    mode: Literal["FINANCIAL_ONLY", "FULL_PRESERVE_CHART"] = "FULL_PRESERVE_CHART"
    confirmation_text: str = Field(min_length=3, max_length=100)
    reason: str = Field(min_length=5, max_length=500)


class OpeningBalanceCreate(BaseModel):
    company_id: UUID
    batch_no: str = Field(min_length=1, max_length=50)
    opening_date: date
    description: str | None = None
    entries: list[VoucherEntryCreate] = Field(min_length=1)
    post_immediately: bool = False


class FiscalYearCreate(BaseModel):
    company_id: UUID
    year_name: str
    start_date: date
    end_date: date


class CostCenterCreate(BaseModel):
    company_id: UUID
    center_code: str = Field(min_length=1, max_length=30)
    center_name: str = Field(min_length=1, max_length=250)
    parent_cost_center_id: UUID | None = None


class PartyCreate(BaseModel):
    company_id: UUID
    party_code: str = Field(min_length=1, max_length=30)
    party_name: str = Field(min_length=1, max_length=250)
    party_type: Literal["CUSTOMER", "VENDOR", "BOTH"]
    tax_registration_no: str | None = None
    email: EmailStr | None = None
    phone: str | None = None
    address: str | None = None
    receivable_account_id: UUID | None = None
    payable_account_id: UUID | None = None
    credit_limit: Decimal = Field(default=0, ge=0)
    payment_terms_days: int = Field(default=0, ge=0)


class BankAccountCreate(BaseModel):
    company_id: UUID
    bank_code: str = Field(min_length=1, max_length=30)
    bank_name: str = Field(min_length=1, max_length=250)
    account_name: str = Field(min_length=1, max_length=250)
    account_number: str | None = None
    iban: str | None = None
    currency: str = Field(default="EGP", min_length=3, max_length=3)
    gl_account_id: UUID
    opening_balance: Decimal = Decimal("0")
    opening_exchange_rate: Decimal | None = Field(default=None, gt=0)


class InvoiceLineCreate(BaseModel):
    description: str = Field(min_length=1, max_length=500)
    account_id: UUID
    quantity: Decimal = Field(default=1, gt=0)
    unit_price: Decimal = Field(default=0, ge=0)
    tax_rate: Decimal = Field(default=0, ge=0)
    cost_center_id: UUID | None = None


class InvoiceCreate(BaseModel):
    company_id: UUID
    invoice_type: Literal["SALES", "PURCHASE"]
    invoice_no: str = Field(min_length=1, max_length=50)
    party_id: UUID
    invoice_date: date
    due_date: date
    currency: str = Field(default="EGP", min_length=3, max_length=3)
    exchange_rate: Decimal | None = Field(default=None, gt=0)
    description: str | None = None
    control_account_id: UUID | None = None
    tax_account_id: UUID | None = None
    payment_method: Literal["CREDIT", "CASH", "BANK"] = "CREDIT"
    settlement_account_id: UUID | None = None
    bank_account_id: UUID | None = None
    lines: list[InvoiceLineCreate] = Field(min_length=1)
    post_immediately: bool = True


class InvoicePaymentCreate(BaseModel):
    payment_no: str = Field(min_length=1, max_length=50)
    payment_date: date
    payment_method: Literal["CASH", "BANK"]
    settlement_account_id: UUID | None = None
    bank_account_id: UUID | None = None
    amount: Decimal = Field(gt=0)
    exchange_rate: Decimal | None = Field(default=None, gt=0)
    reference_no: str | None = Field(default=None, max_length=150)
    description: str | None = None


class CashTransactionCreate(BaseModel):
    company_id: UUID
    transaction_type: Literal["RECEIPT", "PAYMENT"]
    transaction_no: str = Field(min_length=1, max_length=50)
    transaction_date: date
    bank_account_id: UUID
    party_id: UUID | None = None
    offset_account_id: UUID | None = None
    amount: Decimal = Field(gt=0)
    exchange_rate: Decimal | None = Field(default=None, gt=0)
    description: str | None = None
    reference_no: str | None = None


class CurrencyCreate(BaseModel):
    currency_code: str = Field(min_length=3, max_length=3)
    currency_name_ar: str = Field(min_length=1, max_length=100)
    currency_name_en: str | None = Field(default=None, max_length=100)
    symbol: str | None = Field(default=None, max_length=10)
    decimal_places: int = Field(default=2, ge=0, le=6)


class ExchangeRateCreate(BaseModel):
    company_id: UUID | None = None
    rate_date: date
    from_currency: str = Field(min_length=3, max_length=3)
    rate_type: Literal["SPOT", "AVERAGE", "CLOSING"] = "SPOT"
    rate: Decimal = Field(gt=0)
    source: str | None = Field(default=None, max_length=100)
    notes: str | None = None


class BankRevaluationCreate(BaseModel):
    company_id: UUID
    revaluation_date: date
    gain_account_id: UUID
    loss_account_id: UUID


class AssetCategoryCreate(BaseModel):
    company_id: UUID
    category_code: str = Field(min_length=1, max_length=30)
    category_name: str = Field(min_length=1, max_length=250)
    asset_account_id: UUID
    accumulated_depreciation_account_id: UUID
    depreciation_expense_account_id: UUID
    useful_life_months: int = Field(gt=0)


class AssetCreate(BaseModel):
    company_id: UUID
    asset_code: str = Field(min_length=1, max_length=30)
    asset_name: str = Field(min_length=1, max_length=250)
    asset_category_id: UUID
    acquisition_date: date
    placed_in_service_date: date
    acquisition_cost: Decimal = Field(ge=0)
    residual_value: Decimal = Field(default=0, ge=0)
    useful_life_months: int | None = Field(default=None, gt=0)
    location: str | None = None
    notes: str | None = None


class DepreciationRunRequest(BaseModel):
    company_id: UUID
    depreciation_date: date


class UserCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=250)
    email: EmailStr
    password: str = Field(min_length=12)
    role_code: Literal["FINANCE_MANAGER", "ACCOUNTANT", "REVIEWER", "VIEWER"]
    company_id: UUID | None = None
    permissions: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=250)
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=12)
    role_code: Literal["GROUP_ADMIN", "FINANCE_MANAGER", "ACCOUNTANT", "REVIEWER", "VIEWER"] | None = None
    company_id: UUID | None = None
    permissions: list[str] | None = None
    is_active: bool | None = None


def get_current_user(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    try:
        payload = jwt.decode(authorization.removeprefix("Bearer ").strip(), JWT_SECRET, algorithms=[ALGORITHM])
        payload["user_id"] = UUID(payload["sub"])
        payload["group_id"] = UUID(payload["group_id"])
        payload["company_id"] = UUID(payload["company_id"]) if payload.get("company_id") else None
        return payload
    except (jwt.PyJWTError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def require_group_admin(user: dict[str, Any]) -> None:
    if not user["is_group_admin"]:
        raise HTTPException(status_code=403, detail="صلاحية مدير المجموعة مطلوبة")


def effective_permissions(user: dict[str, Any]) -> set[str]:
    if user.get("is_group_admin"):
        return set(ALL_PERMISSIONS)
    role = str(user.get("role_code") or "VIEWER")
    explicit = set(user.get("permissions") or [])
    return set(ROLE_PERMISSIONS.get(role, set())) | explicit


def require_permission(user: dict[str, Any], permission: str) -> None:
    if permission not in effective_permissions(user):
        raise HTTPException(status_code=403, detail=f"لا توجد صلاحية: {permission}")


def ensure_company_access(user: dict[str, Any], company_id: UUID) -> None:
    if not user["is_group_admin"] and user["company_id"] != company_id:
        raise HTTPException(status_code=403, detail="لا توجد صلاحية على هذه الشركة")


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "version": "0.8.0"}


@app.get("/api/system-info")
def system_info() -> dict[str, Any]:
    with pool.connection() as conn:
        row = conn.execute(
            """SELECT group_id, group_code, group_name, presentation_currency
               FROM erp.corporate_groups WHERE is_active=TRUE ORDER BY created_at LIMIT 1"""
        ).fetchone()
    return row or {"group_name": "Holding ERP", "presentation_currency": "EGP"}


@app.get("/api/system-settings")
def system_settings(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT financial_statement_standard FROM erp.corporate_groups WHERE group_id=%s",
            (user["group_id"],),
        ).fetchone()
    return {
        "allow_company_reset": ALLOW_COMPANY_RESET and bool(user.get("is_group_admin")),
        "allow_test_unpost": ALLOW_TEST_UNPOST and bool(user.get("is_group_admin")),
        "financial_statement_standard": (row or {}).get("financial_statement_standard", "IAS1_2026"),
    }


@app.post("/api/auth/login")
def login(data: LoginRequest) -> dict[str, Any]:
    with pool.connection() as conn:
        user = conn.execute(
            """
            SELECT user_id, group_id, company_id, email, password_hash,
                   is_group_admin, role_code, full_name, permissions
            FROM erp.app_users
            WHERE LOWER(email)=LOWER(%s) AND is_active=TRUE
            """,
            (data.email,),
        ).fetchone()
        if not user or not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        conn.execute("UPDATE erp.app_users SET last_login_at=NOW() WHERE user_id=%s", (user["user_id"],))
        conn.commit()
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get("/api/me")
def me(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    with pool.connection() as conn:
        group = conn.execute(
            "SELECT group_code, group_name, presentation_currency FROM erp.corporate_groups WHERE group_id=%s",
            (user["group_id"],),
        ).fetchone() or {}
    return {
        "user_id": str(user["user_id"]), "email": user["email"],
        "group_id": str(user["group_id"]),
        "group_code": group.get("group_code"), "group_name": group.get("group_name"),
        "presentation_currency": group.get("presentation_currency", "EGP"),
        "company_id": str(user["company_id"]) if user["company_id"] else None,
        "is_group_admin": user["is_group_admin"], "role_code": user.get("role_code"),
        "permissions": sorted(effective_permissions(user)),
    }


@app.get("/api/dashboard")
def dashboard(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID | None = None) -> dict[str, Any]:
    if company_id:
        ensure_company_access(user, company_id)
    with pool.connection() as conn:
        group_counts = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM erp.companies WHERE group_id=%s AND is_active) AS companies,
              (SELECT COUNT(*) FROM erp.app_users WHERE group_id=%s AND is_active) AS users,
              (SELECT COUNT(*) FROM erp.group_accounts WHERE group_id=%s AND is_active) AS group_accounts
            """,
            (user["group_id"], user["group_id"], user["group_id"]),
        ).fetchone()
        company_data = {}
        if company_id:
            company_data = conn.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM erp.parties WHERE group_id=%s AND company_id=%s AND is_active) AS parties,
                  (SELECT COUNT(*) FROM erp.invoices WHERE group_id=%s AND company_id=%s AND status='POSTED') AS invoices,
                  (SELECT COALESCE(SUM(base_total_amount),0) FROM erp.invoices WHERE group_id=%s AND company_id=%s AND invoice_type='SALES' AND status IN ('POSTED','PAID')) AS sales,
                  (SELECT COALESCE(SUM(base_total_amount),0) FROM erp.invoices WHERE group_id=%s AND company_id=%s AND invoice_type='PURCHASE' AND status IN ('POSTED','PAID')) AS purchases,
                  (SELECT COUNT(*) FROM erp.fixed_assets WHERE group_id=%s AND company_id=%s AND status='ACTIVE') AS assets,
                  (SELECT COALESCE(SUM(opening_balance),0) FROM erp.bank_accounts WHERE group_id=%s AND company_id=%s AND is_active) AS bank_opening
                """,
                (user["group_id"], company_id, user["group_id"], company_id,
                 user["group_id"], company_id, user["group_id"], company_id,
                 user["group_id"], company_id, user["group_id"], company_id),
            ).fetchone()
    return {"group": group_counts, "company": company_data}


@app.get("/api/companies")
def list_companies(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        if user["is_group_admin"]:
            return conn.execute(
                """SELECT company_id, company_code, company_name, legal_name, company_kind,
                          parent_company_id, ownership_percent, functional_currency, is_active
                   FROM erp.companies WHERE group_id=%s AND is_active=TRUE ORDER BY company_code""",
                (user["group_id"],),
            ).fetchall()
        return conn.execute(
            """SELECT company_id, company_code, company_name, legal_name, company_kind,
                      parent_company_id, ownership_percent, functional_currency, is_active
               FROM erp.companies WHERE group_id=%s AND company_id=%s AND is_active=TRUE""",
            (user["group_id"], user["company_id"]),
        ).fetchall()


@app.post("/api/companies", status_code=201)
def create_company(data: CompanyCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_group_admin(user)
    if data.company_kind != "HOLDING" and data.parent_company_id is None:
        raise HTTPException(status_code=422, detail="الشركة التابعة تحتاج شركة أم")
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO erp.companies
                (group_id, company_code, company_name, legal_name, company_kind,
                 parent_company_id, ownership_percent, functional_currency)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
            """,
            (user["group_id"], data.company_code, data.company_name, data.company_name,
             data.company_kind, data.parent_company_id, data.ownership_percent,
             data.functional_currency.upper()),
        ).fetchone()
        audit(conn, user, "CREATE", "COMPANY", row["company_id"], row["company_id"])
        conn.commit()
    return row


@app.patch("/api/group-profile")
def update_group_profile(data: GroupProfileUpdate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_group_admin(user)
    with pool.connection() as conn:
        row = conn.execute(
            """UPDATE erp.corporate_groups SET group_name=%s
               WHERE group_id=%s RETURNING group_id, group_code, group_name, presentation_currency""",
            (data.group_name.strip(), user["group_id"]),
        ).fetchone()
        audit(conn, user, "UPDATE", "GROUP", user["group_id"], details={"group_name": data.group_name})
        conn.commit()
    return row


@app.patch("/api/companies/{company_id}")
def update_company(company_id: UUID, data: CompanyUpdate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_group_admin(user)
    values = data.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status_code=422, detail="لا توجد تعديلات")
    with pool.connection() as conn:
        current = conn.execute(
            "SELECT * FROM erp.companies WHERE company_id=%s AND group_id=%s",
            (company_id, user["group_id"]),
        ).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="الشركة غير موجودة")
        if current["company_kind"] == "HOLDING":
            values["parent_company_id"] = None
        elif "parent_company_id" in values and values["parent_company_id"] is None:
            raise HTTPException(status_code=422, detail="الشركة التابعة تحتاج شركة أم")
        if values.get("parent_company_id") == company_id:
            raise HTTPException(status_code=422, detail="لا يمكن أن تكون الشركة هي الشركة الأم لنفسها")
        if values.get("functional_currency"):
            values["functional_currency"] = values["functional_currency"].upper()
        columns=[]; params=[]
        for key, value in values.items():
            columns.append(f"{key}=%s")
            params.append(value)
        params.extend([company_id, user["group_id"]])
        try:
            row = conn.execute(
                f"UPDATE erp.companies SET {', '.join(columns)} WHERE company_id=%s AND group_id=%s RETURNING *",
                params,
            ).fetchone()
            audit(conn, user, "UPDATE", "COMPANY", company_id, company_id, values)
            conn.commit()
        except Exception as exc:
            conn.rollback()
            raise HTTPException(status_code=400, detail=f"تعذر تعديل الشركة: {exc}") from exc
    return row


@app.get("/api/group-accounts")
def list_group_accounts(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            """
            WITH RECURSIVE tree AS (
                SELECT ga.group_account_id, ga.account_code, ga.account_name, ga.account_class,
                       ga.normal_balance, ga.parent_group_account_id, ga.is_postable,
                       ga.is_intercompany, ga.intercompany_role, ga.notes,
                       0 AS account_level, ga.account_code::TEXT AS sort_path,
                       NULL::VARCHAR AS parent_account_code, NULL::VARCHAR AS parent_account_name
                FROM erp.group_accounts ga
                WHERE ga.group_id=%s AND ga.is_active=TRUE AND ga.parent_group_account_id IS NULL
                UNION ALL
                SELECT child.group_account_id, child.account_code, child.account_name, child.account_class,
                       child.normal_balance, child.parent_group_account_id, child.is_postable,
                       child.is_intercompany, child.intercompany_role, child.notes,
                       parent.account_level + 1, parent.sort_path || '.' || child.account_code,
                       parent.account_code, parent.account_name
                FROM erp.group_accounts child
                JOIN tree parent ON parent.group_account_id=child.parent_group_account_id
                WHERE child.group_id=%s AND child.is_active=TRUE
            )
            SELECT * FROM tree ORDER BY sort_path
            """,
            (user["group_id"], user["group_id"]),
        ).fetchall()


@app.post("/api/group-accounts", status_code=201)
def create_group_account(data: GroupAccountCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "ACCOUNT_MANAGE")
    if data.is_intercompany and data.intercompany_role == "NONE":
        raise HTTPException(status_code=422, detail="حدد نوع حساب Intercompany")
    if not data.is_postable and data.is_intercompany:
        raise HTTPException(status_code=422, detail="الحساب الرئيسي لا يمكن أن يكون حساب حركة Intercompany")
    with pool.connection() as conn:
        if data.parent_group_account_id:
            parent = conn.execute(
                """SELECT group_account_id, account_code, account_name, account_class, is_postable
                   FROM erp.group_accounts
                   WHERE group_id=%s AND group_account_id=%s AND is_active=TRUE""",
                (user["group_id"], data.parent_group_account_id),
            ).fetchone()
            if not parent:
                raise HTTPException(status_code=422, detail="الحساب الرئيسي المختار غير موجود")
            if parent["account_class"] != data.account_class:
                raise HTTPException(status_code=422, detail="الحساب الفرعي يجب أن يكون من نفس تصنيف الحساب الرئيسي")
            if parent["is_postable"]:
                mapped = conn.execute(
                    "SELECT COUNT(*) AS n FROM erp.accounts WHERE group_id=%s AND group_account_id=%s AND is_active=TRUE",
                    (user["group_id"], data.parent_group_account_id),
                ).fetchone()["n"]
                if mapped:
                    raise HTTPException(status_code=422, detail="الحساب المختار حساب حركة ومستخدم في الشركات؛ أنشئ حساباً رئيسياً جديداً أولاً")
                conn.execute(
                    "UPDATE erp.group_accounts SET is_postable=FALSE WHERE group_id=%s AND group_account_id=%s",
                    (user["group_id"], data.parent_group_account_id),
                )
        row = conn.execute(
            """
            INSERT INTO erp.group_accounts
                (group_id, account_code, account_name, account_class, normal_balance,
                 parent_group_account_id, is_postable, is_intercompany, intercompany_role)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
            """,
            (user["group_id"], data.account_code, data.account_name, data.account_class,
             data.normal_balance, data.parent_group_account_id, data.is_postable,
             data.is_intercompany, data.intercompany_role),
        ).fetchone()
        audit(conn, user, "CREATE", "GROUP_ACCOUNT", row["group_account_id"], details={
            "is_postable": data.is_postable, "parent": str(data.parent_group_account_id) if data.parent_group_account_id else None
        })
        conn.commit()
    return row


@app.patch("/api/group-accounts/{group_account_id}")
def update_group_account(group_account_id: UUID, data: GroupAccountUpdate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "ACCOUNT_MANAGE")
    values = data.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status_code=422, detail="لا توجد تعديلات")
    with pool.connection() as conn:
        current = conn.execute(
            "SELECT * FROM erp.group_accounts WHERE group_account_id=%s AND group_id=%s",
            (group_account_id, user["group_id"]),
        ).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="الحساب غير موجود")
        parent_id = values.get("parent_group_account_id")
        if parent_id == group_account_id:
            raise HTTPException(status_code=422, detail="لا يمكن أن يكون الحساب رئيسياً لنفسه")
        if parent_id:
            parent = conn.execute(
                "SELECT group_account_id, account_class, is_postable FROM erp.group_accounts WHERE group_account_id=%s AND group_id=%s AND is_active=TRUE",
                (parent_id, user["group_id"]),
            ).fetchone()
            if not parent:
                raise HTTPException(status_code=422, detail="الحساب الرئيسي غير موجود")
            target_class = values.get("account_class", current["account_class"])
            if parent["account_class"] != target_class:
                raise HTTPException(status_code=422, detail="الحساب الفرعي يجب أن يكون من نفس تصنيف الحساب الرئيسي")
            if parent["is_postable"]:
                parent_mapped = conn.execute(
                    "SELECT 1 FROM erp.accounts WHERE group_account_id=%s AND is_active=TRUE LIMIT 1", (parent_id,)
                ).fetchone()
                if parent_mapped:
                    raise HTTPException(status_code=422, detail="الحساب الرئيسي المختار حساب حركة مستخدم؛ اختر حساباً تجميعياً")
            cycle = conn.execute(
                """WITH RECURSIVE descendants AS (
                       SELECT group_account_id FROM erp.group_accounts
                        WHERE parent_group_account_id=%s AND group_id=%s
                       UNION ALL
                       SELECT ga.group_account_id FROM erp.group_accounts ga
                       JOIN descendants d ON ga.parent_group_account_id=d.group_account_id
                       WHERE ga.group_id=%s
                   ) SELECT 1 FROM descendants WHERE group_account_id=%s""",
                (group_account_id, user["group_id"], user["group_id"], parent_id),
            ).fetchone()
            if cycle:
                raise HTTPException(status_code=422, detail="اختيار الحساب الرئيسي سيؤدي إلى دائرة في الشجرة")
        if values.get("is_postable") is True:
            child = conn.execute(
                "SELECT 1 FROM erp.group_accounts WHERE parent_group_account_id=%s AND is_active=TRUE LIMIT 1",
                (group_account_id,),
            ).fetchone()
            if child:
                raise HTTPException(status_code=422, detail="الحساب الذي تحته فروع لا يمكن تحويله إلى حساب حركة")
        if current["is_postable"] and values.get("is_postable") is False:
            mapped = conn.execute(
                "SELECT 1 FROM erp.accounts WHERE group_account_id=%s AND is_active=TRUE LIMIT 1", (group_account_id,)
            ).fetchone()
            if mapped:
                raise HTTPException(status_code=422, detail="لا يمكن تحويل حساب حركة مرتبط بالشركات إلى حساب رئيسي. أنشئ حساباً رئيسياً جديداً وانقل الحسابات الجديدة تحته")
        if values.get("account_class") and values["account_class"] != current["account_class"]:
            used = conn.execute(
                """SELECT 1 FROM erp.journal_entries e JOIN erp.accounts a ON a.account_id=e.account_id
                   WHERE a.group_account_id=%s LIMIT 1""", (group_account_id,)
            ).fetchone()
            if used:
                raise HTTPException(status_code=422, detail="لا يمكن تغيير تصنيف حساب له حركات مالية")
        columns=[]; params=[]
        for key,value in values.items():
            columns.append(f"{key}=%s"); params.append(value)
        params.extend([group_account_id,user["group_id"]])
        try:
            row=conn.execute(
                f"UPDATE erp.group_accounts SET {', '.join(columns)} WHERE group_account_id=%s AND group_id=%s RETURNING *",
                params,
            ).fetchone()
            audit(conn,user,"UPDATE","GROUP_ACCOUNT",group_account_id,details=values)
            conn.commit()
        except Exception as exc:
            conn.rollback(); raise HTTPException(status_code=400,detail=f"تعذر تعديل الحساب: {exc}") from exc
    return row


@app.delete("/api/group-accounts/{group_account_id}")
def deactivate_group_account(group_account_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user,"ACCOUNT_MANAGE")
    with pool.connection() as conn:
        child=conn.execute("SELECT 1 FROM erp.group_accounts WHERE parent_group_account_id=%s AND is_active=TRUE LIMIT 1",(group_account_id,)).fetchone()
        mapped=conn.execute("SELECT 1 FROM erp.accounts WHERE group_account_id=%s AND is_active=TRUE LIMIT 1",(group_account_id,)).fetchone()
        if child or mapped:
            raise HTTPException(status_code=422,detail="لا يمكن حذف الحساب لوجود حسابات فرعية أو حسابات شركات مرتبطة به. يمكن تعديل اسمه أو إيقاف الحسابات المرتبطة أولاً.")
        row=conn.execute("UPDATE erp.group_accounts SET is_active=FALSE WHERE group_account_id=%s AND group_id=%s RETURNING group_account_id",(group_account_id,user["group_id"])).fetchone()
        if not row: raise HTTPException(status_code=404,detail="الحساب غير موجود")
        audit(conn,user,"DEACTIVATE","GROUP_ACCOUNT",group_account_id)
        conn.commit()
    return {"message":"تم إيقاف الحساب"}


@app.post("/api/group-accounts/apply-professional-template")
def apply_professional_template(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user,"ACCOUNT_MANAGE")
    with pool.connection() as conn:
        added=seed_professional_chart(conn,user["group_id"])
        mapped=sync_company_accounts_for_group(conn,user["group_id"])
        audit(conn,user,"APPLY_TEMPLATE","GROUP_ACCOUNT",details={"accounts_added":added,"company_accounts_added":mapped})
        conn.commit()
    return {"message":"تم تطبيق نموذج شجرة الحسابات التفصيلي","accounts_added":added,"company_accounts_added":mapped}


@app.get("/api/accounts")
def list_accounts(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT a.account_id, a.local_account_code, a.local_account_name,
                   ga.account_code AS group_account_code, ga.account_name AS group_account_name,
                   ga.account_class, ga.normal_balance, ga.is_intercompany, ga.intercompany_role
            FROM erp.accounts a
            JOIN erp.group_accounts ga ON ga.group_account_id=a.group_account_id AND ga.group_id=a.group_id
            WHERE a.group_id=%s AND a.company_id=%s AND a.is_active=TRUE
            ORDER BY a.local_account_code
            """,
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/accounts", status_code=201)
def create_account(data: CompanyAccountCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "ACCOUNT_MANAGE")
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        group_account = conn.execute(
            "SELECT is_postable FROM erp.group_accounts WHERE group_id=%s AND group_account_id=%s AND is_active=TRUE",
            (user["group_id"], data.group_account_id),
        ).fetchone()
        if not group_account or not group_account["is_postable"]:
            raise HTTPException(status_code=422, detail="يمكن ربط حساب الشركة بحساب حركة فقط، وليس بحساب رئيسي")
        row = conn.execute(
            """
            INSERT INTO erp.accounts
                (group_id, company_id, group_account_id, local_account_code, local_account_name)
            VALUES (%s,%s,%s,%s,%s) RETURNING *
            """,
            (user["group_id"], data.company_id, data.group_account_id,
             data.local_account_code, data.local_account_name),
        ).fetchone()
        audit(conn, user, "CREATE", "ACCOUNT", row["account_id"], data.company_id)
        conn.commit()
    return row


@app.get("/api/currencies")
def list_currencies(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            """SELECT currency_code, currency_name_ar, currency_name_en, symbol,
                      decimal_places, is_base, is_active
               FROM erp.currencies WHERE group_id=%s AND is_active=TRUE
               ORDER BY is_base DESC, currency_code""",
            (user["group_id"],),
        ).fetchall()


@app.post("/api/currencies", status_code=201)
def create_currency(data: CurrencyCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "CURRENCY_MANAGE")
    code = data.currency_code.upper()
    with pool.connection() as conn:
        row = conn.execute(
            """INSERT INTO erp.currencies
                   (group_id, currency_code, currency_name_ar, currency_name_en, symbol, decimal_places)
               VALUES (%s,%s,%s,%s,%s,%s)
               ON CONFLICT (group_id, currency_code) DO UPDATE
                 SET currency_name_ar=EXCLUDED.currency_name_ar,
                     currency_name_en=EXCLUDED.currency_name_en,
                     symbol=EXCLUDED.symbol, decimal_places=EXCLUDED.decimal_places, is_active=TRUE
               RETURNING *""",
            (user["group_id"], code, data.currency_name_ar, data.currency_name_en,
             data.symbol, data.decimal_places),
        ).fetchone()
        audit(conn, user, "UPSERT", "CURRENCY", code)
        conn.commit()
        return row


@app.get("/api/exchange-rates")
def list_exchange_rates(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    company_id: UUID | None = None,
    currency_code: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> list[dict[str, Any]]:
    query = """SELECT exchange_rate_id, company_id, rate_date, from_currency, to_currency,
                      rate_type, rate, source, notes, created_at
               FROM erp.exchange_rates WHERE group_id=%s"""
    params: list[Any] = [user["group_id"]]
    if company_id is not None:
        ensure_company_access(user, company_id)
        query += " AND (company_id=%s OR company_id IS NULL)"
        params.append(company_id)
    if currency_code:
        query += " AND from_currency=%s"
        params.append(currency_code.upper())
    if date_from is not None:
        query += " AND rate_date>=%s"
        params.append(date_from)
    if date_to is not None:
        query += " AND rate_date<=%s"
        params.append(date_to)
    query += " ORDER BY rate_date DESC, from_currency, rate_type"
    with pool.connection() as conn:
        return conn.execute(query, params).fetchall()


@app.post("/api/exchange-rates", status_code=201)
def create_exchange_rate(data: ExchangeRateCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "CURRENCY_MANAGE")
    if data.company_id:
        ensure_company_access(user, data.company_id)
    currency = data.from_currency.upper()
    with pool.connection() as conn:
        base = get_base_currency(conn, user["group_id"])
        if currency == base and data.rate != 1:
            raise HTTPException(status_code=422, detail="سعر العملة الأساسية يجب أن يساوي 1")
        exists = conn.execute(
            "SELECT 1 FROM erp.currencies WHERE group_id=%s AND currency_code=%s AND is_active=TRUE",
            (user["group_id"], currency),
        ).fetchone()
        if not exists:
            raise HTTPException(status_code=422, detail="أضف العملة أولاً")
        row = conn.execute(
            """INSERT INTO erp.exchange_rates
                   (group_id, company_id, rate_date, from_currency, to_currency,
                    rate_type, rate, source, notes, created_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (group_id, company_id, rate_date, from_currency, to_currency, rate_type)
               DO UPDATE SET rate=EXCLUDED.rate, source=EXCLUDED.source, notes=EXCLUDED.notes,
                             created_by=EXCLUDED.created_by, created_at=NOW()
               RETURNING *""",
            (user["group_id"], data.company_id, data.rate_date, currency, base,
             data.rate_type, data.rate, data.source, data.notes, user["user_id"]),
        ).fetchone()
        audit(conn, user, "UPSERT", "EXCHANGE_RATE", row["exchange_rate_id"], data.company_id,
              {"currency": currency, "rate": str(data.rate), "date": str(data.rate_date)})
        conn.commit()
        return row


@app.get("/api/exchange-rates/resolve")
def resolve_exchange_rate(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    currency_code: str,
    rate_date: date,
    company_id: UUID | None = None,
    rate_type: Literal["SPOT", "AVERAGE", "CLOSING"] = "SPOT",
) -> dict[str, Any]:
    if company_id:
        ensure_company_access(user, company_id)
    with pool.connection() as conn:
        rate, source = resolve_exchange_rate_db(
            conn, group_id=user["group_id"], company_id=company_id,
            currency_code=currency_code, rate_date=rate_date, rate_type=rate_type,
        )
        return {"currency": currency_code.upper(), "base_currency": get_base_currency(conn, user["group_id"]),
                "rate": rate, "rate_type": rate_type, "source": source}


@app.get("/api/branches")
def list_branches(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            "SELECT branch_id, branch_code, branch_name, address FROM erp.branches WHERE group_id=%s AND company_id=%s AND is_active ORDER BY branch_code",
            (user["group_id"], company_id),
        ).fetchall()


@app.get("/api/cost-centers")
def list_cost_centers(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT cost_center_id, center_code, center_name, parent_cost_center_id
               FROM erp.cost_centers WHERE group_id=%s AND company_id=%s AND is_active ORDER BY center_code""",
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/cost-centers", status_code=201)
def create_cost_center(data: CostCenterCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        row = conn.execute(
            """INSERT INTO erp.cost_centers
                   (group_id, company_id, center_code, center_name, parent_cost_center_id)
               VALUES (%s,%s,%s,%s,%s) RETURNING *""",
            (user["group_id"], data.company_id, data.center_code, data.center_name, data.parent_cost_center_id),
        ).fetchone()
        audit(conn, user, "CREATE", "COST_CENTER", row["cost_center_id"], data.company_id)
        conn.commit()
    return row


@app.get("/api/fiscal-years")
def list_fiscal_years(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT fy.fiscal_year_id, fy.year_name, fy.start_date, fy.end_date, fy.status,
                      COUNT(fp.period_id) AS periods,
                      COUNT(*) FILTER (WHERE fp.status='OPEN') AS open_periods
               FROM erp.fiscal_years fy LEFT JOIN erp.fiscal_periods fp ON fp.fiscal_year_id=fy.fiscal_year_id
               WHERE fy.group_id=%s AND fy.company_id=%s
               GROUP BY fy.fiscal_year_id ORDER BY fy.start_date DESC""",
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/fiscal-years", status_code=201)
def create_fiscal_year(data: FiscalYearCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        row = conn.execute(
            """INSERT INTO erp.fiscal_years
                   (group_id, company_id, year_name, start_date, end_date)
               VALUES (%s,%s,%s,%s,%s) RETURNING *""",
            (user["group_id"], data.company_id, data.year_name, data.start_date, data.end_date),
        ).fetchone()
        conn.execute("SELECT erp.create_monthly_periods(%s)", (row["fiscal_year_id"],))
        audit(conn, user, "CREATE", "FISCAL_YEAR", row["fiscal_year_id"], data.company_id)
        conn.commit()
    return row


@app.get("/api/fiscal-periods")
def list_fiscal_periods(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, fiscal_year_id: UUID | None = None) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    query = """SELECT period_id, fiscal_year_id, period_no, period_name, start_date, end_date, status
               FROM erp.fiscal_periods
               WHERE group_id=%s AND company_id=%s"""
    params: list[Any] = [user["group_id"], company_id]
    if fiscal_year_id is not None:
        query += " AND fiscal_year_id=%s"
        params.append(fiscal_year_id)
    query += " ORDER BY start_date"
    with pool.connection() as conn:
        return conn.execute(query, params).fetchall()


@app.patch("/api/fiscal-periods/{period_id}")
def update_period(period_id: UUID, new_status: Literal["OPEN", "CLOSED", "LOCKED"], user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    with pool.connection() as conn:
        period = conn.execute("SELECT company_id FROM erp.fiscal_periods WHERE period_id=%s AND group_id=%s", (period_id, user["group_id"])).fetchone()
        if not period:
            raise HTTPException(status_code=404, detail="الفترة غير موجودة")
        ensure_company_access(user, period["company_id"])
        row = conn.execute("UPDATE erp.fiscal_periods SET status=%s WHERE period_id=%s RETURNING *", (new_status, period_id)).fetchone()
        audit(conn, user, "UPDATE_STATUS", "FISCAL_PERIOD", period_id, period["company_id"], {"status": new_status})
        conn.commit()
    return row


@app.get("/api/vouchers")
def list_vouchers(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT voucher_id, voucher_no, voucher_type, status, document_date, posting_date,
                      description, source_module, external_reference, created_at, posted_at,
                      reversal_of_voucher_id, correction_of_voucher_id, action_reason,
                      EXISTS(SELECT 1 FROM erp.journal_vouchers rv WHERE rv.reversal_of_voucher_id=v.voucher_id) AS is_reversed,
                      (SELECT rv.voucher_id FROM erp.journal_vouchers rv WHERE rv.reversal_of_voucher_id=v.voucher_id LIMIT 1) AS reversal_voucher_id,
                      (SELECT COALESCE(SUM(debit_amount),0) FROM erp.journal_entries e WHERE e.voucher_id=v.voucher_id) AS amount
               FROM erp.journal_vouchers v
               WHERE group_id=%s AND company_id=%s ORDER BY posting_date DESC, created_at DESC LIMIT %s""",
            (user["group_id"], company_id, limit),
        ).fetchall()


@app.post("/api/vouchers", status_code=201)
def create_voucher(data: VoucherCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "VOUCHER_CREATE")
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        try:
            voucher = create_voucher_db(
                conn, user=user, company_id=data.company_id, voucher_no=data.voucher_no,
                document_date=data.document_date, posting_date=data.posting_date,
                description=data.description, entries=[e.model_dump() for e in data.entries],
                post_immediately=data.post_immediately,
            )
            audit(conn, user, "CREATE", "VOUCHER", voucher["voucher_id"], data.company_id, {"status": voucher["status"]})
            conn.commit()
            return voucher
        except HTTPException:
            conn.rollback(); raise
        except Exception as exc:
            conn.rollback(); raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/vouchers/{voucher_id}")
def get_voucher(voucher_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    with pool.connection() as conn:
        voucher=conn.execute(
            """SELECT v.*, c.company_code, c.company_name
               FROM erp.journal_vouchers v JOIN erp.companies c ON c.company_id=v.company_id
               WHERE v.group_id=%s AND v.voucher_id=%s""",
            (user["group_id"],voucher_id),
        ).fetchone()
        if not voucher:
            raise HTTPException(status_code=404,detail="القيد غير موجود")
        ensure_company_access(user,voucher["company_id"])
        voucher["entries"]=conn.execute(
            """SELECT e.entry_id,e.line_no,e.account_id,e.entry_description,e.debit_amount,e.credit_amount,
                      e.currency,e.exchange_rate,e.foreign_debit,e.foreign_credit,
                      e.counterparty_company_id,e.intercompany_reference,e.branch_id,e.cost_center_id,
                      a.local_account_code,a.local_account_name,cc.center_code,cc.center_name
               FROM erp.journal_entries e
               JOIN erp.accounts a ON a.account_id=e.account_id
               LEFT JOIN erp.cost_centers cc ON cc.cost_center_id=e.cost_center_id
               WHERE e.voucher_id=%s ORDER BY e.line_no""",(voucher_id,),
        ).fetchall()
        return voucher


@app.put("/api/vouchers/{voucher_id}")
def update_voucher(
    voucher_id: UUID, data: VoucherUpdate, user: Annotated[dict[str, Any], Depends(get_current_user)]
) -> dict[str, Any]:
    require_permission(user, "VOUCHER_EDIT")
    with pool.connection() as conn:
        with conn.transaction():
            voucher = conn.execute(
                "SELECT * FROM erp.journal_vouchers WHERE group_id=%s AND voucher_id=%s FOR UPDATE",
                (user["group_id"], voucher_id),
            ).fetchone()
            if not voucher:
                raise HTTPException(status_code=404, detail="القيد غير موجود")
            ensure_company_access(user, voucher["company_id"])
            if voucher["status"] != "DRAFT":
                raise HTTPException(status_code=409, detail="يمكن تعديل القيود المسودة فقط")
            conn.execute(
                """UPDATE erp.journal_vouchers
                   SET voucher_no=%s, document_date=%s, posting_date=%s, description=%s,
                       updated_by=%s, updated_at=NOW()
                   WHERE voucher_id=%s""",
                (data.voucher_no, data.document_date, data.posting_date, data.description, user["user_id"], voucher_id),
            )
            conn.execute("DELETE FROM erp.journal_entries WHERE voucher_id=%s", (voucher_id,))
            _insert_voucher_entries(
                conn, user=user, company_id=voucher["company_id"], voucher_id=voucher_id,
                entries=[e.model_dump() for e in data.entries],
            )
            audit(conn, user, "UPDATE", "VOUCHER", voucher_id, voucher["company_id"], {"status": "DRAFT"})
            return conn.execute(
                "SELECT voucher_id,voucher_no,voucher_type,status,posting_date,draft_version FROM erp.journal_vouchers WHERE voucher_id=%s",
                (voucher_id,),
            ).fetchone()


@app.delete("/api/vouchers/{voucher_id}")
def delete_voucher(voucher_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, bool]:
    require_permission(user, "VOUCHER_DELETE")
    with pool.connection() as conn:
        with conn.transaction():
            voucher = conn.execute(
                "SELECT company_id,status,voucher_no FROM erp.journal_vouchers WHERE group_id=%s AND voucher_id=%s FOR UPDATE",
                (user["group_id"], voucher_id),
            ).fetchone()
            if not voucher:
                raise HTTPException(status_code=404, detail="القيد غير موجود")
            ensure_company_access(user, voucher["company_id"])
            if voucher["status"] != "DRAFT":
                raise HTTPException(status_code=409, detail="يمكن حذف القيود المسودة فقط")
            audit(conn, user, "DELETE", "VOUCHER", voucher_id, voucher["company_id"], {"voucher_no": voucher["voucher_no"]})
            conn.execute("DELETE FROM erp.journal_vouchers WHERE voucher_id=%s", (voucher_id,))
            return {"deleted": True}


@app.post("/api/vouchers/{voucher_id}/post")
def post_voucher(voucher_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "VOUCHER_POST")
    with pool.connection() as conn:
        with conn.transaction():
            voucher = conn.execute(
                "SELECT company_id,status,posting_date FROM erp.journal_vouchers WHERE group_id=%s AND voucher_id=%s FOR UPDATE",
                (user["group_id"], voucher_id),
            ).fetchone()
            if not voucher:
                raise HTTPException(status_code=404, detail="القيد غير موجود")
            ensure_company_access(user, voucher["company_id"])
            if voucher["status"] != "DRAFT":
                raise HTTPException(status_code=409, detail="القيد ليس مسودة")
            ensure_open_period(conn, voucher["company_id"], voucher["posting_date"])
            conn.execute("SELECT erp.post_voucher(%s,%s)", (voucher_id, user["user_id"]))
            audit(conn, user, "POST", "VOUCHER", voucher_id, voucher["company_id"])
            return {"voucher_id": voucher_id, "status": "POSTED"}


def _voucher_entries_for_copy(conn: Connection, voucher_id: UUID, *, reverse: bool) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT account_id, entry_description, debit_amount, credit_amount,
                  currency, exchange_rate, foreign_debit, foreign_credit,
                  counterparty_company_id, intercompany_reference, branch_id, cost_center_id
           FROM erp.journal_entries WHERE voucher_id=%s ORDER BY line_no""",
        (voucher_id,),
    ).fetchall()
    entries: list[dict[str, Any]] = []
    for row in rows:
        entries.append({
            "account_id": row["account_id"],
            "description": row["entry_description"],
            "debit_amount": row["credit_amount"] if reverse else row["debit_amount"],
            "credit_amount": row["debit_amount"] if reverse else row["credit_amount"],
            "currency": row["currency"],
            "exchange_rate": row["exchange_rate"],
            "foreign_debit": row["foreign_credit"] if reverse else row["foreign_debit"],
            "foreign_credit": row["foreign_debit"] if reverse else row["foreign_credit"],
            "counterparty_company_id": row["counterparty_company_id"],
            "intercompany_reference": row["intercompany_reference"],
            "branch_id": row["branch_id"],
            "cost_center_id": row["cost_center_id"],
        })
    return entries


def _unique_action_voucher_no(conn: Connection, company_id: UUID, prefix: str, source_no: str) -> str:
    base = f"{prefix}-{source_no}"[:42]
    candidate = f"{base}-{datetime.now(timezone.utc).strftime('%H%M%S')}"[:50]
    counter = 1
    while conn.execute(
        "SELECT 1 FROM erp.journal_vouchers WHERE company_id=%s AND voucher_no=%s", (company_id, candidate)
    ).fetchone():
        candidate = f"{base}-{counter}"[:50]
        counter += 1
    return candidate


def _create_reversal_db(
    conn: Connection,
    *,
    user: dict[str, Any],
    original: dict[str, Any],
    action_date: date,
    reason: str,
) -> dict[str, Any]:
    if original["status"] != "POSTED":
        raise HTTPException(status_code=409, detail="يمكن عكس قيد مرحّل فقط")
    if original.get("source_module") not in {"GL", "OPENING"}:
        raise HTTPException(status_code=409, detail="القيد ناتج من فاتورة/بنك/أصل؛ يجب إلغاء المستند من وحدته وليس من اليومية")
    existing = conn.execute(
        "SELECT voucher_id,voucher_no FROM erp.journal_vouchers WHERE reversal_of_voucher_id=%s",
        (original["voucher_id"],),
    ).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail=f"القيد معكوس بالفعل بواسطة {existing['voucher_no']}")
    entries = _voucher_entries_for_copy(conn, original["voucher_id"], reverse=True)
    return create_voucher_db(
        conn,
        user=user,
        company_id=original["company_id"],
        voucher_no=_unique_action_voucher_no(conn, original["company_id"], "REV", original["voucher_no"]),
        document_date=action_date,
        posting_date=action_date,
        description=f"عكس القيد {original['voucher_no']}: {reason}",
        entries=entries,
        source_module="GL",
        external_reference=str(original["voucher_id"]),
        post_immediately=True,
        voucher_type="REVERSAL",
        reversal_of_voucher_id=original["voucher_id"],
        action_reason=reason,
    )


@app.post("/api/vouchers/{voucher_id}/reverse")
def reverse_posted_voucher(
    voucher_id: UUID,
    data: VoucherActionRequest,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_permission(user, "VOUCHER_REVERSE")
    with pool.connection() as conn:
        with conn.transaction():
            original = conn.execute(
                "SELECT * FROM erp.journal_vouchers WHERE group_id=%s AND voucher_id=%s FOR UPDATE",
                (user["group_id"], voucher_id),
            ).fetchone()
            if not original:
                raise HTTPException(status_code=404, detail="القيد غير موجود")
            ensure_company_access(user, original["company_id"])
            ensure_open_period(conn, original["company_id"], data.action_date)
            reversal = _create_reversal_db(conn, user=user, original=original, action_date=data.action_date, reason=data.reason)
            audit(conn, user, "REVERSE", "VOUCHER", voucher_id, original["company_id"], {"reversal_voucher_id": reversal["voucher_id"], "reason": data.reason})
            return {"message": "تم إنشاء وترحيل قيد العكس مع الاحتفاظ بالقيد الأصلي", "reversal": reversal}


@app.post("/api/vouchers/{voucher_id}/correct")
def correct_posted_voucher(
    voucher_id: UUID,
    data: VoucherActionRequest,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_permission(user, "VOUCHER_REVERSE")
    require_permission(user, "VOUCHER_CREATE")
    with pool.connection() as conn:
        with conn.transaction():
            original = conn.execute(
                "SELECT * FROM erp.journal_vouchers WHERE group_id=%s AND voucher_id=%s FOR UPDATE",
                (user["group_id"], voucher_id),
            ).fetchone()
            if not original:
                raise HTTPException(status_code=404, detail="القيد غير موجود")
            ensure_company_access(user, original["company_id"])
            ensure_open_period(conn, original["company_id"], data.action_date)
            reversal = _create_reversal_db(conn, user=user, original=original, action_date=data.action_date, reason=data.reason)
            correction = create_voucher_db(
                conn,
                user=user,
                company_id=original["company_id"],
                voucher_no=_unique_action_voucher_no(conn, original["company_id"], "COR", original["voucher_no"]),
                document_date=data.action_date,
                posting_date=data.action_date,
                description=f"تصحيح القيد {original['voucher_no']}: {data.reason}",
                entries=_voucher_entries_for_copy(conn, original["voucher_id"], reverse=False),
                source_module="GL",
                external_reference=str(original["voucher_id"]),
                post_immediately=False,
                voucher_type="CORRECTION",
                correction_of_voucher_id=original["voucher_id"],
                action_reason=data.reason,
            )
            audit(conn, user, "CORRECT", "VOUCHER", voucher_id, original["company_id"], {"reversal_voucher_id": reversal["voucher_id"], "draft_voucher_id": correction["voucher_id"], "reason": data.reason})
            return {"message": "تم عكس القيد وإنشاء نسخة تصحيح كمسودة قابلة للتعديل", "reversal": reversal, "draft": correction}


@app.post("/api/vouchers/{voucher_id}/unpost-test")
def unpost_voucher_for_testing(
    voucher_id: UUID,
    data: VoucherActionRequest,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_group_admin(user)
    require_permission(user, "VOUCHER_UNPOST_TEST")
    if not ALLOW_TEST_UNPOST:
        raise HTTPException(status_code=403, detail="إرجاع القيد لمسودة معطل. فعّل ALLOW_TEST_UNPOST=true في Render أثناء الاختبار فقط")
    with pool.connection() as conn:
        with conn.transaction():
            voucher = conn.execute(
                "SELECT company_id,status,voucher_no FROM erp.journal_vouchers WHERE group_id=%s AND voucher_id=%s FOR UPDATE",
                (user["group_id"], voucher_id),
            ).fetchone()
            if not voucher:
                raise HTTPException(status_code=404, detail="القيد غير موجود")
            ensure_company_access(user, voucher["company_id"])
            conn.execute("SELECT erp.test_unpost_voucher(%s,%s)", (voucher_id, user["user_id"]))
            audit(conn, user, "UNPOST_TEST", "VOUCHER", voucher_id, voucher["company_id"], {"reason": data.reason})
            return {"message": "تم إرجاع القيد إلى مسودة للاختبار. لا تستخدم هذه العملية في التشغيل الفعلي"}


@app.get("/api/companies/{company_id}/reset-preview")
def company_reset_preview(
    company_id: UUID,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_group_admin(user)
    require_permission(user, "COMPANY_RESET")
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        company = conn.execute(
            "SELECT company_code,company_name FROM erp.companies WHERE group_id=%s AND company_id=%s",
            (user["group_id"], company_id),
        ).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="الشركة غير موجودة")
        counts = {
            "vouchers": conn.execute("SELECT COUNT(*) AS n FROM erp.journal_vouchers WHERE company_id=%s", (company_id,)).fetchone()["n"],
            "entries": conn.execute("SELECT COUNT(*) AS n FROM erp.journal_entries WHERE company_id=%s", (company_id,)).fetchone()["n"],
            "opening_batches": conn.execute("SELECT COUNT(*) AS n FROM erp.opening_balance_batches WHERE company_id=%s", (company_id,)).fetchone()["n"],
            "invoices": conn.execute("SELECT COUNT(*) AS n FROM erp.invoices WHERE company_id=%s", (company_id,)).fetchone()["n"],
            "cash_transactions": conn.execute("SELECT COUNT(*) AS n FROM erp.cash_transactions WHERE company_id=%s", (company_id,)).fetchone()["n"],
            "parties": conn.execute("SELECT COUNT(*) AS n FROM erp.parties WHERE company_id=%s", (company_id,)).fetchone()["n"],
            "bank_accounts": conn.execute("SELECT COUNT(*) AS n FROM erp.bank_accounts WHERE company_id=%s", (company_id,)).fetchone()["n"],
            "fixed_assets": conn.execute("SELECT COUNT(*) AS n FROM erp.fixed_assets WHERE company_id=%s", (company_id,)).fetchone()["n"],
        }
    return {
        "company": company,
        "counts": counts,
        "confirmation_text": f"RESET {company['company_code']}",
        "enabled": ALLOW_COMPANY_RESET,
        "preserved": ["الشركة", "المستخدمون والصلاحيات", "دليل المجموعة", "حسابات الشركة", "سجل التدقيق"],
    }


def _company_reset_counts(conn: Connection, company_id: UUID) -> dict[str, int]:
    tables = [
        "journal_vouchers", "journal_entries", "opening_balance_batches", "invoices",
        "invoice_lines", "cash_transactions", "parties", "bank_accounts", "fixed_assets",
        "asset_categories", "asset_depreciation_entries", "bank_revaluations", "branches",
        "cost_centers", "fiscal_years", "fiscal_periods", "exchange_rates",
    ]
    result: dict[str, int] = {}
    for table in tables:
        result[table] = int(conn.execute(f"SELECT COUNT(*) AS n FROM erp.{table} WHERE company_id=%s", (company_id,)).fetchone()["n"])
    return result


@app.post("/api/companies/{company_id}/reset-data")
def reset_company_data(
    company_id: UUID,
    data: CompanyResetRequest,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_group_admin(user)
    require_permission(user, "COMPANY_RESET")
    if not ALLOW_COMPANY_RESET:
        raise HTTPException(status_code=403, detail="تصفير الشركات معطل. فعّل ALLOW_COMPANY_RESET=true في Render أثناء التجربة فقط")
    with pool.connection() as conn:
        with conn.transaction():
            company = conn.execute(
                "SELECT company_code,company_name FROM erp.companies WHERE group_id=%s AND company_id=%s FOR UPDATE",
                (user["group_id"], company_id),
            ).fetchone()
            if not company:
                raise HTTPException(status_code=404, detail="الشركة غير موجودة")
            expected = f"RESET {company['company_code']}"
            if data.confirmation_text.strip() != expected:
                raise HTTPException(status_code=422, detail=f"اكتب عبارة التأكيد كما هي: {expected}")
            counts = _company_reset_counts(conn, company_id)
            conn.execute("SELECT set_config('erp.company_reset','on',TRUE)")

            # Remove source documents before their linked vouchers.
            conn.execute("DELETE FROM erp.asset_depreciation_entries WHERE company_id=%s", (company_id,))
            conn.execute("DELETE FROM erp.bank_revaluations WHERE company_id=%s", (company_id,))
            conn.execute("DELETE FROM erp.opening_balance_batches WHERE company_id=%s", (company_id,))
            conn.execute("DELETE FROM erp.invoice_lines WHERE company_id=%s", (company_id,))
            conn.execute("DELETE FROM erp.invoices WHERE company_id=%s", (company_id,))
            conn.execute("DELETE FROM erp.cash_transactions WHERE company_id=%s", (company_id,))
            conn.execute("UPDATE erp.journal_vouchers SET reversal_of_voucher_id=NULL, correction_of_voucher_id=NULL WHERE company_id=%s", (company_id,))
            conn.execute("DELETE FROM erp.journal_vouchers WHERE company_id=%s", (company_id,))

            if data.mode == "FULL_PRESERVE_CHART":
                conn.execute("DELETE FROM erp.fixed_assets WHERE company_id=%s", (company_id,))
                conn.execute("DELETE FROM erp.asset_categories WHERE company_id=%s", (company_id,))
                conn.execute("DELETE FROM erp.bank_accounts WHERE company_id=%s", (company_id,))
                conn.execute("DELETE FROM erp.parties WHERE company_id=%s", (company_id,))
                conn.execute("DELETE FROM erp.exchange_rates WHERE company_id=%s", (company_id,))
                conn.execute("DELETE FROM erp.cost_centers WHERE company_id=%s", (company_id,))
                conn.execute("DELETE FROM erp.branches WHERE company_id=%s", (company_id,))
                conn.execute("DELETE FROM erp.fiscal_years WHERE company_id=%s", (company_id,))
                current_year = date.today().year
                fy = conn.execute(
                    """INSERT INTO erp.fiscal_years(group_id,company_id,year_name,start_date,end_date)
                       VALUES (%s,%s,%s,%s,%s) RETURNING fiscal_year_id""",
                    (user["group_id"], company_id, str(current_year), date(current_year,1,1), date(current_year,12,31)),
                ).fetchone()
                conn.execute("SELECT erp.create_monthly_periods(%s)", (fy["fiscal_year_id"],))
            else:
                conn.execute("UPDATE erp.bank_accounts SET opening_balance=0,opening_balance_base=0 WHERE company_id=%s", (company_id,))
                conn.execute("UPDATE erp.fixed_assets SET accumulated_depreciation=0,last_depreciation_date=NULL WHERE company_id=%s", (company_id,))

            reset_row = conn.execute(
                """INSERT INTO erp.company_data_resets(group_id,company_id,reset_mode,counts_before,requested_by,reason)
                   VALUES (%s,%s,%s,%s::jsonb,%s,%s) RETURNING reset_id,created_at""",
                (user["group_id"], company_id, data.mode, json.dumps(counts), user["user_id"], data.reason),
            ).fetchone()
            audit(conn, user, "RESET_COMPANY_DATA", "COMPANY", company_id, company_id, {"mode": data.mode, "counts": counts, "reset_id": reset_row["reset_id"]})
            return {"message": "تم تصفير بيانات الشركة مع الاحتفاظ بالشركة والمستخدمين وشجرة الحسابات", "reset": reset_row, "counts_deleted": counts}


@app.get("/api/opening-balances")
def list_opening_balances(
    user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID
) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT ob.opening_batch_id,ob.batch_no,ob.opening_date,ob.description,
                      v.voucher_id,v.voucher_no,v.status,v.created_at,v.posted_at,
                      COALESCE((SELECT SUM(e.debit_amount) FROM erp.journal_entries e WHERE e.voucher_id=v.voucher_id),0) AS total_debit,
                      COALESCE((SELECT SUM(e.credit_amount) FROM erp.journal_entries e WHERE e.voucher_id=v.voucher_id),0) AS total_credit
               FROM erp.opening_balance_batches ob
               JOIN erp.journal_vouchers v ON v.voucher_id=ob.voucher_id
               WHERE ob.group_id=%s AND ob.company_id=%s
               ORDER BY ob.opening_date DESC,ob.created_at DESC""",
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/opening-balances", status_code=201)
def create_opening_balance(
    data: OpeningBalanceCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]
) -> dict[str, Any]:
    require_permission(user, "OPENING_BALANCE_CREATE")
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        with conn.transaction():
            voucher = create_voucher_db(
                conn, user=user, company_id=data.company_id,
                voucher_no=f"OPEN-{data.batch_no}", voucher_type="OPENING",
                document_date=data.opening_date, posting_date=data.opening_date,
                description=data.description or f"أرصدة افتتاحية {data.batch_no}",
                entries=[e.model_dump() for e in data.entries], source_module="OPENING",
                external_reference=data.batch_no, post_immediately=data.post_immediately,
            )
            batch = conn.execute(
                """INSERT INTO erp.opening_balance_batches
                       (group_id,company_id,batch_no,opening_date,description,voucher_id,created_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (user["group_id"],data.company_id,data.batch_no,data.opening_date,data.description,
                 voucher["voucher_id"],user["user_id"]),
            ).fetchone()
            audit(conn,user,"CREATE","OPENING_BALANCE",batch["opening_batch_id"],data.company_id,{"status":voucher["status"]})
            return {**batch,"status":voucher["status"]}


@app.get("/api/parties")
def list_parties(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, party_type: str | None = None) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    query = """SELECT party_id, party_code, party_name, party_type, tax_registration_no,
                      email, phone, address, receivable_account_id, payable_account_id,
                      credit_limit, payment_terms_days
               FROM erp.parties
               WHERE group_id=%s AND company_id=%s AND is_active=TRUE"""
    params: list[Any] = [user["group_id"], company_id]
    if party_type is not None:
        query += " AND (party_type=%s OR party_type='BOTH')"
        params.append(party_type)
    query += " ORDER BY party_code"
    with pool.connection() as conn:
        return conn.execute(query, params).fetchall()


@app.post("/api/parties", status_code=201)
def create_party(data: PartyCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "PARTY_MANAGE")
    ensure_company_access(user, data.company_id)
    if data.party_type in ("CUSTOMER", "BOTH") and not data.receivable_account_id:
        raise HTTPException(status_code=422, detail="حساب العملاء مطلوب")
    if data.party_type in ("VENDOR", "BOTH") and not data.payable_account_id:
        raise HTTPException(status_code=422, detail="حساب الموردين مطلوب")
    with pool.connection() as conn:
        if data.receivable_account_id:
            ensure_account(conn, user["group_id"], data.company_id, data.receivable_account_id)
        if data.payable_account_id:
            ensure_account(conn, user["group_id"], data.company_id, data.payable_account_id)
        row = conn.execute(
            """INSERT INTO erp.parties
                   (group_id, company_id, party_code, party_name, party_type,
                    tax_registration_no, email, phone, address, receivable_account_id,
                    payable_account_id, credit_limit, payment_terms_days)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (user["group_id"], data.company_id, data.party_code, data.party_name,
             data.party_type, data.tax_registration_no, str(data.email) if data.email else None,
             data.phone, data.address, data.receivable_account_id, data.payable_account_id,
             data.credit_limit, data.payment_terms_days),
        ).fetchone()
        audit(conn, user, "CREATE", "PARTY", row["party_id"], data.company_id, {"type": data.party_type})
        conn.commit()
    return row


@app.get("/api/bank-accounts")
def list_bank_accounts(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT b.bank_account_id, b.bank_code, b.bank_name, b.account_name,
                      b.account_number, b.iban, b.currency, b.opening_balance,
                      b.opening_exchange_rate, b.opening_balance_base,
                      a.local_account_code, a.local_account_name,
                      b.opening_balance + COALESCE(SUM(CASE WHEN ct.transaction_type='RECEIPT' THEN ct.amount ELSE -ct.amount END),0) AS current_balance,
                      b.opening_balance_base + COALESCE(SUM(CASE WHEN ct.transaction_type='RECEIPT' THEN ct.base_amount ELSE -ct.base_amount END),0) AS current_balance_base
               FROM erp.bank_accounts b
               JOIN erp.accounts a ON a.account_id=b.gl_account_id
               LEFT JOIN erp.cash_transactions ct ON ct.bank_account_id=b.bank_account_id AND ct.status='POSTED'
               WHERE b.group_id=%s AND b.company_id=%s AND b.is_active=TRUE
               GROUP BY b.bank_account_id, a.account_id ORDER BY b.bank_code""",
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/bank-accounts", status_code=201)
def create_bank_account(data: BankAccountCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "BANK_MANAGE")
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        currency = data.currency.upper()
        rate = data.opening_exchange_rate
        source = "MANUAL" if rate else "BASE"
        if rate is None:
            rate, source = resolve_exchange_rate_db(
                conn, group_id=user["group_id"], company_id=data.company_id,
                currency_code=currency, rate_date=date.today(), rate_type="SPOT",
            )
        opening_base = money(data.opening_balance * rate)
        row = conn.execute(
            """INSERT INTO erp.bank_accounts
                   (group_id, company_id, bank_code, bank_name, account_name,
                    account_number, iban, currency, gl_account_id, opening_balance,
                    opening_exchange_rate, opening_balance_base)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (user["group_id"], data.company_id, data.bank_code, data.bank_name,
             data.account_name, data.account_number, data.iban, currency,
             data.gl_account_id, data.opening_balance, rate, opening_base),
        ).fetchone()
        audit(conn, user, "CREATE", "BANK_ACCOUNT", row["bank_account_id"], data.company_id,
              {"currency": currency, "rate": str(rate), "rate_source": source})
        conn.commit()
    return row


@app.get("/api/invoices")
def list_invoices(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, invoice_type: str | None = None) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    query = """SELECT i.invoice_id, i.invoice_type, i.invoice_no, i.invoice_date, i.due_date,
                      i.currency, i.exchange_rate, i.subtotal, i.tax_amount, i.total_amount,
                      i.base_subtotal, i.base_tax_amount, i.base_total_amount, i.status,
                      i.payment_method, i.paid_amount, i.base_paid_amount,
                      GREATEST(i.total_amount - i.paid_amount, 0) AS outstanding_amount,
                      GREATEST(i.base_total_amount - i.base_paid_amount, 0) AS base_outstanding_amount,
                      p.party_code, p.party_name, i.description
               FROM erp.invoices i JOIN erp.parties p ON p.party_id=i.party_id
               WHERE i.group_id=%s AND i.company_id=%s"""
    params: list[Any] = [user["group_id"], company_id]
    if invoice_type is not None:
        query += " AND i.invoice_type=%s"
        params.append(invoice_type)
    query += " ORDER BY i.invoice_date DESC, i.created_at DESC"
    with pool.connection() as conn:
        return conn.execute(query, params).fetchall()


@app.post("/api/invoices", status_code=201)
def create_invoice(data: InvoiceCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "PARTY_MANAGE")
    ensure_company_access(user, data.company_id)
    if data.due_date < data.invoice_date:
        raise HTTPException(status_code=422, detail="تاريخ الاستحقاق لا يسبق تاريخ الفاتورة")
    with pool.connection() as conn:
        with conn.transaction():
            party = conn.execute(
                "SELECT * FROM erp.parties WHERE group_id=%s AND company_id=%s AND party_id=%s AND is_active",
                (user["group_id"], data.company_id, data.party_id),
            ).fetchone()
            if not party:
                raise HTTPException(status_code=422, detail="العميل/المورد غير موجود")
            if data.invoice_type == "SALES" and party["party_type"] not in ("CUSTOMER", "BOTH"):
                raise HTTPException(status_code=422, detail="الطرف ليس عميلاً")
            if data.invoice_type == "PURCHASE" and party["party_type"] not in ("VENDOR", "BOTH"):
                raise HTTPException(status_code=422, detail="الطرف ليس مورداً")

            control_account = data.control_account_id or (
                party["receivable_account_id"] if data.invoice_type == "SALES" else party["payable_account_id"]
            )
            if not control_account:
                raise HTTPException(status_code=422, detail="حدد حساب العملاء/الموردين للطرف أو الفاتورة")
            ensure_account(conn, user["group_id"], data.company_id, control_account)

            payment_method = data.payment_method
            settlement_account: UUID | None = None
            bank_account_id: UUID | None = None
            bank = None
            if payment_method == "CASH":
                if not data.settlement_account_id:
                    raise HTTPException(status_code=422, detail="اختر حساب الصندوق للفاتورة النقدية")
                settlement_account = data.settlement_account_id
                ensure_account(conn, user["group_id"], data.company_id, settlement_account)
            elif payment_method == "BANK":
                if not data.bank_account_id:
                    raise HTTPException(status_code=422, detail="اختر الحساب البنكي")
                bank = conn.execute(
                    "SELECT * FROM erp.bank_accounts WHERE group_id=%s AND company_id=%s AND bank_account_id=%s AND is_active",
                    (user["group_id"], data.company_id, data.bank_account_id),
                ).fetchone()
                if not bank:
                    raise HTTPException(status_code=422, detail="الحساب البنكي غير موجود")
                settlement_account = bank["gl_account_id"]
                bank_account_id = bank["bank_account_id"]

            currency = data.currency.upper()
            if bank and str(bank["currency"]).upper() != currency:
                raise HTTPException(status_code=422, detail="عملة الحساب البنكي يجب أن تطابق عملة الفاتورة")
            if data.exchange_rate is not None:
                rate, rate_source = Decimal(str(data.exchange_rate)), "MANUAL"
            else:
                rate, rate_source = resolve_exchange_rate_db(
                    conn, group_id=user["group_id"], company_id=data.company_id,
                    currency_code=currency, rate_date=data.invoice_date, rate_type="SPOT",
                )

            line_values=[]
            subtotal=tax_total=Decimal("0")
            for line in data.lines:
                ensure_account(conn, user["group_id"], data.company_id, line.account_id)
                net = money(line.quantity * line.unit_price)
                tax = money(net * line.tax_rate / Decimal("100"))
                total = money(net + tax)
                line_values.append((line, net, tax, total, money(net*rate), money(tax*rate), money(total*rate)))
                subtotal += net
                tax_total += tax
            subtotal=money(subtotal)
            tax_total=money(tax_total)
            total_amount=money(subtotal+tax_total)
            base_subtotal=money(subtotal*rate)
            base_tax=money(tax_total*rate)
            base_total=money(total_amount*rate)

            immediate_paid = data.post_immediately and payment_method in ("CASH", "BANK")
            paid_amount = total_amount if immediate_paid else Decimal("0")
            base_paid = base_total if immediate_paid else Decimal("0")

            invoice = conn.execute(
                """INSERT INTO erp.invoices
                       (group_id, company_id, invoice_type, invoice_no, party_id,
                        invoice_date, due_date, currency, exchange_rate, exchange_rate_source, description,
                        subtotal, tax_amount, total_amount, base_subtotal, base_tax_amount, base_total_amount,
                        control_account_id, tax_account_id, payment_method, settlement_account_id,
                        bank_account_id, paid_amount, base_paid_amount, created_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   RETURNING *""",
                (user["group_id"], data.company_id, data.invoice_type, data.invoice_no,
                 data.party_id, data.invoice_date, data.due_date, currency, rate, rate_source,
                 data.description, subtotal, tax_total, total_amount, base_subtotal, base_tax, base_total,
                 control_account, data.tax_account_id, payment_method, settlement_account,
                 bank_account_id, paid_amount, base_paid, user["user_id"]),
            ).fetchone()

            for idx,(line,net,tax,total,bnet,btax,btotal) in enumerate(line_values,1):
                conn.execute(
                    """INSERT INTO erp.invoice_lines
                           (invoice_id, group_id, company_id, line_no, description,
                            account_id, quantity, unit_price, tax_rate, net_amount, tax_amount, total_amount,
                            base_net_amount, base_tax_amount, base_total_amount, cost_center_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (invoice["invoice_id"], user["group_id"], data.company_id, idx, line.description,
                     line.account_id, line.quantity, line.unit_price, line.tax_rate, net, tax, total,
                     bnet, btax, btotal, line.cost_center_id),
                )

            if data.post_immediately:
                entries=[]
                debit_or_credit_account = control_account if payment_method == "CREDIT" else settlement_account
                if not debit_or_credit_account:
                    raise HTTPException(status_code=422, detail="تعذر تحديد حساب السداد")
                if data.invoice_type == "SALES":
                    entries.append({"account_id": debit_or_credit_account, "debit_amount": base_total, "credit_amount": 0, "description": f"فاتورة مبيعات {data.invoice_no}"})
                    for line,net,tax,total,bnet,btax,btotal in line_values:
                        entries.append({"account_id": line.account_id, "debit_amount": 0, "credit_amount": bnet, "description": line.description, "cost_center_id": line.cost_center_id})
                    if base_tax and data.tax_account_id:
                        entries.append({"account_id": data.tax_account_id, "debit_amount": 0, "credit_amount": base_tax, "description": "ضريبة مخرجات"})
                else:
                    for line,net,tax,total,bnet,btax,btotal in line_values:
                        entries.append({"account_id": line.account_id, "debit_amount": bnet, "credit_amount": 0, "description": line.description, "cost_center_id": line.cost_center_id})
                    if base_tax and data.tax_account_id:
                        entries.append({"account_id": data.tax_account_id, "debit_amount": base_tax, "credit_amount": 0, "description": "ضريبة مدخلات"})
                    entries.append({"account_id": debit_or_credit_account, "debit_amount": 0, "credit_amount": base_total, "description": f"فاتورة مشتريات {data.invoice_no}"})

                voucher=create_voucher_db(
                    conn, user=user, company_id=data.company_id,
                    voucher_no=f"{'SI' if data.invoice_type == 'SALES' else 'PI'}-{data.invoice_no}",
                    document_date=data.invoice_date, posting_date=data.invoice_date,
                    description=data.description or f"فاتورة {data.invoice_no}", entries=entries,
                    source_module="AR" if data.invoice_type == "SALES" else "AP",
                    external_reference=data.invoice_no, post_immediately=True,
                )
                new_status = "PAID" if payment_method in ("CASH", "BANK") else "POSTED"
                conn.execute(
                    "UPDATE erp.invoices SET status=%s, voucher_id=%s WHERE invoice_id=%s",
                    (new_status, voucher["voucher_id"], invoice["invoice_id"]),
                )
                invoice["status"] = new_status
                invoice["voucher_id"] = voucher["voucher_id"]
                if immediate_paid:
                    conn.execute(
                        """INSERT INTO erp.invoice_payments
                               (group_id, company_id, invoice_id, payment_no, payment_date,
                                payment_method, settlement_account_id, bank_account_id,
                                amount, currency, exchange_rate, base_amount, reference_no,
                                description, voucher_id, created_by)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (user["group_id"], data.company_id, invoice["invoice_id"],
                         f"AUTO-{'SI' if data.invoice_type == 'SALES' else 'PI'}-{data.invoice_no}",
                         data.invoice_date, payment_method, settlement_account, bank_account_id,
                         total_amount, currency, rate, base_total, data.invoice_no,
                         "سداد فوري مع الفاتورة", voucher["voucher_id"], user["user_id"]),
                    )

            audit(conn, user, "CREATE", "INVOICE", invoice["invoice_id"], data.company_id,
                  {"type": data.invoice_type, "payment_method": payment_method,
                   "foreign_total": str(total_amount), "base_total": str(base_total),
                   "currency": currency, "rate": str(rate)})
            return invoice


@app.post("/api/invoices/{invoice_id}/post")
def post_invoice(invoice_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "VOUCHER_POST")
    with pool.connection() as conn:
        with conn.transaction():
            inv = conn.execute(
                "SELECT * FROM erp.invoices WHERE group_id=%s AND invoice_id=%s FOR UPDATE",
                (user["group_id"], invoice_id),
            ).fetchone()
            if not inv:
                raise HTTPException(status_code=404, detail="الفاتورة غير موجودة")
            ensure_company_access(user, inv["company_id"])
            if inv["status"] != "DRAFT":
                raise HTTPException(status_code=409, detail="يمكن ترحيل الفاتورة المسودة فقط")
            lines = conn.execute(
                "SELECT * FROM erp.invoice_lines WHERE invoice_id=%s ORDER BY line_no",
                (invoice_id,),
            ).fetchall()
            if not lines:
                raise HTTPException(status_code=422, detail="الفاتورة لا تحتوي على بنود")

            payment_method = inv["payment_method"]
            settlement_account = inv["settlement_account_id"]
            bank_account_id = inv["bank_account_id"]
            if payment_method == "CASH" and not settlement_account:
                raise HTTPException(status_code=422, detail="حدد حساب الصندوق قبل الترحيل")
            if payment_method == "BANK":
                if not bank_account_id:
                    raise HTTPException(status_code=422, detail="حدد الحساب البنكي قبل الترحيل")
                bank = conn.execute(
                    "SELECT * FROM erp.bank_accounts WHERE bank_account_id=%s AND company_id=%s AND group_id=%s AND is_active",
                    (bank_account_id, inv["company_id"], user["group_id"]),
                ).fetchone()
                if not bank:
                    raise HTTPException(status_code=422, detail="الحساب البنكي غير موجود أو غير نشط")
                settlement_account = bank["gl_account_id"]

            debit_or_credit_account = inv["control_account_id"] if payment_method == "CREDIT" else settlement_account
            entries=[]
            if inv["invoice_type"] == "SALES":
                entries.append({"account_id": debit_or_credit_account, "debit_amount": inv["base_total_amount"], "credit_amount": 0, "description": f"فاتورة مبيعات {inv['invoice_no']}"})
                for line in lines:
                    entries.append({"account_id": line["account_id"], "debit_amount": 0, "credit_amount": line["base_net_amount"], "description": line["description"], "cost_center_id": line["cost_center_id"]})
                if inv["base_tax_amount"] and inv["tax_account_id"]:
                    entries.append({"account_id": inv["tax_account_id"], "debit_amount": 0, "credit_amount": inv["base_tax_amount"], "description": "ضريبة مخرجات"})
            else:
                for line in lines:
                    entries.append({"account_id": line["account_id"], "debit_amount": line["base_net_amount"], "credit_amount": 0, "description": line["description"], "cost_center_id": line["cost_center_id"]})
                if inv["base_tax_amount"] and inv["tax_account_id"]:
                    entries.append({"account_id": inv["tax_account_id"], "debit_amount": inv["base_tax_amount"], "credit_amount": 0, "description": "ضريبة مدخلات"})
                entries.append({"account_id": debit_or_credit_account, "debit_amount": 0, "credit_amount": inv["base_total_amount"], "description": f"فاتورة مشتريات {inv['invoice_no']}"})

            voucher = create_voucher_db(
                conn, user=user, company_id=inv["company_id"],
                voucher_no=f"{'SI' if inv['invoice_type'] == 'SALES' else 'PI'}-{inv['invoice_no']}",
                document_date=inv["invoice_date"], posting_date=inv["invoice_date"],
                description=inv["description"] or f"فاتورة {inv['invoice_no']}", entries=entries,
                source_module="AR" if inv["invoice_type"] == "SALES" else "AP",
                external_reference=inv["invoice_no"], post_immediately=True,
            )
            immediate_paid = payment_method in ("CASH", "BANK")
            new_status = "PAID" if immediate_paid else "POSTED"
            paid_amount = inv["total_amount"] if immediate_paid else Decimal("0")
            base_paid = inv["base_total_amount"] if immediate_paid else Decimal("0")
            conn.execute(
                """UPDATE erp.invoices
                   SET status=%s, voucher_id=%s, settlement_account_id=%s,
                       paid_amount=%s, base_paid_amount=%s
                   WHERE invoice_id=%s""",
                (new_status, voucher["voucher_id"], settlement_account,
                 paid_amount, base_paid, invoice_id),
            )
            if immediate_paid:
                conn.execute(
                    """INSERT INTO erp.invoice_payments
                           (group_id, company_id, invoice_id, payment_no, payment_date,
                            payment_method, settlement_account_id, bank_account_id,
                            amount, currency, exchange_rate, base_amount, reference_no,
                            description, voucher_id, created_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (invoice_id, payment_no) DO NOTHING""",
                    (user["group_id"], inv["company_id"], invoice_id,
                     f"AUTO-{'SI' if inv['invoice_type'] == 'SALES' else 'PI'}-{inv['invoice_no']}",
                     inv["invoice_date"], payment_method, settlement_account, bank_account_id,
                     inv["total_amount"], inv["currency"], inv["exchange_rate"], inv["base_total_amount"],
                     inv["invoice_no"], "سداد فوري مع الفاتورة", voucher["voucher_id"], user["user_id"]),
                )
            audit(conn, user, "POST", "INVOICE", invoice_id, inv["company_id"],
                  {"invoice_no": inv["invoice_no"], "payment_method": payment_method})
            return {"message": "تم ترحيل الفاتورة", "status": new_status, "voucher_id": voucher["voucher_id"]}


@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    with pool.connection() as conn:
        inv=conn.execute(
            """SELECT i.*, p.party_code, p.party_name, p.tax_registration_no, p.address,
                      c.company_code, c.company_name, c.legal_name, c.tax_registration_no AS company_tax_no,
                      c.address AS company_address,
                      GREATEST(i.total_amount-i.paid_amount,0) AS outstanding_amount,
                      GREATEST(i.base_total_amount-i.base_paid_amount,0) AS base_outstanding_amount
               FROM erp.invoices i
               JOIN erp.parties p ON p.party_id=i.party_id
               JOIN erp.companies c ON c.company_id=i.company_id
               WHERE i.group_id=%s AND i.invoice_id=%s""",
            (user["group_id"], invoice_id),
        ).fetchone()
        if not inv:
            raise HTTPException(status_code=404, detail="الفاتورة غير موجودة")
        ensure_company_access(user, inv["company_id"])
        inv["lines"]=conn.execute(
            """SELECT il.*, a.local_account_code, a.local_account_name
               FROM erp.invoice_lines il JOIN erp.accounts a ON a.account_id=il.account_id
               WHERE il.invoice_id=%s ORDER BY il.line_no""", (invoice_id,),
        ).fetchall()
        inv["payments"]=conn.execute(
            """SELECT ip.invoice_payment_id, ip.payment_no, ip.payment_date,
                      ip.payment_method, ip.amount, ip.currency, ip.exchange_rate,
                      ip.base_amount, ip.reference_no, ip.description, ip.status,
                      b.bank_name, b.account_name, a.local_account_code, a.local_account_name
               FROM erp.invoice_payments ip
               JOIN erp.accounts a ON a.account_id=ip.settlement_account_id
               LEFT JOIN erp.bank_accounts b ON b.bank_account_id=ip.bank_account_id
               WHERE ip.invoice_id=%s
               ORDER BY ip.payment_date, ip.created_at""", (invoice_id,),
        ).fetchall()
        return inv


@app.get("/api/invoices/{invoice_id}/payments")
def list_invoice_payments(invoice_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        inv = conn.execute(
            "SELECT company_id FROM erp.invoices WHERE group_id=%s AND invoice_id=%s",
            (user["group_id"], invoice_id),
        ).fetchone()
        if not inv:
            raise HTTPException(status_code=404, detail="الفاتورة غير موجودة")
        ensure_company_access(user, inv["company_id"])
        return conn.execute(
            """SELECT ip.*, b.bank_name, b.account_name,
                      a.local_account_code, a.local_account_name
               FROM erp.invoice_payments ip
               JOIN erp.accounts a ON a.account_id=ip.settlement_account_id
               LEFT JOIN erp.bank_accounts b ON b.bank_account_id=ip.bank_account_id
               WHERE ip.group_id=%s AND ip.invoice_id=%s
               ORDER BY ip.payment_date, ip.created_at""",
            (user["group_id"], invoice_id),
        ).fetchall()


@app.post("/api/invoices/{invoice_id}/payments", status_code=201)
def create_invoice_payment(
    invoice_id: UUID,
    data: InvoicePaymentCreate,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_permission(user, "BANK_MANAGE")
    with pool.connection() as conn:
        with conn.transaction():
            inv = conn.execute(
                """SELECT i.*, p.party_name
                   FROM erp.invoices i JOIN erp.parties p ON p.party_id=i.party_id
                   WHERE i.group_id=%s AND i.invoice_id=%s
                   FOR UPDATE""",
                (user["group_id"], invoice_id),
            ).fetchone()
            if not inv:
                raise HTTPException(status_code=404, detail="الفاتورة غير موجودة")
            ensure_company_access(user, inv["company_id"])
            if inv["status"] in ("DRAFT", "CANCELLED"):
                raise HTTPException(status_code=409, detail="لا يمكن سداد فاتورة مسودة أو ملغاة")
            outstanding = money(Decimal(str(inv["total_amount"])) - Decimal(str(inv["paid_amount"])))
            if outstanding <= 0 or inv["status"] == "PAID":
                raise HTTPException(status_code=409, detail="الفاتورة مسددة بالكامل")
            amount = money(data.amount)
            if amount > outstanding:
                raise HTTPException(status_code=422, detail=f"المبلغ أكبر من المتبقي {outstanding}")

            settlement_account: UUID | None = None
            bank_account_id: UUID | None = None
            if data.payment_method == "BANK":
                if not data.bank_account_id:
                    raise HTTPException(status_code=422, detail="اختر الحساب البنكي")
                bank = conn.execute(
                    "SELECT * FROM erp.bank_accounts WHERE group_id=%s AND company_id=%s AND bank_account_id=%s AND is_active",
                    (user["group_id"], inv["company_id"], data.bank_account_id),
                ).fetchone()
                if not bank:
                    raise HTTPException(status_code=422, detail="الحساب البنكي غير موجود")
                if str(bank["currency"]).upper() != str(inv["currency"]).upper():
                    raise HTTPException(status_code=422, detail="عملة الحساب البنكي يجب أن تطابق عملة الفاتورة")
                settlement_account = bank["gl_account_id"]
                bank_account_id = bank["bank_account_id"]
            else:
                if not data.settlement_account_id:
                    raise HTTPException(status_code=422, detail="اختر حساب الصندوق")
                settlement_account = data.settlement_account_id
                ensure_account(conn, user["group_id"], inv["company_id"], settlement_account)

            # Settlement uses the invoice carrying rate. Foreign-currency bank balances
            # can be revalued later from the bank revaluation screen.
            rate = Decimal(str(inv["exchange_rate"]))
            if data.exchange_rate is not None and money(Decimal(str(data.exchange_rate)) - rate) != 0:
                raise HTTPException(status_code=422, detail="حالياً يجب أن يكون سعر سداد الفاتورة مساوياً لسعر الفاتورة؛ استخدم إعادة تقييم البنك لفروق العملة")
            base_amount = money(amount * rate)
            description = data.description or (
                f"تحصيل فاتورة {inv['invoice_no']}" if inv["invoice_type"] == "SALES"
                else f"سداد فاتورة {inv['invoice_no']}"
            )
            if inv["invoice_type"] == "SALES":
                entries = [
                    {"account_id": settlement_account, "debit_amount": base_amount, "credit_amount": 0, "description": description},
                    {"account_id": inv["control_account_id"], "debit_amount": 0, "credit_amount": base_amount, "description": description},
                ]
                source_module = "AR"
            else:
                entries = [
                    {"account_id": inv["control_account_id"], "debit_amount": base_amount, "credit_amount": 0, "description": description},
                    {"account_id": settlement_account, "debit_amount": 0, "credit_amount": base_amount, "description": description},
                ]
                source_module = "AP"

            voucher = create_voucher_db(
                conn, user=user, company_id=inv["company_id"],
                voucher_no=f"PAY-{data.payment_no}",
                document_date=data.payment_date, posting_date=data.payment_date,
                description=description, entries=entries, source_module=source_module,
                external_reference=data.reference_no or data.payment_no,
                post_immediately=True,
            )
            payment = conn.execute(
                """INSERT INTO erp.invoice_payments
                       (group_id, company_id, invoice_id, payment_no, payment_date,
                        payment_method, settlement_account_id, bank_account_id,
                        amount, currency, exchange_rate, base_amount, reference_no,
                        description, voucher_id, created_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   RETURNING *""",
                (user["group_id"], inv["company_id"], invoice_id, data.payment_no,
                 data.payment_date, data.payment_method, settlement_account,
                 bank_account_id, amount, inv["currency"], rate, base_amount,
                 data.reference_no, description, voucher["voucher_id"], user["user_id"]),
            ).fetchone()
            new_paid = money(Decimal(str(inv["paid_amount"])) + amount)
            new_base_paid = money(Decimal(str(inv["base_paid_amount"])) + base_amount)
            new_status = "PAID" if new_paid >= money(Decimal(str(inv["total_amount"]))) else "PARTIALLY_PAID"
            conn.execute(
                "UPDATE erp.invoices SET paid_amount=%s, base_paid_amount=%s, status=%s WHERE invoice_id=%s",
                (new_paid, new_base_paid, new_status, invoice_id),
            )
            audit(conn, user, "CREATE", "INVOICE_PAYMENT", payment["invoice_payment_id"], inv["company_id"],
                  {"invoice_id": str(invoice_id), "invoice_no": inv["invoice_no"],
                   "method": data.payment_method, "amount": str(amount), "currency": inv["currency"]})
            payment["invoice_status"] = new_status
            payment["invoice_paid_amount"] = new_paid
            payment["invoice_outstanding_amount"] = money(Decimal(str(inv["total_amount"])) - new_paid)
            return payment


@app.get("/api/cash-transactions")
def list_cash_transactions(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT ct.cash_transaction_id, ct.transaction_type, ct.transaction_no,
                      ct.transaction_date, ct.amount, ct.description, ct.reference_no,
                      b.bank_name, b.account_name, p.party_name, ct.status
               FROM erp.cash_transactions ct
               JOIN erp.bank_accounts b ON b.bank_account_id=ct.bank_account_id
               LEFT JOIN erp.parties p ON p.party_id=ct.party_id
               WHERE ct.group_id=%s AND ct.company_id=%s
               ORDER BY ct.transaction_date DESC, ct.created_at DESC""",
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/cash-transactions", status_code=201)
def create_cash_transaction(data: CashTransactionCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "BANK_MANAGE")
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        with conn.transaction():
            bank=conn.execute(
                "SELECT * FROM erp.bank_accounts WHERE group_id=%s AND company_id=%s AND bank_account_id=%s AND is_active",
                (user["group_id"], data.company_id, data.bank_account_id),
            ).fetchone()
            if not bank:
                raise HTTPException(status_code=422, detail="الحساب البنكي غير موجود")
            party=None
            if data.party_id:
                party=conn.execute(
                    "SELECT * FROM erp.parties WHERE group_id=%s AND company_id=%s AND party_id=%s",
                    (user["group_id"], data.company_id, data.party_id),
                ).fetchone()
            offset=data.offset_account_id
            if not offset and party:
                offset = party["receivable_account_id"] if data.transaction_type=="RECEIPT" else party["payable_account_id"]
            if not offset:
                raise HTTPException(status_code=422, detail="حدد الحساب المقابل أو اختر عميلاً/مورداً له حساب مراقبة")
            ensure_account(conn, user["group_id"], data.company_id, offset)
            currency=str(bank["currency"]).upper()
            if data.exchange_rate is not None:
                rate=Decimal(str(data.exchange_rate)); rate_source="MANUAL"
            else:
                rate, rate_source=resolve_exchange_rate_db(
                    conn, group_id=user["group_id"], company_id=data.company_id,
                    currency_code=currency, rate_date=data.transaction_date, rate_type="SPOT",
                )
            base_amount=money(data.amount*rate)
            description=data.description or ("سند قبض" if data.transaction_type=="RECEIPT" else "سند صرف")
            if data.transaction_type=="RECEIPT":
                entries=[
                    {"account_id": bank["gl_account_id"], "debit_amount": base_amount, "credit_amount": 0, "description": description},
                    {"account_id": offset, "debit_amount": 0, "credit_amount": base_amount, "description": description},
                ]
            else:
                entries=[
                    {"account_id": offset, "debit_amount": base_amount, "credit_amount": 0, "description": description},
                    {"account_id": bank["gl_account_id"], "debit_amount": 0, "credit_amount": base_amount, "description": description},
                ]
            voucher=create_voucher_db(
                conn, user=user, company_id=data.company_id, voucher_no=f"BANK-{data.transaction_no}",
                document_date=data.transaction_date, posting_date=data.transaction_date,
                description=description, entries=entries, source_module="BANK",
                external_reference=data.reference_no or data.transaction_no, post_immediately=True,
            )
            row=conn.execute(
                """INSERT INTO erp.cash_transactions
                       (group_id, company_id, transaction_type, transaction_no,
                        transaction_date, bank_account_id, party_id, offset_account_id,
                        amount, currency, exchange_rate, base_amount, description, reference_no,
                        status, voucher_id, created_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'POSTED',%s,%s) RETURNING *""",
                (user["group_id"], data.company_id, data.transaction_type, data.transaction_no,
                 data.transaction_date, data.bank_account_id, data.party_id, offset, data.amount,
                 currency, rate, base_amount, description, data.reference_no, voucher["voucher_id"], user["user_id"]),
            ).fetchone()
            audit(conn, user, "CREATE", "CASH_TRANSACTION", row["cash_transaction_id"], data.company_id,
                  {"currency": currency, "foreign_amount": str(data.amount), "base_amount": str(base_amount), "rate": str(rate), "rate_source": rate_source})
            return row


@app.get("/api/bank-revaluation-preview")
def bank_revaluation_preview(
    user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, revaluation_date: date
) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        base=get_base_currency(conn,user["group_id"])
        banks=conn.execute(
            """SELECT b.bank_account_id,b.bank_code,b.bank_name,b.account_name,b.currency,b.gl_account_id,
                      b.opening_balance + COALESCE(SUM(CASE WHEN ct.transaction_type='RECEIPT' THEN ct.amount ELSE -ct.amount END),0) AS foreign_balance,
                      b.opening_balance_base + COALESCE(SUM(CASE WHEN ct.transaction_type='RECEIPT' THEN ct.base_amount ELSE -ct.base_amount END),0) AS book_base_balance
               FROM erp.bank_accounts b
               LEFT JOIN erp.cash_transactions ct ON ct.bank_account_id=b.bank_account_id AND ct.status='POSTED' AND ct.transaction_date<=%s
               WHERE b.group_id=%s AND b.company_id=%s AND b.is_active=TRUE AND b.currency<>%s
               GROUP BY b.bank_account_id ORDER BY b.bank_code""",
            (revaluation_date,user["group_id"],company_id,base),
        ).fetchall()
        result=[]
        for b in banks:
            rate,source=resolve_exchange_rate_db(conn,group_id=user["group_id"],company_id=company_id,currency_code=b["currency"],rate_date=revaluation_date,rate_type="CLOSING")
            revalued=money(Decimal(str(b["foreign_balance"]))*rate)
            difference=money(revalued-Decimal(str(b["book_base_balance"])))
            result.append({**b,"closing_rate":rate,"rate_source":source,"revalued_base_balance":revalued,"difference_amount":difference})
        return result


@app.post("/api/bank-revaluations", status_code=201)
def create_bank_revaluations(data: BankRevaluationCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "BANK_MANAGE")
    ensure_company_access(user,data.company_id)
    with pool.connection() as conn:
        preview=bank_revaluation_preview(user,data.company_id,data.revaluation_date)
        posted=[];total=Decimal("0")
        with conn.transaction():
            ensure_account(conn,user["group_id"],data.company_id,data.gain_account_id)
            ensure_account(conn,user["group_id"],data.company_id,data.loss_account_id)
            for item in preview:
                diff=money(item["difference_amount"])
                if diff==0: continue
                if diff>0:
                    entries=[
                        {"account_id":item["gl_account_id"],"debit_amount":diff,"credit_amount":0,"description":"إعادة تقييم عملة بنك"},
                        {"account_id":data.gain_account_id,"debit_amount":0,"credit_amount":diff,"description":"أرباح فروق عملة"},
                    ]
                else:
                    amt=money(-diff)
                    entries=[
                        {"account_id":data.loss_account_id,"debit_amount":amt,"credit_amount":0,"description":"خسائر فروق عملة"},
                        {"account_id":item["gl_account_id"],"debit_amount":0,"credit_amount":amt,"description":"إعادة تقييم عملة بنك"},
                    ]
                voucher=create_voucher_db(
                    conn,user=user,company_id=data.company_id,
                    voucher_no=f"FX-{data.revaluation_date.strftime('%Y%m%d')}-{item['bank_code']}",
                    document_date=data.revaluation_date,posting_date=data.revaluation_date,
                    description=f"إعادة تقييم {item['bank_name']} {item['currency']}",entries=entries,
                    source_module="FX",external_reference=item["bank_code"],post_immediately=True,
                )
                row=conn.execute(
                    """INSERT INTO erp.bank_revaluations
                           (group_id,company_id,bank_account_id,revaluation_date,currency,closing_rate,
                            foreign_balance,book_base_balance,revalued_base_balance,difference_amount,voucher_id,created_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING bank_revaluation_id""",
                    (user["group_id"],data.company_id,item["bank_account_id"],data.revaluation_date,item["currency"],
                     item["closing_rate"],item["foreign_balance"],item["book_base_balance"],
                     item["revalued_base_balance"],diff,voucher["voucher_id"],user["user_id"]),
                ).fetchone()
                posted.append(row);total+=diff
            audit(conn,user,"CREATE","BANK_REVALUATION",None,data.company_id,{"date":str(data.revaluation_date),"count":len(posted),"net_difference":str(money(total))})
        return {"posted_count":len(posted),"net_difference":money(total)}


@app.get("/api/asset-categories")
def list_asset_categories(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT ac.*, aa.local_account_name AS asset_account_name,
                      ad.local_account_name AS accumulated_account_name,
                      de.local_account_name AS expense_account_name
               FROM erp.asset_categories ac
               JOIN erp.accounts aa ON aa.account_id=ac.asset_account_id
               JOIN erp.accounts ad ON ad.account_id=ac.accumulated_depreciation_account_id
               JOIN erp.accounts de ON de.account_id=ac.depreciation_expense_account_id
               WHERE ac.group_id=%s AND ac.company_id=%s AND ac.is_active ORDER BY ac.category_code""",
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/asset-categories", status_code=201)
def create_asset_category(data: AssetCategoryCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "ASSET_MANAGE")
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        for account_id in (data.asset_account_id, data.accumulated_depreciation_account_id, data.depreciation_expense_account_id):
            ensure_account(conn, user["group_id"], data.company_id, account_id)
        row = conn.execute(
            """INSERT INTO erp.asset_categories
                   (group_id, company_id, category_code, category_name, asset_account_id,
                    accumulated_depreciation_account_id, depreciation_expense_account_id,
                    useful_life_months)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (user["group_id"], data.company_id, data.category_code, data.category_name,
             data.asset_account_id, data.accumulated_depreciation_account_id,
             data.depreciation_expense_account_id, data.useful_life_months),
        ).fetchone()
        audit(conn, user, "CREATE", "ASSET_CATEGORY", row["asset_category_id"], data.company_id)
        conn.commit()
    return row


@app.get("/api/assets")
def list_assets(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT fa.*, ac.category_code, ac.category_name,
                      (fa.acquisition_cost-fa.residual_value)/fa.useful_life_months AS monthly_depreciation,
                      fa.acquisition_cost-fa.accumulated_depreciation AS net_book_value
               FROM erp.fixed_assets fa JOIN erp.asset_categories ac ON ac.asset_category_id=fa.asset_category_id
               WHERE fa.group_id=%s AND fa.company_id=%s ORDER BY fa.asset_code""",
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/assets", status_code=201)
def create_asset(data: AssetCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "ASSET_MANAGE")
    ensure_company_access(user, data.company_id)
    if data.residual_value > data.acquisition_cost:
        raise HTTPException(status_code=422, detail="القيمة التخريدية لا تتجاوز تكلفة الأصل")
    with pool.connection() as conn:
        category = conn.execute(
            "SELECT * FROM erp.asset_categories WHERE group_id=%s AND company_id=%s AND asset_category_id=%s",
            (user["group_id"], data.company_id, data.asset_category_id),
        ).fetchone()
        if not category:
            raise HTTPException(status_code=422, detail="فئة الأصل غير موجودة")
        row = conn.execute(
            """INSERT INTO erp.fixed_assets
                   (group_id, company_id, asset_code, asset_name, asset_category_id,
                    acquisition_date, placed_in_service_date, acquisition_cost,
                    residual_value, useful_life_months, location, notes)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (user["group_id"], data.company_id, data.asset_code, data.asset_name,
             data.asset_category_id, data.acquisition_date, data.placed_in_service_date,
             data.acquisition_cost, data.residual_value,
             data.useful_life_months or category["useful_life_months"], data.location, data.notes),
        ).fetchone()
        audit(conn, user, "CREATE", "FIXED_ASSET", row["asset_id"], data.company_id)
        conn.commit()
    return row


@app.get("/api/assets/depreciation-preview")
def depreciation_preview(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, depreciation_date: date) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        rows = conn.execute(
            """SELECT fa.asset_id, fa.asset_code, fa.asset_name, fa.acquisition_cost,
                      fa.residual_value, fa.accumulated_depreciation, fa.useful_life_months,
                      ac.depreciation_expense_account_id, ac.accumulated_depreciation_account_id,
                      GREATEST(LEAST((fa.acquisition_cost-fa.residual_value)/fa.useful_life_months,
                           fa.acquisition_cost-fa.residual_value-fa.accumulated_depreciation),0)::NUMERIC(20,4) AS amount
               FROM erp.fixed_assets fa JOIN erp.asset_categories ac ON ac.asset_category_id=fa.asset_category_id
               WHERE fa.group_id=%s AND fa.company_id=%s AND fa.status='ACTIVE'
                 AND fa.placed_in_service_date<=%s
                 AND (fa.last_depreciation_date IS NULL OR fa.last_depreciation_date<%s)
               ORDER BY fa.asset_code""",
            (user["group_id"], company_id, depreciation_date, depreciation_date),
        ).fetchall()
    return [r for r in rows if Decimal(str(r["amount"])) > 0]


@app.post("/api/assets/run-depreciation", status_code=201)
def run_depreciation(data: DepreciationRunRequest, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_permission(user, "ASSET_MANAGE")
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        try:
            rows = conn.execute(
                """SELECT fa.asset_id, fa.asset_code, fa.asset_name,
                          ac.depreciation_expense_account_id, ac.accumulated_depreciation_account_id,
                          GREATEST(LEAST((fa.acquisition_cost-fa.residual_value)/fa.useful_life_months,
                               fa.acquisition_cost-fa.residual_value-fa.accumulated_depreciation),0)::NUMERIC(20,4) AS amount
                   FROM erp.fixed_assets fa JOIN erp.asset_categories ac ON ac.asset_category_id=fa.asset_category_id
                   WHERE fa.group_id=%s AND fa.company_id=%s AND fa.status='ACTIVE'
                     AND fa.placed_in_service_date<=%s
                     AND (fa.last_depreciation_date IS NULL OR fa.last_depreciation_date<%s)
                   FOR UPDATE OF fa""",
                (user["group_id"], data.company_id, data.depreciation_date, data.depreciation_date),
            ).fetchall()
            rows = [r for r in rows if Decimal(str(r["amount"])) > 0]
            if not rows:
                raise HTTPException(status_code=422, detail="لا توجد أصول مستحقة للإهلاك")
            entries = []
            for row in rows:
                entries.extend([
                    {"account_id": row["depreciation_expense_account_id"], "debit_amount": row["amount"], "credit_amount": 0, "description": f"إهلاك {row['asset_name']}"},
                    {"account_id": row["accumulated_depreciation_account_id"], "debit_amount": 0, "credit_amount": row["amount"], "description": f"مجمع إهلاك {row['asset_name']}"},
                ])
            voucher = create_voucher_db(
                conn, user=user, company_id=data.company_id,
                voucher_no=f"DEP-{data.depreciation_date.strftime('%Y%m%d')}",
                document_date=data.depreciation_date, posting_date=data.depreciation_date,
                description=f"إهلاك الأصول حتى {data.depreciation_date}", entries=entries,
                source_module="FA", external_reference=str(data.depreciation_date), post_immediately=True,
            )
            total = Decimal("0")
            for row in rows:
                total += Decimal(str(row["amount"]))
                conn.execute(
                    """INSERT INTO erp.asset_depreciation_entries
                           (group_id, company_id, asset_id, depreciation_date, amount, voucher_id)
                       VALUES (%s,%s,%s,%s,%s,%s)""",
                    (user["group_id"], data.company_id, row["asset_id"], data.depreciation_date, row["amount"], voucher["voucher_id"]),
                )
                conn.execute(
                    """UPDATE erp.fixed_assets
                       SET accumulated_depreciation=accumulated_depreciation+%s,
                           last_depreciation_date=%s WHERE asset_id=%s""",
                    (row["amount"], data.depreciation_date, row["asset_id"]),
                )
            audit(conn, user, "RUN", "DEPRECIATION", voucher["voucher_id"], data.company_id, {"assets": len(rows), "total": str(total)})
            conn.commit()
            return {"voucher_id": voucher["voucher_id"], "assets_count": len(rows), "total_amount": money(total)}
        except HTTPException:
            conn.rollback(); raise
        except Exception as exc:
            conn.rollback(); raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/users")
def list_users(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> list[dict[str, Any]]:
    require_group_admin(user)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT u.user_id, u.full_name, u.email, u.role_code, u.permissions, u.is_group_admin,
                      u.company_id, c.company_name, u.is_active, u.last_login_at, u.created_at
               FROM erp.app_users u LEFT JOIN erp.companies c ON c.company_id=u.company_id
               WHERE u.group_id=%s ORDER BY u.created_at""",
            (user["group_id"],),
        ).fetchall()


@app.post("/api/users", status_code=201)
def create_user(data: UserCreate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_group_admin(user)
    if data.company_id is None:
        raise HTTPException(status_code=422, detail="حدد شركة للمستخدم")
    with pool.connection() as conn:
        if data.company_id:
            company = conn.execute("SELECT 1 FROM erp.companies WHERE group_id=%s AND company_id=%s", (user["group_id"], data.company_id)).fetchone()
            if not company:
                raise HTTPException(status_code=422, detail="الشركة غير موجودة")
        row = conn.execute(
            """INSERT INTO erp.app_users
                   (group_id, company_id, email, password_hash, is_group_admin,
                    full_name, role_code, permissions)
               VALUES (%s,%s,%s,%s,FALSE,%s,%s,%s::jsonb)
               RETURNING user_id, full_name, email, role_code, company_id, permissions, is_active""",
            (user["group_id"], data.company_id, str(data.email).lower(), hash_password(data.password),
             data.full_name, data.role_code, json.dumps(data.permissions)),
        ).fetchone()
        audit(conn, user, "CREATE", "USER", row["user_id"], data.company_id, {"role": data.role_code})
        conn.commit()
    return row


@app.patch("/api/users/{user_id}")
def update_user(user_id: UUID, data: UserUpdate, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_group_admin(user)
    values=data.model_dump(exclude_unset=True)
    if not values: raise HTTPException(status_code=422,detail="لا توجد تعديلات")
    with pool.connection() as conn:
        target=conn.execute("SELECT * FROM erp.app_users WHERE user_id=%s AND group_id=%s",(user_id,user["group_id"])).fetchone()
        if not target: raise HTTPException(status_code=404,detail="المستخدم غير موجود")
        if target["is_group_admin"] and values.get("role_code") not in (None,"GROUP_ADMIN"):
            raise HTTPException(status_code=422,detail="لا يمكن تحويل مدير المجموعة إلى دور شركة من هذه الشاشة")
        if user_id == user["user_id"] and values.get("is_active") is False:
            raise HTTPException(status_code=422,detail="لا يمكنك إيقاف المستخدم الذي سجلت الدخول به")
        if target["is_group_admin"] and values.get("is_active") is False:
            admins=conn.execute("SELECT COUNT(*) AS n FROM erp.app_users WHERE group_id=%s AND is_group_admin=TRUE AND is_active=TRUE",(user["group_id"],)).fetchone()["n"]
            if admins<=1:
                raise HTTPException(status_code=422,detail="لا يمكن إيقاف آخر مدير نشط للمجموعة")
        if not target["is_group_admin"] and values.get("company_id") is None and "company_id" in values:
            raise HTTPException(status_code=422,detail="حدد شركة للمستخدم")
        if values.get("company_id"):
            exists=conn.execute("SELECT 1 FROM erp.companies WHERE company_id=%s AND group_id=%s",(values["company_id"],user["group_id"])).fetchone()
            if not exists: raise HTTPException(status_code=422,detail="الشركة غير موجودة")
        if "password" in values:
            values["password_hash"]=hash_password(values.pop("password"))
        if "email" in values: values["email"]=str(values["email"]).lower()
        if "permissions" in values: values["permissions"]=json.dumps(values["permissions"])
        columns=[];params=[]
        for key,value in values.items():
            if key=="permissions": columns.append("permissions=%s::jsonb")
            else: columns.append(f"{key}=%s")
            params.append(value)
        params.extend([user_id,user["group_id"]])
        try:
            row=conn.execute(f"UPDATE erp.app_users SET {', '.join(columns)} WHERE user_id=%s AND group_id=%s RETURNING user_id,full_name,email,role_code,company_id,permissions,is_active,is_group_admin",params).fetchone()
            audit(conn,user,"UPDATE","USER",user_id,row.get("company_id"),{k:v for k,v in values.items() if k!="password_hash"})
            conn.commit()
        except Exception as exc:
            conn.rollback(); raise HTTPException(status_code=400,detail=f"تعذر تعديل المستخدم: {exc}") from exc
    return row


@app.delete("/api/users/{user_id}")
def delete_user(user_id: UUID, user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    require_group_admin(user)
    if user_id==user["user_id"]:
        raise HTTPException(status_code=422,detail="لا يمكنك حذف المستخدم الذي سجلت الدخول به")
    with pool.connection() as conn:
        target=conn.execute("SELECT user_id,is_group_admin,company_id FROM erp.app_users WHERE user_id=%s AND group_id=%s",(user_id,user["group_id"])).fetchone()
        if not target: raise HTTPException(status_code=404,detail="المستخدم غير موجود")
        if target["is_group_admin"]:
            admins=conn.execute("SELECT COUNT(*) AS n FROM erp.app_users WHERE group_id=%s AND is_group_admin=TRUE AND is_active=TRUE",(user["group_id"],)).fetchone()["n"]
            if admins<=1: raise HTTPException(status_code=422,detail="لا يمكن حذف آخر مدير نشط للمجموعة")
        conn.execute("UPDATE erp.app_users SET is_active=FALSE WHERE user_id=%s",(user_id,))
        audit(conn,user,"DEACTIVATE","USER",user_id,target.get("company_id"))
        conn.commit()
    return {"message":"تم حذف المستخدم من الاستخدام مع الاحتفاظ بسجل التدقيق"}


@app.get("/api/journal-register")
def journal_register(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    company_id: UUID,
    date_from: date,
    date_to: date,
    account_id: UUID | None = None,
    voucher_status: Literal["POSTED","DRAFT","ALL"] = "POSTED",
) -> list[dict[str, Any]]:
    require_permission(user,"REPORT_VIEW")
    ensure_company_access(user,company_id)
    if date_from>date_to: raise HTTPException(status_code=422,detail="تاريخ البداية أكبر من تاريخ النهاية")
    with pool.connection() as conn:
        return conn.execute(
            """SELECT v.voucher_id,v.voucher_no,v.voucher_type,v.status,v.document_date,v.posting_date,
                      v.description AS voucher_description,v.created_at,v.posted_at,
                      COALESCE(u.full_name,u.email,'—') AS created_by_name,
                      e.line_no,e.entry_description,a.account_id,a.local_account_code AS account_code,
                      a.local_account_name AS account_name,e.debit_amount,e.credit_amount,
                      e.currency,e.exchange_rate,e.foreign_debit,e.foreign_credit
               FROM erp.journal_vouchers v
               JOIN erp.journal_entries e ON e.voucher_id=v.voucher_id AND e.company_id=v.company_id AND e.group_id=v.group_id
               JOIN erp.accounts a ON a.account_id=e.account_id AND a.company_id=e.company_id AND a.group_id=e.group_id
               LEFT JOIN erp.app_users u ON u.user_id=v.created_by
               WHERE v.group_id=%s AND v.company_id=%s
                 AND v.posting_date BETWEEN %s AND %s
                 AND (%s='ALL' OR v.status=%s)
                 AND (%s::uuid IS NULL OR e.account_id=%s::uuid)
               ORDER BY v.posting_date,v.voucher_no,e.line_no""",
            (user["group_id"],company_id,date_from,date_to,voucher_status,voucher_status,account_id,account_id),
        ).fetchall()


@app.get("/api/trial-balance")
def trial_balance(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    company_id: UUID,
    as_of_date: date = Query(default_factory=date.today),
    date_from: date | None = None,
    include_zero: bool = False,
) -> list[dict[str, Any]]:
    """Internal control report. IFRS does not prescribe a trial-balance format."""
    require_permission(user, "REPORT_VIEW")
    ensure_company_access(user, company_id)
    period_start = date_from or date(as_of_date.year, 1, 1)
    if period_start > as_of_date:
        raise HTTPException(status_code=422, detail="تاريخ البداية أكبر من تاريخ التقرير")
    with pool.connection() as conn:
        return conn.execute(
            """SELECT a.local_account_code AS account_code, a.local_account_name AS account_name,
                      ga.account_class, ga.normal_balance,
                      COALESCE(SUM(e.debit_amount) FILTER (WHERE v.posting_date < %s),0)::NUMERIC(20,4) AS opening_debit,
                      COALESCE(SUM(e.credit_amount) FILTER (WHERE v.posting_date < %s),0)::NUMERIC(20,4) AS opening_credit,
                      COALESCE(SUM(e.debit_amount) FILTER (WHERE v.posting_date BETWEEN %s AND %s),0)::NUMERIC(20,4) AS period_debit,
                      COALESCE(SUM(e.credit_amount) FILTER (WHERE v.posting_date BETWEEN %s AND %s),0)::NUMERIC(20,4) AS period_credit,
                      COALESCE(SUM(e.debit_amount) FILTER (WHERE v.voucher_id IS NOT NULL),0)::NUMERIC(20,4) AS total_debit,
                      COALESCE(SUM(e.credit_amount) FILTER (WHERE v.voucher_id IS NOT NULL),0)::NUMERIC(20,4) AS total_credit,
                      GREATEST(COALESCE(SUM(e.debit_amount-e.credit_amount) FILTER (WHERE v.voucher_id IS NOT NULL),0),0)::NUMERIC(20,4) AS closing_debit,
                      GREATEST(-COALESCE(SUM(e.debit_amount-e.credit_amount) FILTER (WHERE v.voucher_id IS NOT NULL),0),0)::NUMERIC(20,4) AS closing_credit,
                      COALESCE(SUM(e.debit_amount-e.credit_amount) FILTER (WHERE v.voucher_id IS NOT NULL),0)::NUMERIC(20,4) AS net_balance
               FROM erp.accounts a
               JOIN erp.group_accounts ga ON ga.group_account_id=a.group_account_id AND ga.group_id=a.group_id
               LEFT JOIN erp.journal_entries e ON e.account_id=a.account_id AND e.company_id=a.company_id AND e.group_id=a.group_id
               LEFT JOIN erp.journal_vouchers v ON v.voucher_id=e.voucher_id AND v.status='POSTED' AND v.posting_date<=%s
               WHERE a.group_id=%s AND a.company_id=%s AND a.is_active=TRUE
               GROUP BY a.account_id,ga.account_class,ga.normal_balance
               HAVING %s OR COALESCE(SUM(ABS(e.debit_amount)+ABS(e.credit_amount)) FILTER (WHERE v.voucher_id IS NOT NULL),0)<>0
               ORDER BY a.local_account_code""",
            (period_start,period_start,period_start,as_of_date,period_start,as_of_date,as_of_date,user["group_id"],company_id,include_zero),
        ).fetchall()


@app.get("/api/general-ledger")
def general_ledger(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, account_id: UUID, date_from: date, date_to: date) -> list[dict[str, Any]]:
    require_permission(user, "REPORT_VIEW")
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT v.posting_date, v.voucher_no, v.source_module, v.description AS voucher_description,
                      e.line_no, e.entry_description, e.debit_amount, e.credit_amount,
                      SUM(e.debit_amount-e.credit_amount) OVER (ORDER BY v.posting_date, v.created_at, e.line_no) AS running_balance
               FROM erp.journal_entries e JOIN erp.journal_vouchers v ON v.voucher_id=e.voucher_id
               WHERE e.group_id=%s AND e.company_id=%s AND e.account_id=%s
                 AND v.status='POSTED' AND v.posting_date BETWEEN %s AND %s
               ORDER BY v.posting_date, v.created_at, e.line_no""",
            (user["group_id"], company_id, account_id, date_from, date_to),
        ).fetchall()


def _safe_prior_year_date(value: date) -> date:
    try:
        return value.replace(year=value.year - 1)
    except ValueError:
        return value.replace(year=value.year - 1, day=28)


def _fiscal_year_start(conn: Connection, company_id: UUID, as_of_date: date) -> date:
    row = conn.execute(
        """SELECT start_date FROM erp.fiscal_years
           WHERE company_id=%s AND %s BETWEEN start_date AND end_date
           ORDER BY start_date DESC LIMIT 1""",
        (company_id, as_of_date),
    ).fetchone()
    return row["start_date"] if row else date(as_of_date.year, 1, 1)


def _sfp_snapshot(conn: Connection, group_id: UUID, company_id: UUID, as_of_date: date) -> dict[str, Any]:
    rows = conn.execute(
        """SELECT COALESCE(ga.ifrs_category,
                       CASE ga.account_class WHEN 'ASSET' THEN 'NONCURRENT_ASSET'
                                             WHEN 'LIABILITY' THEN 'NONCURRENT_LIABILITY'
                                             ELSE 'EQUITY' END) AS section,
                  COALESCE(ga.ifrs_line_code,ga.account_code) AS line_code,
                  COALESCE(ga.ifrs_line_name_ar,ga.account_name) AS line_name,
                  COALESCE(ga.ifrs_sort_order,999) AS sort_order,
                  SUM(CASE WHEN ga.account_class='ASSET'
                           THEN e.debit_amount-e.credit_amount
                           ELSE e.credit_amount-e.debit_amount END)::NUMERIC(20,4) AS amount
           FROM erp.journal_entries e
           JOIN erp.journal_vouchers v ON v.voucher_id=e.voucher_id AND v.status='POSTED'
           JOIN erp.accounts a ON a.account_id=e.account_id AND a.company_id=e.company_id AND a.group_id=e.group_id
           JOIN erp.group_accounts ga ON ga.group_account_id=a.group_account_id AND ga.group_id=a.group_id
           WHERE e.group_id=%s AND e.company_id=%s AND v.posting_date<=%s
             AND ga.account_class IN ('ASSET','LIABILITY','EQUITY')
           GROUP BY section,line_code,line_name,sort_order
           HAVING SUM(ABS(e.debit_amount)+ABS(e.credit_amount))<>0
           ORDER BY sort_order,line_name""",
        (group_id, company_id, as_of_date),
    ).fetchall()
    fy_start = _fiscal_year_start(conn, company_id, as_of_date)
    profit_row = conn.execute(
        """SELECT COALESCE(SUM(CASE WHEN ga.account_class='REVENUE'
                                    THEN e.credit_amount-e.debit_amount
                                    ELSE -(e.debit_amount-e.credit_amount) END),0)::NUMERIC(20,4) AS profit
           FROM erp.journal_entries e
           JOIN erp.journal_vouchers v ON v.voucher_id=e.voucher_id AND v.status='POSTED'
           JOIN erp.accounts a ON a.account_id=e.account_id
           JOIN erp.group_accounts ga ON ga.group_account_id=a.group_account_id
           WHERE e.group_id=%s AND e.company_id=%s AND v.posting_date BETWEEN %s AND %s
             AND ga.account_class IN ('REVENUE','EXPENSE')""",
        (group_id, company_id, fy_start, as_of_date),
    ).fetchone()
    current_profit = money(profit_row["profit"] if profit_row else 0)
    if current_profit:
        rows.append({"section":"EQUITY","line_code":"CURRENT_PERIOD_RESULT","line_name":"نتيجة الفترة الحالية","sort_order":590,"amount":current_profit})
    totals = {
        "current_assets": money(sum(Decimal(str(r["amount"])) for r in rows if r["section"] == "CURRENT_ASSET")),
        "noncurrent_assets": money(sum(Decimal(str(r["amount"])) for r in rows if r["section"] == "NONCURRENT_ASSET")),
        "current_liabilities": money(sum(Decimal(str(r["amount"])) for r in rows if r["section"] == "CURRENT_LIABILITY")),
        "noncurrent_liabilities": money(sum(Decimal(str(r["amount"])) for r in rows if r["section"] == "NONCURRENT_LIABILITY")),
        "equity": money(sum(Decimal(str(r["amount"])) for r in rows if r["section"] == "EQUITY")),
    }
    totals["total_assets"] = money(totals["current_assets"] + totals["noncurrent_assets"])
    totals["total_liabilities"] = money(totals["current_liabilities"] + totals["noncurrent_liabilities"])
    totals["liabilities_and_equity"] = money(totals["total_liabilities"] + totals["equity"])
    totals["difference"] = money(totals["total_assets"] - totals["liabilities_and_equity"])
    return {"rows": rows, "totals": totals, "fiscal_year_start": fy_start, "current_period_profit": current_profit}


@app.get("/api/ifrs-statement-financial-position")
def ifrs_statement_financial_position(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    company_id: UUID,
    as_of_date: date,
    comparative_date: date | None = None,
) -> dict[str, Any]:
    require_permission(user, "REPORT_VIEW")
    ensure_company_access(user, company_id)
    comparative_date = comparative_date or _safe_prior_year_date(as_of_date)
    with pool.connection() as conn:
        current = _sfp_snapshot(conn, user["group_id"], company_id, as_of_date)
        comparative = _sfp_snapshot(conn, user["group_id"], company_id, comparative_date)
        standard_row = conn.execute(
            "SELECT financial_statement_standard,presentation_currency FROM erp.corporate_groups WHERE group_id=%s",
            (user["group_id"],),
        ).fetchone()
    merged: dict[tuple[str,str], dict[str, Any]] = {}
    for row in current["rows"]:
        merged[(row["section"],row["line_code"])] = {**row, "current_amount": row["amount"], "comparative_amount": Decimal("0")}
    for row in comparative["rows"]:
        key=(row["section"],row["line_code"])
        item=merged.setdefault(key,{**row,"current_amount":Decimal("0"),"comparative_amount":Decimal("0")})
        item["comparative_amount"]=row["amount"]
    section_order={"CURRENT_ASSET":1,"NONCURRENT_ASSET":2,"CURRENT_LIABILITY":3,"NONCURRENT_LIABILITY":4,"EQUITY":5}
    rows=sorted(merged.values(),key=lambda r:(section_order.get(r["section"],9),r.get("sort_order",999),r["line_name"]))
    return {
        "standard": (standard_row or {}).get("financial_statement_standard","IAS1_2026"),
        "presentation_currency": (standard_row or {}).get("presentation_currency","EGP"),
        "as_of_date": as_of_date,
        "comparative_date": comparative_date,
        "rows": rows,
        "totals": current["totals"],
        "comparative_totals": comparative["totals"],
        "notes": [
            "عرض متداول/غير متداول وفق إعدادات التصنيف بالحسابات.",
            "تم إدراج نتيجة الفترة الحالية ضمن حقوق الملكية لأغراض الاتزان قبل قيد الإقفال.",
            "يلزم اعتماد السياسات والإفصاحات النهائية من الإدارة والمراجع الخارجي.",
        ],
    }


@app.get("/api/income-statement")
def income_statement(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, date_from: date, date_to: date) -> dict[str, Any]:
    require_permission(user, "REPORT_VIEW")
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        rows = conn.execute(
            """SELECT ga.account_class, a.local_account_code AS account_code, a.local_account_name AS account_name,
                      CASE WHEN ga.account_class='REVENUE' THEN SUM(e.credit_amount-e.debit_amount)
                           ELSE SUM(e.debit_amount-e.credit_amount) END::NUMERIC(20,4) AS amount
               FROM erp.journal_entries e JOIN erp.journal_vouchers v ON v.voucher_id=e.voucher_id
               JOIN erp.accounts a ON a.account_id=e.account_id
               JOIN erp.group_accounts ga ON ga.group_account_id=a.group_account_id
               WHERE e.group_id=%s AND e.company_id=%s AND v.status='POSTED'
                 AND v.posting_date BETWEEN %s AND %s AND ga.account_class IN ('REVENUE','EXPENSE')
               GROUP BY ga.account_class, a.account_id ORDER BY ga.account_class DESC, a.local_account_code""",
            (user["group_id"], company_id, date_from, date_to),
        ).fetchall()
    revenues = sum(Decimal(str(r["amount"])) for r in rows if r["account_class"] == "REVENUE")
    expenses = sum(Decimal(str(r["amount"])) for r in rows if r["account_class"] == "EXPENSE")
    return {"rows": rows, "total_revenue": money(revenues), "total_expense": money(expenses), "net_profit": money(revenues-expenses)}


@app.get("/api/balance-sheet")
def balance_sheet(user: Annotated[dict[str, Any], Depends(get_current_user)], company_id: UUID, as_of_date: date) -> dict[str, Any]:
    """Backward-compatible alias using the IFRS-oriented statement logic."""
    require_permission(user, "REPORT_VIEW")
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        snapshot = _sfp_snapshot(conn, user["group_id"], company_id, as_of_date)
    legacy_rows=[]
    for r in snapshot["rows"]:
        legacy_rows.append({"account_class": r["section"], "account_code": r["line_code"], "account_name": r["line_name"], "amount": r["amount"]})
    return {"rows":legacy_rows,"totals":{"ASSET":snapshot["totals"]["total_assets"],"LIABILITY":snapshot["totals"]["total_liabilities"],"EQUITY":snapshot["totals"]["equity"]},"difference":snapshot["totals"]["difference"]}


@app.get("/api/consolidated-trial-balance")
def consolidated_trial_balance(user: Annotated[dict[str, Any], Depends(get_current_user)], as_of_date: date = Query(default_factory=date.today)) -> list[dict[str, Any]]:
    require_permission(user, "REPORT_VIEW")
    require_group_admin(user)
    with pool.connection() as conn:
        rows = conn.execute(
            """SELECT ga.account_code, ga.account_name, c.company_code,
                      SUM(e.debit_amount-e.credit_amount)::NUMERIC(20,4) AS net_balance
               FROM erp.journal_entries e
               JOIN erp.journal_vouchers v ON v.voucher_id=e.voucher_id
               JOIN erp.accounts a ON a.account_id=e.account_id
               JOIN erp.group_accounts ga ON ga.group_account_id=a.group_account_id
               JOIN erp.companies c ON c.company_id=e.company_id
               WHERE e.group_id=%s AND v.status='POSTED' AND v.posting_date<=%s
               GROUP BY ga.group_account_id, c.company_code ORDER BY ga.account_code, c.company_code""",
            (user["group_id"], as_of_date),
        ).fetchall()
    pivot: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = pivot.setdefault(row["account_code"], {"account_code": row["account_code"], "account_name": row["account_name"], "companies": {}, "consolidated_net": 0})
        amount = float(row["net_balance"])
        item["companies"][row["company_code"]] = amount
        item["consolidated_net"] += amount
    return list(pivot.values())


@app.get("/api/audit-log")
def audit_log(user: Annotated[dict[str, Any], Depends(get_current_user)], limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    require_group_admin(user)
    with pool.connection() as conn:
        return conn.execute(
            """SELECT al.audit_id, al.created_at, al.action, al.entity_type, al.entity_id,
                      al.company_id, al.details, u.full_name, u.email, c.company_name
               FROM erp.audit_log al LEFT JOIN erp.app_users u ON u.user_id=al.user_id
               LEFT JOIN erp.companies c ON c.company_id=al.company_id
               WHERE al.group_id=%s ORDER BY al.created_at DESC LIMIT %s""",
            (user["group_id"], limit),
        ).fetchall()
