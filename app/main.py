from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, Field
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
AUTO_MIGRATE = os.environ.get("AUTO_MIGRATE", "true").lower() == "true"
ALGORITHM = "HS256"

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
        "company_id": str(user["company_id"]) if user["company_id"] else None,
        "is_group_admin": bool(user["is_group_admin"]),
        "email": user["email"],
        "iat": now,
        "exp": now + timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def migrate_and_seed() -> None:
    schema_path = Path(__file__).resolve().parent.parent / "database" / "001_schema.sql"
    with pool.connection() as conn:
        if AUTO_MIGRATE:
            conn.execute(schema_path.read_text(encoding="utf-8"))
            conn.commit()

        admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com").lower().strip()
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if len(admin_password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters")

        group_code = os.environ.get("ADMIN_GROUP_CODE", "GROUP001").strip()
        group_name = os.environ.get("ADMIN_GROUP_NAME", "My Holding Group").strip()

        group = conn.execute(
            """
            INSERT INTO erp.corporate_groups (group_code, group_name)
            VALUES (%s, %s)
            ON CONFLICT (group_code)
            DO UPDATE SET group_name = EXCLUDED.group_name
            RETURNING group_id
            """,
            (group_code, group_name),
        ).fetchone()

        existing = conn.execute(
            "SELECT user_id FROM erp.app_users WHERE group_id=%s AND email=%s",
            (group["group_id"], admin_email),
        ).fetchone()
        if not existing:
            conn.execute(
                """
                INSERT INTO erp.app_users
                    (group_id, email, password_hash, is_group_admin)
                VALUES (%s, %s, %s, TRUE)
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
    title="Holding ERP Cloud Starter",
    version="0.1.0",
    description="Starter API for multi-company General Ledger",
    lifespan=lifespan,
)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CompanyCreate(BaseModel):
    company_code: str = Field(min_length=1, max_length=30)
    company_name: str = Field(min_length=1, max_length=250)
    company_kind: str = Field(pattern="^(HOLDING|SUBSIDIARY|ELIMINATION)$")
    parent_company_id: UUID | None = None
    ownership_percent: float = Field(default=100, gt=0, le=100)
    functional_currency: str = Field(default="EGP", min_length=3, max_length=3)


class GroupAccountCreate(BaseModel):
    account_code: str = Field(min_length=1, max_length=50)
    account_name: str = Field(min_length=1, max_length=250)
    account_class: str = Field(pattern="^(ASSET|LIABILITY|EQUITY|REVENUE|EXPENSE)$")
    normal_balance: str = Field(pattern="^(DEBIT|CREDIT)$")
    parent_group_account_id: UUID | None = None
    is_postable: bool = True
    is_intercompany: bool = False
    intercompany_role: str = "NONE"


class CompanyAccountCreate(BaseModel):
    company_id: UUID
    group_account_id: UUID
    local_account_code: str = Field(min_length=1, max_length=50)
    local_account_name: str = Field(min_length=1, max_length=250)


class VoucherEntryCreate(BaseModel):
    account_id: UUID
    description: str | None = None
    debit_amount: float = Field(default=0, ge=0)
    credit_amount: float = Field(default=0, ge=0)
    counterparty_company_id: UUID | None = None
    intercompany_reference: str | None = None


class VoucherCreate(BaseModel):
    company_id: UUID
    voucher_no: str = Field(min_length=1, max_length=50)
    document_date: date
    posting_date: date
    description: str | None = None
    entries: list[VoucherEntryCreate] = Field(min_length=2)
    post_immediately: bool = True


def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        payload["user_id"] = UUID(payload["sub"])
        payload["group_id"] = UUID(payload["group_id"])
        payload["company_id"] = UUID(payload["company_id"]) if payload.get("company_id") else None
        return payload
    except (jwt.PyJWTError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def require_group_admin(user: dict[str, Any]) -> None:
    if not user["is_group_admin"]:
        raise HTTPException(status_code=403, detail="Group administrator permission required")


def ensure_company_access(user: dict[str, Any], company_id: UUID) -> None:
    if not user["is_group_admin"] and user["company_id"] != company_id:
        raise HTTPException(status_code=403, detail="No access to this company")


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


@app.post("/api/auth/login")
def login(data: LoginRequest) -> dict[str, Any]:
    with pool.connection() as conn:
        user = conn.execute(
            """
            SELECT user_id, group_id, company_id, email, password_hash, is_group_admin
            FROM erp.app_users
            WHERE LOWER(email)=LOWER(%s) AND is_active=TRUE
            """,
            (data.email,),
        ).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get("/api/me")
def me(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, Any]:
    return {
        "user_id": str(user["user_id"]),
        "email": user["email"],
        "group_id": str(user["group_id"]),
        "company_id": str(user["company_id"]) if user["company_id"] else None,
        "is_group_admin": user["is_group_admin"],
    }


@app.get("/api/companies")
def list_companies(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        if user["is_group_admin"]:
            rows = conn.execute(
                """
                SELECT company_id, company_code, company_name, company_kind,
                       parent_company_id, ownership_percent, functional_currency
                FROM erp.companies
                WHERE group_id=%s AND is_active=TRUE
                ORDER BY company_code
                """,
                (user["group_id"],),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT company_id, company_code, company_name, company_kind,
                       parent_company_id, ownership_percent, functional_currency
                FROM erp.companies
                WHERE group_id=%s AND company_id=%s AND is_active=TRUE
                """,
                (user["group_id"], user["company_id"]),
            ).fetchall()
    return rows


@app.post("/api/companies", status_code=status.HTTP_201_CREATED)
def create_company(
    data: CompanyCreate,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_group_admin(user)
    if data.company_kind != "HOLDING" and data.parent_company_id is None:
        raise HTTPException(status_code=422, detail="Subsidiary/elimination company requires parent_company_id")
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO erp.companies
                (group_id, company_code, company_name, company_kind,
                 parent_company_id, ownership_percent, functional_currency)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
            """,
            (
                user["group_id"], data.company_code, data.company_name,
                data.company_kind, data.parent_company_id,
                data.ownership_percent, data.functional_currency.upper(),
            ),
        ).fetchone()
        conn.commit()
    return row


@app.get("/api/group-accounts")
def list_group_accounts(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT group_account_id, account_code, account_name, account_class,
                   normal_balance, parent_group_account_id, is_postable,
                   is_intercompany, intercompany_role
            FROM erp.group_accounts
            WHERE group_id=%s AND is_active=TRUE
            ORDER BY account_code
            """,
            (user["group_id"],),
        ).fetchall()


@app.post("/api/group-accounts", status_code=201)
def create_group_account(
    data: GroupAccountCreate,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    require_group_admin(user)
    if data.is_intercompany and data.intercompany_role == "NONE":
        raise HTTPException(status_code=422, detail="Intercompany role is required")
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO erp.group_accounts
                (group_id, account_code, account_name, account_class, normal_balance,
                 parent_group_account_id, is_postable, is_intercompany, intercompany_role)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
            """,
            (
                user["group_id"], data.account_code, data.account_name,
                data.account_class, data.normal_balance, data.parent_group_account_id,
                data.is_postable, data.is_intercompany, data.intercompany_role,
            ),
        ).fetchone()
        conn.commit()
    return row


@app.get("/api/accounts")
def list_accounts(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    company_id: UUID,
) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT a.account_id, a.local_account_code, a.local_account_name,
                   ga.account_code AS group_account_code,
                   ga.account_name AS group_account_name,
                   ga.is_intercompany, ga.intercompany_role
            FROM erp.accounts a
            JOIN erp.group_accounts ga
              ON ga.group_account_id=a.group_account_id AND ga.group_id=a.group_id
            WHERE a.group_id=%s AND a.company_id=%s AND a.is_active=TRUE
            ORDER BY a.local_account_code
            """,
            (user["group_id"], company_id),
        ).fetchall()


@app.post("/api/accounts", status_code=201)
def create_account(
    data: CompanyAccountCreate,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    ensure_company_access(user, data.company_id)
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO erp.accounts
                (group_id, company_id, group_account_id, local_account_code, local_account_name)
            VALUES (%s,%s,%s,%s,%s)
            RETURNING *
            """,
            (
                user["group_id"], data.company_id, data.group_account_id,
                data.local_account_code, data.local_account_name,
            ),
        ).fetchone()
        conn.commit()
    return row


@app.post("/api/vouchers", status_code=201)
def create_voucher(
    data: VoucherCreate,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    ensure_company_access(user, data.company_id)
    debit = round(sum(e.debit_amount for e in data.entries), 4)
    credit = round(sum(e.credit_amount for e in data.entries), 4)
    if debit <= 0 or debit != credit:
        raise HTTPException(status_code=422, detail=f"Voucher is not balanced: debit={debit}, credit={credit}")
    for entry in data.entries:
        if (entry.debit_amount > 0) == (entry.credit_amount > 0):
            raise HTTPException(status_code=422, detail="Each entry must be debit or credit, not both")

    with pool.connection() as conn:
        try:
            voucher = conn.execute(
                """
                INSERT INTO erp.journal_vouchers
                    (group_id, company_id, voucher_no, document_date, posting_date,
                     description, created_by, status, posted_by, posted_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING voucher_id, voucher_no, status, posting_date
                """,
                (
                    user["group_id"], data.company_id, data.voucher_no,
                    data.document_date, data.posting_date, data.description,
                    user["user_id"], "DRAFT", None, None,
                ),
            ).fetchone()
            for line_no, entry in enumerate(data.entries, start=1):
                account = conn.execute(
                    """
                    SELECT ga.is_intercompany
                    FROM erp.accounts a
                    JOIN erp.group_accounts ga
                      ON ga.group_account_id=a.group_account_id AND ga.group_id=a.group_id
                    WHERE a.account_id=%s AND a.company_id=%s AND a.group_id=%s
                    """,
                    (entry.account_id, data.company_id, user["group_id"]),
                ).fetchone()
                if not account:
                    raise HTTPException(status_code=422, detail=f"Invalid account: {entry.account_id}")
                if account["is_intercompany"] and not entry.counterparty_company_id:
                    raise HTTPException(status_code=422, detail="Counterparty is required for intercompany account")
                if account["is_intercompany"] and not entry.intercompany_reference:
                    raise HTTPException(status_code=422, detail="Intercompany reference is required")
                conn.execute(
                    """
                    INSERT INTO erp.journal_entries
                        (voucher_id, group_id, company_id, account_id, line_no,
                         entry_description, debit_amount, credit_amount,
                         counterparty_company_id, intercompany_reference)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        voucher["voucher_id"], user["group_id"], data.company_id,
                        entry.account_id, line_no, entry.description,
                        entry.debit_amount, entry.credit_amount,
                        entry.counterparty_company_id, entry.intercompany_reference,
                    ),
                )
            if data.post_immediately:
                conn.execute(
                    "SELECT erp.post_voucher(%s, %s)",
                    (voucher["voucher_id"], user["user_id"]),
                )
                voucher["status"] = "POSTED"
            conn.commit()
            return voucher
        except HTTPException:
            conn.rollback()
            raise
        except Exception as exc:
            conn.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/trial-balance")
def trial_balance(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    company_id: UUID,
    as_of_date: date = Query(default_factory=date.today),
) -> list[dict[str, Any]]:
    ensure_company_access(user, company_id)
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT
                a.local_account_code AS account_code,
                a.local_account_name AS account_name,
                SUM(e.debit_amount)::NUMERIC(20,4) AS total_debit,
                SUM(e.credit_amount)::NUMERIC(20,4) AS total_credit,
                SUM(e.debit_amount-e.credit_amount)::NUMERIC(20,4) AS net_balance
            FROM erp.journal_entries e
            JOIN erp.journal_vouchers v
              ON v.voucher_id=e.voucher_id AND v.company_id=e.company_id AND v.group_id=e.group_id
            JOIN erp.accounts a
              ON a.account_id=e.account_id AND a.company_id=e.company_id AND a.group_id=e.group_id
            WHERE e.group_id=%s AND e.company_id=%s
              AND v.status='POSTED' AND v.posting_date <= %s
            GROUP BY a.account_id, a.local_account_code, a.local_account_name
            HAVING SUM(e.debit_amount) <> 0 OR SUM(e.credit_amount) <> 0
            ORDER BY a.local_account_code
            """,
            (user["group_id"], company_id, as_of_date),
        ).fetchall()


@app.get("/api/consolidated-trial-balance")
def consolidated_trial_balance(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    as_of_date: date = Query(default_factory=date.today),
) -> list[dict[str, Any]]:
    require_group_admin(user)
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT
                ga.account_code,
                ga.account_name,
                c.company_code,
                SUM(e.debit_amount-e.credit_amount)::NUMERIC(20,4) AS net_balance
            FROM erp.journal_entries e
            JOIN erp.journal_vouchers v
              ON v.voucher_id=e.voucher_id AND v.company_id=e.company_id AND v.group_id=e.group_id
            JOIN erp.accounts a
              ON a.account_id=e.account_id AND a.company_id=e.company_id AND a.group_id=e.group_id
            JOIN erp.group_accounts ga
              ON ga.group_account_id=a.group_account_id AND ga.group_id=a.group_id
            JOIN erp.companies c
              ON c.company_id=e.company_id AND c.group_id=e.group_id
            WHERE e.group_id=%s AND v.status='POSTED' AND v.posting_date <= %s
            GROUP BY ga.group_account_id, ga.account_code, ga.account_name, c.company_code
            ORDER BY ga.account_code, c.company_code
            """,
            (user["group_id"], as_of_date),
        ).fetchall()

    pivot: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = row["account_code"]
        item = pivot.setdefault(
            key,
            {"account_code": key, "account_name": row["account_name"], "companies": {}, "consolidated_net": 0},
        )
        amount = float(row["net_balance"])
        item["companies"][row["company_code"]] = amount
        item["consolidated_net"] += amount
    return list(pivot.values())
