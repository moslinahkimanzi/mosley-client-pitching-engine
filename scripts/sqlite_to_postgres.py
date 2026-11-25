#!/usr/bin/env python3
"""One-off copy of MCAS SQLite data into the PostgreSQL schema.

Usage (from the repo root, venv active, DATABASE_URL set):
  python scripts/sqlite_to_postgres.py --sqlite /tmp/mcas-copy.db --dry-run
  python scripts/sqlite_to_postgres.py --sqlite /tmp/mcas-copy.db --truncate

Everything runs in ONE transaction. --dry-run rolls it back after the report.
The SQLite file is opened read-only. Nothing in backend/app.py is imported.

Skipped on purpose (short-lived rows): security_rate_limits,
google_auth_nonces, oauth_states. Expired sessions are skipped too.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Integer, text  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from backend.models.core import Base  # noqa: E402

UTC = timezone.utc
# Fixed namespace: the same old id always maps to the same UUID.
NS = uuid.UUID("6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f")

# Parents first. emptynull: '' becomes NULL (keeps UNIQUE columns usable).
TABLES = [
    ("users", {"uuid": ["id"]}),
    ("workspace_preferences", {"uuid": ["user_id"]}),
    ("sessions", {"uuid": ["user_id"]}),
    ("integrations", {"uuid": ["user_id"]}),
    ("leads", {"uuid": ["id", "user_id"]}),
    ("drafts", {"uuid": ["id", "user_id", "lead_id", "audit_report_id"]}),
    ("followups", {"uuid": ["id", "user_id", "lead_id"]}),
    ("proposals", {"uuid": ["id", "user_id", "lead_id"]}),
    ("website_audit_reports", {"uuid": ["id", "user_id", "lead_id"]}),
    ("audit_log", {"uuid": ["user_id"]}),
    ("customer_feedback", {"uuid": ["id", "user_id"]}),
    ("improvement_reviews", {"uuid": ["id", "created_by"]}),
    ("improvement_review_feedback", {"uuid": ["review_id", "feedback_id"]}),
    ("billing_accounts", {"uuid": ["user_id"]}),
    ("billing_orders", {"uuid": ["id", "user_id"], "emptynull": ["provider_transaction_id"]}),
    ("billing_webhook_events", {"uuid": []}),
    ("billing_credit_ledger", {"uuid": ["id", "user_id"]}),
]


class DryRun(Exception):
    pass


def to_ts(v):
    if v is None or str(v).strip() == "":
        return None
    s = str(v).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_json(v, col):
    default = [] if "recommendations" in col else {}
    if v is None or str(v).strip() == "":
        return default
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return {"raw": str(v)}


def make_uuid_converter(idmap):
    def conv(v):
        if v is None or str(v).strip() == "":
            return None
        s = str(v).strip()
        try:
            return uuid.UUID(s)
        except ValueError:
            new = uuid.uuid5(NS, s)
            idmap[s] = str(new)
            return new
    return conv


def load_rows(src, name):
    exists = src.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    if not exists:
        return []
    return [dict(r) for r in src.execute(f'SELECT * FROM "{name}"')]


def convert_row(name, spec, row, tbl, uuid_conv, stats, now_dt):
    colnames = set(tbl.c.keys())
    out = {}
    for col, v in row.items():
        if col not in colnames:
            continue  # legacy column that no longer exists
        ctype = tbl.c[col].type
        if col in spec["uuid"]:
            v = uuid_conv(v)
        elif col in spec.get("emptynull", []):
            v = None if v is None or str(v).strip() == "" else str(v)
        elif isinstance(ctype, DateTime):
            parsed = to_ts(v)
            if parsed is None and v not in (None, ""):
                stats["bad_timestamps"] += 1
            if parsed is None and not tbl.c[col].nullable:
                parsed = now_dt
                stats["fixed_timestamps"] += 1
            v = parsed
        elif isinstance(ctype, JSONB):
            v = to_json(v, col)
        elif isinstance(ctype, Boolean):
            v = None if v is None else bool(int(v))
        elif isinstance(ctype, (Integer, BigInteger)):
            v = None if v is None else int(v)
        elif isinstance(ctype, Float):
            v = None if v is None else float(v)
        out[col] = v

    if name == "users" and out.get("email"):
        out["email"] = str(out["email"]).strip().lower()
    if name == "billing_accounts":
        out["plan_code"] = out.get("plan_code") or "free"
        for c in ("monthly_credits", "purchased_credits"):
            val = out.get(c) or 0
            if val < 0:
                stats["clamped_negative"] += 1
                val = 0
            out[c] = val
    if "updated_at" in colnames and "updated_at" not in out and "created_at" in out:
        out["updated_at"] = out["created_at"]
    return out


async def run(args):
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL is not set")
    sqlite_path = Path(args.sqlite)
    if not sqlite_path.exists():
        sys.exit(f"SQLite file not found: {sqlite_path}")

    src = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    admins = {e.strip().lower() for e in (args.admin_emails or "").split(",") if e.strip()}
    idmap: dict[str, str] = {}
    uuid_conv = make_uuid_converter(idmap)
    now_dt = datetime.now(UTC)
    now_epoch = int(time.time())
    all_stats: dict[str, Counter] = {}
    loaded_ids: dict[str, set] = {}
    seen_emails: set[str] = set()

    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            names = [t for t, _ in TABLES]
            if args.truncate:
                quoted = ", ".join(f'"{n}"' for n in names)
                await conn.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))
            else:
                n = (await conn.execute(text("SELECT count(*) FROM users"))).scalar()
                if n:
                    sys.exit("users table is not empty. Re-run with --truncate to replace it.")

            for name, spec in TABLES:
                tbl = Base.metadata.tables[name]
                stats = Counter()
                all_stats[name] = stats
                rows = load_rows(src, name)
                stats["source"] = len(rows)
                pk_cols = [c.key for c in tbl.primary_key.columns]
                loaded_ids[name] = set()
                batch = []
                fks = {
                    c.key: list(c.foreign_keys)[0].column.table.name
                    for c in tbl.c
                    if c.foreign_keys
                }

                for row in rows:
                    if name == "sessions" and int(row.get("expires_at") or 0) < now_epoch:
                        stats["skipped_expired"] += 1
                        continue
                    out = convert_row(name, spec, row, tbl, uuid_conv, stats, now_dt)

                    if name == "users":
                        email = out.get("email")
                        if email in seen_emails:
                            raise RuntimeError(f"Duplicate email after lowercasing: {email}")
                        seen_emails.add(email)
                        out["is_admin"] = email in admins
                        out["is_verified"] = bool(args.verify_existing)

                    skip = False
                    for col, parent in fks.items():
                        val = out.get(col)
                        if val is not None and val not in loaded_ids.get(parent, set()):
                            if tbl.c[col].nullable:
                                out[col] = None
                                stats["orphan_fk_nulled"] += 1
                            else:
                                skip = True
                                stats["skipped_orphan"] += 1
                                break
                    if skip:
                        continue

                    missing = [
                        c.key for c in tbl.c
                        if not c.nullable and c.key in out and out[c.key] is None
                    ]
                    if missing:
                        stats["skipped_null"] += 1
                        continue

                    if len(pk_cols) == 1 and pk_cols[0] in out:
                        loaded_ids[name].add(out[pk_cols[0]])
                    batch.append(out)

                for i in range(0, len(batch), 500):
                    await conn.execute(tbl.insert(), batch[i:i + 500])
                stats["loaded"] = len(batch)

            await conn.execute(text(
                "SELECT setval(pg_get_serial_sequence('audit_log','id'), "
                "COALESCE((SELECT MAX(id) FROM audit_log),0)+1, false)"
            ))

            print(f"\n{'table':32} {'source':>7} {'loaded':>7}  notes")
            ok = True
            for name, _ in TABLES:
                st = all_stats[name]
                pg_count = (await conn.execute(text(f'SELECT count(*) FROM "{name}"'))).scalar()
                if pg_count != st["loaded"]:
                    ok = False
                notes = ", ".join(
                    f"{k}={v}" for k, v in st.items() if k not in ("source", "loaded")
                )
                print(f"{name:32} {st['source']:>7} {st['loaded']:>7}  {notes}")

            sq = src.execute(
                "SELECT COALESCE(SUM(monthly_credits),0), COALESCE(SUM(purchased_credits),0) "
                "FROM billing_accounts"
            ).fetchone()
            pg = (await conn.execute(text(
                "SELECT COALESCE(SUM(monthly_credits),0), COALESCE(SUM(purchased_credits),0) "
                "FROM billing_accounts"
            ))).one()
            print(f"\ncredit totals  sqlite monthly/purchased: {tuple(sq)}  postgres: {tuple(pg)}")
            print(f"ids remapped to deterministic UUIDs: {len(idmap)}")

            if idmap:
                out_path = ROOT / "data" / "id_map.json"
                out_path.parent.mkdir(exist_ok=True)
                out_path.write_text(json.dumps(idmap, indent=1))
                os.chmod(out_path, 0o600)
                print(f"old->new id map written to {out_path}")

            if not ok:
                raise RuntimeError("Row count mismatch between loaded rows and Postgres")
            if args.dry_run:
                raise DryRun
        print("\nCOMMITTED.")
    except DryRun:
        print("\nDRY RUN: everything rolled back.")
    finally:
        await engine.dispose()
        src.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", default=os.environ.get(
        "MCAS_DATABASE_PATH", str(ROOT / "data" / "mcas.db")))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--truncate", action="store_true",
                    help="empty the target tables first")
    ap.add_argument("--verify-existing", action="store_true",
                    help="set is_verified=true for every migrated user")
    ap.add_argument("--admin-emails", default=os.environ.get("MCAS_ADMIN_EMAILS", ""),
                    help="comma-separated emails that get is_admin=true")
    asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    main()
