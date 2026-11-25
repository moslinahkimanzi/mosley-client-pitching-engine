"""Thin async layer over SQLAlchemy Core so SQLite-style call sites port 1:1.

    async with tx() as c:
        row = await c.one("SELECT * FROM users WHERE email=?", (email,))
        rows = await c.all("SELECT * FROM leads WHERE user_id=?", (uid,))
        await c.execute("UPDATE leads SET score=? WHERE id=?", (5, lid))

Rules when porting a query:
* '?' placeholders are converted to bound parameters. Do not put a literal '?'
  inside a SQL string.
* Pass datetime objects (tz-aware UTC) for timestamptz columns, never ISO text.
* INSERT OR IGNORE  -> INSERT ... ON CONFLICT DO NOTHING
* INSERT OR REPLACE -> INSERT ... ON CONFLICT (...) DO UPDATE SET ...
* cursor.rowcount works via the returned result: res.rowcount
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from backend.db.session import engine


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _convert(sql: str, params: Any) -> tuple[str, dict[str, Any]]:
    if params is None:
        return sql, {}
    if isinstance(params, Mapping):
        return sql, dict(params)
    values = list(params) if isinstance(params, Sequence) and not isinstance(params, str) else [params]
    out: list[str] = []
    bound: dict[str, Any] = {}
    idx = 0
    for ch in sql:
        if ch == "?":
            name = f"p{idx}"
            bound[name] = values[idx]
            out.append(":" + name)
            idx += 1
        else:
            out.append(ch)
    if idx != len(values):
        raise ValueError(f"{idx} placeholders but {len(values)} parameters")
    return "".join(out), bound


class Tx:
    def __init__(self, conn: AsyncConnection) -> None:
        self.conn = conn

    async def execute(self, sql: str, params: Any = None):
        s, p = _convert(sql, params)
        return await self.conn.execute(text(s), p)

    async def one(self, sql: str, params: Any = None) -> dict[str, Any] | None:
        res = await self.execute(sql, params)
        row = res.mappings().first()
        return dict(row) if row is not None else None

    async def all(self, sql: str, params: Any = None) -> list[dict[str, Any]]:
        res = await self.execute(sql, params)
        return [dict(r) for r in res.mappings().all()]

    async def scalar(self, sql: str, params: Any = None) -> Any:
        res = await self.execute(sql, params)
        return res.scalar()


@asynccontextmanager
async def tx() -> AsyncIterator[Tx]:
    """One transaction: commits on success, rolls back on any exception."""
    async with engine.begin() as conn:
        yield Tx(conn)
